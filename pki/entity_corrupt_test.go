package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// logReject 按“输入 / 判定依据 / 最终结论”打印拒绝类测试日志，
// 并断言错误链中包含 want 且不包含其他可混淆的哨兵错误。
func logReject(t *testing.T, input, basis string, got, want error, notConfused ...error) {
	t.Helper()
	t.Logf("输入: %s | 判定依据: %s | 最终结论: %v", input, basis, got)
	if !errors.Is(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for _, other := range notConfused {
		if errors.Is(got, other) {
			t.Fatalf("错误原因被混淆: got %v, 不应包含 %v", got, other)
		}
	}
}

// writeCorruptState 在 dir 中准备一份含已登记实体 "web" 的正常状态，
// 然后应用 corrupt 修改并落盘，返回目录供重新加载。
func writeCorruptState(t *testing.T, corrupt func(st *state)) string {
	t.Helper()
	dir := t.TempDir()
	ca, err := NewCA(dir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	mustRegister(t, ca, "web")

	data, err := os.ReadFile(filepath.Join(dir, stateFileName))
	if err != nil {
		t.Fatal(err)
	}
	var st state
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatal(err)
	}
	corrupt(&st)
	out, err := json.MarshalIndent(&st, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, stateFileName), out, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// entityOf 取出状态中实体 "web" 的记录供修改。
func entityOf(st *state) *entityRecord {
	rec := st.Entities["web"]
	return &rec
}

// putEntity 把修改后的记录写回状态。
func putEntity(st *state, rec *entityRecord) {
	st.Entities["web"] = *rec
}

// TestCorruptEntityRecordRejectedOnLoad 覆盖加载路径：
// 实体记录各类损坏都必须让加载明确失败，且原因可一眼区分为“状态损坏”。
func TestCorruptEntityRecordRejectedOnLoad(t *testing.T) {
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		corrupt func(st *state)
	}{
		{"当前密钥代在密钥历史中找不到", func(st *state) {
			rec := entityOf(st)
			rec.CurrentEpoch = 99
			putEntity(st, rec)
		}},
		{"密钥历史缺了一代", func(st *state) {
			rec := entityOf(st)
			rec.Keys = append(rec.Keys, rec.Keys[0]) // 先凑出两代再删第一代
			rec.Keys[1].Epoch = 2
			rec.CurrentEpoch = 2
			rec.Keys = rec.Keys[1:] // 历史只剩第 2 代，缺第 1 代
			putEntity(st, rec)
		}},
		{"密钥历史出现重复的代", func(st *state) {
			rec := entityOf(st)
			dup := rec.Keys[0]
			rec.Keys = append(rec.Keys, dup) // 两代都是 epoch 1
			rec.CurrentEpoch = 2
			putEntity(st, rec)
		}},
		{"密钥代超出当前代范围", func(st *state) {
			rec := entityOf(st)
			extra := rec.Keys[0]
			extra.Epoch = 5
			rec.Keys = append(rec.Keys, extra, rec.Keys[0])
			rec.Keys[1] = extra
			rec.Keys[2].Epoch = 2
			rec.CurrentEpoch = 3 // 历史 {1,5,2}：代 5 超出 [1,3]
			putEntity(st, rec)
		}},
		{"密钥材料长度非法", func(st *state) {
			rec := entityOf(st)
			rec.Keys[0].Public = rec.Keys[0].Public[:16]
			putEntity(st, rec)
		}},
		{"公钥与私钥不对应", func(st *state) {
			rec := entityOf(st)
			rec.Keys[0].Public = otherPub
			putEntity(st, rec)
		}},
		{"当前密钥代为 0", func(st *state) {
			rec := entityOf(st)
			rec.CurrentEpoch = 0
			putEntity(st, rec)
		}},
		{"密钥历史为空", func(st *state) {
			rec := entityOf(st)
			rec.Keys = nil
			putEntity(st, rec)
		}},
		{"授权用途含未知位", func(st *state) {
			rec := entityOf(st)
			rec.AllowedUsages = 0x80
			putEntity(st, rec)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeCorruptState(t, tc.corrupt)
			_, err := NewCA(dir)
			logReject(t, "加载含损坏实体记录的状态: "+tc.name,
				"加载时校验实体记录内部一致性", err, ErrStoreCorrupt,
				ErrStoreVersion, ErrEntityNotRegistered)
			// 结论稳定：同一损坏状态重复加载必须给出相同拒绝。
			_, err2 := NewCA(dir)
			logReject(t, "重复加载同一损坏状态", "拒绝结论不随次数变化", err2, ErrStoreCorrupt)
		})
	}
}

// tamperEntityInMemory 直接修改内存中的实体记录（模拟运行期记录被改坏）。
func tamperEntityInMemory(t *testing.T, ca *CA, identity string, fn func(*entityRecord)) {
	t.Helper()
	ca.mu.Lock()
	defer ca.mu.Unlock()
	rec := ca.st.Entities[identity]
	fn(&rec)
	ca.st.Entities[identity] = rec
}

// TestIssueRejectsCorruptEntityRecord 覆盖签发路径：
// 实体记录损坏时不允许把证书当作签发成功返回，
// 杜绝“签发成功、紧接着自己的校验判 UNKNOWN_SUBJECT”的自相矛盾。
func TestIssueRejectsCorruptEntityRecord(t *testing.T) {
	ca := newTestCA(t)
	mid := testBase.Add(time.Hour)
	mustRegister(t, ca, "web")

	good, err := ca.Issue(validRequest("web", UsageSign))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	logVerdict(t, "损坏前签发的证书", "实体记录一致", ca.Verify(good, mid, UsageSign), VerdictOK)

	// 把当前密钥代改到历史中不存在的代。
	tamperEntityInMemory(t, ca, "web", func(rec *entityRecord) { rec.CurrentEpoch = 99 })
	cert, err := ca.Issue(validRequest("web", UsageSign))
	if cert != nil {
		t.Fatalf("记录损坏时签发不得返回证书: %+v", cert)
	}
	logReject(t, "实体当前密钥代被改为 99 后签发",
		"签发前校验实体记录一致性，当前代不在历史中", err, ErrStoreCorrupt,
		ErrUsageNotAuthorized, ErrEntityNotRegistered, ErrUsageConflict)

	// 拒绝签发不得改变已确认证书的判定结论。
	logVerdict(t, "损坏后再次校验此前签发的证书", "实体记录已损坏，不作为可信判定依据",
		ca.Verify(good, mid, UsageSign), VerdictUnknownSubject)
}

// TestVerifyRejectsCorruptEntityRecord 覆盖校验路径：
// 实体记录被改坏到密钥代对不上时，校验不得放行任何依赖该记录的证书。
func TestVerifyRejectsCorruptEntityRecord(t *testing.T) {
	ca := newTestCA(t)
	mid := testBase.Add(time.Hour)
	mustRegister(t, ca, "web")
	cert, err := ca.Issue(validRequest("web", UsageSign))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	logVerdict(t, "损坏前校验", "实体记录一致", ca.Verify(cert, mid, UsageSign), VerdictOK)

	corruptions := []struct {
		name string
		fn   func(*entityRecord)
	}{
		{"当前密钥代与历史对不上", func(rec *entityRecord) { rec.CurrentEpoch = 42 }},
		{"密钥历史被清空", func(rec *entityRecord) { rec.Keys = nil }},
		{"密钥材料被改坏", func(rec *entityRecord) { rec.Keys[0].Private = rec.Keys[0].Private[:10] }},
	}
	// 每轮先恢复完好记录再施加损坏，避免损坏累积。
	var good entityRecord
	ca.mu.Lock()
	good = ca.st.Entities["web"]
	good.Keys = append([]entityKeyRecord(nil), good.Keys...)
	ca.mu.Unlock()
	for _, tc := range corruptions {
		tamperEntityInMemory(t, ca, "web", func(rec *entityRecord) {
			*rec = good
			rec.Keys = append([]entityKeyRecord(nil), good.Keys...)
			tc.fn(rec)
		})
		v := ca.Verify(cert, mid, UsageSign)
		logVerdict(t, "实体记录损坏后校验: "+tc.name,
			"损坏记录不作为可信判定依据，不得放行", v, VerdictUnknownSubject)
		if v.OK() {
			t.Fatalf("损坏记录下校验不得通过: %s", tc.name)
		}
	}
}

// TestCorruptEntityRecordConcurrent 覆盖并发路径：
// 登记、签发、轮换、授权调整、校验并发交织时，对损坏记录的拒绝结论必须稳定。
func TestCorruptEntityRecordConcurrent(t *testing.T) {
	ca := newTestCA(t)
	mid := testBase.Add(time.Hour)
	mustRegister(t, ca, "web")
	cert, err := ca.Issue(validRequest("web", UsageSign))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	tamperEntityInMemory(t, ca, "web", func(rec *entityRecord) { rec.CurrentEpoch = 99 })

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers*5)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := ca.Issue(validRequest("web", UsageSign)); !errors.Is(err, ErrStoreCorrupt) {
				errs <- fmt.Errorf("并发签发: got %v, want %v", err, ErrStoreCorrupt)
			}
			if v := ca.Verify(cert, mid, UsageSign); v != VerdictUnknownSubject {
				errs <- fmt.Errorf("并发校验: got %s, want %s", v, VerdictUnknownSubject)
			}
			if _, err := ca.RotateEntityKey("web"); !errors.Is(err, ErrStoreCorrupt) {
				errs <- fmt.Errorf("并发轮换: got %v, want %v", err, ErrStoreCorrupt)
			}
			if err := ca.SetEntityUsages("web", UsageSign); !errors.Is(err, ErrStoreCorrupt) {
				errs <- fmt.Errorf("并发授权调整: got %v, want %v", err, ErrStoreCorrupt)
			}
			if _, err := ca.EntityUsages("web"); !errors.Is(err, ErrStoreCorrupt) {
				errs <- fmt.Errorf("并发查询授权: got %v, want %v", err, ErrStoreCorrupt)
			}
			// 重复登记已存在（且已损坏）的实体：稳定拒绝为“已登记”，不得静默修复。
			if err := ca.RegisterEntity("web", UsageSign); !errors.Is(err, ErrEntityExists) {
				errs <- fmt.Errorf("并发重复登记: got %v, want %v", err, ErrEntityExists)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("并发结论不稳定: %v", err)
	}
	t.Logf("输入: %d 路并发签发/校验/轮换/授权调整/重复登记（实体记录已损坏） | 判定依据: 所有路径一致拒绝 | 最终结论: 全部稳定拒绝", workers)
}

// TestCorruptEntityRecordRestartConsistency 覆盖重启路径：
// 损坏落盘后每次重启都拒绝加载；仅内存中的损坏不会泄漏到磁盘，
// 从同一份完好状态重建后结论一致。
func TestCorruptEntityRecordRestartConsistency(t *testing.T) {
	dir := t.TempDir()
	mid := testBase.Add(time.Hour)
	ca, err := NewCA(dir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	mustRegister(t, ca, "web")
	cert, err := ca.Issue(validRequest("web", UsageSign))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// 仅内存损坏：不落盘，重启后从完好状态重建，结论与损坏前一致。
	tamperEntityInMemory(t, ca, "web", func(rec *entityRecord) { rec.CurrentEpoch = 99 })
	ca2, err := NewCA(dir)
	if err != nil {
		t.Fatalf("NewCA after in-memory tamper: %v", err)
	}
	logVerdict(t, "内存损坏后从磁盘重建并校验", "内存损坏未持久化，磁盘状态完好",
		ca2.Verify(cert, mid, UsageSign), VerdictOK)

	// 磁盘损坏：每次重启都必须给出相同的损坏拒绝。
	badDir := writeCorruptState(t, func(st *state) {
		rec := entityOf(st)
		rec.CurrentEpoch = 99
		putEntity(st, rec)
	})
	for i := 0; i < 3; i++ {
		_, err := NewCA(badDir)
		logReject(t, fmt.Sprintf("第 %d 次从损坏状态重启", i+1),
			"加载即拒绝，不按猜出来的代次服务", err, ErrStoreCorrupt, ErrStoreVersion)
	}
}
