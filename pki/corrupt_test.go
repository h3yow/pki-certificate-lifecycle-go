package pki

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// rewriteEntityRecord 用 mutate 改写 dir 状态文件中指定实体的记录后落盘，
// 模拟本地状态被改坏的情形。
func rewriteEntityRecord(t *testing.T, dir, identity string, mutate func(*entityRecord)) {
	t.Helper()
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	st, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	rec, ok := st.Entities[identity]
	if !ok {
		t.Fatalf("实体 %q 未登记", identity)
	}
	mutate(&rec)
	st.Entities[identity] = rec
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, stateFileName), data, 0o600); err != nil {
		t.Fatalf("写回状态: %v", err)
	}
}

// corruptEntityInMemory 用 mutate 直接改写运行中 CA 的内存实体记录，
// 模拟状态在加载后被改坏的情形（绕过 Load 校验，用于检验操作路径的防护）。
func corruptEntityInMemory(t *testing.T, ca *CA, identity string, mutate func(*entityRecord)) {
	t.Helper()
	ca.mu.Lock()
	defer ca.mu.Unlock()
	next := ca.st.clone()
	rec, ok := next.Entities[identity]
	if !ok {
		t.Fatalf("实体 %q 未登记", identity)
	}
	mutate(&rec)
	next.Entities[identity] = rec
	ca.st = next
}

// newRegisteredCA 在 dir 建立 CA 并登记一个全用途实体，返回实体当前密钥代。
func newRegisteredCA(t *testing.T, dir, identity string) *CA {
	t.Helper()
	ca, err := NewCA(dir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	mustRegister(t, ca, identity)
	return ca
}

func TestLoadRejectsCorruptEntityRecords(t *testing.T) {
	cases := []struct {
		name   string
		basis  string
		mutate func(rec *entityRecord)
	}{
		{"当前代不在密钥历史", "CurrentEpoch=2 但密钥历史只有第 1 代", func(rec *entityRecord) {
			rec.CurrentEpoch = 2
		}},
		{"密钥历史缺一代", "密钥历史为第 1、3 代，缺第 2 代", func(rec *entityRecord) {
			if err := rec.addKey(3); err != nil {
				t.Fatalf("addKey: %v", err)
			}
			rec.CurrentEpoch = 3
		}},
		{"密钥历史出现重复的代", "密钥历史含两条第 1 代记录", func(rec *entityRecord) {
			rec.Keys = append(rec.Keys, rec.Keys[0])
			rec.CurrentEpoch = 2
		}},
		{"密钥代次为0", "密钥历史中出现第 0 代", func(rec *entityRecord) {
			rec.Keys[0].Epoch = 0
		}},
		{"私钥长度不合法", "第 1 代私钥被截断", func(rec *entityRecord) {
			rec.Keys[0].Private = rec.Keys[0].Private[:10]
		}},
		{"公钥与私钥不匹配", "第 1 代公钥被改一个字节", func(rec *entityRecord) {
			rec.Keys[0].Public[0] ^= 0xff
		}},
		{"授权用途非法", "授权用途被改写为 0", func(rec *entityRecord) {
			rec.AllowedUsages = 0
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			newRegisteredCA(t, dir, "victim")
			rewriteEntityRecord(t, dir, "victim", tc.mutate)

			_, err := NewCA(dir)
			t.Logf("输入: 加载含损坏实体记录的状态（%s） | 判定依据: %s | 最终结论: %v", tc.name, tc.basis, err)
			if !errors.Is(err, ErrStoreCorrupt) {
				t.Fatalf("got %v, want %v", err, ErrStoreCorrupt)
			}
			// 结论必须稳定：同一损坏状态重复加载给出同一拒绝结论。
			_, err2 := NewCA(dir)
			if !errors.Is(err2, ErrStoreCorrupt) {
				t.Fatalf("重复加载结论不稳定: 第一次 %v, 第二次 %v", err, err2)
			}
			t.Logf("输入: 同一损坏状态再次加载 | 判定依据: 拒绝结论需幂等 | 最终结论: %v（一致）", err2)
		})
	}
}

func TestIssueRejectsCorruptEntityRecord(t *testing.T) {
	ca := newTestCA(t)
	mustRegister(t, ca, "svc")

	// 把当前密钥代改到历史中不存在的代：这是“签发成功但自己的校验
	// 判 UNKNOWN_SUBJECT”的成因场景，现在必须在签发处就拒绝。
	corruptEntityInMemory(t, ca, "svc", func(rec *entityRecord) {
		rec.CurrentEpoch = 99
	})
	issuedBefore := len(ca.st.Issued)

	cert, err := ca.Issue(validRequest("svc", UsageSign))
	t.Logf("输入: 实体当前密钥代 99 不在密钥历史中时签发 | 判定依据: 实体记录内部一致性校验 | 最终结论: %v", err)
	if !errors.Is(err, ErrStoreCorrupt) {
		t.Fatalf("got %v, want %v", err, ErrStoreCorrupt)
	}
	if cert != nil {
		t.Fatalf("损坏记录下不得返回证书: %+v", cert)
	}
	if len(ca.st.Issued) != issuedBefore {
		t.Fatalf("损坏记录下不得新增签发记录: %d -> %d", issuedBefore, len(ca.st.Issued))
	}
	t.Logf("输入: 检查签发副作用 | 判定依据: 拒绝即无任何签发记录 | 最终结论: 签发记录数不变 (%d)", issuedBefore)
}

func TestVerifyRejectsCorruptEntityRecord(t *testing.T) {
	ca := newTestCA(t)
	mid := testBase.Add(time.Hour)
	mustRegister(t, ca, "svc")
	cert, err := ca.Issue(validRequest("svc", UsageSign))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	logVerdict(t, "损坏前校验证书", "实体记录一致", ca.Verify(cert, mid, UsageSign), VerdictOK)

	// 追加一条重复的第 1 代记录：证书声明的第 1 代密钥仍能查到，
	// 若不做一致性校验会被误判通过；现在必须拒绝。
	corruptEntityInMemory(t, ca, "svc", func(rec *entityRecord) {
		rec.Keys = append(rec.Keys, rec.Keys[0])
		rec.CurrentEpoch = 2
	})
	logVerdict(t, "实体密钥历史含重复代时校验证书", "实体记录自相矛盾即不可辨认，不按猜出的代次放行",
		ca.Verify(cert, mid, UsageSign), VerdictUnknownSubject)
}

func TestEntityOpsRejectCorruptRecord(t *testing.T) {
	ca := newTestCA(t)
	mustRegister(t, ca, "svc")
	corruptEntityInMemory(t, ca, "svc", func(rec *entityRecord) {
		rec.Keys = rec.Keys[:0] // 密钥历史被清空，当前代无着落
	})

	_, err := ca.RotateEntityKey("svc")
	t.Logf("输入: 密钥历史被清空后轮换实体密钥 | 判定依据: 不能在不一致的历史上追加代次 | 最终结论: %v", err)
	if !errors.Is(err, ErrStoreCorrupt) {
		t.Fatalf("RotateEntityKey: got %v, want %v", err, ErrStoreCorrupt)
	}

	err = ca.SetEntityUsages("svc", UsageSign)
	t.Logf("输入: 密钥历史被清空后调整授权 | 判定依据: 损坏记录不得当成正常实体修改 | 最终结论: %v", err)
	if !errors.Is(err, ErrStoreCorrupt) {
		t.Fatalf("SetEntityUsages: got %v, want %v", err, ErrStoreCorrupt)
	}

	_, err = ca.EntityUsages("svc")
	t.Logf("输入: 密钥历史被清空后查询授权 | 判定依据: 损坏记录不得当成正常实体读取 | 最终结论: %v", err)
	if !errors.Is(err, ErrStoreCorrupt) {
		t.Fatalf("EntityUsages: got %v, want %v", err, ErrStoreCorrupt)
	}

	err = ca.RegisterEntity("svc", UsageSign)
	t.Logf("输入: 重复登记记录已损坏的实体 | 判定依据: 与正常重复登记（ErrEntityExists）可区分 | 最终结论: %v", err)
	if !errors.Is(err, ErrStoreCorrupt) {
		t.Fatalf("RegisterEntity: got %v, want %v", err, ErrStoreCorrupt)
	}
	if errors.Is(err, ErrEntityExists) {
		t.Fatalf("损坏记录被混淆为正常重复登记: %v", err)
	}
}

func TestCorruptRecordConcurrentConsistency(t *testing.T) {
	ca := newTestCA(t)
	mid := testBase.Add(time.Hour)
	mustRegister(t, ca, "bad")
	mustRegister(t, ca, "good")
	goodCert, err := ca.Issue(validRequest("good", UsageSign))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	corruptEntityInMemory(t, ca, "bad", func(rec *entityRecord) {
		rec.CurrentEpoch = 7 // 密钥历史中没有第 7 代
	})

	var wg sync.WaitGroup
	errs := make(chan error, 256)
	// 对损坏实体并发执行登记/签发/轮换/授权调整/校验：结论必须一致拒绝。
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if _, err := ca.Issue(validRequest("bad", UsageSign)); !errors.Is(err, ErrStoreCorrupt) {
					errs <- fmt.Errorf("并发签发损坏实体: %v", err)
				}
				if _, err := ca.RotateEntityKey("bad"); !errors.Is(err, ErrStoreCorrupt) {
					errs <- fmt.Errorf("并发轮换损坏实体: %v", err)
				}
				if err := ca.SetEntityUsages("bad", UsageSign); !errors.Is(err, ErrStoreCorrupt) {
					errs <- fmt.Errorf("并发调整损坏实体授权: %v", err)
				}
				forged := &Certificate{
					Serial: 1, Identity: "bad", Usages: UsageSign,
					NotBefore: testBase, NotAfter: testBase.Add(24 * time.Hour),
					SubjectID: "subj:bad", SubjectEpoch: 1,
				}
				if v := ca.Verify(forged, mid, UsageSign); v.OK() {
					errs <- fmt.Errorf("并发校验损坏实体证书被放行: %s", v)
				}
			}
		}()
	}
	// 健康实体的正常操作并发进行，不得受损坏实体影响。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			if _, err := ca.Issue(validRequest("good", UsageSign)); err != nil {
				errs <- fmt.Errorf("健康实体并发签发: %v", err)
			}
			if v := ca.Verify(goodCert, mid, UsageSign); v != VerdictOK {
				errs <- fmt.Errorf("健康实体并发校验: %s", v)
			}
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("并发结论不一致: %v", err)
	}
	t.Logf("输入: 损坏实体与健康实体并发交织（签发/轮换/授权/校验） | 判定依据: 损坏实体全部稳定拒绝 ErrStoreCorrupt/非OK，健康实体全部成功 | 最终结论: 一致")
}

func TestRestartConsistentRejection(t *testing.T) {
	dir := t.TempDir()
	newRegisteredCA(t, dir, "svc")
	// 状态落盘后被改坏：当前代越界。
	rewriteEntityRecord(t, dir, "svc", func(rec *entityRecord) {
		rec.CurrentEpoch = 5
	})

	// 进程重启（重新构建 CA）必须稳定拒绝，而不是按猜出的代次继续服务。
	for i := 0; i < 3; i++ {
		_, err := NewCA(dir)
		t.Logf("输入: 第 %d 次从损坏状态重启 | 判定依据: 实体记录当前代 5 不在密钥历史 | 最终结论: %v", i+1, err)
		if !errors.Is(err, ErrStoreCorrupt) {
			t.Fatalf("第 %d 次重启: got %v, want %v", i+1, err, ErrStoreCorrupt)
		}
	}
}
