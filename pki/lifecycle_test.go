package pki

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestRotationKeepsHistory(t *testing.T) {
	ca := newTestCA(t)
	mid := testBase.Add(time.Hour)

	registerTestEntity(t, ca, "old-entity", UsageSign)
	registerTestEntity(t, ca, "new-entity", UsageSign)
	old, err := ca.Issue(validRequest("old-entity", UsageSign))
	if err != nil {
		t.Fatalf("Issue old: %v", err)
	}
	epoch, err := ca.Rotate()
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	t.Logf("输入: 轮换签发方密钥 | 判定依据: 原子切换当前密钥代 | 最终结论: 新代 %d", epoch)

	fresh, err := ca.Issue(validRequest("new-entity", UsageSign))
	if err != nil {
		t.Fatalf("Issue new: %v", err)
	}
	t.Logf("输入: 轮换后签发 | 判定依据: 使用当前密钥代 | 最终结论: 证书代 %d (期望 %d)", fresh.IssuerEpoch, epoch)
	if fresh.IssuerEpoch != epoch || old.IssuerEpoch == fresh.IssuerEpoch {
		t.Fatalf("epoch mismatch: old=%d new=%d", old.IssuerEpoch, fresh.IssuerEpoch)
	}

	// 历史证书按其签发时刻的信任关系判定：旧代密钥仍被保留。
	logVerdict(t, "轮换前签发的历史证书", "按证书记录的旧密钥代判定", ca.Verify(old, mid, UsageSign), VerdictOK)
	logVerdict(t, "轮换后签发的新证书", "按当前密钥代判定", ca.Verify(fresh, mid, UsageSign), VerdictOK)
}

func TestRotationFailureLeavesNoPartialState(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA(dir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	registerTestEntity(t, ca, "stable", UsageSign)
	before, err := ca.Issue(validRequest("stable", UsageSign))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	registerTestEntity(t, ca, "after-fail", UsageSign)

	// 注入一次持久化失败：轮换必须整体失败，旧状态保持可见。
	ca.store.failSaves.Store(1)
	_, err = ca.Rotate()
	t.Logf("输入: 轮换且持久化失败 | 判定依据: 原子提交失败即整体回退 | 最终结论: %v", err)
	if !errors.Is(err, ErrRotationFailed) {
		t.Fatalf("Rotate: got %v, want %v", err, ErrRotationFailed)
	}
	mid := testBase.Add(time.Hour)
	logVerdict(t, "轮换失败后校验旧证书", "旧信任材料未被半更新", ca.Verify(before, mid, UsageSign), VerdictOK)

	// 失败后签发的证书仍使用旧密钥代，必须被旧信任接受。
	after, err := ca.Issue(validRequest("after-fail", UsageSign))
	if err != nil {
		t.Fatalf("Issue after failed rotate: %v", err)
	}
	t.Logf("输入: 轮换失败后签发 | 判定依据: 当前密钥代未切换 | 最终结论: 证书代 %d (期望 %d)", after.IssuerEpoch, before.IssuerEpoch)
	if after.IssuerEpoch != before.IssuerEpoch {
		t.Fatalf("epoch advanced after failed rotation: %d -> %d", before.IssuerEpoch, after.IssuerEpoch)
	}
	logVerdict(t, "轮换失败后签发的证书", "仍由旧代密钥签发", ca.Verify(after, mid, UsageSign), VerdictOK)

	// 故障消除后轮换可成功完成。
	if _, err := ca.Rotate(); err != nil {
		t.Fatalf("Rotate after recovery: %v", err)
	}
}

func TestRestartRecovery(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA(dir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	registerTestEntity(t, ca, "kept", UsageAuth)
	registerTestEntity(t, ca, "doomed", UsageAuth)
	kept, err := ca.Issue(validRequest("kept", UsageAuth))
	if err != nil {
		t.Fatalf("Issue kept: %v", err)
	}
	revoked, err := ca.Issue(validRequest("doomed", UsageAuth))
	if err != nil {
		t.Fatalf("Issue doomed: %v", err)
	}
	if err := ca.Revoke(revoked.Serial); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// 模拟进程中断重启：从同一目录重建签发方。
	ca2, err := NewCA(dir)
	if err != nil {
		t.Fatalf("NewCA after restart: %v", err)
	}
	mid := testBase.Add(time.Hour)
	logVerdict(t, "重启后校验保留证书", "签发记录已持久化", ca2.Verify(kept, mid, UsageAuth), VerdictOK)
	logVerdict(t, "重启后校验已吊销证书", "吊销记录已持久化", ca2.Verify(revoked, mid, UsageAuth), VerdictRevoked)

	// 序列号游标已持久化：重启后签发不得重复历史序列号。
	registerTestEntity(t, ca2, "post-restart", UsageSign)
	next, err := ca2.Issue(validRequest("post-restart", UsageSign))
	if err != nil {
		t.Fatalf("Issue after restart: %v", err)
	}
	t.Logf("输入: 重启后签发 | 判定依据: 序列号游标持久化 | 最终结论: 序列号 %d (期望 > %d)", next.Serial, revoked.Serial)
	if next.Serial <= revoked.Serial {
		t.Fatalf("serial reused after restart: %d", next.Serial)
	}
}

func TestStoreCorruptionAndVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, stateFileName)

	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewCA(dir)
	t.Logf("输入: 损坏的状态文件 | 判定依据: 严格解析失败 | 最终结论: %v", err)
	if !errors.Is(err, ErrStoreCorrupt) {
		t.Fatalf("corrupt: got %v, want %v", err, ErrStoreCorrupt)
	}

	if err := os.WriteFile(path, []byte(`{"version": 99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = NewCA(dir)
	t.Logf("输入: 版本 99 的状态文件 | 判定依据: 超出支持版本 1 | 最终结论: %v", err)
	if !errors.Is(err, ErrStoreVersion) {
		t.Fatalf("version: got %v, want %v", err, ErrStoreVersion)
	}

	// 未知字段视为损坏：不得静默错列或丢弃。
	if err := os.WriteFile(path, []byte(`{"version":1,"unknownField":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = NewCA(dir)
	t.Logf("输入: 含未知字段的状态文件 | 判定依据: 严格解码拒绝未知字段 | 最终结论: %v", err)
	if !errors.Is(err, ErrStoreCorrupt) {
		t.Fatalf("unknown field: got %v, want %v", err, ErrStoreCorrupt)
	}
}

func TestStoreMissingFieldDefaults(t *testing.T) {
	dir := t.TempDir()
	// 缺失字段语义：nextSerial 缺省视为 1，keys 缺省视为空（触发初始化）。
	if err := os.WriteFile(filepath.Join(dir, stateFileName), []byte(`{"version":1,"nextSerial":7}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ca, err := NewCA(dir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	registerTestEntity(t, ca, "defaults", UsageSign)
	cert, err := ca.Issue(validRequest("defaults", UsageSign))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	t.Logf("输入: 仅含 nextSerial=7 的状态 | 判定依据: 缺省字段语义确定 | 最终结论: 序列号 %d (期望 7)", cert.Serial)
	if cert.Serial != 7 {
		t.Fatalf("serial: got %d, want 7", cert.Serial)
	}
}

func TestConcurrentIssueVerifyRotate(t *testing.T) {
	ca := newTestCA(t)
	mid := testBase.Add(time.Hour)

	const workers = 8
	const perWorker = 20
	var wg sync.WaitGroup
	serials := make(chan uint64, workers*perWorker)
	errs := make(chan error, workers*perWorker*2)

	for w := 0; w < workers; w++ {
		for i := 0; i < perWorker; i++ {
			registerTestEntity(t, ca, fmt.Sprintf("entity-%d-%d", w, i), UsageSign)
		}
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				cert, err := ca.Issue(validRequest(fmt.Sprintf("entity-%d-%d", w, i), UsageSign))
				if err != nil {
					errs <- err
					return
				}
				serials <- cert.Serial
				// 并发校验：结论必须确定（此处应为 OK）。
				if v := ca.Verify(cert, mid, UsageSign); v != VerdictOK {
					errs <- fmt.Errorf("并发校验序列号 %d: %s", cert.Serial, v)
				}
			}
		}(w)
	}
	// 与签发交织的并发轮换。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 3; i++ {
			if _, err := ca.Rotate(); err != nil {
				errs <- err
			}
		}
	}()
	wg.Wait()
	close(serials)
	close(errs)

	for err := range errs {
		t.Fatalf("并发错误: %v", err)
	}
	seen := make(map[uint64]bool)
	count := 0
	for s := range serials {
		if seen[s] {
			t.Fatalf("重复序列号: %d", s)
		}
		seen[s] = true
		count++
	}
	t.Logf("输入: %d 路并发签发 x %d + 3 次并发轮换 | 判定依据: 序列号唯一且校验结论一致 | 最终结论: %d 张证书全部唯一且 OK",
		workers, perWorker, count)
	if count != workers*perWorker {
		t.Fatalf("issued %d, want %d", count, workers*perWorker)
	}
}
