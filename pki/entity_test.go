package pki

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// signWithCA 用签发方当前密钥对证书签名（测试内部构造场景用）。
func signWithCA(t *testing.T, ca *CA, cert *Certificate) *Certificate {
	t.Helper()
	ca.mu.Lock()
	defer ca.mu.Unlock()
	key := ca.st.currentKey()
	if key == nil {
		t.Fatal("no current CA key")
	}
	cert.IssuerEpoch = key.Epoch
	cert.Signature = ed25519.Sign(key.Private, signingPayload(cert))
	return cert
}

func TestIssueRequiresRegistration(t *testing.T) {
	ca := newTestCA(t)

	_, err := ca.Issue(validRequest("ghost", UsageSign))
	t.Logf("输入: 未登记实体签发 | 判定依据: 实体表无该标识 | 最终结论: %v", err)
	if !errors.Is(err, ErrEntityNotRegistered) {
		t.Fatalf("got %v, want %v", err, ErrEntityNotRegistered)
	}
	// 可区分性：不得与其他签发失败原因混淆。
	if errors.Is(err, ErrUsageConflict) || errors.Is(err, ErrUsageNotAuthorized) {
		t.Fatalf("未登记错误与其他原因混淆: %v", err)
	}
}

func TestRegisterOutcomes(t *testing.T) {
	ca := newTestCA(t)

	if err := ca.RegisterEntity("web", UsageSign|UsageAuth); err != nil {
		t.Fatalf("RegisterEntity: %v", err)
	}
	t.Logf("输入: 登记 web 授权 sign|auth | 判定依据: 标识合法且未登记 | 最终结论: 成功")

	err := ca.RegisterEntity("web", UsageSign)
	t.Logf("输入: 重复登记 web | 判定依据: 实体表已含该标识 | 最终结论: %v", err)
	if !errors.Is(err, ErrEntityExists) {
		t.Fatalf("duplicate register: got %v, want %v", err, ErrEntityExists)
	}

	err = ca.RegisterEntity("bad/key", UsageSign)
	t.Logf("输入: 非法标识登记 | 判定依据: 标识字符集约束 | 最终结论: %v", err)
	if !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("bad identity: got %v, want %v", err, ErrInvalidIdentity)
	}

	err = ca.RegisterEntity("zero", 0)
	t.Logf("输入: 空授权用途登记 | 判定依据: 用途掩码必须非空且未知位为 0 | 最终结论: %v", err)
	if !errors.Is(err, ErrUsageConflict) {
		t.Fatalf("empty usages: got %v, want %v", err, ErrUsageConflict)
	}
}

func TestIssueBeyondAuthorizedUsage(t *testing.T) {
	ca := newTestCA(t)
	if err := ca.RegisterEntity("limited", UsageSign); err != nil {
		t.Fatalf("RegisterEntity: %v", err)
	}

	if _, err := ca.Issue(validRequest("limited", UsageSign)); err != nil {
		t.Fatalf("Issue within scope: %v", err)
	}
	t.Logf("输入: 授权内用途 sign 签发 | 判定依据: sign ⊆ 授权 sign | 最终结论: 成功")

	_, err := ca.Issue(validRequest("limited", UsageSign|UsageEncrypt))
	t.Logf("输入: 申请 sign|encrypt（授权仅 sign） | 判定依据: 申请用途不是授权范围子集 | 最终结论: %v", err)
	if !errors.Is(err, ErrUsageNotAuthorized) {
		t.Fatalf("got %v, want %v", err, ErrUsageNotAuthorized)
	}
	// 可区分性：授权不足与用途掩码非法是不同原因。
	if errors.Is(err, ErrUsageConflict) {
		t.Fatalf("授权不足被混淆为用途冲突: %v", err)
	}

	// 调整授权范围后，同一申请变为允许；重复设置为相同范围是幂等成功。
	if err := ca.SetEntityUsages("limited", UsageSign|UsageEncrypt); err != nil {
		t.Fatalf("SetEntityUsages: %v", err)
	}
	if err := ca.SetEntityUsages("limited", UsageSign|UsageEncrypt); err != nil {
		t.Fatalf("SetEntityUsages idempotent: %v", err)
	}
	t.Logf("输入: 调整授权为 sign|encrypt（两次） | 判定依据: 已登记实体授权更新幂等 | 最终结论: 均成功")
	if _, err := ca.Issue(validRequest("limited", UsageSign|UsageEncrypt)); err != nil {
		t.Fatalf("Issue after widen: %v", err)
	}
	t.Logf("输入: 调整后签发 sign|encrypt | 判定依据: 申请 ⊆ 新授权范围 | 最终结论: 成功")

	err = ca.SetEntityUsages("ghost", UsageSign)
	t.Logf("输入: 调整未登记实体授权 | 判定依据: 实体表无该标识 | 最终结论: %v", err)
	if !errors.Is(err, ErrEntityNotRegistered) {
		t.Fatalf("got %v, want %v", err, ErrEntityNotRegistered)
	}
}

func TestEntityKeyRotationKeepsHistory(t *testing.T) {
	ca := newTestCA(t)
	mid := testBase.Add(time.Hour)
	mustRegister(t, ca, "rot")

	before, err := ca.Issue(validRequest("rot", UsageSign))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	t.Logf("输入: 轮换前签发 | 判定依据: 使用实体当前密钥代 | 最终结论: 实体密钥代 %d (期望 1)", before.SubjectEpoch)
	if before.SubjectEpoch != 1 {
		t.Fatalf("SubjectEpoch: got %d, want 1", before.SubjectEpoch)
	}

	epoch, err := ca.RotateEntityKey("rot")
	if err != nil {
		t.Fatalf("RotateEntityKey: %v", err)
	}
	t.Logf("输入: 轮换实体密钥 | 判定依据: 原子切换实体当前密钥代 | 最终结论: 新代 %d (期望 2)", epoch)
	if epoch != 2 {
		t.Fatalf("epoch: got %d, want 2", epoch)
	}

	after, err := ca.Issue(validRequest("rot", UsageSign))
	if err != nil {
		t.Fatalf("Issue after rotate: %v", err)
	}
	t.Logf("输入: 轮换后签发 | 判定依据: 使用实体新密钥代 | 最终结论: 实体密钥代 %d (期望 2)", after.SubjectEpoch)
	if after.SubjectEpoch != 2 {
		t.Fatalf("SubjectEpoch: got %d, want 2", after.SubjectEpoch)
	}

	// 历史证书仍按签发时的实体密钥代判定：不因轮换失效或误判。
	logVerdict(t, "轮换前签发的历史证书", "旧实体密钥代仍保留在密钥历史中", ca.Verify(before, mid, UsageSign), VerdictOK)
	logVerdict(t, "轮换后签发的新证书", "按新实体密钥代判定", ca.Verify(after, mid, UsageSign), VerdictOK)

	// 未登记实体不能轮换密钥。
	_, err = ca.RotateEntityKey("ghost")
	t.Logf("输入: 轮换未登记实体密钥 | 判定依据: 实体表无该标识 | 最终结论: %v", err)
	if !errors.Is(err, ErrEntityNotRegistered) {
		t.Fatalf("got %v, want %v", err, ErrEntityNotRegistered)
	}
}

func TestUnknownSubjectVerdict(t *testing.T) {
	ca := newTestCA(t)
	mid := testBase.Add(time.Hour)
	mustRegister(t, ca, "known")

	// 构造一张签名有效但声称不存在实体密钥代的证书。
	forged := signWithCA(t, ca, &Certificate{
		Serial: 9001, Identity: "known", Usages: UsageSign,
		NotBefore: testBase, NotAfter: testBase.Add(24 * time.Hour),
		SubjectID: "subj:known", SubjectEpoch: 99,
	})
	logVerdict(t, "签名有效但实体密钥代 99 不存在", "实体密钥历史中无该代", ca.Verify(forged, mid, UsageSign), VerdictUnknownSubject)

	// 实体未登记但证书声称其实体密钥代：同样明确拒绝。
	orphan := signWithCA(t, ca, &Certificate{
		Serial: 9002, Identity: "ghost", Usages: UsageSign,
		NotBefore: testBase, NotAfter: testBase.Add(24 * time.Hour),
		SubjectID: "subj:ghost", SubjectEpoch: 1,
	})
	logVerdict(t, "签名有效但实体未登记", "实体表无该标识", ca.Verify(orphan, mid, UsageSign), VerdictUnknownSubject)
}

func TestEntityRotationFailureLeavesNoPartialState(t *testing.T) {
	ca := newTestCA(t)
	mid := testBase.Add(time.Hour)
	mustRegister(t, ca, "fragile")

	before, err := ca.Issue(validRequest("fragile", UsageSign))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// 注入一次持久化失败：轮换必须整体失败，旧状态保持可见。
	ca.store.failSaves.Store(1)
	_, err = ca.RotateEntityKey("fragile")
	t.Logf("输入: 实体密钥轮换且持久化失败 | 判定依据: 原子提交失败即整体回退 | 最终结论: %v", err)
	if !errors.Is(err, ErrRotationFailed) {
		t.Fatalf("got %v, want %v", err, ErrRotationFailed)
	}
	logVerdict(t, "轮换失败后校验历史证书", "旧实体密钥代未被半更新", ca.Verify(before, mid, UsageSign), VerdictOK)

	// 失败后签发仍使用旧实体密钥代，必须仍被承认。
	after, err := ca.Issue(validRequest("fragile", UsageSign))
	if err != nil {
		t.Fatalf("Issue after failed rotate: %v", err)
	}
	t.Logf("输入: 轮换失败后签发 | 判定依据: 实体当前密钥代未切换 | 最终结论: 实体密钥代 %d (期望 %d)", after.SubjectEpoch, before.SubjectEpoch)
	if after.SubjectEpoch != before.SubjectEpoch {
		t.Fatalf("entity epoch advanced after failed rotation: %d -> %d", before.SubjectEpoch, after.SubjectEpoch)
	}
	logVerdict(t, "轮换失败后签发的证书", "仍由旧实体密钥代签发", ca.Verify(after, mid, UsageSign), VerdictOK)

	// 故障消除后轮换可成功，且历史证书判定不变。
	if _, err := ca.RotateEntityKey("fragile"); err != nil {
		t.Fatalf("RotateEntityKey after recovery: %v", err)
	}
	logVerdict(t, "恢复后再次校验历史证书", "旧代密钥仍保留", ca.Verify(before, mid, UsageSign), VerdictOK)
}

func TestLegacyStateAndCertCompat(t *testing.T) {
	dir := t.TempDir()
	mid := testBase.Add(time.Hour)

	// 先构造一份状态，再改写成版本 1（无实体表）模拟旧版落盘数据。
	ca0, err := NewCA(dir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	_ = ca0
	data, err := os.ReadFile(filepath.Join(dir, stateFileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "entities") {
		t.Fatalf("fresh state should not contain entities: %s", data)
	}
	legacy := strings.Replace(string(data), `"version": 2`, `"version": 1`, 1)
	if legacy == string(data) {
		t.Fatalf("version field not rewritten: %s", data)
	}
	if err := os.WriteFile(filepath.Join(dir, stateFileName), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	// 旧状态必须被确定地加载：不视为损坏，实体表视为空。
	ca, err := NewCA(dir)
	if err != nil {
		t.Fatalf("NewCA on v1 state: %v", err)
	}
	t.Logf("输入: 版本 1 且无实体表的状态 | 判定依据: 向后兼容加载，entities 缺省为空 | 最终结论: 加载成功")

	// 旧格式证书（SubjectEpoch=0，签名编码与旧格式一致）按旧规则判定：
	// 不视为损坏、不视为不受信，也不要求实体已登记。
	legacyCert := signWithCA(t, ca, &Certificate{
		Serial: 42, Identity: "legacy-client", Usages: UsageSign,
		NotBefore: testBase, NotAfter: testBase.Add(24 * time.Hour),
		SubjectID: "subj:legacy-client", SubjectEpoch: 0,
	})
	logVerdict(t, "旧格式证书（无实体密钥代）", "SubjectEpoch=0 走旧判定路径", ca.Verify(legacyCert, mid, UsageSign), VerdictOK)

	// 但新签发仍执行新规则：未登记实体拒绝。
	_, err = ca.Issue(validRequest("legacy-client", UsageSign))
	t.Logf("输入: 旧状态加载后对未登记实体签发 | 判定依据: 实体表为空 | 最终结论: %v", err)
	if !errors.Is(err, ErrEntityNotRegistered) {
		t.Fatalf("got %v, want %v", err, ErrEntityNotRegistered)
	}

	// 升级后的状态保存为当前版本，重启后结论一致。
	mustRegister(t, ca, "modern")
	cert, err := ca.Issue(validRequest("modern", UsageSign))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	ca2, err := NewCA(dir)
	if err != nil {
		t.Fatalf("NewCA after upgrade save: %v", err)
	}
	logVerdict(t, "升级保存并重启后校验新证书", "状态按当前版本落盘", ca2.Verify(cert, mid, UsageSign), VerdictOK)
	logVerdict(t, "升级保存并重启后校验旧证书", "旧证书判定路径不受升级影响", ca2.Verify(legacyCert, mid, UsageSign), VerdictOK)
}

func TestConcurrentEntityOpsAndRestart(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA(dir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	mid := testBase.Add(time.Hour)

	const entities = 4
	const perEntity = 15
	for i := 0; i < entities; i++ {
		// 仅授权 sign：重启后申请 encrypt 必须仍被拒绝。
		if err := ca.RegisterEntity(fmt.Sprintf("svc-%d", i), UsageSign); err != nil {
			t.Fatalf("RegisterEntity: %v", err)
		}
	}

	var wg sync.WaitGroup
	certs := make(chan *Certificate, entities*perEntity)
	errs := make(chan error, entities*perEntity*4)

	// 并发签发 + 校验。
	for w := 0; w < entities; w++ {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			for i := 0; i < perEntity; i++ {
				cert, err := ca.Issue(validRequest(id, UsageSign))
				if err != nil {
					errs <- err
					return
				}
				certs <- cert
				if v := ca.Verify(cert, mid, UsageSign); v != VerdictOK {
					errs <- fmt.Errorf("并发校验序列号 %d: %s", cert.Serial, v)
				}
			}
		}(fmt.Sprintf("svc-%d", w))
	}
	// 并发实体密钥轮换与签发方密钥轮换。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < entities; i++ {
			if _, err := ca.RotateEntityKey(fmt.Sprintf("svc-%d", i)); err != nil {
				errs <- err
			}
			if _, err := ca.Rotate(); err != nil {
				errs <- err
			}
		}
	}()
	// 并发重复登记与授权调整：结果必须稳定（已登记/幂等），不得出错。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < entities; i++ {
			id := fmt.Sprintf("svc-%d", i)
			if err := ca.RegisterEntity(id, UsageSign); err != nil && !errors.Is(err, ErrEntityExists) {
				errs <- fmt.Errorf("重复登记 %s: %v", id, err)
			}
			if err := ca.SetEntityUsages(id, UsageSign); err != nil {
				errs <- fmt.Errorf("授权调整 %s: %v", id, err)
			}
		}
	}()
	wg.Wait()
	close(certs)
	close(errs)

	for err := range errs {
		t.Fatalf("并发错误: %v", err)
	}
	var all []*Certificate
	for cert := range certs {
		all = append(all, cert)
	}
	t.Logf("输入: %d 实体 x %d 并发签发 + 并发轮换/登记/授权调整 | 判定依据: 无并发错误 | 最终结论: %d 张证书签发成功",
		entities, perEntity, len(all))
	if len(all) != entities*perEntity {
		t.Fatalf("issued %d, want %d", len(all), entities*perEntity)
	}

	// 进程重启后：已确认的签发结论不丢失，逐张重验必须一致。
	ca2, err := NewCA(dir)
	if err != nil {
		t.Fatalf("NewCA after restart: %v", err)
	}
	epochs := make(map[uint64]uint64)
	for _, cert := range all {
		if v := ca2.Verify(cert, mid, UsageSign); v != VerdictOK {
			t.Fatalf("重启后校验序列号 %d: %s", cert.Serial, v)
		}
		epochs[cert.Serial] = cert.SubjectEpoch
	}
	t.Logf("输入: 重启后重验 %d 张证书 | 判定依据: 签发记录与实体密钥历史已持久化 | 最终结论: 全部 OK", len(all))

	// 重启后授权范围仍然生效：超出授权的申请必须被拒绝。
	_, err = ca2.Issue(validRequest("svc-0", UsageEncrypt))
	t.Logf("输入: 重启后申请未授权用途 encrypt | 判定依据: 授权范围已持久化 | 最终结论: %v", err)
	if !errors.Is(err, ErrUsageNotAuthorized) {
		t.Fatalf("got %v, want %v", err, ErrUsageNotAuthorized)
	}
}
