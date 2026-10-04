package pki

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestIssueRejectsUnregisteredAndUnauthorized 覆盖：
// 未登记实体禁止签发；超出授权用途的签发被独立拒绝（ErrUsageNotAuthorized），
// 且该原因与其他签发失败原因可区分；授权范围调整后结果稳定。
func TestIssueRejectsUnregisteredAndUnauthorized(t *testing.T) {
	ca := newTestCA(t)
	mid := testBase.Add(time.Hour)

	// 未登记实体：不允许签发。
	_, err := ca.Issue(validRequest("ghost", UsageSign))
	t.Logf("输入: 向未登记实体 ghost 签发 sign | 判定依据: 实体登记库无此标识 | 最终结论: %v (期望 %v)", err, ErrEntityNotFound)
	if !errors.Is(err, ErrEntityNotFound) {
		t.Fatalf("unregistered: got %v, want %v", err, ErrEntityNotFound)
	}

	// 登记但只授权 sign。
	info, err := ca.RegisterEntity("limited", UsageSign)
	if err != nil {
		t.Fatalf("RegisterEntity: %v", err)
	}
	t.Logf("输入: 登记实体 limited 授权 sign | 判定依据: 登记即限定用途 | 最终结论: 当前密钥代 %d, 授权 %s",
		info.CurrentEpoch, info.AllowedUsages)
	if info.CurrentEpoch != 1 {
		t.Fatalf("initial entity epoch: got %d, want 1", info.CurrentEpoch)
	}

	// 授权范围内：通过。
	cert, err := ca.Issue(validRequest("limited", UsageSign))
	if err != nil {
		t.Fatalf("Issue within authorization: %v", err)
	}
	logVerdict(t, "授权范围内签发 sign", "证书实体代次与登记一致", ca.Verify(cert, mid, UsageSign), VerdictOK)

	// 超出授权：独立的拒绝原因，不能与请求约束类失败混淆。
	_, err = ca.Issue(validRequest("limited", UsageEncrypt))
	t.Logf("输入: limited 仅授权 sign 却申请 encrypt | 判定依据: 授权位不含申请位 | 最终结论: %v (期望 %v)",
		err, ErrUsageNotAuthorized)
	if !errors.Is(err, ErrUsageNotAuthorized) {
		t.Fatalf("over-authorization: got %v, want %v", err, ErrUsageNotAuthorized)
	}
	// 组合用途中只要含一个未授权位也要拒掉。
	_, err = ca.Issue(validRequest("limited", UsageSign|UsageAuth))
	t.Logf("输入: limited 申请 sign|auth（含未授权 auth） | 判定依据: 申请必须是授权的子集 | 最终结论: %v", err)
	if !errors.Is(err, ErrUsageNotAuthorized) {
		t.Fatalf("partial over-authorization: got %v, want %v", err, ErrUsageNotAuthorized)
	}

	// 重复登记：稳定失败，无副作用（授权范围不被重置）。
	_, err = ca.RegisterEntity("limited", UsageAuth)
	t.Logf("输入: 重复登记 limited | 判定依据: 标识唯一 | 最终结论: %v (期望 %v)", err, ErrEntityAlreadyExists)
	if !errors.Is(err, ErrEntityAlreadyExists) {
		t.Fatalf("duplicate register: got %v, want %v", err, ErrEntityAlreadyExists)
	}
	if got, _ := ca.Entity("limited"); got.AllowedUsages != UsageSign {
		t.Fatalf("重复登记改动了授权范围: %s", got.AllowedUsages)
	}

	// 事后扩权：之前被拒的用途现在可签。
	updated, err := ca.SetEntityAuthorizedUsages("limited", UsageSign|UsageAuth)
	if err != nil {
		t.Fatalf("SetEntityAuthorizedUsages: %v", err)
	}
	t.Logf("输入: 调整 limited 授权为 sign|auth | 判定依据: 全量替换立即生效 | 最终结论: 授权 %s", updated.AllowedUsages)
	if updated.AllowedUsages != UsageSign|UsageAuth {
		t.Fatalf("updated usages: %s", updated.AllowedUsages)
	}
	cert2, err := ca.Issue(validRequest("limited", UsageAuth))
	if err != nil {
		t.Fatalf("Issue auth after widening: %v", err)
	}
	logVerdict(t, "扩权后签发 auth", "新授权范围允许", ca.Verify(cert2, mid, UsageAuth), VerdictOK)

	// 事后收权：刚放开的用途再次被拒；历史证书仍按证书内容判定，不被追溯改变。
	if _, err := ca.SetEntityAuthorizedUsages("limited", UsageSign); err != nil {
		t.Fatalf("narrow authorization: %v", err)
	}
	_, err = ca.Issue(validRequest("limited", UsageAuth))
	t.Logf("输入: 收权为 sign 后再申请 auth | 判定依据: 当前授权不含 auth | 最终结论: %v (期望 %v)",
		err, ErrUsageNotAuthorized)
	if !errors.Is(err, ErrUsageNotAuthorized) {
		t.Fatalf("after narrowing: got %v, want %v", err, ErrUsageNotAuthorized)
	}
	logVerdict(t, "收权前签发的 auth 历史证书", "授权调整不追溯已签发证书", ca.Verify(cert2, mid, UsageAuth), VerdictOK)

	// 对不存在的实体调整授权：明确拒绝。
	_, err = ca.SetEntityAuthorizedUsages("nobody", UsageSign)
	t.Logf("输入: 调整不存在实体的授权 | 判定依据: 实体登记库无此标识 | 最终结论: %v (期望 %v)",
		err, ErrEntityNotFound)
	if !errors.Is(err, ErrEntityNotFound) {
		t.Fatalf("update missing entity: got %v, want %v", err, ErrEntityNotFound)
	}
}

// TestEntityKeyRotationHistory 覆盖实体密钥轮换：
// 证书记录签发时的实体密钥代次；轮换后新证书用新代，历史证书按旧代仍正确判定；
// 手工伪造的代次/指纹不匹配分别得到 SUBJECT_EPOCH_UNKNOWN / SUBJECT_KEY_MISMATCH。
func TestEntityKeyRotationHistory(t *testing.T) {
	ca := newTestCA(t)
	registerTestEntity(t, ca, "svc", UsageSign|UsageAuth)
	mid := testBase.Add(time.Hour)

	before, err := ca.Issue(validRequest("svc", UsageSign))
	if err != nil {
		t.Fatalf("Issue before rotation: %v", err)
	}
	t.Logf("输入: 轮换前签发 | 判定依据: 记录实体当前密钥代 | 最终结论: SubjectEpoch=%d KeyID=%s",
		before.SubjectEpoch, before.SubjectKeyID[:12])
	if before.SubjectEpoch != 1 {
		t.Fatalf("initial subject epoch: got %d, want 1", before.SubjectEpoch)
	}

	epoch, err := ca.RotateEntityKey("svc")
	if err != nil {
		t.Fatalf("RotateEntityKey: %v", err)
	}
	t.Logf("输入: 轮换实体 svc 密钥 | 判定依据: 原子提交新一代 | 最终结论: 新代 %d", epoch)
	if epoch != 2 {
		t.Fatalf("new entity epoch: got %d, want 2", epoch)
	}

	after, err := ca.Issue(validRequest("svc", UsageAuth))
	if err != nil {
		t.Fatalf("Issue after rotation: %v", err)
	}
	t.Logf("输入: 轮换后签发 | 判定依据: 使用实体当前密钥代 | 最终结论: SubjectEpoch=%d (期望 2)",
		after.SubjectEpoch)
	if after.SubjectEpoch != 2 || after.SubjectKeyID == before.SubjectKeyID {
		t.Fatalf("new cert did not bind new entity key: %d vs %d", after.SubjectEpoch, before.SubjectEpoch)
	}

	// 核心不变量：旧证书被旧代承认，新证书被新代承认，互不串扰。
	logVerdict(t, "轮换前的历史证书", "按证书记录的实体旧代密钥判定", ca.Verify(before, mid, UsageSign), VerdictOK)
	logVerdict(t, "轮换后的新证书", "按实体新代密钥判定", ca.Verify(after, mid, UsageAuth), VerdictOK)

	// 实体从登记库中缺失（模拟主体不存在）：新样式证书 -> UNKNOWN_ENTITY。
	// 通过构造一个不含实体段的独立状态目录来检验，避免污染原目录的后续判定。
	ghostDir := t.TempDir()
	ca.mu.Lock()
	ghost := ca.st.clone()
	ghost.Entities = nil
	if err := (&Store{dir: ghostDir}).Save(ghost); err != nil {
		ca.mu.Unlock()
		t.Fatalf("save ghost state: %v", err)
	}
	ca.mu.Unlock()
	ghostCA, err := NewCA(ghostDir)
	if err != nil {
		t.Fatalf("ghost NewCA: %v", err)
	}
	logVerdict(t, "实体未登记时校验其证书", "登记库无该主体", ghostCA.Verify(after, mid, UsageAuth), VerdictUnknownEntity)

	// 在原目录重新加载：两代实体密钥都已持久化，历史与新证书结论不变。
	reloaded, err := NewCA(ca.store.dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	logVerdict(t, "重新加载后历史证书仍可判", "旧代实体密钥已持久化保留", reloaded.Verify(before, mid, UsageSign), VerdictOK)
	logVerdict(t, "重新加载后新证书仍可判", "新代实体密钥已持久化", reloaded.Verify(after, mid, UsageAuth), VerdictOK)

	// 声称一个不存在的实体密钥代次：明确拒绝，不猜测。
	forgedEpoch := *after
	forgedEpoch.SubjectEpoch = 99
	forgedEpoch.Signature = reSign(t, reloaded, &forgedEpoch)
	logVerdict(t, "伪造实体密钥代 99", "实体密钥史无该代", reloaded.Verify(&forgedEpoch, mid, UsageAuth), VerdictSubjectEpoch)

	// 代次存在但指纹被改：指纹比对不一致。
	forgedKey := *after
	forgedKey.SubjectKeyID = "deadbeef"
	forgedKey.Signature = reSign(t, reloaded, &forgedKey)
	logVerdict(t, "篡改实体公钥指纹", "该代登记指纹与证书不一致", reloaded.Verify(&forgedKey, mid, UsageAuth), VerdictSubjectKey)
}

// reSign 用签发方当前密钥重新签名被手工改动的证书，
// 使签名本身保持有效，从而单独检验实体绑定层的判定。
func reSign(t *testing.T, ca *CA, cert *Certificate) []byte {
	t.Helper()
	ca.mu.Lock()
	defer ca.mu.Unlock()
	key := ca.st.currentKey()
	if key == nil {
		t.Fatal("no current issuer key")
	}
	return ed25519.Sign(key.Private, signingPayload(cert))
}

// TestEntityRotationFailureLeavesNoPartialState 覆盖实体密钥轮换中途失败：
// 当前代不前进，旧证书仍被承认，恢复后轮换可成功完成。
func TestEntityRotationFailureLeavesNoPartialState(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA(dir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	registerTestEntity(t, ca, "svc", UsageSign)
	before, err := ca.Issue(validRequest("svc", UsageSign))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	mid := testBase.Add(time.Hour)

	ca.store.failSaves.Store(1)
	_, err = ca.RotateEntityKey("svc")
	t.Logf("输入: 实体密钥轮换且持久化失败 | 判定依据: 提交失败整体回退 | 最终结论: %v (期望 %v)",
		err, ErrRotationFailed)
	if !errors.Is(err, ErrRotationFailed) {
		t.Fatalf("failed rotation: got %v, want %v", err, ErrRotationFailed)
	}

	info, _ := ca.Entity("svc")
	t.Logf("输入: 查询轮换失败后的当前代 | 判定依据: 内存状态未切换 | 最终结论: %d (期望 1)", info.CurrentEpoch)
	if info.CurrentEpoch != 1 {
		t.Fatalf("current epoch advanced after failed rotation: %d", info.CurrentEpoch)
	}
	logVerdict(t, "轮换失败后旧证书", "旧代实体密钥仍是当前代", ca.Verify(before, mid, UsageSign), VerdictOK)

	// 重启后结论一致：失败的轮换没有留下半更新持久化状态。
	reloaded, err := NewCA(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	info2, _ := reloaded.Entity("svc")
	t.Logf("输入: 重启后查询实体当前代 | 判定依据: 半更新状态未落盘 | 最终结论: %d (期望 1)", info2.CurrentEpoch)
	if info2.CurrentEpoch != 1 {
		t.Fatalf("epoch persisted despite failed rotation: %d", info2.CurrentEpoch)
	}
	logVerdict(t, "重启后旧证书", "持久化状态未被半更新", reloaded.Verify(before, mid, UsageSign), VerdictOK)

	epoch, err := reloaded.RotateEntityKey("svc")
	if err != nil {
		t.Fatalf("rotation after recovery: %v", err)
	}
	t.Logf("输入: 故障消除后再次轮换 | 判定依据: 新代正常提交 | 最终结论: 新代 %d", epoch)
	if epoch != 2 {
		t.Fatalf("recovered rotation epoch: got %d, want 2", epoch)
	}
	after, err := reloaded.Issue(validRequest("svc", UsageSign))
	if err != nil {
		t.Fatalf("Issue after recovered rotation: %v", err)
	}
	logVerdict(t, "恢复轮换后签发的证书", "实体新代密钥", reloaded.Verify(after, mid, UsageSign), VerdictOK)
	logVerdict(t, "恢复轮换前的历史证书", "实体旧代密钥保留", reloaded.Verify(before, mid, UsageSign), VerdictOK)
}

// legacySigningPayload 复现实体层出现之前的签名载荷（仅 7 个字段），
// 用于构造真实的“旧状态 + 旧样式证书”兼容用例。
func legacySigningPayload(cert *Certificate) []byte {
	buf := make([]byte, 0, 128)
	var num [8]byte
	putU64 := func(v uint64) { binary.BigEndian.PutUint64(num[:], v); buf = append(buf, num[:]...) }
	putStr := func(s string) { putU64(uint64(len(s))); buf = append(buf, s...) }
	putU64(cert.Serial)
	putStr(cert.Identity)
	putU64(uint64(cert.Usages))
	putU64(uint64(cert.NotBefore.UnixNano()))
	putU64(uint64(cert.NotAfter.UnixNano()))
	putU64(cert.IssuerEpoch)
	putStr(cert.SubjectID)
	return buf
}

// TestLegacyStateAndCertCompatibility 覆盖兼容范围：
// 实体层出现之前保存的旧状态（无 entities）与旧样式证书（无实体代次/指纹）
// 必须被确定地按旧规则处理：能加载、能判 OK/过期/吊销/坏签名，
// 不被当成损坏，也不被（错误地）要求实体绑定。
func TestLegacyStateAndCertCompatibility(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA(dir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	// 用旧版载荷格式真实签发一张“旧证书”，并把旧状态（无 entities 段）落盘。
	ca.mu.Lock()
	issuerKey := ca.st.currentKey()
	legacyCert := &Certificate{
		Serial:      1,
		Identity:    "legacy-svc",
		Usages:      UsageSign | UsageAuth,
		NotBefore:   testBase,
		NotAfter:    testBase.Add(24 * time.Hour),
		IssuerEpoch: issuerKey.Epoch,
		SubjectID:   "subj:legacy-svc",
	}
	legacyCert.Signature = ed25519.Sign(issuerKey.Private, legacySigningPayload(legacyCert))
	legacy := ca.st.clone()
	legacy.Entities = nil
	legacy.Issued = []certRecord{{
		Serial:      legacyCert.Serial,
		Identity:    legacyCert.Identity,
		Usages:      legacyCert.Usages,
		NotBefore:   legacyCert.NotBefore,
		NotAfter:    legacyCert.NotAfter,
		IssuerEpoch: legacyCert.IssuerEpoch,
		SubjectID:   legacyCert.SubjectID,
		Signature:   legacyCert.Signature,
	}}
	legacy.NextSerial = 2
	if err := ca.store.Save(legacy); err != nil {
		ca.mu.Unlock()
		t.Fatalf("save legacy state: %v", err)
	}
	ca.mu.Unlock()

	// 旧状态必须能被加载：新代码把实体层视为追加能力。
	old, err := NewCA(dir)
	if err != nil {
		t.Fatalf("加载旧状态: %v (期望成功)", err)
	}
	mid := testBase.Add(time.Hour)
	logVerdict(t, "旧样式证书（无实体绑定字段）", "按旧规则放行实体绑定检查", old.Verify(legacyCert, mid, UsageSign), VerdictOK)
	logVerdict(t, "旧证书过期判定", "有效期判定不受实体层影响",
		old.Verify(legacyCert, testBase.Add(25*time.Hour), UsageSign), VerdictExpired)
	logVerdict(t, "旧证书未生效判定", "有效期判定不受实体层影响",
		old.Verify(legacyCert, testBase.Add(-time.Minute), UsageSign), VerdictNotYetValid)
	logVerdict(t, "旧证书用途判定", "用途判定不受实体层影响",
		old.Verify(legacyCert, mid, UsageEncrypt), VerdictUsageMismatch)

	// 旧证书同样可被吊销，且吊销后重启仍判定 REVOKED。
	if err := old.Revoke(legacyCert.Serial); err != nil {
		t.Fatalf("Revoke legacy cert: %v", err)
	}
	reloaded, err := NewCA(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	logVerdict(t, "重启后旧吊销证书", "旧数据与新持久化共存",
		reloaded.Verify(legacyCert, mid, UsageSign), VerdictRevoked)

	// 篡改过的旧证书仍然是 BAD_SIGNATURE，不会因无实体绑定而被放行。
	tampered := *legacyCert
	tampered.Identity = "mallory"
	logVerdict(t, "篡改的旧证书", "签名仍受签发方密钥约束",
		reloaded.Verify(&tampered, mid, UsageSign), VerdictBadSignature)

	// 未知签发密钥代仍然 UNTRUSTED_ISSUER，兼容不放宽任何旧判定。
	foreign := *legacyCert
	foreign.IssuerEpoch = 999
	logVerdict(t, "旧证书引用未知签发代", "信任库无该签发代",
		reloaded.Verify(&foreign, mid, UsageSign), VerdictUntrustedIssuer)

	// 旧状态下试图签发新证书：实体未登记，必须拒绝（不把旧状态当损坏，也不放行）。
	_, err = reloaded.Issue(validRequest("legacy-svc", UsageSign))
	t.Logf("输入: 旧状态（无实体段）上直接签发 | 判定依据: 新签发必须先登记 | 最终结论: %v (期望 %v)",
		err, ErrEntityNotFound)
	if !errors.Is(err, ErrEntityNotFound) {
		t.Fatalf("issue on legacy state: got %v, want %v", err, ErrEntityNotFound)
	}

	// 升级路径：在旧状态目录上登记实体并签发新样式证书，新旧证书可并存判定。
	registerTestEntity(t, reloaded, "new-svc", UsageSign)
	fresh, err := reloaded.Issue(validRequest("new-svc", UsageSign))
	if err != nil {
		t.Fatalf("Issue after upgrade: %v", err)
	}
	logVerdict(t, "升级后签发的新样式证书", "携带实体代次/指纹并通过实体绑定",
		reloaded.Verify(fresh, mid, UsageSign), VerdictOK)
	logVerdict(t, "升级后旧证书仍按旧规则判吊销", "旧证书无实体绑定字段，跳过实体检查",
		reloaded.Verify(legacyCert, mid, UsageSign), VerdictRevoked)
}

// TestEntityStoreCorruption 覆盖状态被改坏/代次对不上时明确拒绝加载。
func TestEntityStoreCorruption(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA(dir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	registerTestEntity(t, ca, "svc", UsageSign)
	if _, err := ca.Issue(validRequest("svc", UsageSign)); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	cases := []struct {
		name   string
		mangle func(st *state)
	}{
		{"实体重复登记", func(st *state) { st.Entities = append(st.Entities, st.Entities[0]) }},
		{"授权用途含未知位", func(st *state) { st.Entities[0].AllowedUsages = 1 << 14 }},
		{"实体无任何密钥代", func(st *state) { st.Entities[0].Keys = nil }},
		{"实体存在零代次密钥", func(st *state) { st.Entities[0].Keys[0].Epoch = 0 }},
		{"当前密钥代不在密钥史中", func(st *state) { st.Entities[0].CurrentEpoch = 99 }},
		{"实体公钥被改坏与指纹不符", func(st *state) { st.Entities[0].Keys[0].Public[0] ^= 0xFF }},
	}
	for _, tc := range cases {
		ca.mu.Lock()
		bad := ca.st.clone()
		tc.mangle(bad)
		err := ca.store.Save(bad)
		ca.mu.Unlock()
		if err != nil {
			t.Fatalf("%s: save: %v", tc.name, err)
		}
		_, err = NewCA(dir)
		t.Logf("输入: %s | 判定依据: 加载时实体层完整性校验 | 最终结论: %v (期望 %v)",
			tc.name, err, ErrStoreCorrupt)
		if !errors.Is(err, ErrStoreCorrupt) {
			t.Fatalf("%s: got %v, want %v", tc.name, err, ErrStoreCorrupt)
		}
		// 恢复一份干净状态供下一个用例使用。
		ca.mu.Lock()
		if err := ca.store.Save(ca.st); err != nil {
			ca.mu.Unlock()
			t.Fatalf("%s: restore: %v", tc.name, err)
		}
		ca.mu.Unlock()
	}

	// 版本 99 仍然按版本规则拒绝（回归确认新字段没有改变版本判定）。
	if err := os.WriteFile(filepath.Join(dir, stateFileName), []byte(`{"version":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCA(dir); !errors.Is(err, ErrStoreVersion) {
		t.Fatalf("version 99: got %v, want %v", err, ErrStoreVersion)
	}
}

// TestConcurrentRegisterIssueRotateVerify 覆盖登记/签发/实体轮换/校验并发交织
// 以及进程重启后结论一致：每张成功签发的证书始终可被判定为 OK。
func TestConcurrentRegisterIssueRotateVerify(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA(dir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	mid := testBase.Add(time.Hour)

	const entities = 6
	const perEntity = 15
	var wg sync.WaitGroup
	var mu sync.Mutex
	var issued []*Certificate
	errs := make(chan error, entities*perEntity*2)

	// 登记与签发在不同 goroutine 中并发交织；签发方在实体登记成功后才会成功。
	for e := 0; e < entities; e++ {
		wg.Add(1)
		go func(e int) {
			defer wg.Done()
			id := fmt.Sprintf("ent-%d", e)
			if _, err := ca.RegisterEntity(id, UsageSign|UsageAuth); err != nil {
				errs <- err
				return
			}
			for i := 0; i < perEntity; i++ {
				req := validRequest(id, UsageSign)
				cert, err := ca.Issue(req)
				if err != nil {
					errs <- fmt.Errorf("issue %s: %w", id, err)
					return
				}
				mu.Lock()
				issued = append(issued, cert)
				mu.Unlock()
				if v := ca.Verify(cert, mid, UsageSign); v != VerdictOK {
					errs <- fmt.Errorf("verify %s serial %d: %s", id, cert.Serial, v)
				}
			}
		}(e)
		// 与签发交织的实体密钥轮换。
		wg.Add(1)
		go func(e int) {
			defer wg.Done()
			id := fmt.Sprintf("ent-%d", e)
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := ca.RotateEntityKey(id); err != nil {
					// 登记可能尚未完成：实体不存在是可预期的交织结果。
					if errors.Is(err, ErrEntityNotFound) {
						continue
					}
					errs <- err
					return
				}
			}
		}(e)
	}
	// 同时交织签发方轮换。
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
	close(errs)
	for err := range errs {
		t.Fatalf("并发错误: %v", err)
	}

	t.Logf("输入: %d 个实体并发登记/签发 %d 张 + 实体轮换 + 3 次签发方轮换 | 判定依据: 每张证书记录确定的双代次",
		entities, perEntity)

	// 重启：所有已确认的证书与实体密钥史都必须保持一致结论。
	reloaded, err := NewCA(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	bad := 0
	mu.Lock()
	saved := append([]*Certificate(nil), issued...)
	mu.Unlock()
	for _, cert := range saved {
		if v := reloaded.Verify(cert, mid, UsageSign); v != VerdictOK {
			bad++
			t.Errorf("重启后证书 serial=%d entity=%s subjectEpoch=%d: %s",
				cert.Serial, cert.Identity, cert.SubjectEpoch, v)
		}
	}
	t.Logf("判定依据: 实体旧代密钥全部保留且持久化 | 最终结论: %d 张历史证书重启后全部 OK (异常 %d)",
		len(saved), bad)
	if len(saved) != entities*perEntity {
		t.Fatalf("issued count: got %d, want %d", len(saved), entities*perEntity)
	}
}
