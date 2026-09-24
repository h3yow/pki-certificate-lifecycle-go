package pki

import (
	"errors"
	"testing"
	"time"
)

var testBase = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func newTestCA(t *testing.T) *CA {
	t.Helper()
	ca, err := NewCA(t.TempDir())
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	return ca
}

func validRequest(identity string, usages KeyUsage) IssueRequest {
	return IssueRequest{
		Identity:  identity,
		Usages:    usages,
		NotBefore: testBase,
		NotAfter:  testBase.Add(24 * time.Hour),
	}
}

// logVerdict 按“输入 / 判定依据 / 最终结论”打印测试日志。
func logVerdict(t *testing.T, input, basis string, got, want Verdict) {
	t.Helper()
	t.Logf("输入: %s | 判定依据: %s | 最终结论: %s (期望 %s)", input, basis, got, want)
	if got != want {
		t.Fatalf("结论不匹配: got %s, want %s", got, want)
	}
}

func TestVerifyVerdicts(t *testing.T) {
	ca := newTestCA(t)
	cert, err := ca.Issue(validRequest("alice", UsageSign|UsageAuth))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	mid := testBase.Add(time.Hour)

	logVerdict(t, "有效窗口内 + 用途 sign", "证书未过期且用途匹配", ca.Verify(cert, mid, UsageSign), VerdictOK)
	logVerdict(t, "生效时刻之前", "at < NotBefore", ca.Verify(cert, testBase.Add(-time.Minute), UsageSign), VerdictNotYetValid)
	logVerdict(t, "失效时刻之后", "at >= NotAfter", ca.Verify(cert, testBase.Add(25*time.Hour), UsageSign), VerdictExpired)
	logVerdict(t, "要求未授予的用途 encrypt", "证书用途 sign|auth 不含 encrypt", ca.Verify(cert, mid, UsageEncrypt), VerdictUsageMismatch)
	logVerdict(t, "要求非法用途 0", "校验方要求的用途本身非法", ca.Verify(cert, mid, 0), VerdictUsageMismatch)

	tampered := *cert
	tampered.Identity = "mallory"
	logVerdict(t, "篡改标识后的证书", "签名不覆盖篡改内容", ca.Verify(&tampered, mid, UsageSign), VerdictBadSignature)

	foreign := *cert
	foreign.IssuerEpoch = 999
	logVerdict(t, "未知签发密钥代 999", "信任库中不存在该代密钥", ca.Verify(&foreign, mid, UsageSign), VerdictUntrustedIssuer)

	if err := ca.Revoke(cert.Serial); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	logVerdict(t, "吊销后的证书", "序列号在吊销列表中", ca.Verify(cert, mid, UsageSign), VerdictRevoked)
}

func TestIssueRejects(t *testing.T) {
	ca := newTestCA(t)
	cases := []struct {
		name string
		req  IssueRequest
		want error
	}{
		{"空标识", validRequest("", UsageSign), ErrInvalidIdentity},
		{"超长标识", validRequest(string(make([]byte, maxIdentityLen+1)), UsageSign), ErrInvalidIdentity},
		{"非法字符标识", validRequest("a/b", UsageSign), ErrInvalidIdentity},
		{"空用途", validRequest("bob", 0), ErrUsageConflict},
		{"未知用途位", validRequest("bob", 1<<15), ErrUsageConflict},
		{"零值有效期", IssueRequest{Identity: "bob", Usages: UsageSign}, ErrInvalidValidity},
		{"生效晚于失效", IssueRequest{Identity: "bob", Usages: UsageSign, NotBefore: testBase.Add(time.Hour), NotAfter: testBase}, ErrInvalidValidity},
		{"有效期过短", IssueRequest{Identity: "bob", Usages: UsageSign, NotBefore: testBase, NotAfter: testBase.Add(time.Second)}, ErrInvalidValidity},
		{"有效期过长", IssueRequest{Identity: "bob", Usages: UsageSign, NotBefore: testBase, NotAfter: testBase.Add(maxLifetime + time.Hour)}, ErrInvalidValidity},
	}
	for _, tc := range cases {
		_, err := ca.Issue(tc.req)
		t.Logf("输入: %s | 判定依据: 请求约束校验 | 最终结论: %v (期望 %v)", tc.name, err, tc.want)
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}

	// 序列号重复：显式指定已占用的序列号必须被拒绝，不得用默认值兜底。
	cert, err := ca.Issue(validRequest("carol", UsageSign))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	dup := validRequest("dave", UsageSign)
	dup.Serial = cert.Serial
	_, err = ca.Issue(dup)
	t.Logf("输入: 显式序列号 %d (已占用) | 判定依据: 序列号唯一性 | 最终结论: %v", dup.Serial, err)
	if !errors.Is(err, ErrSerialConflict) {
		t.Fatalf("duplicate serial: got %v, want %v", err, ErrSerialConflict)
	}
}

func TestRevokeOutcomes(t *testing.T) {
	ca := newTestCA(t)
	cert, err := ca.Issue(validRequest("erin", UsageAuth))
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := ca.Revoke(cert.Serial); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	t.Logf("输入: 吊销序列号 %d | 判定依据: 已签发且未吊销 | 最终结论: 成功", cert.Serial)

	err = ca.Revoke(cert.Serial)
	t.Logf("输入: 重复吊销序列号 %d | 判定依据: 吊销列表已含该序列号 | 最终结论: %v", cert.Serial, err)
	if !errors.Is(err, ErrAlreadyRevoked) {
		t.Fatalf("re-revoke: got %v, want %v", err, ErrAlreadyRevoked)
	}

	err = ca.Revoke(cert.Serial + 1000)
	t.Logf("输入: 吊销不存在的序列号 %d | 判定依据: 签发记录中不存在 | 最终结论: %v", cert.Serial+1000, err)
	if !errors.Is(err, ErrCertNotFound) {
		t.Fatalf("revoke unknown: got %v, want %v", err, ErrCertNotFound)
	}

	if !ca.IsRevoked(cert.Serial) {
		t.Fatal("IsRevoked should be true")
	}
}
