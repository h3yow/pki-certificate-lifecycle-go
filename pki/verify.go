package pki

import (
	"crypto/ed25519"
	"time"
)

// Verify 在 at 时刻按 requireUsage 校验证书，返回可区分的结论。
// 判定顺序：签发方可信 → 签名有效 → 尚未生效 → 已过期 → 用途匹配 → 未吊销。
// 历史证书按其证书中记录的签发密钥代判定，轮换不影响其信任关系。
// 任何失败结论都不会被静默当作通过。
func (c *CA) Verify(cert *Certificate, at time.Time, requireUsage KeyUsage) Verdict {
	if cert == nil {
		return VerdictBadSignature
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.st.keyForEpoch(cert.IssuerEpoch)
	if key == nil {
		return VerdictUntrustedIssuer
	}
	if !ed25519.Verify(key.Public, signingPayload(cert), cert.Signature) {
		return VerdictBadSignature
	}
	at = at.UTC()
	if at.Before(cert.NotBefore) {
		return VerdictNotYetValid
	}
	if !at.Before(cert.NotAfter) {
		return VerdictExpired
	}
	if !requireUsage.Valid() || !cert.Usages.Has(requireUsage) {
		return VerdictUsageMismatch
	}
	for _, r := range c.st.Revoked {
		if r.Serial == cert.Serial {
			return VerdictRevoked
		}
	}
	return VerdictOK
}
