package pki

import (
	"crypto/ed25519"
	"time"
)

// Verify 在 at 时刻按 requireUsage 校验证书，返回可区分的结论。
// 判定顺序：签发方可信 → 签名有效 → 实体绑定（实体存在/代次存在/公钥指纹一致）
// → 尚未生效 → 已过期 → 用途匹配 → 未吊销。
// 历史证书按其证书中记录的签发密钥代判定，签发方轮换不影响其信任关系；
// 实体密钥轮换后旧代密钥保留，历史证书按其记录的实体密钥代判定。
// 旧证书（实体密钥代次与公钥指纹均缺省）按登记实体层出现之前的规则处理，
// 不做实体绑定检查（见 README 兼容范围）。任何失败结论都不会被静默当作通过。
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
	if v := c.verifyEntityBinding(cert); v != VerdictOK {
		return v
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

// verifyEntityBinding 校验证书与受管实体密钥的绑定关系。
// 新证书必须满足：实体已登记；证书声称的实体密钥代次在该实体密钥史中存在；
// 该代公钥指纹与证书记录一致。任何一条不满足都明确拒绝，不按猜测放行。
// 旧证书（SubjectEpoch==0 且 SubjectKeyID 为空）无实体绑定信息，按兼容规则放行。
func (c *CA) verifyEntityBinding(cert *Certificate) Verdict {
	if cert.SubjectEpoch == 0 && cert.SubjectKeyID == "" {
		return VerdictOK
	}
	entity := c.st.findEntity(cert.Identity)
	if entity == nil {
		return VerdictUnknownEntity
	}
	k := entity.entityKeyForEpoch(cert.SubjectEpoch)
	if k == nil {
		return VerdictSubjectEpoch
	}
	if k.KeyID != cert.SubjectKeyID {
		return VerdictSubjectKey
	}
	return VerdictOK
}
