// Package pki 提供本地可运行的证书签发与生命周期管理组件：
// 使用本地密钥材料与本地持久化存储模拟私有签发方（CA）与受管实体。
package pki

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// KeyUsage 表示证书密钥用途位掩码。
type KeyUsage uint16

const (
	UsageSign    KeyUsage = 1 << iota // 数字签名
	UsageEncrypt                      // 数据加密
	UsageAuth                         // 身份认证
)

// knownUsages 是当前支持的全部用途位。
const knownUsages = UsageSign | UsageEncrypt | UsageAuth

// Has 报告 u 是否包含 o 中的全部用途位。
func (u KeyUsage) Has(o KeyUsage) bool { return u&o == o }

// Valid 报告用途掩码是否非空且不含未知位。
func (u KeyUsage) Valid() bool { return u != 0 && u&^knownUsages == 0 }

// String 返回用途的可读表示，用于日志与错误信息。
func (u KeyUsage) String() string {
	if u == 0 {
		return "(none)"
	}
	var parts []string
	if u.Has(UsageSign) {
		parts = append(parts, "sign")
	}
	if u.Has(UsageEncrypt) {
		parts = append(parts, "encrypt")
	}
	if u.Has(UsageAuth) {
		parts = append(parts, "auth")
	}
	if unknown := u &^ knownUsages; unknown != 0 {
		parts = append(parts, fmt.Sprintf("unknown(0x%x)", uint16(unknown)))
	}
	return strings.Join(parts, "|")
}

// 签发请求可被拒绝的原因，彼此可区分，不用默认值兜底。
var (
	ErrInvalidIdentity = errors.New("pki: 标识非法")
	ErrInvalidValidity = errors.New("pki: 有效期参数越界")
	ErrUsageConflict   = errors.New("pki: 密钥用途冲突")
	ErrSerialConflict  = errors.New("pki: 序列号重复")
)

// 吊销操作的可区分结论。
var (
	ErrAlreadyRevoked = errors.New("pki: 证书已被吊销")
	ErrCertNotFound   = errors.New("pki: 证书不存在")
)

// 本地状态加载与轮换的可区分失败原因。
var (
	ErrStoreCorrupt   = errors.New("pki: 本地状态损坏")
	ErrStoreVersion   = errors.New("pki: 状态格式版本超出支持范围")
	ErrRotationFailed = errors.New("pki: 轮换失败")
)

// 受管实体操作的可区分失败原因。
var (
	ErrEntityNotFound      = errors.New("pki: 受管实体不存在")
	ErrEntityAlreadyExists = errors.New("pki: 受管实体已登记")
	ErrUsageNotAuthorized  = errors.New("pki: 实体未被授权该用途")
)

// 标识与有效期的约束常量。
const (
	maxIdentityLen = 64
	minLifetime    = time.Minute
	maxLifetime    = 3650 * 24 * time.Hour
)

// IssueRequest 描述一次证书签发请求。
type IssueRequest struct {
	Identity  string    // 受管实体标识
	Usages    KeyUsage  // 申请的密钥用途
	NotBefore time.Time // 生效时刻
	NotAfter  time.Time // 失效时刻
	Serial    uint64    // 指定序列号；0 表示由签发方分配
	SubjectID string    // 实体密钥标识（实体轮换时变化）；空表示由标识派生
}

// validate 校验请求约束；任何越界都返回可区分的原因，不用默认值兜底。
func (r IssueRequest) validate() error {
	if err := validateIdentity(r.Identity); err != nil {
		return err
	}
	if !r.Usages.Valid() {
		return fmt.Errorf("%w: 用途为空或含未知位 (%s)", ErrUsageConflict, r.Usages)
	}
	if r.NotBefore.IsZero() || r.NotAfter.IsZero() {
		return fmt.Errorf("%w: 生效/失效时刻必须显式给出", ErrInvalidValidity)
	}
	if !r.NotBefore.Before(r.NotAfter) {
		return fmt.Errorf("%w: 生效时刻 %s 不早于失效时刻 %s",
			ErrInvalidValidity, r.NotBefore.UTC(), r.NotAfter.UTC())
	}
	if d := r.NotAfter.Sub(r.NotBefore); d < minLifetime || d > maxLifetime {
		return fmt.Errorf("%w: 有效期 %s 超出允许范围 [%s, %s]",
			ErrInvalidValidity, d, minLifetime, maxLifetime)
	}
	return nil
}

// validateIdentity 校验受管实体标识：非空、长度受限、字符集受限。
func validateIdentity(id string) error {
	if id == "" {
		return fmt.Errorf("%w: 标识为空", ErrInvalidIdentity)
	}
	if len(id) > maxIdentityLen {
		return fmt.Errorf("%w: 标识长度 %d 超过上限 %d", ErrInvalidIdentity, len(id), maxIdentityLen)
	}
	for i := 0; i < len(id); i++ {
		ch := id[i]
		ok := ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' ||
			ch >= '0' && ch <= '9' || ch == '.' || ch == '_' || ch == '-'
		if !ok {
			return fmt.Errorf("%w: 标识含非法字符 %q", ErrInvalidIdentity, ch)
		}
	}
	return nil
}

// Certificate 是签发方签发的证书。
type Certificate struct {
	Serial      uint64
	Identity    string
	Usages      KeyUsage
	NotBefore   time.Time
	NotAfter    time.Time
	IssuerEpoch uint64 // 签发时使用的签发方密钥代数
	SubjectID   string
	// SubjectKeyID 是实体公钥的指纹；SubjectEpoch 是签发时该实体密钥的代次。
	// 旧证书两者均为零值，校验时按旧规则放行（见兼容语义）。
	SubjectKeyID string
	SubjectEpoch uint64
	Signature    []byte
}

// Verdict 是证书校验结论，各类失败彼此可区分。
type Verdict int

const (
	VerdictOK Verdict = iota
	VerdictExpired
	VerdictNotYetValid
	VerdictUntrustedIssuer
	VerdictUsageMismatch
	VerdictRevoked
	VerdictBadSignature
	VerdictUnknownEntity // 证书主体未在实体登记库中
	VerdictSubjectEpoch  // 证书声称的实体密钥代次与登记库对不上
	VerdictSubjectKey    // 实体公钥指纹与证书记录不一致
)

// String 返回结论的可读表示。
func (v Verdict) String() string {
	switch v {
	case VerdictOK:
		return "OK"
	case VerdictExpired:
		return "EXPIRED"
	case VerdictNotYetValid:
		return "NOT_YET_VALID"
	case VerdictUntrustedIssuer:
		return "UNTRUSTED_ISSUER"
	case VerdictUsageMismatch:
		return "USAGE_MISMATCH"
	case VerdictRevoked:
		return "REVOKED"
	case VerdictBadSignature:
		return "BAD_SIGNATURE"
	case VerdictUnknownEntity:
		return "UNKNOWN_ENTITY"
	case VerdictSubjectEpoch:
		return "SUBJECT_EPOCH_UNKNOWN"
	case VerdictSubjectKey:
		return "SUBJECT_KEY_MISMATCH"
	default:
		return fmt.Sprintf("Verdict(%d)", int(v))
	}
}

// OK 报告结论是否为通过。
func (v Verdict) OK() bool { return v == VerdictOK }
