package pki

import "time"

// stateFormatVersion 是当前支持的持久化格式版本。
const stateFormatVersion = 1

// keyRecord 是一代签发方密钥材料；轮换后旧代保留以校验历史证书。
type keyRecord struct {
	Epoch   uint64 `json:"epoch"`
	Public  []byte `json:"public"`
	Private []byte `json:"private"`
	Retired bool   `json:"retired,omitempty"`
}

// certRecord 是已签发证书的持久化记录。
type certRecord struct {
	Serial      uint64    `json:"serial"`
	Identity    string    `json:"identity"`
	Usages      KeyUsage  `json:"usages"`
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`
	IssuerEpoch uint64    `json:"issuerEpoch"`
	SubjectID   string    `json:"subjectId"`
	Signature   []byte    `json:"signature"`
}

// revokeRecord 是一条吊销记录。
type revokeRecord struct {
	Serial    uint64    `json:"serial"`
	RevokedAt time.Time `json:"revokedAt"`
}

// state 是签发方的完整持久化状态。
// 缺失字段语义：version 缺省视为 1；revoked/issued/keys 缺省视为空；
// nextSerial 缺省视为 1；currentEpoch 缺省视为 keys 中最大代数。
type state struct {
	Version      uint64         `json:"version"`
	NextSerial   uint64         `json:"nextSerial"`
	CurrentEpoch uint64         `json:"currentEpoch"`
	Keys         []keyRecord    `json:"keys"`
	Issued       []certRecord   `json:"issued"`
	Revoked      []revokeRecord `json:"revoked"`
}
