package pki

import (
	"crypto"
	"crypto/ecdsa"
	"time"
)

// KeyUsage is a bitmask of intended key usages. Only the bits defined below
// are accepted; requests containing unknown bits are rejected.
type KeyUsage uint16

const (
	UsageDigitalSignature KeyUsage = 1 << iota
	UsageKeyEncipherment
	UsageClientAuth
	UsageServerAuth
	// UsageKnownMask covers every accepted usage bit.
	UsageKnownMask KeyUsage = UsageDigitalSignature | UsageKeyEncipherment |
		UsageClientAuth | UsageServerAuth
)

// Has reports whether u contains all bits in other.
func (u KeyUsage) Has(other KeyUsage) bool { return u&other == other }

// IssuerInfo describes one generation of the private issuer.
type IssuerInfo struct {
	Generation int
	// IssuerID uniquely identifies the trust domain across independently
	// bootstrapped PKIs. Two unrelated PKIs both have "generation 1" but
	// never share an IssuerID, so a foreign certificate is reported as
	// untrusted rather than misattributed to a same-numbered local issuer.
	IssuerID  []byte
	Cert      []byte // DER-encoded issuer certificate
	Key       *ecdsa.PrivateKey
	notBefore time.Time
	notAfter  time.Time
}

// EntityRecord is the managed registration of one named entity.
type EntityRecord struct {
	Name    string
	Key     *ecdsa.PrivateKey
	Allowed KeyUsage // usages this entity is permitted to request
}

// IssueRequest binds the constraints for a single certificate issuance.
type IssueRequest struct {
	// Entity is the subject identity. It must match a registered entity and
	// satisfy the identity grammar; no default substitution is performed.
	Entity string
	// Usages are the requested key usages. They must be non-empty, contain
	// only known bits and be a subset of the entity's allowed usages.
	Usages KeyUsage
	// TTL is the requested validity duration. It must be within
	// (0, MaxTTL]; zero is rejected rather than defaulted.
	TTL time.Duration
	// SerialNumber optionally pins the serial number. Zero means the issuer
	// allocates the next monotonic serial; a non-zero duplicate is rejected.
	SerialNumber int64
	// NotBefore optionally offsets validity start. The zero value means
	// "now"; an explicit value is never replaced by a default.
	NotBefore time.Time
}

// IssuedCertificate is an issuance result together with enough provenance to
// explain later verification conclusions.
type IssuedCertificate struct {
	Serial    int64
	Entity    string
	Cert      []byte // DER-encoded certificate
	Key       crypto.PrivateKey
	Usages    KeyUsage
	IssuerGen int
	NotBefore time.Time
	NotAfter  time.Time
}

// RevocationRecord is the irrevocable conclusion that a certificate is
// revoked. Records are append-only and never removed.
type RevocationRecord struct {
	Serial    int64
	Entity    string
	RevokedAt time.Time
	Reason    string
}

// VerifyResult is the explainable conclusion of a verification.
type VerifyResult struct {
	OK        bool
	Serial    int64
	Entity    string
	IssuerGen int
	CheckedAt time.Time
	NotBefore time.Time
	NotAfter  time.Time
	Usages    KeyUsage
	Required  KeyUsage
	Revoked   bool
	Reason    error  // nil when OK
	Basis     string // human-readable basis of the conclusion
}
