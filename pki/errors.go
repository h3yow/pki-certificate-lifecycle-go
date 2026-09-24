// Package pki implements a local certificate issuance and lifecycle manager
// that simulates a private issuer and managed entities with on-disk key
// material and state.
package pki

import "errors"

// Distinguishable failure reasons. Callers can use errors.Is to tell the
// conclusions apart; a failed verification is never reported as success.
var (
	// ErrInvalidIdentity is returned when an entity identity is empty or
	// contains characters outside the permitted set.
	ErrInvalidIdentity = errors.New("pki: invalid entity identity")

	// ErrTTLOutOfRange is returned when a requested validity duration is
	// non-positive or longer than the issuer-enforced maximum.
	ErrTTLOutOfRange = errors.New("pki: requested TTL out of allowed range")

	// ErrUsageConflict is returned when key usages are missing, contain
	// unknown bits, or exceed the usages permitted for the entity.
	ErrUsageConflict = errors.New("pki: key usage conflict")

	// ErrIdentityNotFound is returned when an operation references an
	// entity that has never been registered.
	ErrIdentityNotFound = errors.New("pki: entity identity not found")

	// ErrIdentityExists is returned when registering an identity that is
	// already managed.
	ErrIdentityExists = errors.New("pki: entity identity already registered")

	// ErrMalformedCertificate is returned when verification input cannot
	// be parsed as a DER certificate; it is never treated as success.
	ErrMalformedCertificate = errors.New("pki: malformed certificate")

	// ErrCertificateNotFound is returned when a revocation references a
	// serial number that has no issuance record.
	ErrCertificateNotFound = errors.New("pki: certificate not found")

	// ErrSerialDuplicate is returned when an issuance request supplies a
	// serial number that has already been used.
	ErrSerialDuplicate = errors.New("pki: serial number already used")

	// ErrSerialOutOfRange is returned when a supplied serial number is
	// negative or otherwise outside the allowed positive range.
	ErrSerialOutOfRange = errors.New("pki: serial number out of range")

	// Verify conclusions; each is mutually distinguishable.
	ErrUntrustedIssuer        = errors.New("pki: issuer is not trusted")
	ErrCertificateExpired     = errors.New("pki: certificate is expired")
	ErrCertificateNotYetValid = errors.New("pki: certificate is not yet valid")
	ErrUsageMismatch          = errors.New("pki: certificate key usage does not match")
	ErrRevoked                = errors.New("pki: certificate has been revoked")
	ErrSignatureInvalid       = errors.New("pki: certificate signature is invalid")

	// ErrAlreadyRevoked is returned when a revoke targets a certificate
	// whose revocation is already recorded.
	ErrAlreadyRevoked = errors.New("pki: certificate already revoked")

	// ErrStateCorrupt is returned when persisted state cannot be parsed or
	// fails integrity checks.
	ErrStateCorrupt = errors.New("pki: persisted state is corrupt")

	// ErrStateVersionUnsupported is returned when the persisted state's
	// format version is newer than this build understands.
	ErrStateVersionUnsupported = errors.New("pki: persisted state format version not supported")
)
