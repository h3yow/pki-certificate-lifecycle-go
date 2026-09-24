package pki

import (
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

// mutableClock lets a single manager observe different instants.
type mutableClock struct{ t time.Time }

func (c *mutableClock) Now() time.Time { return c.t }

func (c *mutableClock) Set(t time.Time) { c.t = t }

func newMutableManager(t *testing.T) (*Manager, *mutableClock) {
	t.Helper()
	base := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	m, err := NewManager(NewFileStore(dir + "/state.json"))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	clk := &mutableClock{t: base}
	m.WithClock(clk)
	if err := m.RegisterEntity("svc", UsageServerAuth|UsageClientAuth); err != nil {
		t.Fatalf("register: %v", err)
	}
	return m, clk
}

func assertReason(t *testing.T, der []byte, required KeyUsage, want error, m *Manager, label string) {
	t.Helper()
	res, err := m.Verify(der, required)
	if err != nil {
		t.Fatalf("[%s] Verify returned error %v", label, err)
	}
	if want == nil {
		if !res.OK || res.Reason != nil {
			t.Fatalf("[%s] want success, got reason=%v basis=%s", label, res.Reason, res.Basis)
		}
	} else {
		if res.OK {
			t.Fatalf("[%s] want failure %v but Verify reported success", label, want)
		}
		if !errors.Is(res.Reason, want) {
			t.Fatalf("[%s] reason=%v want %v; basis=%s", label, res.Reason, want, res.Basis)
		}
	}
	t.Logf("[%s] input(required=0x%x) basis=%q -> conclusion=%v",
		label, required, res.Basis, conclusion(want))
}

func conclusion(want error) string {
	if want == nil {
		return "OK"
	}
	return want.Error()
}

func TestVerifyTimeWindowConclusions(t *testing.T) {
	m, clk := newMutableManager(t)
	c := mustIssue(t, m, IssueRequest{
		Entity: "svc", Usages: UsageServerAuth, TTL: 2 * time.Hour,
	})

	// valid
	clk.Set(time.Date(2026, 9, 25, 1, 0, 0, 0, time.UTC))
	assertReason(t, c.Cert, UsageServerAuth, nil, m, "within window")

	// not yet valid: issued with an explicit future NotBefore
	future := mustIssue(t, m, IssueRequest{
		Entity:    "svc",
		Usages:    UsageServerAuth,
		TTL:       time.Hour,
		NotBefore: time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC),
	})
	clk.Set(time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC))
	assertReason(t, future.Cert, UsageServerAuth, ErrCertificateNotYetValid, m, "not yet valid")

	// expired
	clk.Set(time.Date(2026, 9, 25, 3, 0, 0, 0, time.UTC))
	assertReason(t, c.Cert, UsageServerAuth, ErrCertificateExpired, m, "expired")

	// conclusions must be mutually distinguishable
	if errors.Is(ErrCertificateExpired, ErrCertificateNotYetValid) {
		t.Fatal("expired and not-yet-valid must be distinguishable")
	}
}

func TestVerifyUsageMismatch(t *testing.T) {
	m, _ := newMutableManager(t)
	c := mustIssue(t, m, IssueRequest{
		Entity: "svc", Usages: UsageServerAuth, TTL: time.Hour,
	})
	assertReason(t, c.Cert, UsageServerAuth, nil, m, "matching usage")
	assertReason(t, c.Cert, UsageClientAuth, ErrUsageMismatch, m, "mismatched usage")
}

func TestVerifyRevoked(t *testing.T) {
	m, _ := newMutableManager(t)
	c := mustIssue(t, m, IssueRequest{
		Entity: "svc", Usages: UsageServerAuth, TTL: time.Hour,
	})
	assertReason(t, c.Cert, UsageServerAuth, nil, m, "before revocation")
	if err := m.Revoke(c.Serial, "key compromise"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	assertReason(t, c.Cert, UsageServerAuth, ErrRevoked, m, "after revocation")

	// repeat / unknown revocation are distinguishable
	if err := m.Revoke(c.Serial, "again"); !errors.Is(err, ErrAlreadyRevoked) {
		t.Fatalf("repeat revoke: got %v want ErrAlreadyRevoked", err)
	}
	if err := m.Revoke(99999, "ghost"); !errors.Is(err, ErrCertificateNotFound) {
		t.Fatalf("ghost revoke: got %v want ErrCertificateNotFound", err)
	}
	// IsRevoked on an unknown serial must not silently say false.
	if _, err := m.IsRevoked(99999); !errors.Is(err, ErrCertificateNotFound) {
		t.Fatalf("IsRevoked unknown: got %v want ErrCertificateNotFound", err)
	}
}

func TestVerifyUntrustedIssuerAndBadSignature(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)

	m1, err := NewManager(NewFileStore(dir + "/a.json"))
	if err != nil {
		t.Fatal(err)
	}
	m1.WithClock(frozenClock{base})
	if err := m1.RegisterEntity("svc", UsageServerAuth); err != nil {
		t.Fatal(err)
	}
	c1 := mustIssue(t, m1, IssueRequest{Entity: "svc", Usages: UsageServerAuth, TTL: time.Hour})

	// Independent trust domain: same shape, different root -> untrusted.
	m2, err := NewManager(NewFileStore(dir + "/b.json"))
	if err != nil {
		t.Fatal(err)
	}
	m2.WithClock(frozenClock{base})
	if err := m2.RegisterEntity("svc", UsageServerAuth); err != nil {
		t.Fatal(err)
	}

	res, err := m2.Verify(c1.Cert, UsageServerAuth)
	if err != nil {
		t.Fatalf("verify foreign cert: %v", err)
	}
	if res.OK || !errors.Is(res.Reason, ErrUntrustedIssuer) {
		t.Fatalf("foreign cert: got reason=%v want ErrUntrustedIssuer; basis=%s", res.Reason, res.Basis)
	}
	t.Logf("[foreign trust] basis=%q -> %v", res.Basis, res.Reason)

	// Tampered signature: flip a byte in the signature region (tail bytes).
	tampered := append([]byte(nil), c1.Cert...)
	tampered[len(tampered)-3] ^= 0xFF
	// Re-parseability depends on whether DER still parses; if it does not,
	// ErrMalformedCertificate is itself a distinct non-success conclusion.
	res2, err2 := m1.Verify(tampered, UsageServerAuth)
	if err2 != nil {
		if !errors.Is(err2, ErrMalformedCertificate) {
			t.Fatalf("tampered parse error: %v", err2)
		}
		t.Logf("[tampered] malformed input rejected: %v", err2)
		return
	}
	if res2.OK || (!errors.Is(res2.Reason, ErrSignatureInvalid) &&
		!errors.Is(res2.Reason, ErrMalformedCertificate)) {
		t.Fatalf("tampered cert: reason=%v basis=%s", res2.Reason, res2.Basis)
	}
	t.Logf("[tampered] basis=%q -> %v", res2.Basis, res2.Reason)
}

func TestVerifyBadInputsNeverPass(t *testing.T) {
	m, _ := newMutableManager(t)
	if _, err := m.Verify(nil, UsageServerAuth); !errors.Is(err, ErrMalformedCertificate) {
		t.Fatalf("nil cert: %v", err)
	}
	c := mustIssue(t, m, IssueRequest{Entity: "svc", Usages: UsageServerAuth, TTL: time.Hour})
	if _, err := m.Verify(c.Cert, 0); !errors.Is(err, ErrUsageConflict) {
		t.Fatalf("zero required usage: %v", err)
	}
	if _, err := m.Verify(c.Cert, UsageServerAuth|UsageClientAuth); !errors.Is(err, ErrUsageConflict) {
		t.Fatalf("multi-bit required usage: %v", err)
	}
	if _, err := m.Verify(c.Cert, KeyUsage(0x8000)); !errors.Is(err, ErrUsageConflict) {
		t.Fatalf("unknown required usage: %v", err)
	}
}

var _ = x509.ParseCertificate

func TestRotateEntityKeyKeepsOldCertValid(t *testing.T) {
	m, _ := newMutableManager(t)
	old := mustIssue(t, m, IssueRequest{Entity: "svc", Usages: UsageServerAuth, TTL: time.Hour})

	newKey, err := m.RotateEntityKey("svc")
	if err != nil {
		t.Fatalf("rotate entity key: %v", err)
	}
	if newKey == nil {
		t.Fatal("new entity key is nil")
	}
	// The certificate issued before rotation stays verifiable.
	assertReason(t, old.Cert, UsageServerAuth, nil, m, "old cert after entity key rotation")
	// New issuance uses the rotated key but stays under the same issuer.
	fresh := mustIssue(t, m, IssueRequest{Entity: "svc", Usages: UsageServerAuth, TTL: time.Hour})
	assertReason(t, fresh.Cert, UsageServerAuth, nil, m, "new cert after entity key rotation")
	if fresh.IssuerGen != old.IssuerGen {
		t.Fatalf("issuer gen changed on entity key rotation: %d vs %d",
			fresh.IssuerGen, old.IssuerGen)
	}
	// Rotating an unknown entity is a distinct failure.
	if _, err := m.RotateEntityKey("ghost"); !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("rotate unknown entity: got %v want ErrIdentityNotFound", err)
	}
}
