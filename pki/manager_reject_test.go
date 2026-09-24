package pki

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// newTestManager builds a manager backed by a fresh temp state file with a
// fixed clock so validity conclusions are reproducible.
func newTestManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	m, err := NewManager(NewFileStore(filepath.Join(dir, "state.json")))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m.WithClock(frozenClock{time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)})
}

func TestIssueRejectionReasonsAreDistinguishable(t *testing.T) {
	base := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name  string
		setup func(m *Manager)
		req   IssueRequest
		want  error
	}{
		{
			name: "illegal identity",
			req:  IssueRequest{Entity: "Bad Name", Usages: UsageServerAuth, TTL: time.Hour},
			want: ErrInvalidIdentity,
		},
		{
			name: "unknown entity",
			req:  IssueRequest{Entity: "nobody", Usages: UsageServerAuth, TTL: time.Hour},
			want: ErrIdentityNotFound,
		},
		{
			name:  "empty usage",
			setup: func(m *Manager) { mustRegister(t, m, "svc", UsageServerAuth) },
			req:   IssueRequest{Entity: "svc", Usages: 0, TTL: time.Hour},
			want:  ErrUsageConflict,
		},
		{
			name:  "unknown usage bit",
			setup: func(m *Manager) { mustRegister(t, m, "svc", UsageServerAuth|UsageClientAuth) },
			req:   IssueRequest{Entity: "svc", Usages: KeyUsage(0x8000), TTL: time.Hour},
			want:  ErrUsageConflict,
		},
		{
			name:  "usage exceeds entity allowed",
			setup: func(m *Manager) { mustRegister(t, m, "svc", UsageServerAuth) },
			req:   IssueRequest{Entity: "svc", Usages: UsageServerAuth | UsageClientAuth, TTL: time.Hour},
			want:  ErrUsageConflict,
		},
		{
			name:  "zero ttl not defaulted",
			setup: func(m *Manager) { mustRegister(t, m, "svc", UsageServerAuth) },
			req:   IssueRequest{Entity: "svc", Usages: UsageServerAuth, TTL: 0},
			want:  ErrTTLOutOfRange,
		},
		{
			name:  "oversized ttl",
			setup: func(m *Manager) { mustRegister(t, m, "svc", UsageServerAuth) },
			req:   IssueRequest{Entity: "svc", Usages: UsageServerAuth, TTL: MaxTTL + time.Hour},
			want:  ErrTTLOutOfRange,
		},
		{
			name:  "negative serial",
			setup: func(m *Manager) { mustRegister(t, m, "svc", UsageServerAuth) },
			req:   IssueRequest{Entity: "svc", Usages: UsageServerAuth, TTL: time.Hour, SerialNumber: -3},
			want:  ErrSerialOutOfRange,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := newTestManager(t)
			if c.setup != nil {
				c.setup(m)
			}
			// explicit NotBefore so output is deterministic
			c.req.NotBefore = base
			_, err := m.Issue(c.req)
			if !errors.Is(err, c.want) {
				t.Fatalf("Issue(%q) err = %v, want %v", c.name, err, c.want)
			}
			t.Logf("input=%+v -> rejected with %v (distinct reason)", c.req, err)
		})
	}
}

func TestRegisterRejectsBadInput(t *testing.T) {
	m := newTestManager(t)
	if err := m.RegisterEntity("Bad Name", UsageServerAuth); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("got %v want ErrInvalidIdentity", err)
	}
	if err := m.RegisterEntity("ok", 0); !errors.Is(err, ErrUsageConflict) {
		t.Fatalf("got %v want ErrUsageConflict", err)
	}
	if err := m.RegisterEntity("ok", KeyUsage(0x4000)); !errors.Is(err, ErrUsageConflict) {
		t.Fatalf("got %v want ErrUsageConflict", err)
	}
	if err := m.RegisterEntity("ok", UsageServerAuth); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := m.RegisterEntity("ok", UsageServerAuth); !errors.Is(err, ErrIdentityExists) {
		t.Fatalf("dup register got %v want ErrIdentityExists", err)
	}
}

func mustRegister(t *testing.T, m *Manager, name string, allowed KeyUsage) {
	t.Helper()
	if err := m.RegisterEntity(name, allowed); err != nil {
		t.Fatalf("register %q: %v", name, err)
	}
}

func mustIssue(t *testing.T, m *Manager, req IssueRequest) *IssuedCertificate {
	t.Helper()
	c, err := m.Issue(req)
	if err != nil {
		t.Fatalf("issue %+v: %v", req, err)
	}
	return c
}
