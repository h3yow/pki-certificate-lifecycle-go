package pki

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// failStore wraps a FileStore and fails Save failTimes times before
// succeeding again, simulating a transient storage error mid-transition.
type failStore struct {
	path      string
	failTimes int
	saves     int
}

func (f *failStore) Load() ([]byte, bool, error) {
	return NewFileStore(f.path).Load()
}

func (f *failStore) Save(state []byte) error {
	if f.failTimes > 0 {
		f.failTimes--
		return errors.New("simulated storage failure")
	}
	f.saves++
	return NewFileStore(f.path).Save(state)
}

func TestRotationFailureLeavesConsistentTrust(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	m, err := NewManager(NewFileStore(path))
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	m.WithClock(frozenClock{base})
	if err := m.RegisterEntity("svc", UsageServerAuth); err != nil {
		t.Fatal(err)
	}
	old := mustIssue(t, m, IssueRequest{Entity: "svc", Usages: UsageServerAuth, TTL: time.Hour})

	// Re-open with a store whose next Save fails: the rotation must be
	// rejected and the old issuer must remain fully active.
	failing := &failStore{path: path, failTimes: 1}
	m2, err := NewManager(failing)
	if err != nil {
		t.Fatal(err)
	}
	m2.WithClock(frozenClock{base})
	if _, err := m2.RotateIssuer(); err == nil {
		t.Fatal("expected rotation to fail, got nil")
	} else {
		t.Logf("rotation failure surfaced: %v", err)
	}
	if g := m2.ActiveIssuerGeneration(); g != 1 {
		t.Fatalf("active gen after failed rotation = %d want 1", g)
	}
	res, err := m2.Verify(old.Cert, UsageServerAuth)
	if err != nil || !res.OK {
		t.Fatalf("old cert after failed rotation: err=%v res=%v basis=%s", err, res, safeBasis(res))
	}
	// A new issuance must still use the old (still trusted) generation.
	c := mustIssue(t, m2, IssueRequest{Entity: "svc", Usages: UsageServerAuth, TTL: time.Hour})
	if c.IssuerGen != 1 {
		t.Fatalf("post-failure issuance issuer gen = %d want 1", c.IssuerGen)
	}

	// Reopen from disk: no partial generation persisted.
	m3, err := NewManager(NewFileStore(path))
	if err != nil {
		t.Fatalf("reopen after failed rotation: %v", err)
	}
	if g := m3.ActiveIssuerGeneration(); g != 1 {
		t.Fatalf("persisted active gen = %d want 1", g)
	}
	if _, err := m3.Verify(old.Cert, UsageServerAuth); err != nil {
		t.Fatalf("old cert verifies on reopen: %v", err)
	}
}

func TestIssueFailureDoesNotAdvanceSerialOrTrust(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	m, err := NewManager(NewFileStore(path))
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	m.WithClock(frozenClock{base})
	if err := m.RegisterEntity("svc", UsageServerAuth); err != nil {
		t.Fatal(err)
	}

	failing := &failStore{path: path, failTimes: 1}
	m2, err := NewManager(failing)
	if err != nil {
		t.Fatal(err)
	}
	m2.WithClock(frozenClock{base})
	_, err = m2.Issue(IssueRequest{Entity: "svc", Usages: UsageServerAuth, TTL: time.Hour})
	if err == nil {
		t.Fatal("expected issue to fail on save")
	}
	t.Logf("issue failure surfaced: %v", err)

	// Reopen: the failed issuance must not consume a serial or exist on disk.
	m3, err := NewManager(NewFileStore(path))
	if err != nil {
		t.Fatal(err)
	}
	m3.WithClock(frozenClock{base})
	if _, ok := m3.IssuedSerial(1); ok {
		t.Fatal("failed issuance was persisted")
	}
	c := mustIssue(t, m3, IssueRequest{Entity: "svc", Usages: UsageServerAuth, TTL: time.Hour})
	if c.Serial != 1 {
		t.Fatalf("serial after failed issuance = %d want 1", c.Serial)
	}
}

func TestRestartPreservesIssuanceAndRevocation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	base := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)

	m, err := NewManager(NewFileStore(path))
	if err != nil {
		t.Fatal(err)
	}
	m.WithClock(frozenClock{base})
	if err := m.RegisterEntity("svc", UsageServerAuth); err != nil {
		t.Fatal(err)
	}
	c1 := mustIssue(t, m, IssueRequest{Entity: "svc", Usages: UsageServerAuth, TTL: time.Hour})
	gen := 0
	if gen, err = m.RotateIssuer(); err != nil {
		t.Fatal(err)
	}
	c2 := mustIssue(t, m, IssueRequest{Entity: "svc", Usages: UsageServerAuth, TTL: time.Hour})
	if err := m.Revoke(c1.Serial, "compromise"); err != nil {
		t.Fatal(err)
	}

	// Simulate process interruption: a brand new manager loads the file.
	m2, err := NewManager(NewFileStore(path))
	if err != nil {
		t.Fatalf("restart load: %v", err)
	}
	m2.WithClock(frozenClock{base})
	if m2.ActiveIssuerGeneration() != gen {
		t.Fatalf("after restart active gen = %d want %d", m2.ActiveIssuerGeneration(), gen)
	}

	// The already-announced revocation must still be visible and irrevocable.
	revoked, err := m2.IsRevoked(c1.Serial)
	if err != nil || !revoked {
		t.Fatalf("after restart revocation lost: revoked=%v err=%v", revoked, err)
	}
	res, err := m2.Verify(c1.Cert, UsageServerAuth)
	if err != nil {
		t.Fatalf("verify revoked cert: %v", err)
	}
	if res.OK || !errors.Is(res.Reason, ErrRevoked) {
		t.Fatalf("revoked cert after restart: %+v", res)
	}
	// A certificate issued under the previous generation still verifies by
	// the trust active at its issuance moment.
	res2, err := m2.Verify(c2.Cert, UsageServerAuth)
	if err != nil || !res2.OK {
		t.Fatalf("gen-%d cert after restart: err=%v res=%v", c2.IssuerGen, err, safeBasisR(res2, err))
	}
	t.Logf("restart: revocation preserved; gen-1 cert=%v gen-%d cert=%v",
		res.Reason, c2.IssuerGen, res2.OK)
}

func TestCorruptAndFutureVersionRejected(t *testing.T) {
	dir := t.TempDir()

	// 1. Garbage bytes are corrupt.
	garbage := filepath.Join(dir, "garbage.json")
	if err := os.WriteFile(garbage, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewManager(NewFileStore(garbage)); !errors.Is(err, ErrStateCorrupt) {
		t.Fatalf("garbage state: got %v want ErrStateCorrupt", err)
	}

	// 2. A truncated/half-written snapshot is corrupt.
	good := filepath.Join(dir, "good.json")
	m, err := NewManager(NewFileStore(good))
	if err != nil {
		t.Fatal(err)
	}
	m.WithClock(frozenClock{time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)})
	if err := m.RegisterEntity("svc", UsageServerAuth); err != nil {
		t.Fatal(err)
	}
	mustIssue(t, m, IssueRequest{Entity: "svc", Usages: UsageServerAuth, TTL: time.Hour})
	raw, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	truncated := filepath.Join(dir, "truncated.json")
	if err := os.WriteFile(truncated, raw[:len(raw)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewManager(NewFileStore(truncated)); !errors.Is(err, ErrStateCorrupt) {
		t.Fatalf("truncated state: got %v want ErrStateCorrupt", err)
	}

	// 3. A future format version is explicitly unsupported, not guessed.
	var snap snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatal(err)
	}
	snap.FormatVersion = stateFormatVersion + 1
	future, err := json.Marshal(&snap)
	if err != nil {
		t.Fatal(err)
	}
	futurePath := filepath.Join(dir, "future.json")
	if err := os.WriteFile(futurePath, future, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewManager(NewFileStore(futurePath)); !errors.Is(err, ErrStateVersionUnsupported) {
		t.Fatalf("future version: got %v want ErrStateVersionUnsupported", err)
	}
	t.Logf("corrupt/truncated/future-version state all rejected, no service on uncertain state")
}

func TestMissingFieldsDecodeDeterministically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")
	// A structurally present but incomplete record must be rejected rather
	// than silently dropped or misaligned.
	if err := os.WriteFile(path, []byte(`{
	  "formatVersion": 1,
	  "issuerGen": 1,
	  "activeIssuerGen": 1,
	  "trustedIssuers": [],
	  "nextSerial": 1,
	  "entities": [],
	  "certs": [],
	  "revocations": []
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewManager(NewFileStore(path)); !errors.Is(err, ErrStateCorrupt) {
		t.Fatalf("missing issuer: got %v want ErrStateCorrupt", err)
	}

	// A freshly bootstrapped snapshot always declares an explicit v1; an
	// absent formatVersion is only tolerated (as zero == v1) for reading
	// older documents, never emitted by this build.
	freshDir := t.TempDir()
	freshPath := filepath.Join(freshDir, "s.json")
	if _, err := NewManager(NewFileStore(freshPath)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(freshPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"formatVersion": 1`)) {
		t.Fatalf("expected formatVersion in snapshot: %s", raw)
	}

	// Backward compatibility: strip the formatVersion field entirely. An
	// older document that omitted it must still decode with the stable v1
	// zero-value semantics and remain usable.
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	delete(generic, "formatVersion")
	oldDoc, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	oldPath := filepath.Join(t.TempDir(), "old.json")
	if err := os.WriteFile(oldPath, oldDoc, 0o600); err != nil {
		t.Fatal(err)
	}
	mgr, err := NewManager(NewFileStore(oldPath))
	if err != nil {
		t.Fatalf("loading document without formatVersion: %v", err)
	}
	if g := mgr.ActiveIssuerGeneration(); g != 1 {
		t.Fatalf("active gen from versionless doc = %d want 1", g)
	}
}

func safeBasis(r *VerifyResult) string {
	if r == nil {
		return "<nil result>"
	}
	return r.Basis
}

func safeBasisR(r *VerifyResult, err error) string {
	if err != nil {
		return err.Error()
	}
	return safeBasis(r)
}

func TestRecoverPersistedButInactiveIssuer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	base := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)

	m, err := NewManager(NewFileStore(path))
	if err != nil {
		t.Fatal(err)
	}
	m.WithClock(frozenClock{base})
	if err := m.RegisterEntity("svc", UsageServerAuth); err != nil {
		t.Fatal(err)
	}
	old := mustIssue(t, m, IssueRequest{Entity: "svc", Usages: UsageServerAuth, TTL: time.Hour})

	// Simulate a crash after gen-2 material was persisted but before the
	// active pointer moved: hand-craft a snapshot with an extra trusted
	// issuer while activeIssuerGen stays 1.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var snap snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatal(err)
	}
	newKey, err := generateKey()
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := marshalECPrivateKey(newKey)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := createIssuer(2, snap.TrustedIssuers[0].IssuerID, newKey, base, base.Add(issuerTTL))
	if err != nil {
		t.Fatal(err)
	}
	snap.IssuerGen = 2
	snap.ActiveIssuerGen = 1 // activation did not commit
	snap.TrustedIssuers = append(snap.TrustedIssuers, persistedIssuer{
		Generation: 2,
		IssuerID:   snap.TrustedIssuers[0].IssuerID,
		Cert:       iss.Cert,
		Key:        keyDER,
		NotBefore:  base,
		NotAfter:   base.Add(issuerTTL),
	})
	out, err := json.MarshalIndent(&snap, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}

	// Recovery must accept the state, keep gen 1 active and still verify the
	// existing certificate (no orphan trusted by neither old nor new).
	m2, err := NewManager(NewFileStore(path))
	if err != nil {
		t.Fatalf("recover crashed rotation: %v", err)
	}
	m2.WithClock(frozenClock{base})
	if g := m2.ActiveIssuerGeneration(); g != 1 {
		t.Fatalf("active gen after recovery = %d want 1", g)
	}
	res, err := m2.Verify(old.Cert, UsageServerAuth)
	if err != nil || !res.OK {
		t.Fatalf("old cert after crash recovery: err=%v res=%+v", err, res)
	}
	// A subsequent rotation must not reuse the crashed gen-2 number.
	gen, err := m2.RotateIssuer()
	if err != nil {
		t.Fatalf("rotate after recovery: %v", err)
	}
	if gen != 3 {
		t.Fatalf("next rotation gen = %d want 3 (must not reuse crashed gen 2)", gen)
	}
	t.Logf("recovered inactive gen-2; old cert OK; next rotation became gen %d", gen)
}
