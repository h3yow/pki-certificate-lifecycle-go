package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"sort"
	"sync"
	"time"
)

// MaxTTL bounds every issuance request; longer TTLs are rejected.
const MaxTTL = time.Duration(365*24) * time.Hour // one year

// issuerTTL is the validity window assigned to each issuer generation.
const issuerTTL = 10 * 365 * 24 * time.Hour

// issuerCNPrefix encodes the issuer generation in the issuer certificate
// subject so verification can name the claimed generation before trusting
// any key.
const issuerCNPrefix = "local-private-issuer-gen-"

// liveState is the in-memory authoritative state guarded by Manager.mu.
type liveState struct {
	issuerID        []byte
	issuerGen       int
	activeIssuerGen int
	trustedIssuers  map[int]*IssuerInfo

	nextSerial  int64
	entities    map[string]*EntityRecord
	certs       map[int64]*persistedCert
	revocations map[int64]*persistedRevoke
}

func newLiveState() *liveState {
	return &liveState{
		trustedIssuers: map[int]*IssuerInfo{},
		entities:       map[string]*EntityRecord{},
		certs:          map[int64]*persistedCert{},
		revocations:    map[int64]*persistedRevoke{},
	}
}

// Manager is the concurrency-safe entry point for issuance, verification,
// rotation and revocation. All state transitions are serialized by mu and
// are made durable before they become visible.
type Manager struct {
	store StateStore
	clock Clock

	mu sync.RWMutex
	st *liveState
}

// NewManager loads durable state from store or bootstraps a fresh private
// issuer. Corrupt state or an unsupported format version is rejected rather
// than served from uncertain state.
func NewManager(store StateStore) (*Manager, error) {
	if store == nil {
		return nil, fmt.Errorf("pki: nil state store")
	}
	data, exists, err := store.Load()
	if err != nil {
		return nil, err
	}
	var st *liveState
	if !exists {
		st, err = bootstrapState(time.Now())
		if err != nil {
			return nil, err
		}
		encoded, err := encodeState(st.toSnapshot())
		if err != nil {
			return nil, err
		}
		if err := store.Save(encoded); err != nil {
			return nil, err
		}
	} else {
		snap, err := decodeState(data)
		if err != nil {
			return nil, err
		}
		st, err = stateFromSnapshot(snap)
		if err != nil {
			return nil, err
		}
	}
	return &Manager{store: store, clock: systemClock{}, st: st}, nil
}

// WithClock overrides the clock. Intended for setup and tests that need
// reproducible validity conclusions.
func (m *Manager) WithClock(c Clock) *Manager {
	if c == nil {
		return m
	}
	m.mu.Lock()
	m.clock = c
	m.mu.Unlock()
	return m
}

// ---------------------------------------------------------------------------
// Snapshot conversion
// ---------------------------------------------------------------------------

func (s *liveState) toSnapshot() *snapshot {
	snap := &snapshot{
		FormatVersion:   stateFormatVersion,
		IssuerGen:       s.issuerGen,
		ActiveIssuerGen: s.activeIssuerGen,
		NextSerial:      s.nextSerial,
	}
	gens := make([]int, 0, len(s.trustedIssuers))
	for g := range s.trustedIssuers {
		gens = append(gens, g)
	}
	sort.Ints(gens)
	for _, g := range gens {
		iss := s.trustedIssuers[g]
		keyDER, err := marshalECPrivateKey(iss.Key)
		if err != nil {
			panic(fmt.Errorf("pki: encode issuer key: %w", err))
		}
		snap.TrustedIssuers = append(snap.TrustedIssuers, persistedIssuer{
			Generation: iss.Generation,
			IssuerID:   iss.IssuerID,
			Cert:       iss.Cert,
			Key:        keyDER,
			NotBefore:  iss.notBefore,
			NotAfter:   iss.notAfter,
		})
	}
	names := make([]string, 0, len(s.entities))
	for n := range s.entities {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		e := s.entities[n]
		keyDER, err := marshalECPrivateKey(e.Key)
		if err != nil {
			panic(fmt.Errorf("pki: encode entity key: %w", err))
		}
		snap.Entities = append(snap.Entities, persistedEntity{
			Name: n, Key: keyDER, Allowed: e.Allowed,
		})
	}
	serials := make([]int64, 0, len(s.certs))
	for sn := range s.certs {
		serials = append(serials, sn)
	}
	sort.Slice(serials, func(i, j int) bool { return serials[i] < serials[j] })
	for _, sn := range serials {
		snap.Certs = append(snap.Certs, *s.certs[sn])
	}
	revoked := make([]int64, 0, len(s.revocations))
	for sn := range s.revocations {
		revoked = append(revoked, sn)
	}
	sort.Slice(revoked, func(i, j int) bool { return revoked[i] < revoked[j] })
	for _, sn := range revoked {
		snap.Revocations = append(snap.Revocations, *s.revocations[sn])
	}
	return snap
}

func stateFromSnapshot(snap *snapshot) (*liveState, error) {
	s := newLiveState()
	s.issuerGen = snap.IssuerGen
	s.activeIssuerGen = snap.ActiveIssuerGen
	s.nextSerial = snap.NextSerial

	for _, pi := range snap.TrustedIssuers {
		key, err := parseECPrivateKey(pi.Key)
		if err != nil {
			return nil, fmt.Errorf("%w: issuer gen %d key: %v", ErrStateCorrupt, pi.Generation, err)
		}
		if _, err := parseCert(pi.Cert); err != nil {
			return nil, fmt.Errorf("%w: issuer gen %d cert: %v", ErrStateCorrupt, pi.Generation, err)
		}
		// Every generation of one trust domain must share one id; a mixed
		// set is ambiguous and must be rejected rather than trusted.
		if len(s.issuerID) == 0 {
			s.issuerID = append([]byte(nil), pi.IssuerID...)
		} else if !bytes.Equal(s.issuerID, pi.IssuerID) {
			return nil, fmt.Errorf("%w: issuer gen %d trust-domain id mismatch",
				ErrStateCorrupt, pi.Generation)
		}
		s.trustedIssuers[pi.Generation] = &IssuerInfo{
			Generation: pi.Generation,
			IssuerID:   append([]byte(nil), pi.IssuerID...),
			Cert:       pi.Cert,
			Key:        key,
			notBefore:  pi.NotBefore,
			notAfter:   pi.NotAfter,
		}
	}
	if len(s.issuerID) == 0 {
		return nil, fmt.Errorf("%w: missing trust-domain id", ErrStateCorrupt)
	}
	if s.issuerGen == 0 || s.activeIssuerGen == 0 {
		return nil, fmt.Errorf("%w: missing issuer generation", ErrStateCorrupt)
	}
	if s.activeIssuerGen > s.issuerGen {
		return nil, fmt.Errorf("%w: active gen %d above max gen %d",
			ErrStateCorrupt, s.activeIssuerGen, s.issuerGen)
	}
	// Every generation up to and including the active one must be present:
	// these are the materials that may have signed certificates.
	for g := 1; g <= s.activeIssuerGen; g++ {
		if _, ok := s.trustedIssuers[g]; !ok {
			return nil, fmt.Errorf("%w: issuer generation %d missing", ErrStateCorrupt, g)
		}
	}
	// A stored generation strictly above the active one can only result
	// from a crash after the new issuer material was persisted but before
	// activation completed. It is retained as trusted (it never signed) and
	// the high-water counter is advanced to it so the next rotation cannot
	// reuse the number.
	maxStored := 0
	for g := range s.trustedIssuers {
		if g > maxStored {
			maxStored = g
		}
		if g < 1 {
			return nil, fmt.Errorf("%w: non-positive issuer generation", ErrStateCorrupt)
		}
	}
	if maxStored > s.issuerGen {
		s.issuerGen = maxStored
	}

	for _, pe := range snap.Entities {
		key, err := parseECPrivateKey(pe.Key)
		if err != nil {
			return nil, fmt.Errorf("%w: entity %q key: %v", ErrStateCorrupt, pe.Name, err)
		}
		if !validIdentity(pe.Name) {
			return nil, fmt.Errorf("%w: entity name %q", ErrStateCorrupt, pe.Name)
		}
		s.entities[pe.Name] = &EntityRecord{Name: pe.Name, Key: key, Allowed: pe.Allowed}
	}

	maxSerial := int64(0)
	for _, pc := range snap.Certs {
		c := pc
		if _, err := parseCert(c.Cert); err != nil {
			return nil, fmt.Errorf("%w: cert %d: %v", ErrStateCorrupt, c.Serial, err)
		}
		if _, ok := s.trustedIssuers[c.IssuerGen]; !ok {
			return nil, fmt.Errorf("%w: cert %d issuer gen %d missing", ErrStateCorrupt, c.Serial, c.IssuerGen)
		}
		if _, ok := s.entities[c.Entity]; !ok {
			return nil, fmt.Errorf("%w: cert %d entity %q missing", ErrStateCorrupt, c.Serial, c.Entity)
		}
		s.certs[c.Serial] = &c
		if c.Serial > maxSerial {
			maxSerial = c.Serial
		}
	}
	if s.nextSerial <= maxSerial {
		return nil, fmt.Errorf("%w: nextSerial %d not above max serial %d",
			ErrStateCorrupt, s.nextSerial, maxSerial)
	}

	for _, pr := range snap.Revocations {
		r := pr
		s.revocations[r.Serial] = &r
	}
	return s, nil
}

func bootstrapState(now time.Time) (*liveState, error) {
	s := newLiveState()
	s.issuerGen = 1
	s.activeIssuerGen = 1
	s.nextSerial = 1
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	s.issuerID = id
	key, err := generateKey()
	if err != nil {
		return nil, err
	}
	iss, err := createIssuer(1, s.issuerID, key, now, now.Add(issuerTTL))
	if err != nil {
		return nil, err
	}
	s.trustedIssuers[1] = iss
	return s, nil
}

// encodeLocked serializes the current in-memory state.
func (m *Manager) encodeLocked() ([]byte, error) {
	return encodeState(m.st.toSnapshot())
}

// restoreLocked rebuilds in-memory state from a previously encoded snapshot
// to roll back after a durable write fails.
func (m *Manager) restoreLocked(before []byte) error {
	snap, err := decodeState(before)
	if err != nil {
		return err
	}
	st, err := stateFromSnapshot(snap)
	if err != nil {
		return err
	}
	m.st = st
	return nil
}

// commitLocked makes pending in-memory changes durable. On failure the prior
// state is restored exactly, so no mutation is left half-visible.
func (m *Manager) commitLocked(before []byte) error {
	after, err := m.encodeLocked()
	if err != nil {
		_ = m.restoreLocked(before)
		return err
	}
	if err := m.store.Save(after); err != nil {
		if rerr := m.restoreLocked(before); rerr != nil {
			return fmt.Errorf("save failed (%v) and rollback failed: %w", err, rerr)
		}
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// Entity management
// ---------------------------------------------------------------------------

// RegisterEntity records a managed entity and the usages it may request.
func (m *Manager) RegisterEntity(name string, allowed KeyUsage) error {
	if !validIdentity(name) {
		return fmt.Errorf("%w: %q", ErrInvalidIdentity, name)
	}
	if allowed == 0 || allowed&^UsageKnownMask != 0 {
		return fmt.Errorf("%w: allowed usages 0x%x empty or contain unknown bits",
			ErrUsageConflict, allowed)
	}
	key, err := generateKey()
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.st.entities[name]; ok {
		return fmt.Errorf("%w: %q", ErrIdentityExists, name)
	}
	before, err := m.encodeLocked()
	if err != nil {
		return err
	}
	m.st.entities[name] = &EntityRecord{Name: name, Key: key, Allowed: allowed}
	return m.commitLocked(before)
}

// RotateEntityKey generates a fresh key for an existing entity. Certificates
// already issued remain verifiable; later issuances use the new key. The
// switch is durable and atomic.
func (m *Manager) RotateEntityKey(name string) (*ecdsa.PrivateKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.st.entities[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrIdentityNotFound, name)
	}
	newKey, err := generateKey()
	if err != nil {
		return nil, err
	}
	before, err := m.encodeLocked()
	if err != nil {
		return nil, err
	}
	e.Key = newKey
	if err := m.commitLocked(before); err != nil {
		return nil, err
	}
	return newKey, nil
}

// ---------------------------------------------------------------------------
// Issuance
// ---------------------------------------------------------------------------

// Issue signs and durably records a certificate under the request
// constraints. It never substitutes defaults for invalid input.
func (m *Manager) Issue(req IssueRequest) (*IssuedCertificate, error) {
	if !validIdentity(req.Entity) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidIdentity, req.Entity)
	}
	if req.Usages == 0 || req.Usages&^UsageKnownMask != 0 {
		return nil, fmt.Errorf("%w: requested usages 0x%x empty or contain unknown bits",
			ErrUsageConflict, req.Usages)
	}
	if req.TTL <= 0 {
		return nil, fmt.Errorf("%w: TTL %s is not positive", ErrTTLOutOfRange, req.TTL)
	}
	if req.TTL > MaxTTL {
		return nil, fmt.Errorf("%w: TTL %s exceeds max %s", ErrTTLOutOfRange, req.TTL, MaxTTL)
	}
	if req.SerialNumber < 0 {
		return nil, fmt.Errorf("%w: serial %d must be positive or zero", ErrSerialOutOfRange, req.SerialNumber)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	entity, ok := m.st.entities[req.Entity]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrIdentityNotFound, req.Entity)
	}
	if !entity.Allowed.Has(req.Usages) {
		return nil, fmt.Errorf("%w: requested 0x%x exceeds allowed 0x%x for %q",
			ErrUsageConflict, req.Usages, entity.Allowed, req.Entity)
	}
	if req.SerialNumber != 0 {
		if _, dup := m.st.certs[req.SerialNumber]; dup {
			return nil, fmt.Errorf("%w: serial %d", ErrSerialDuplicate, req.SerialNumber)
		}
	}

	now := m.clock.Now()
	serial := req.SerialNumber
	if serial == 0 {
		serial = m.st.nextSerial
	}
	issuer := m.st.trustedIssuers[m.st.activeIssuerGen]

	// Snapshot before mutation so a failed durable write can roll back
	// exactly; signing happens against stable in-memory material.
	before, err := m.encodeLocked()
	if err != nil {
		return nil, err
	}
	issued, err := issueCertificate(issuer, entity, req, serial, now)
	if err != nil {
		return nil, err
	}
	record := &persistedCert{
		Serial:    issued.Serial,
		Entity:    issued.Entity,
		Cert:      issued.Cert,
		Usages:    issued.Usages,
		IssuerGen: issued.IssuerGen,
		NotBefore: issued.NotBefore,
		NotAfter:  issued.NotAfter,
	}

	m.st.certs[serial] = record
	if m.st.nextSerial <= serial {
		m.st.nextSerial = serial + 1
	}
	if err := m.commitLocked(before); err != nil {
		return nil, err
	}
	return issued, nil
}

// ---------------------------------------------------------------------------
// Issuer rotation
// ---------------------------------------------------------------------------

// RotateIssuer creates a new issuer generation and makes it active
// atomically. Every earlier generation remains in the trusted set so
// certificates issued at earlier moments verify under the trust that was
// active when they were signed. On persistence failure the old issuer stays
// active and no certificate is left trusted by neither material.
func (m *Manager) RotateIssuer() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	newGen := m.st.issuerGen + 1
	key, err := generateKey()
	if err != nil {
		return 0, err
	}
	now := m.clock.Now()
	iss, err := createIssuer(newGen, m.st.issuerID, key, now, now.Add(issuerTTL))
	if err != nil {
		return 0, err
	}

	before, err := m.encodeLocked()
	if err != nil {
		return 0, err
	}
	m.st.trustedIssuers[newGen] = iss
	m.st.issuerGen = newGen
	m.st.activeIssuerGen = newGen
	if err := m.commitLocked(before); err != nil {
		return 0, err
	}
	return newGen, nil
}

// ActiveIssuerGeneration returns the currently active issuer generation.
func (m *Manager) ActiveIssuerGeneration() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.st.activeIssuerGen
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

// Revoke records an irrevocable revocation. It is visible to every later
// verification and can never be reverted.
func (m *Manager) Revoke(serial int64, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cert, ok := m.st.certs[serial]
	if !ok {
		return fmt.Errorf("%w: serial %d", ErrCertificateNotFound, serial)
	}
	if _, already := m.st.revocations[serial]; already {
		return fmt.Errorf("%w: serial %d", ErrAlreadyRevoked, serial)
	}
	before, err := m.encodeLocked()
	if err != nil {
		return err
	}
	m.st.revocations[serial] = &persistedRevoke{
		Serial:    serial,
		Entity:    cert.Entity,
		RevokedAt: m.clock.Now(),
		Reason:    reason,
	}
	return m.commitLocked(before)
}

// IsRevoked reports whether serial is revoked. An unknown serial yields
// ErrCertificateNotFound rather than a silent "not revoked".
func (m *Manager) IsRevoked(serial int64) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.st.certs[serial]; !ok {
		return false, fmt.Errorf("%w: serial %d", ErrCertificateNotFound, serial)
	}
	_, revoked := m.st.revocations[serial]
	return revoked, nil
}

// IssuedSerial returns the issuance record for a serial.
func (m *Manager) IssuedSerial(serial int64) (*IssuedCertificate, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.st.certs[serial]
	if !ok {
		return nil, false
	}
	return &IssuedCertificate{
		Serial:    c.Serial,
		Entity:    c.Entity,
		Cert:      c.Cert,
		Usages:    c.Usages,
		IssuerGen: c.IssuerGen,
		NotBefore: c.NotBefore,
		NotAfter:  c.NotAfter,
	}, true
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

// Verify checks a DER certificate at the clock's current instant against a
// required usage. The conclusion order is fixed and each failure is
// distinguishable: trust/signature -> time window -> revocation -> usage.
// No failure path is ever reported as success.
func (m *Manager) Verify(certDER []byte, required KeyUsage) (*VerifyResult, error) {
	if required == 0 || required&^UsageKnownMask != 0 ||
		required&(required-1) != 0 {
		return nil, fmt.Errorf("%w: required usage 0x%x must be a single known bit",
			ErrUsageConflict, required)
	}
	cert, err := parseCert(certDER)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedCertificate, err)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	now := m.clock.Now()

	// 1. The certificate must name a trusted issuer generation within this
	//    trust domain and carry a valid signature under that generation's
	//    stored key. The domain id distinguishes an independently bootstrapped
	//    PKI whose generation numbers happen to match.
	gen, issuerID, ok := parseIssuerCN(cert.Issuer.CommonName)
	if !ok {
		return failResult(cert, 0, now, required, 0, false,
			ErrUntrustedIssuer, "issuer subject does not encode a known issuer"), nil
	}
	if !bytes.Equal(issuerID, m.st.issuerID) {
		return failResult(cert, gen, now, required, 0, false,
			ErrUntrustedIssuer, fmt.Sprintf("issuer trust-domain id %x is foreign to %x",
				issuerID, m.st.issuerID)), nil
	}
	issuer, trusted := m.st.trustedIssuers[gen]
	if !trusted {
		return failResult(cert, gen, now, required, 0, false,
			ErrUntrustedIssuer, fmt.Sprintf("issuer generation %d is not in the trusted set", gen)), nil
	}
	issuerCert, err := parseCert(issuer.Cert)
	if err != nil {
		return nil, fmt.Errorf("%w: stored issuer gen %d unparsable", ErrStateCorrupt, gen)
	}
	if err := verifySignature(issuerCert, cert); err != nil {
		return failResult(cert, gen, now, required, 0, false,
			ErrSignatureInvalid, "signature did not verify under trusted issuer key"), nil
	}

	// 2. Time window: not-before and not-after are reported separately.
	if now.Before(cert.NotBefore) {
		return failResult(cert, gen, now, required, 0, false,
			ErrCertificateNotYetValid, fmt.Sprintf("now %s precedes notBefore %s",
				now.UTC().Format(time.RFC3339), cert.NotBefore.UTC().Format(time.RFC3339))), nil
	}
	if now.After(cert.NotAfter) {
		return failResult(cert, gen, now, required, 0, false,
			ErrCertificateExpired, fmt.Sprintf("now %s follows notAfter %s",
				now.UTC().Format(time.RFC3339), cert.NotAfter.UTC().Format(time.RFC3339))), nil
	}

	// 3. Revocation is authoritative local state and precedes usage.
	serial := cert.SerialNumber.Int64()
	record, known := m.st.certs[serial]
	if !known {
		return failResult(cert, gen, now, required, 0, false,
			ErrCertificateNotFound, fmt.Sprintf("serial %d has no issuance record", serial)), nil
	}
	if rev, revoked := m.st.revocations[serial]; revoked {
		return failResult(cert, gen, now, required, record.Usages, true,
			ErrRevoked, fmt.Sprintf("revoked at %s: %s",
				rev.RevokedAt.UTC().Format(time.RFC3339), rev.Reason)), nil
	}

	// 4. Usage must include the single required bit (authoritative record).
	if !record.Usages.Has(required) {
		return failResult(cert, gen, now, required, record.Usages, false,
			ErrUsageMismatch, fmt.Sprintf("cert usages 0x%x lack required 0x%x",
				record.Usages, required)), nil
	}

	return &VerifyResult{
		OK:        true,
		Serial:    serial,
		Entity:    cert.Subject.CommonName,
		IssuerGen: gen,
		CheckedAt: now,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		Usages:    record.Usages,
		Required:  required,
		Revoked:   false,
		Reason:    nil,
		Basis: fmt.Sprintf("trusted issuer gen %d signature valid; %s within [%s,%s]; not revoked; usage 0x%x contains 0x%x",
			gen, now.UTC().Format(time.RFC3339),
			cert.NotBefore.UTC().Format(time.RFC3339),
			cert.NotAfter.UTC().Format(time.RFC3339), record.Usages, required),
	}, nil
}

// failResult builds an explainable failed VerifyResult from the parsed
// certificate. usages is the locally recorded usage mask when known, else 0.
func failResult(cert *x509.Certificate, gen int, now time.Time, required KeyUsage,
	usages KeyUsage, revoked bool, reason error, basis string) *VerifyResult {
	res := &VerifyResult{
		OK:        false,
		IssuerGen: gen,
		CheckedAt: now,
		Required:  required,
		Usages:    usages,
		Revoked:   revoked,
		Reason:    reason,
		Basis:     basis,
	}
	if cert != nil {
		if cert.SerialNumber != nil {
			res.Serial = cert.SerialNumber.Int64()
		}
		res.Entity = cert.Subject.CommonName
		res.NotBefore = cert.NotBefore
		res.NotAfter = cert.NotAfter
	}
	return res
}
