package pki

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// stateFormatVersion is the only persisted format version written by this
// build. Older versions may be read; newer versions must be rejected.
const stateFormatVersion = 1

// snapshot is the on-disk representation of all durable conclusions.
// Missing JSON fields decode to zero values, whose semantics are fixed:
//
//   - missing formatVersion (0) is accepted as the v1 layout,
//   - zero issuer generation / serial counters behave as "start from 1",
//   - absent trust/entity/cert/revocation slices behave as empty,
//   - records with zero timestamps are rejected as corrupt rather than
//     silently mis-dated.
type snapshot struct {
	FormatVersion int `json:"formatVersion"`

	IssuerGen       int               `json:"issuerGen"`
	ActiveIssuerGen int               `json:"activeIssuerGen"`
	TrustedIssuers  []persistedIssuer `json:"trustedIssuers"`

	NextSerial  int64             `json:"nextSerial"`
	Entities    []persistedEntity `json:"entities"`
	Certs       []persistedCert   `json:"certs"`
	Revocations []persistedRevoke `json:"revocations"`
}

type persistedIssuer struct {
	Generation int       `json:"generation"`
	IssuerID   []byte    `json:"issuerId"`
	Cert       []byte    `json:"cert"`
	Key        []byte    `json:"key"`
	NotBefore  time.Time `json:"notBefore"`
	NotAfter   time.Time `json:"notAfter"`
}

type persistedEntity struct {
	Name    string   `json:"name"`
	Key     []byte   `json:"key"`
	Allowed KeyUsage `json:"allowed"`
}

type persistedCert struct {
	Serial    int64     `json:"serial"`
	Entity    string    `json:"entity"`
	Cert      []byte    `json:"cert"`
	Usages    KeyUsage  `json:"usages"`
	IssuerGen int       `json:"issuerGen"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
}

type persistedRevoke struct {
	Serial    int64     `json:"serial"`
	Entity    string    `json:"entity"`
	RevokedAt time.Time `json:"revokedAt"`
	Reason    string    `json:"reason,omitempty"`
}

// StateStore persists a single JSON snapshot atomically.
type StateStore interface {
	// Load returns the raw snapshot and reports whether one exists.
	Load() (data []byte, exists bool, err error)
	// Save replaces the snapshot atomically.
	Save(state []byte) error
}

// FileStore writes snapshots to a local file via temp-file + rename so a
// crash cannot leave a half-written state behind.
type FileStore struct {
	path string
}

// NewFileStore creates a file-backed store at path.
func NewFileStore(path string) *FileStore { return &FileStore{path: path} }

// Load reads the snapshot file. A missing file is reported as not existing
// rather than as an error so callers can bootstrap fresh state.
func (s *FileStore) Load() ([]byte, bool, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if len(data) == 0 {
		return nil, false, nil
	}
	return data, true, nil
}

// Save writes state to a temp file in the same directory, fsyncs it and
// renames it over the snapshot, so the on-disk file is never observed
// half-written.
func (s *FileStore) Save(state []byte) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".pki-state-*")
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(state); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("fsync state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close state: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		cleanup()
		return fmt.Errorf("chmod state: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		cleanup()
		return fmt.Errorf("commit state: %w", err)
	}
	// Best-effort directory fsync so the rename itself is durable.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// encodeState serializes a snapshot as indented JSON for inspectability.
func encodeState(snap *snapshot) ([]byte, error) {
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStateCorrupt, err)
	}
	return data, nil
}

// decodeState parses a snapshot, rejecting unsupported format versions and
// structurally corrupt records. It deliberately checks field-level
// invariants so missing fields cannot be silently misinterpreted.
func decodeState(data []byte) (*snapshot, error) {
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("%w: invalid JSON: %v", ErrStateCorrupt, err)
	}
	// 0 means the field was absent and is accepted as the v1 layout; any
	// version newer than this build cannot be interpreted safely.
	if snap.FormatVersion > stateFormatVersion {
		return nil, fmt.Errorf("%w: version %d > supported %d",
			ErrStateVersionUnsupported, snap.FormatVersion, stateFormatVersion)
	}

	seenSerials := make(map[int64]struct{}, len(snap.Certs))
	for i, c := range snap.Certs {
		if c.Serial <= 0 {
			return nil, fmt.Errorf("%w: cert[%d] has non-positive serial", ErrStateCorrupt, i)
		}
		if _, dup := seenSerials[c.Serial]; dup {
			return nil, fmt.Errorf("%w: duplicate serial %d in state", ErrStateCorrupt, c.Serial)
		}
		seenSerials[c.Serial] = struct{}{}
		if len(c.Cert) == 0 || c.Entity == "" {
			return nil, fmt.Errorf("%w: cert[%d] missing cert bytes or entity", ErrStateCorrupt, i)
		}
		if c.NotBefore.IsZero() || c.NotAfter.IsZero() || !c.NotBefore.Before(c.NotAfter) {
			return nil, fmt.Errorf("%w: cert[%d] invalid validity window", ErrStateCorrupt, i)
		}
	}
	for i, r := range snap.Revocations {
		if r.Serial <= 0 {
			return nil, fmt.Errorf("%w: revocation[%d] has non-positive serial", ErrStateCorrupt, i)
		}
		if r.RevokedAt.IsZero() {
			return nil, fmt.Errorf("%w: revocation[%d] missing revokedAt", ErrStateCorrupt, i)
		}
		if _, ok := seenSerials[r.Serial]; !ok {
			return nil, fmt.Errorf("%w: revocation[%d] references unknown serial %d",
				ErrStateCorrupt, i, r.Serial)
		}
	}
	for i, e := range snap.Entities {
		if e.Name == "" || len(e.Key) == 0 {
			return nil, fmt.Errorf("%w: entity[%d] missing name or key", ErrStateCorrupt, i)
		}
	}
	for i, iss := range snap.TrustedIssuers {
		if iss.Generation <= 0 || len(iss.Cert) == 0 || len(iss.Key) == 0 {
			return nil, fmt.Errorf("%w: issuer[%d] incomplete", ErrStateCorrupt, i)
		}
		if len(iss.IssuerID) == 0 {
			return nil, fmt.Errorf("%w: issuer[%d] missing trust-domain id", ErrStateCorrupt, i)
		}
		if iss.NotBefore.IsZero() || iss.NotAfter.IsZero() {
			return nil, fmt.Errorf("%w: issuer[%d] missing validity", ErrStateCorrupt, i)
		}
	}
	return &snap, nil
}
