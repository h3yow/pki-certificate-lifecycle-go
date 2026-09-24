package pki

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestDuplicatePinnedSerialRejected(t *testing.T) {
	m := newTestManager(t)
	mustRegister(t, m, "svc", UsageServerAuth)

	first := mustIssue(t, m, IssueRequest{
		Entity: "svc", Usages: UsageServerAuth, TTL: time.Hour, SerialNumber: 100,
	})
	if first.Serial != 100 {
		t.Fatalf("pinned serial = %d want 100", first.Serial)
	}

	// A later request that pins the same serial must be rejected distinctly
	// and must not advance the automatic counter.
	_, err := m.Issue(IssueRequest{
		Entity: "svc", Usages: UsageServerAuth, TTL: time.Hour, SerialNumber: 100,
	})
	if !errors.Is(err, ErrSerialDuplicate) {
		t.Fatalf("duplicate serial: got %v want ErrSerialDuplicate", err)
	}
	t.Logf("duplicate pinned serial rejected: %v", err)

	// Auto allocation advances strictly past the high-water mark so it can
	// never collide with a previously pinned serial.
	auto := mustIssue(t, m, IssueRequest{
		Entity: "svc", Usages: UsageServerAuth, TTL: time.Hour,
	})
	if auto.Serial != 101 {
		t.Fatalf("auto serial after pinning 100 = %d want 101", auto.Serial)
	}
	auto2 := mustIssue(t, m, IssueRequest{
		Entity: "svc", Usages: UsageServerAuth, TTL: time.Hour,
	})
	if auto2.Serial != 102 {
		t.Fatalf("second auto serial = %d want 102", auto2.Serial)
	}
}

func TestConcurrentIssueUniqueSerials(t *testing.T) {
	m := newTestManager(t)
	mustRegister(t, m, "svc", UsageServerAuth)

	const n = 60
	var wg sync.WaitGroup
	errs := make(chan error, n)
	serials := make(chan int64, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			c, err := m.Issue(IssueRequest{
				Entity: "svc", Usages: UsageServerAuth, TTL: time.Hour,
			})
			if err != nil {
				errs <- err
				return
			}
			serials <- c.Serial
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	close(serials)

	for err := range errs {
		t.Fatalf("concurrent issue error: %v", err)
	}
	seen := make(map[int64]int, n)
	for s := range serials {
		seen[s]++
	}
	if len(seen) != n {
		t.Fatalf("unique serials = %d want %d (duplicates present)", len(seen), n)
	}
	for s, count := range seen {
		if count != 1 {
			t.Fatalf("serial %d issued %d times", s, count)
		}
	}
	t.Logf("concurrent issuances produced %d unique serials in range [1,%d]", n, n)

	// Every issued serial is verifiable under the live state.
	for s := range seen {
		rec, ok := m.IssuedSerial(s)
		if !ok {
			t.Fatalf("serial %d not recorded", s)
		}
		res, err := m.Verify(rec.Cert, UsageServerAuth)
		if err != nil || !res.OK {
			t.Fatalf("serial %d verify: err=%v res=%v", s, err, res)
		}
	}
}

func TestConcurrentInterleavedIssueVerifyRotate(t *testing.T) {
	m := newTestManager(t)
	mustRegister(t, m, "svc", UsageServerAuth)

	// Pre-issue a generation-1 certificate that must survive rotation.
	old := mustIssue(t, m, IssueRequest{Entity: "svc", Usages: UsageServerAuth, TTL: time.Hour})

	const workers = 8
	const rounds = 15
	var wg sync.WaitGroup
	var failMu sync.Mutex
	var firstErr error
	recordErr := func(err error) {
		failMu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		failMu.Unlock()
	}
	start := make(chan struct{})

	// issuers
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < rounds; i++ {
				if _, err := m.Issue(IssueRequest{
					Entity: "svc", Usages: UsageServerAuth, TTL: time.Hour,
				}); err != nil {
					recordErr(fmt.Errorf("issue: %w", err))
					return
				}
			}
		}()
	}
	// verifiers constantly re-check the historical gen-1 certificate
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < rounds; i++ {
				res, err := m.Verify(old.Cert, UsageServerAuth)
				if err != nil {
					recordErr(fmt.Errorf("verify: %w", err))
					return
				}
				if !res.OK {
					recordErr(fmt.Errorf("historical cert failed: %w", res.Reason))
					return
				}
			}
		}()
	}
	// a rotator moves issuer generations repeatedly
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 3; i++ {
			if _, err := m.RotateIssuer(); err != nil {
				recordErr(fmt.Errorf("rotate: %w", err))
				return
			}
		}
	}()

	close(start)
	wg.Wait()
	if firstErr != nil {
		t.Fatalf("interleaved workload: %v", firstErr)
	}
	t.Logf("interleaved issue/verify/rotate finished at issuer gen %d; old cert still trusted",
		m.ActiveIssuerGeneration())

	// After all rotations the gen-1 certificate still verifies under its
	// issuance-time trust relationship.
	res, err := m.Verify(old.Cert, UsageServerAuth)
	if err != nil || !res.OK {
		t.Fatalf("old cert after rotations: err=%v res=%+v", err, res)
	}
}
