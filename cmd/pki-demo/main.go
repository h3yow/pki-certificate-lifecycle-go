// Command pki-demo exercises the local PKI lifecycle end to end against a
// state file under a temp/default directory: bootstrap, register, issue,
// verify, rotate issuer (new and old certificates both verifiable), and
// revoke (later verification reports a distinguishable revocation).
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	pki "github.com/h3yow/pki-certificate-lifecycle-go/pki"
)

func main() {
	statePath := flag.String("state", filepath.Join(os.TempDir(), "pki-demo-state.json"), "state file path")
	flag.Parse()

	store := pki.NewFileStore(*statePath)
	m, err := pki.NewManager(store)
	if err != nil {
		fatal("bootstrap", err)
	}
	fmt.Printf("active issuer generation: %d\n", m.ActiveIssuerGeneration())

	// Registration is idempotent across runs: ignore "already registered".
	if err := m.RegisterEntity("svc.orders", pki.UsageServerAuth|pki.UsageClientAuth); err != nil &&
		!errors.Is(err, pki.ErrIdentityExists) {
		fatal("register", err)
	}
	fmt.Println("registered entity svc.orders")

	// Issue a certificate under generation 1.
	c1, err := m.Issue(pki.IssueRequest{
		Entity: "svc.orders",
		Usages: pki.UsageServerAuth,
		TTL:    time.Hour,
	})
	if err != nil {
		fatal("issue gen1", err)
	}
	fmt.Printf("issued serial=%d issuerGen=%d notAfter=%s\n",
		c1.Serial, c1.IssuerGen, c1.NotAfter.Format(time.RFC3339))

	showVerify(m, c1.Cert, pki.UsageServerAuth, "gen1 cert / server auth")
	showVerify(m, c1.Cert, pki.UsageClientAuth, "gen1 cert / mismatched usage")

	// Rotate issuer: gen-1 cert must still verify; new issuance uses gen 2.
	gen, err := m.RotateIssuer()
	if err != nil {
		fatal("rotate issuer", err)
	}
	fmt.Printf("rotated issuer to generation %d\n", gen)

	c2, err := m.Issue(pki.IssueRequest{
		Entity: "svc.orders",
		Usages: pki.UsageClientAuth,
		TTL:    time.Hour,
	})
	if err != nil {
		fatal("issue gen2", err)
	}
	fmt.Printf("issued serial=%d issuerGen=%d\n", c2.Serial, c2.IssuerGen)
	showVerify(m, c1.Cert, pki.UsageServerAuth, "old gen1 cert after rotation")
	showVerify(m, c2.Cert, pki.UsageClientAuth, "new gen2 cert")

	// Revoke c1: every later verification reports ErrRevoked.
	if err := m.Revoke(c1.Serial, "demo revocation"); err != nil {
		fatal("revoke", err)
	}
	fmt.Printf("revoked serial=%d\n", c1.Serial)
	showVerify(m, c1.Cert, pki.UsageServerAuth, "gen1 cert after revocation")

	if err := m.Revoke(c1.Serial, "again"); err != nil {
		fmt.Printf("repeat revoke rejected as expected: %v\n", err)
	}
	fmt.Println("demo complete; state at", *statePath)
}

func showVerify(m *pki.Manager, der []byte, required pki.KeyUsage, label string) {
	res, err := m.Verify(der, required)
	if err != nil {
		fmt.Printf("[verify:%-32s] input error: %v\n", label, err)
		return
	}
	if res.OK {
		fmt.Printf("[verify:%-32s] PASS basis=%s\n", label, res.Basis)
		return
	}
	fmt.Printf("[verify:%-32s] FAIL reason=%v basis=%s\n", label, res.Reason, res.Basis)
}

func fatal(stage string, err error) {
	fmt.Fprintf(os.Stderr, "%s failed: %v\n", stage, err)
	os.Exit(1)
}
