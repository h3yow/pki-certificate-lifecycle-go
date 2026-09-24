package pki

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// toX509KeyUsage maps the local usage bitmask onto X.509 key-usage bits and
// EKU oids. An empty usage is rejected by request validation earlier.
func toX509KeyUsage(u KeyUsage) (x509.KeyUsage, []x509.ExtKeyUsage) {
	var ku x509.KeyUsage
	var eku []x509.ExtKeyUsage
	if u.Has(UsageDigitalSignature) {
		ku |= x509.KeyUsageDigitalSignature
	}
	if u.Has(UsageKeyEncipherment) {
		ku |= x509.KeyUsageKeyEncipherment
	}
	if u.Has(UsageClientAuth) {
		eku = append(eku, x509.ExtKeyUsageClientAuth)
	}
	if u.Has(UsageServerAuth) {
		eku = append(eku, x509.ExtKeyUsageServerAuth)
	}
	return ku, eku
}

// encodeIssuerCN embeds the trust-domain IssuerID and generation in the
// issuer subject so a relying party can name both before trusting any key:
//
//	local-private-issuer-gen-<n>-id-<hex>
func encodeIssuerCN(gen int, issuerID []byte) string {
	return fmt.Sprintf("%s%d-id-%s", issuerCNPrefix, gen, hex.EncodeToString(issuerID))
}

// parseIssuerCN extracts the generation and trust-domain id from an issuer
// common name. Any shape deviation yields ok=false (untrusted), never a
// guessed identity.
func parseIssuerCN(cn string) (gen int, issuerID []byte, ok bool) {
	genPart := issuerCNPrefix
	idMarker := "-id-"
	if !strings.HasPrefix(cn, genPart) {
		return 0, nil, false
	}
	rest := cn[len(genPart):]
	idx := strings.Index(rest, idMarker)
	if idx <= 0 || idx+len(idMarker) >= len(rest) {
		return 0, nil, false
	}
	g, err := strconv.Atoi(rest[:idx])
	if err != nil || g <= 0 {
		return 0, nil, false
	}
	id, err := hex.DecodeString(rest[idx+len(idMarker):])
	if err != nil || len(id) == 0 {
		return 0, nil, false
	}
	return g, id, true
}

// createIssuer mints a new self-signed issuer (CA) certificate.
func createIssuer(gen int, issuerID []byte, key *ecdsa.PrivateKey, notBefore, notAfter time.Time) (*IssuerInfo, error) {
	tmpl := &x509.Certificate{
		SerialNumber: bigSerial(int64(gen)),
		Subject: pkix.Name{
			CommonName:   encodeIssuerCN(gen, issuerID),
			Organization: []string{"local-pki"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(nil, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create issuer certificate: %w", err)
	}
	return &IssuerInfo{
		Generation: gen,
		IssuerID:   append([]byte(nil), issuerID...),
		Cert:       der,
		Key:        key,
		notBefore:  notBefore,
		notAfter:   notAfter,
	}, nil
}

// issueCertificate signs an entity certificate under the active issuer.
func issueCertificate(issuer *IssuerInfo, entity *EntityRecord, req IssueRequest, serial int64, now time.Time) (*IssuedCertificate, error) {
	notBefore := req.NotBefore
	if notBefore.IsZero() {
		notBefore = now
	}
	notAfter := notBefore.Add(req.TTL)

	ku, eku := toX509KeyUsage(req.Usages)
	tmpl := &x509.Certificate{
		SerialNumber: bigSerial(serial),
		Subject: pkix.Name{
			CommonName:   req.Entity,
			Organization: []string{"local-pki-managed"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              ku,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	issuerCert, err := parseCert(issuer.Cert)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(nil, tmpl, issuerCert, &entity.Key.PublicKey, issuer.Key)
	if err != nil {
		return nil, fmt.Errorf("sign entity certificate: %w", err)
	}
	return &IssuedCertificate{
		Serial:    serial,
		Entity:    req.Entity,
		Cert:      der,
		Key:       entity.Key,
		Usages:    req.Usages,
		IssuerGen: issuer.Generation,
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}, nil
}

// parseCert decodes a DER certificate.
func parseCert(der []byte) (*x509.Certificate, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedCertificate, err)
	}
	return c, nil
}

// verifySignature checks cert's signature against the issuer certificate's
// public key, returning ErrSignatureInvalid on any mismatch.
func verifySignature(issuerCert, cert *x509.Certificate) error {
	if err := cert.CheckSignatureFrom(issuerCert); err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	return nil
}
