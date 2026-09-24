package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
)

// generateKey creates a new P-256 ECDSA key.
func generateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// marshalECPrivateKey serializes an EC key to PKCS#8 DER for storage.
func marshalECPrivateKey(k *ecdsa.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(k)
}

// parseECPrivateKey parses a PKCS#8 EC key from storage.
func parseECPrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrStateCorrupt
	}
	return ecKey, nil
}

// bigSerial converts a positive int64 serial into a math/big value used by
// X.509 certificates.
func bigSerial(n int64) *big.Int { return big.NewInt(n) }
