package peer

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"math/rand/v2"
	"time"

	"github.com/getlantern/samizdat"
)

// reverseCoverDomains are popular HTTPS hosts the portal can pass for. Each
// must fit reverse.MaxDomainLen and serve HTTPS, because the portal forwards
// probes that fail authentication to it.
var reverseCoverDomains = []string{
	"www.google.com",
	"www.microsoft.com",
	"www.apple.com",
	"www.amazon.com",
	"www.cloudflare.com",
	"www.wikipedia.org",
	"www.mozilla.org",
	"www.github.com",
}

func pickReverseCoverDomain() string {
	return reverseCoverDomains[rand.IntN(len(reverseCoverDomains))]
}

// reverseCreds is one identity of the reverse portal. PrivateKey and KeyPEM
// are secrets and must never be logged.
type reverseCreds struct {
	PrivateKey, PublicKey [32]byte
	CertPEM, KeyPEM       []byte
	SPKI                  [32]byte
	CoverDomain           string
}

func newReverseCreds(coverDomain string) (reverseCreds, error) {
	xkey, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		return reverseCreds{}, fmt.Errorf("generate listener key: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return reverseCreds{}, fmt.Errorf("generate certificate key: %w", err)
	}
	serial, err := crand.Int(crand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return reverseCreds{}, fmt.Errorf("generate serial number: %w", err)
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"Internet"}},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		DNSNames:              []string{coverDomain},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(crand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return reverseCreds{}, fmt.Errorf("create certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return reverseCreds{}, fmt.Errorf("marshal certificate key: %w", err)
	}
	spki, err := samizdat.SPKISHA256(certDER)
	if err != nil {
		return reverseCreds{}, fmt.Errorf("hash certificate key: %w", err)
	}
	var certPEM, keyPEM bytes.Buffer
	if err := pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return reverseCreds{}, fmt.Errorf("encode certificate: %w", err)
	}
	if err := pem.Encode(&keyPEM, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return reverseCreds{}, fmt.Errorf("encode certificate key: %w", err)
	}
	creds := reverseCreds{
		CertPEM:     certPEM.Bytes(),
		KeyPEM:      keyPEM.Bytes(),
		SPKI:        spki,
		CoverDomain: coverDomain,
	}
	copy(creds.PrivateKey[:], xkey.Bytes())
	copy(creds.PublicKey[:], xkey.PublicKey().Bytes())
	return creds, nil
}
