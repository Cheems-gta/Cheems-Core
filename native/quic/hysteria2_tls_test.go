package quictransport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestHysteriaTLSStrictByDefault(t *testing.T) {
	c, err := newHysteria2TLSConfig(Hysteria2Config{ServerName: "edge.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	if c.InsecureSkipVerify {
		t.Fatal("default TLS must verify server identity")
	}
	if c.ServerName != "edge.example.org" {
		t.Fatalf("unexpected SNI %q", c.ServerName)
	}
	if len(c.NextProtos) != 1 || c.NextProtos[0] != "h3" {
		t.Fatal("missing HTTP/3 ALPN")
	}
}

func TestHysteriaTLSRejectsMalformedTrustInputs(t *testing.T) {
	for _, cfg := range []Hysteria2Config{
		{TrustedCAPEM: "not a certificate"},
		{TrustedCAPEM: string(make([]byte, 2*1024*1024+1))},
		{CertificateSHA256: "invalid-cert-pin"},
		{CertificateSHA256: "ab:cd"},
	} {
		if _, err := newHysteria2TLSConfig(cfg); err == nil {
			t.Fatal("accepted malformed TLS trust configuration")
		}
	}
}

func TestHysteriaTLSPinsOnlyTheLeaf(t *testing.T) {
	leaf := &x509.Certificate{Raw: []byte("test-server-leaf-certificate")}
	sum := sha256.Sum256(leaf.Raw)
	cfg := Hysteria2Config{ServerName: "edge.example.org",
		CertificateSHA256:  hex.EncodeToString(sum[:]),
		AllowUnverifiedTLS: true}
	c, err := newHysteria2TLSConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !c.InsecureSkipVerify || c.VerifyConnection == nil {
		t.Fatal("pin-only trust must enforce explicit leaf fingerprint callback")
	}
	if err = c.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}); err != nil {
		t.Fatal(err)
	}
	if err = c.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: []byte("forged")}, leaf}}); err == nil {
		t.Fatal("accepted a different leaf with a pinned CA/chain certificate")
	}
	if err = c.VerifyConnection(tls.ConnectionState{}); err == nil {
		t.Fatal("accepted missing certificate")
	}
}

func TestHysteriaTLSAcceptsInlineCAWithStrictValidation(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(71),
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		DNSNames:              []string{"edge.example.org"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	c, err := newHysteria2TLSConfig(Hysteria2Config{ServerName: "edge.example.org", TrustedCAPEM: strings.Repeat(caPEM, 200)})
	if err != nil {
		t.Fatal(err)
	}
	if c.InsecureSkipVerify {
		t.Fatal("custom CA must not bypass hostname checks")
	}
	if c.RootCAs == nil {
		t.Fatal("custom CA not installed")
	}
	if _, err = cert.Verify(x509.VerifyOptions{Roots: c.RootCAs, DNSName: "edge.example.org"}); err != nil {
		t.Fatal(err)
	}
	if _, err = cert.Verify(x509.VerifyOptions{Roots: c.RootCAs, DNSName: "wrong.example.org"}); err == nil {
		t.Fatal("custom CA disabled hostname validation")
	}
}
