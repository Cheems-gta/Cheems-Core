package quictransport

// REALITY handshake follows the public XTLS protocol and SagerNet's client
// reference (common/tls/reality_client.go, GPL-3.0-or-later). This adapter fails
// closed instead of issuing a fallback HTTP request after authentication failure.
import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	utls "github.com/metacubex/utls"
	"golang.org/x/crypto/hkdf"
	"io"
	"net"
	"strings"
	"time"
)

type RealityConfig struct{ PublicKey, ShortID, Fingerprint string }

func (c RealityConfig) validate() error {
	key, e := base64.RawURLEncoding.DecodeString(c.PublicKey)
	if e != nil || len(key) != 32 {
		return errors.New("Reality public key must be 32-byte unpadded base64url")
	}
	short, e := hex.DecodeString(c.ShortID)
	if e != nil || len(short) > 8 {
		return errors.New("Reality short ID must be even-length hex up to 16 characters")
	}
	switch c.Fingerprint {
	case "", "chrome", "firefox":
	default:
		return errors.New("unsupported Reality fingerprint; use chrome or firefox")
	}
	return nil
}
func realityHandshake(ctx context.Context, raw net.Conn, sni string, cfg RealityConfig) (net.Conn, error) {
	fail := func(e error) (net.Conn, error) { raw.Close(); return nil, e }
	if e := cfg.validate(); e != nil {
		return fail(e)
	}
	if sni == "" || strings.ContainsAny(sni, "/\\\r\n") {
		return fail(errors.New("Reality server name required"))
	}
	pubBytes, _ := base64.RawURLEncoding.DecodeString(cfg.PublicKey)
	pub, e := ecdh.X25519().NewPublicKey(pubBytes)
	if e != nil {
		return fail(e)
	}
	short, _ := hex.DecodeString(cfg.ShortID)
	verified := false
	var authKey []byte
	config := &utls.Config{ServerName: sni, MinVersion: utls.VersionTLS13, MaxVersion: utls.VersionTLS13, SessionTicketsDisabled: true, InsecureSkipVerify: true}
	config.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("Reality peer certificate missing")
		}
		cert, e := x509.ParseCertificate(rawCerts[0])
		if e != nil {
			return e
		}
		publicKey, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok || len(authKey) != 32 {
			return errors.New("Reality authentication failed")
		}
		mac := hmac.New(sha512.New, authKey)
		mac.Write(publicKey)
		if !hmac.Equal(mac.Sum(nil), cert.Signature) {
			return errors.New("Reality authentication failed")
		}
		verified = true
		return nil
	}
	fingerprint := utls.HelloChrome_Auto
	if cfg.Fingerprint == "firefox" {
		fingerprint = utls.HelloFirefox_Auto
	}
	conn := utls.UClient(raw, config, fingerprint)
	if e = conn.BuildHandshakeState(); e != nil {
		return fail(e)
	}
	hello := conn.HandshakeState.Hello
	if hello == nil || len(hello.Raw) < 71 || len(hello.Random) != 32 || len(hello.SessionId) != 32 {
		return fail(errors.New("unsupported Reality ClientHello layout"))
	}
	keys := conn.HandshakeState.State13.KeyShareKeys
	if keys == nil || keys.Ecdhe == nil {
		return fail(errors.New("Reality X25519 key share missing"))
	}
	authKey, e = keys.Ecdhe.ECDH(pub)
	if e != nil {
		return fail(e)
	}
	if _, e = io.ReadFull(hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")), authKey); e != nil {
		return fail(e)
	}
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:71], hello.SessionId)
	// Cheems protocol client version 0.1.0; no upstream application impersonation.
	hello.SessionId[1] = 1
	binary.BigEndian.PutUint32(hello.SessionId[4:8], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:16], short)
	block, e := aes.NewCipher(authKey)
	if e != nil {
		return fail(e)
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return fail(e)
	}
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:71], hello.SessionId)
	if e = conn.HandshakeContext(ctx); e != nil {
		return fail(e)
	}
	if !verified {
		return fail(errors.New("Reality authentication failed"))
	}
	return conn, nil
}
