package quictransport

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"golang.org/x/crypto/hkdf"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

type realityReplayConn struct {
	net.Conn
	reader io.Reader
}

func (c *realityReplayConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

// Independent reference peer parses the wire ClientHello and authenticates the
// encrypted session ID before exposing an authenticated TLS echo stream.
func realityReferenceHello(raw []byte, key *ecdh.PrivateKey, short []byte) ([]byte, error) {
	if len(raw) < 75 || raw[0] != 1 || raw[38] != 32 {
		return nil, errors.New("invalid ClientHello")
	}
	pos := 71
	size := int(binary.BigEndian.Uint16(raw[pos:]))
	pos += 2 + size
	if pos >= len(raw) {
		return nil, io.ErrUnexpectedEOF
	}
	pos += 1 + int(raw[pos])
	if pos+2 > len(raw) {
		return nil, io.ErrUnexpectedEOF
	}
	pos += 2
	var clientPub []byte
	for pos+4 <= len(raw) {
		kind := binary.BigEndian.Uint16(raw[pos:])
		size := int(binary.BigEndian.Uint16(raw[pos+2:]))
		pos += 4
		if pos+size > len(raw) {
			return nil, io.ErrUnexpectedEOF
		}
		if kind == 51 {
			data := raw[pos : pos+size]
			for n := 2; n+4 <= len(data); {
				group := binary.BigEndian.Uint16(data[n:])
				length := int(binary.BigEndian.Uint16(data[n+2:]))
				n += 4
				if n+length > len(data) {
					return nil, io.ErrUnexpectedEOF
				}
				if group == 29 {
					clientPub = data[n : n+length]
					break
				}
				n += length
			}
		}
		pos += size
	}
	if len(clientPub) != 32 {
		return nil, errors.New("missing X25519 key")
	}
	pub, e := ecdh.X25519().NewPublicKey(clientPub)
	if e != nil {
		return nil, e
	}
	auth, e := key.ECDH(pub)
	if e != nil {
		return nil, e
	}
	if _, e = io.ReadFull(hkdf.New(sha256.New, auth, raw[6:26], []byte("REALITY")), auth); e != nil {
		return nil, e
	}
	block, _ := aes.NewCipher(auth)
	aead, _ := cipher.NewGCM(block)
	aad := append([]byte(nil), raw...)
	clear(aad[39:71])
	plain, e := aead.Open(nil, raw[26:38], raw[39:71], aad)
	if e != nil {
		return nil, e
	}
	var expected [8]byte
	copy(expected[:], short)
	if !bytes.Equal(plain[8:16], expected[:]) {
		return nil, errors.New("short ID mismatch")
	}
	if time.Since(time.Unix(int64(binary.BigEndian.Uint32(plain[4:8])), 0)).Abs() > time.Minute {
		return nil, errors.New("client timestamp mismatch")
	}
	return auth, nil
}
func TestRealityVLESSAuthenticatedRoundTripAndRejection(t *testing.T) {
	key, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"chrome", "firefox", "wrong-key", "wrong-short-id", "ordinary-tls"} {
		t.Run(mode, func(t *testing.T) {
			listener, e := net.Listen("tcp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			serverResult := make(chan error, 1)
			go func() {
				conn, e := listener.Accept()
				if e != nil {
					serverResult <- e
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				header := make([]byte, 5)
				if _, e = io.ReadFull(conn, header); e != nil {
					serverResult <- e
					return
				}
				record := make([]byte, int(binary.BigEndian.Uint16(header[3:])))
				if _, e = io.ReadFull(conn, record); e != nil {
					serverResult <- e
					return
				}
				auth, e := realityReferenceHello(record, key, []byte{1, 2})
				if e != nil {
					serverResult <- e
					return
				}
				pub, private, _ := ed25519.GenerateKey(rand.Reader)
				template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "reality.test"}, DNSNames: []string{"reality.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
				der, e := x509.CreateCertificate(rand.Reader, template, template, pub, private)
				if e != nil {
					serverResult <- e
					return
				}
				if mode != "ordinary-tls" {
					mac := hmac.New(sha512.New, auth)
					mac.Write(pub)
					copy(der[len(der)-64:], mac.Sum(nil))
				}
				replay := &realityReplayConn{Conn: conn, reader: io.MultiReader(bytes.NewReader(append(header, record...)), conn)}
				secure := tls.Server(replay, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
					if len(info.SignatureSchemes) > 0 {
						info.SignatureSchemes[0] = tls.Ed25519
					}
					return nil, nil
				}})
				if e = secure.Handshake(); e != nil {
					serverResult <- e
					return
				}
				defer secure.Close()
				request := make([]byte, 23)
				if _, e = io.ReadFull(secure, request); e != nil {
					serverResult <- e
					return
				}
				if request[21] != 2 {
					serverResult <- errors.New("wrong VLESS target type")
					return
				}
				if _, e = io.CopyN(io.Discard, secure, int64(request[22])); e != nil {
					serverResult <- e
					return
				}
				if _, e = secure.Write([]byte{0, 0}); e != nil {
					serverResult <- e
					return
				}
				payload := make([]byte, 5)
				_, e = io.ReadFull(secure, payload)
				if e == nil {
					_, e = secure.Write(payload)
				}
				serverResult <- e
			}()
			pub := key.PublicKey().Bytes()
			sid := "0102"
			fingerprint := "chrome"
			if mode == "firefox" {
				fingerprint = "firefox"
			}
			if mode == "wrong-key" {
				other, _ := ecdh.X25519().GenerateKey(rand.Reader)
				pub = other.PublicKey().Bytes()
			}
			if mode == "wrong-short-id" {
				sid = "ffff"
			}
			client, e := NewVLESSClient(VLESSConfig{Address: listener.Addr().String(), ServerName: "reality.test", UUID: testVLESSUUID, Network: &testNetwork{allow: true}, Timeout: 3 * time.Second, Reality: &RealityConfig{PublicKey: base64.RawURLEncoding.EncodeToString(pub), ShortID: sid, Fingerprint: fingerprint}})
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			stream, e := client.OpenTCP(ctx, "echo.invalid", 443)
			if mode == "wrong-key" || mode == "wrong-short-id" || mode == "ordinary-tls" {
				if e == nil {
					stream.Close()
					t.Fatal("unauthenticated Reality accepted")
				}
				<-serverResult
				return
			}
			if e != nil {
				t.Fatalf("client: %v; server: %v", e, <-serverResult)
			}
			defer stream.Close()
			stream.(net.Conn).SetDeadline(time.Now().Add(3 * time.Second))
			if _, e = stream.Write([]byte("hello")); e != nil {
				t.Fatal(e)
			}
			got := make([]byte, 5)
			if _, e = io.ReadFull(stream, got); e != nil {
				t.Fatal(e)
			}
			if string(got) != "hello" {
				t.Fatal("bad echo")
			}
			if e = <-serverResult; e != nil {
				t.Fatal(e)
			}
		})
	}
}
