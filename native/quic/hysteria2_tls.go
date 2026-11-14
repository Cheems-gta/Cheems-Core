package quictransport

import (
 "crypto/sha256"
 "crypto/subtle"
 "crypto/tls"
 "crypto/x509"
 "encoding/hex"
 "errors"
 "strings"
)

// newHysteria2TLSConfig keeps normal certificate and hostname verification by
// default. Supplying a CA extends trust; supplying a fingerprint pins the leaf.
// An unverified TLS session must be explicitly authorized in the Android UI.
func newHysteria2TLSConfig(cfg Hysteria2Config) (*tls.Config,error) {
 c:=&tls.Config{
  ServerName:cfg.ServerName,
  NextProtos:[]string{"h3"},
  MinVersion:tls.VersionTLS13,
 }
 if len(cfg.TrustedCAPEM)>64*1024 {
  return nil,errors.New("custom CA exceeds 64 KiB")
 }
 if pem:=strings.TrimSpace(cfg.TrustedCAPEM);pem!="" {
  roots,err:=x509.SystemCertPool()
  if err!=nil || roots==nil {roots=x509.NewCertPool()}
  if !roots.AppendCertsFromPEM([]byte(pem)) {
   return nil,errors.New("custom CA is not a valid PEM certificate")
  }
  c.RootCAs=roots
 }
 var expectedPin []byte
 if fingerprint:=strings.TrimSpace(cfg.CertificateSHA256);fingerprint!="" {
  normalized:=strings.ReplaceAll(strings.ReplaceAll(fingerprint,":","")," ","")
  pin,err:=hex.DecodeString(normalized)
  if err!=nil || len(pin)!=sha256.Size {
   return nil,errors.New("invalid HY2 certificate SHA-256 fingerprint")
  }
  expectedPin=pin
  c.VerifyConnection=func(cs tls.ConnectionState) error {
   if len(cs.PeerCertificates)==0 {
    return errors.New("HY2 certificate pin: server presented no certificate")
   }
   actual:=sha256.Sum256(cs.PeerCertificates[0].Raw)
   if subtle.ConstantTimeCompare(actual[:],expectedPin)!=1 {
    return errors.New("HY2 certificate pin: server fingerprint mismatch")
   }
   return nil
  }
 }
 // Go skips the default certificate-chain and hostname checks only for the
 // explicitly selected one-time insecure session. When a fingerprint is given,
 // VerifyConnection above still rejects an unexpected server certificate.
 if cfg.AllowUnverifiedTLS {
  c.InsecureSkipVerify=true
 }
 return c,nil
}
