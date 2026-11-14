package quictransport

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"time"
)

// VLESSConfig describes the explicitly supported VLESS TCP + TLS transport.
// Reality, WebSocket, gRPC, XTLS Vision and UDP are intentionally out of scope.
type VLESSConfig struct {
	Address            string
	ServerName         string
	UUID               string
	Timeout            time.Duration
	Network            Network
	TrustedCAPEM       string
	CertificateSHA256  string
	AllowUnverifiedTLS bool
}

type VLESSClient struct {
	addressHost string
	addressPort string
	userID      [16]byte
	tlsConfig   *tls.Config
	timeout     time.Duration
	network     Network
}

func NewVLESSClient(cfg VLESSConfig) (*VLESSClient, error) {
	host, port, err := net.SplitHostPort(cfg.Address)
	if err != nil || host == "" {
		return nil, errors.New("invalid VLESS server address")
	}
	userID, err := parseVLESSUUID(cfg.UUID)
	if err != nil {
		return nil, err
	}
	if cfg.Network == nil {
		return nil, errors.New("protected physical network callback required")
	}
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if len(cfg.TrustedCAPEM) > 2*1024*1024 {
		return nil, errors.New("combined platform and custom CA bundle exceeds 2 MiB")
	}
	tlsConfig, err := newVLESSTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &VLESSClient{addressHost: host, addressPort: port, userID: userID, tlsConfig: tlsConfig, timeout: cfg.Timeout, network: cfg.Network}, nil
}

func parseVLESSUUID(value string) ([16]byte, error) {
	var result [16]byte
	value = strings.TrimSpace(value)
	compact := strings.ReplaceAll(value, "-", "")
	if len(value) != 36 || len(compact) != 32 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return result, errors.New("VLESS UUID must use canonical UUID format")
	}
	decoded, err := hex.DecodeString(compact)
	if err != nil {
		return result, errors.New("invalid VLESS UUID")
	}
	copy(result[:], decoded)
	return result, nil
}

func newVLESSTLSConfig(cfg VLESSConfig) (*tls.Config, error) {
	if cfg.ServerName == "" || strings.ContainsAny(cfg.ServerName, "/\\\r\n") {
		return nil, errors.New("invalid VLESS TLS server name")
	}
	config := &tls.Config{ServerName: cfg.ServerName, MinVersion: tls.VersionTLS12}
	if strings.TrimSpace(cfg.TrustedCAPEM) != "" {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(cfg.TrustedCAPEM)) {
			return nil, errors.New("VLESS trusted CA bundle is not valid PEM")
		}
		config.RootCAs = roots
	}
	if fingerprint := strings.TrimSpace(cfg.CertificateSHA256); fingerprint != "" {
		fingerprint = strings.NewReplacer(":", "", " ", "").Replace(fingerprint)
		pin, err := hex.DecodeString(fingerprint)
		if err != nil || len(pin) != sha256.Size {
			return nil, errors.New("invalid VLESS certificate SHA-256 fingerprint")
		}
		config.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("VLESS certificate pin: server presented no certificate")
			}
			actual := sha256.Sum256(state.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(actual[:], pin) != 1 {
				return errors.New("VLESS certificate pin mismatch")
			}
			return nil
		}
	}
	if cfg.AllowUnverifiedTLS {
		config.InsecureSkipVerify = true
	}
	return config, nil
}

func (c *VLESSClient) OpenTCP(ctx context.Context, destination string, port int) (io.ReadWriteCloser, error) {
	if c == nil {
		return nil, errors.New("VLESS client is closed")
	}
	if destination == "" || port < 1 || port > 65535 {
		return nil, errors.New("invalid VLESS destination")
	}
	ip := net.ParseIP(destination)
	addrType := byte(2)
	addr := []byte(destination)
	if ip4 := ip.To4(); ip4 != nil {
		addrType, addr = 1, ip4
	} else if ip6 := ip.To16(); ip6 != nil {
		addrType, addr = 3, ip6
	} else if len(addr) > 255 {
		return nil, errors.New("VLESS domain name exceeds 255 bytes")
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resolved := c.addressHost
	serverIP := net.ParseIP(resolved)
	if serverIP == nil {
		value, err := c.network.Resolve(resolved)
		if err != nil {
			return nil, fmt.Errorf("physical network DNS: %w", err)
		}
		serverIP = net.ParseIP(value)
		if serverIP == nil {
			return nil, errors.New("physical network resolver returned a non-IP address")
		}
		resolved = value
	}
	family := "tcp6"
	if serverIP.To4() != nil {
		family = "tcp4"
	}
	dialer := net.Dialer{Timeout: c.timeout, Control: func(_, _ string, raw syscall.RawConn) error {
		var protectErr error
		if err := raw.Control(func(fd uintptr) {
			if !c.network.Protect(int64(fd)) {
				protectErr = errors.New("VPN socket protection or physical-network binding rejected")
			}
		}); err != nil {
			return err
		}
		return protectErr
	}}
	conn, err := dialer.DialContext(ctx, family, net.JoinHostPort(resolved, c.addressPort))
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, c.tlsConfig.Clone())
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("VLESS TLS handshake: %w", err)
	}
	request, err := vlessRequest(c.userID, port, addrType, addr)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	if _, err = tlsConn.Write(request); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("VLESS request: %w", err)
	}
	var response [2]byte
	if _, err = io.ReadFull(tlsConn, response[:]); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("VLESS response: %w", err)
	}
	if response[0] != 0 {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("unsupported VLESS response version %d", response[0])
	}
	if response[1] > 0 {
		addons := make([]byte, int(response[1]))
		if _, err = io.ReadFull(tlsConn, addons); err != nil {
			_ = tlsConn.Close()
			return nil, fmt.Errorf("VLESS response addons: %w", err)
		}
	}
	return tlsConn, nil
}

func vlessRequest(userID [16]byte, port int, addrType byte, addr []byte) ([]byte, error) {
	if port < 1 || port > 65535 {
		return nil, errors.New("invalid VLESS destination port")
	}
	if addrType == 2 && len(addr) == 0 {
		return nil, errors.New("empty VLESS domain")
	}
	request := make([]byte, 0, 26+len(addr))
	request = append(request, 0)
	request = append(request, userID[:]...)
	request = append(request, 0, 1) // no addons, TCP command
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))
	request = append(request, portBytes[:]...)
	request = append(request, addrType)
	if addrType == 2 {
		request = append(request, byte(len(addr)))
	}
	request = append(request, addr...)
	return request, nil
}

func (c *VLESSClient) Close() error { return nil }
