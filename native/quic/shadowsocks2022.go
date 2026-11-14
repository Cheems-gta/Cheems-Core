package quictransport

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	M "github.com/sagernet/sing/common/metadata"
)

// Shadowsocks2022Config covers the standard direct TCP transport. Plugins and
// UDP relay are intentionally handled as separate capabilities.
type Shadowsocks2022Config struct {
	Address  string
	Method   string
	Password string // standard base64 PSK
	Timeout  time.Duration
	Network  Network
}

type Shadowsocks2022Client struct {
	host, port string
	method     shadowsocks.Method
	timeout    time.Duration
	network    Network
}

func NewShadowsocks2022Client(cfg Shadowsocks2022Config) (*Shadowsocks2022Client, error) {
	host, port, err := net.SplitHostPort(cfg.Address)
	if err != nil || host == "" {
		return nil, errors.New("invalid Shadowsocks 2022 server address")
	}
	if cfg.Network == nil {
		return nil, errors.New("protected physical network callback required")
	}
	method := strings.ToLower(strings.TrimSpace(cfg.Method))
	keySize := 0
	switch method {
	case "2022-blake3-aes-128-gcm":
		keySize = 16
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		keySize = 32
	default:
		return nil, fmt.Errorf("unsupported Shadowsocks 2022 method %q", method)
	}
	key, err := base64.StdEncoding.DecodeString(cfg.Password)
	if err != nil || len(key) != keySize {
		return nil, fmt.Errorf("Shadowsocks 2022 PSK must be standard base64 for exactly %d bytes", keySize)
	}
	clientMethod, err := shadowaead_2022.New(method, [][]byte{key}, nil)
	if err != nil {
		return nil, fmt.Errorf("Shadowsocks 2022 setup: %w", err)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &Shadowsocks2022Client{host: host, port: port, method: clientMethod, timeout: cfg.Timeout, network: cfg.Network}, nil
}

func (c *Shadowsocks2022Client) OpenTCP(ctx context.Context, destination string, port int) (io.ReadWriteCloser, error) {
	if c == nil || c.method == nil {
		return nil, errors.New("Shadowsocks 2022 client is closed")
	}
	if destination == "" || port < 1 || port > 65535 {
		return nil, errors.New("invalid Shadowsocks 2022 destination")
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	upstream, err := c.dialUpstream(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := c.method.DialConn(upstream, M.ParseSocksaddr(net.JoinHostPort(destination, strconv.Itoa(port))))
	if err != nil {
		_ = upstream.Close()
		return nil, fmt.Errorf("Shadowsocks 2022 request: %w", err)
	}
	_ = stream.SetDeadline(time.Time{})
	return stream, nil
}

func (c *Shadowsocks2022Client) dialUpstream(ctx context.Context) (net.Conn, error) {
	address := net.JoinHostPort(c.host, c.port)
	if net.ParseIP(c.host) == nil {
		resolved, err := c.network.Resolve(c.host)
		if err != nil {
			return nil, fmt.Errorf("physical network DNS: %w", err)
		}
		ip := net.ParseIP(resolved)
		if ip == nil {
			return nil, errors.New("physical network resolver returned a non-IP address")
		}
		address = net.JoinHostPort(ip.String(), c.port)
	}
	dialer := net.Dialer{Timeout: c.timeout, Control: func(_, _ string, raw syscall.RawConn) error {
		var protectErr error
		if err := raw.Control(func(fd uintptr) {
			if !c.network.Protect(int64(fd)) {
				protectErr = errors.New("VPN socket protection rejected")
			}
		}); err != nil {
			return err
		}
		return protectErr
	}}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(c.timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
	return conn, nil
}

func (c *Shadowsocks2022Client) Close() error { return nil }
