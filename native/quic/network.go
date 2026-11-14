package quictransport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
)

// Network supplies the Android physical-network resolver and VpnService socket
// protection. Implementations must return one IP literal and bound resolver work.
type Network interface {
	Protect(fd int64) bool
	Resolve(host string) (string, error)
}

func protectedPacket(ctx context.Context, address string, platform Network) (net.PacketConn, *net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, nil, err
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return nil, nil, errors.New("invalid upstream port")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		resolved, e := platform.Resolve(host)
		if e != nil {
			return nil, nil, fmt.Errorf("physical network DNS: %w", e)
		}
		ip = net.ParseIP(resolved)
		if ip == nil {
			return nil, nil, errors.New("physical network resolver returned a non-IP address")
		}
	}
	if err = ctx.Err(); err != nil {
		return nil, nil, err
	}
	family, local := "udp4", "0.0.0.0:0"
	if ip.To4() == nil {
		family, local = "udp6", "[::]:0"
	}
	lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var protectErr error
		if e := raw.Control(func(fd uintptr) {
			if !platform.Protect(int64(fd)) {
				protectErr = errors.New("VPN socket protection rejected")
			}
		}); e != nil {
			return e
		}
		return protectErr
	}}
	packet, err := lc.ListenPacket(ctx, family, local)
	if err != nil {
		return nil, nil, err
	}
	return packet, &net.UDPAddr{IP: ip, Port: n}, nil
}
