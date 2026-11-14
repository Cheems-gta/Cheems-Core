package quictransport

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

func (s *SOCKS5Server) handleUDPAssociate(control net.Conn, requestedHost string, requestedPort int) {
	if s.session == nil || !s.session.UDPEnabled {
		_, _ = control.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	peer, ok := control.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	requestedIP := net.ParseIP(requestedHost)
	if requestedIP != nil && !requestedIP.IsUnspecified() && !requestedIP.Equal(peer.IP) {
		_, _ = control.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	local := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	if peer.IP.To4() == nil {
		local = &net.UDPAddr{IP: net.IPv6loopback}
	}
	udp, err := net.ListenUDP("udp", local)
	if err != nil {
		_, _ = control.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	assoc, err := s.session.OpenUDPAssociation()
	if err != nil {
		udp.Close()
		_, _ = control.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer assoc.Close()
	defer udp.Close()
	if err = writeSOCKSReply(control, udp.LocalAddr().(*net.UDPAddr)); err != nil {
		return
	}
	_ = control.SetDeadline(time.Time{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	var endpointMu sync.RWMutex
	var clientEndpoint *net.UDPAddr
	if requestedPort != 0 {
		clientEndpoint = &net.UDPAddr{IP: peer.IP, Port: requestedPort}
	}
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			n, source, e := udp.ReadFromUDP(buf)
			if e != nil {
				return
			}
			if !source.IP.Equal(peer.IP) || requestedPort != 0 && source.Port != requestedPort {
				continue
			}
			endpointMu.Lock()
			if clientEndpoint == nil {
				clientEndpoint = &net.UDPAddr{IP: source.IP, Port: source.Port}
			}
			endpointMu.Unlock()
			dest, payload, e := parseSOCKSUDP(buf[:n])
			if e != nil {
				continue
			}
			if e = assoc.WriteTo(payload, dest); e != nil {
				continue
			}
		}
	}()
	go func() {
		for {
			m, e := assoc.Read(ctx)
			if e != nil {
				return
			}
			frame, e := marshalSOCKSUDP(m.Address, m.Payload)
			if e != nil {
				continue
			}
			endpointMu.RLock()
			dest := clientEndpoint
			endpointMu.RUnlock()
			if dest != nil {
				_, _ = udp.WriteToUDP(frame, dest)
			}
		}
	}()
	_, _ = io.Copy(io.Discard, control)
	cancel()
	_ = udp.Close()
	<-done
}

func writeSOCKSReply(w io.Writer, a *net.UDPAddr) error {
	if a == nil || a.IP == nil {
		return errors.New("invalid SOCKS UDP bind address")
	}
	if ip := a.IP.To4(); ip != nil {
		b := []byte{5, 0, 0, 1}
		b = append(b, ip...)
		var p [2]byte
		binary.BigEndian.PutUint16(p[:], uint16(a.Port))
		b = append(b, p[:]...)
		_, e := w.Write(b)
		return e
	}
	b := []byte{5, 0, 0, 4}
	b = append(b, a.IP.To16()...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(a.Port))
	b = append(b, p[:]...)
	_, e := w.Write(b)
	return e
}

func parseSOCKSUDP(b []byte) (string, []byte, error) {
	if len(b) < 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return "", nil, errors.New("invalid or fragmented SOCKS UDP packet")
	}
	i := 4
	var host string
	switch b[3] {
	case 1:
		if len(b) < i+4+2 {
			return "", nil, errors.New("truncated SOCKS UDP IPv4 address")
		}
		host = net.IP(b[i : i+4]).String()
		i += 4
	case 4:
		if len(b) < i+16+2 {
			return "", nil, errors.New("truncated SOCKS UDP IPv6 address")
		}
		host = net.IP(b[i : i+16]).String()
		i += 16
	case 3:
		if len(b) < i+1 {
			return "", nil, errors.New("truncated SOCKS UDP domain length")
		}
		n := int(b[i])
		i++
		if n == 0 || len(b) < i+n+2 {
			return "", nil, errors.New("invalid SOCKS UDP domain")
		}
		host = string(b[i : i+n])
		i += n
	default:
		return "", nil, errors.New("unsupported SOCKS UDP address type")
	}
	port := int(binary.BigEndian.Uint16(b[i : i+2]))
	if port == 0 {
		return "", nil, errors.New("invalid SOCKS UDP destination port")
	}
	i += 2
	return net.JoinHostPort(host, strconv.Itoa(port)), b[i:], nil
}

func marshalSOCKSUDP(address string, payload []byte) ([]byte, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid UDP source port")
	}
	b := []byte{0, 0, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			b = append(b, 1)
			b = append(b, v4...)
		} else {
			b = append(b, 4)
			b = append(b, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("invalid UDP source host")
		}
		b = append(b, 3, byte(len(host)))
		b = append(b, host...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(port))
	b = append(b, p[:]...)
	b = append(b, payload...)
	return b, nil
}
