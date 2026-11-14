package quictransport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// SOCKS5Client provides TCP CONNECT and UDP ASSOCIATE through one SOCKS5 node.
// Its upstream TCP and UDP sockets are protected by the Android physical network.
type SOCKS5Client struct {
	serverHost   string
	serverPort   string
	username     string
	password     string
	timeout      time.Duration
	network      Network
	mu           sync.Mutex
	closed       bool
	associations map[*SOCKS5UDPAssociation]struct{}
}

func NewSOCKS5Client(address, username, password string, network Network, timeout time.Duration) (*SOCKS5Client, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return nil, errors.New("invalid SOCKS5 server address")
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return nil, errors.New("invalid SOCKS5 server port")
	}
	if network == nil {
		return nil, errors.New("protected physical network callback required")
	}
	if len(username) > 255 || len(password) > 255 || (username == "") != (password == "") {
		return nil, errors.New("SOCKS5 username and password must both be empty or non-empty and at most 255 bytes")
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &SOCKS5Client{serverHost: host, serverPort: port, username: username, password: password, timeout: timeout, network: network, associations: make(map[*SOCKS5UDPAssociation]struct{})}, nil
}

func (c *SOCKS5Client) OpenTCP(ctx context.Context, host string, port int) (io.ReadWriteCloser, error) {
	if c == nil || host == "" || port < 1 || port > 65535 {
		return nil, errors.New("invalid SOCKS5 TCP destination")
	}
	if c.isClosed() {
		return nil, errors.New("SOCKS5 client is closed")
	}
	conn, err := c.dialServer(ctx)
	if err != nil {
		return nil, err
	}
	if err = c.negotiate(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err = writeSOCKS5Request(conn, 1, host, port); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if _, _, err = readSOCKS5Reply(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func (c *SOCKS5Client) OpenUDPAssociation() (*SOCKS5UDPAssociation, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	control, err := c.dialServer(ctx)
	if err != nil {
		return nil, err
	}
	if err = c.negotiate(control); err != nil {
		_ = control.Close()
		return nil, err
	}
	if err = writeSOCKS5Request(control, 3, "0.0.0.0", 0); err != nil {
		_ = control.Close()
		return nil, err
	}
	relayHost, relayPort, err := readSOCKS5Reply(control)
	if err != nil {
		_ = control.Close()
		return nil, err
	}
	if relayPort == 0 {
		_ = control.Close()
		return nil, errors.New("SOCKS5 UDP relay returned port zero")
	}
	if ip := net.ParseIP(relayHost); ip != nil && ip.IsUnspecified() {
		relayHost = c.serverHost
	}
	resolved, err := c.resolve(relayHost)
	if err != nil {
		_ = control.Close()
		return nil, err
	}
	relayAddress := net.JoinHostPort(resolved, strconv.Itoa(relayPort))
	udp, err := c.dialProtectedUDP(ctx, relayAddress)
	if err != nil {
		_ = control.Close()
		return nil, fmt.Errorf("SOCKS5 UDP relay socket: %w", err)
	}
	_ = control.SetDeadline(time.Time{})
	association := &SOCKS5UDPAssociation{control: control, packet: udp, closed: make(chan struct{})}
	association.onClose = func() { c.removeAssociation(association) }
	if !c.registerAssociation(association) {
		_ = association.Close()
		return nil, errors.New("SOCKS5 client is closed")
	}
	go func() {
		_, _ = io.Copy(io.Discard, control)
		_ = association.Close()
	}()
	return association, nil
}

func (c *SOCKS5Client) dialServer(ctx context.Context) (net.Conn, error) {
	resolved, err := c.resolve(c.serverHost)
	if err != nil {
		return nil, err
	}
	family := "tcp6"
	if net.ParseIP(resolved).To4() != nil {
		family = "tcp4"
	}
	dialer := net.Dialer{Timeout: c.timeout, Control: c.socketControl}
	conn, err := dialer.DialContext(ctx, family, net.JoinHostPort(resolved, c.serverPort))
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	return conn, nil
}

func (c *SOCKS5Client) dialProtectedUDP(ctx context.Context, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	resolved, err := c.resolve(host)
	if err != nil {
		return nil, err
	}
	family := "udp6"
	if net.ParseIP(resolved).To4() != nil {
		family = "udp4"
	}
	dialer := net.Dialer{Timeout: c.timeout, Control: c.socketControl}
	return dialer.DialContext(ctx, family, net.JoinHostPort(resolved, port))
}

func (c *SOCKS5Client) socketControl(_, _ string, raw syscall.RawConn) error {
	var protectErr error
	if err := raw.Control(func(fd uintptr) {
		if !c.network.Protect(int64(fd)) {
			protectErr = errors.New("VPN socket protection or physical-network binding rejected")
		}
	}); err != nil {
		return err
	}
	return protectErr
}

func (c *SOCKS5Client) resolve(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	resolved, err := c.network.Resolve(host)
	if err != nil {
		return "", fmt.Errorf("physical network DNS: %w", err)
	}
	ip := net.ParseIP(resolved)
	if ip == nil {
		return "", errors.New("physical network resolver returned a non-IP address")
	}
	return ip.String(), nil
}

func (c *SOCKS5Client) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *SOCKS5Client) registerAssociation(association *SOCKS5UDPAssociation) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	c.associations[association] = struct{}{}
	return true
}

func (c *SOCKS5Client) removeAssociation(association *SOCKS5UDPAssociation) {
	c.mu.Lock()
	delete(c.associations, association)
	c.mu.Unlock()
}

func (c *SOCKS5Client) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	associations := make([]*SOCKS5UDPAssociation, 0, len(c.associations))
	for association := range c.associations {
		associations = append(associations, association)
	}
	c.mu.Unlock()
	var firstErr error
	for _, association := range associations {
		if err := association.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (c *SOCKS5Client) negotiate(conn net.Conn) error {
	if c.username == "" {
		if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
			return err
		}
	} else {
		if _, err := conn.Write([]byte{5, 1, 2}); err != nil {
			return err
		}
	}
	var method [2]byte
	if _, err := io.ReadFull(conn, method[:]); err != nil {
		return err
	}
	if method[0] != 5 || method[1] == 0xff {
		return errors.New("SOCKS5 server rejected authentication methods")
	}
	if method[1] == 0 && c.username == "" {
		return nil
	}
	if method[1] != 2 || c.username == "" {
		return errors.New("SOCKS5 server selected an unsupported authentication method")
	}
	if _, err := conn.Write([]byte{1, byte(len(c.username))}); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, c.username); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{byte(len(c.password))}); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, c.password); err != nil {
		return err
	}
	var result [2]byte
	if _, err := io.ReadFull(conn, result[:]); err != nil {
		return err
	}
	if result[0] != 1 || result[1] != 0 {
		return errors.New("SOCKS5 username/password authentication failed")
	}
	return nil
}

func writeSOCKS5Request(w io.Writer, command byte, host string, port int) error {
	if port < 0 || port > 65535 {
		return errors.New("invalid SOCKS5 destination port")
	}
	if _, err := w.Write([]byte{5, command, 0}); err != nil {
		return err
	}
	if err := writeSOCKS5Address(w, host); err != nil {
		return err
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(port))
	_, err := w.Write(p[:])
	return err
}

func writeSOCKS5Address(w io.Writer, host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			if _, err := w.Write([]byte{1}); err != nil {
				return err
			}
			_, err := w.Write(v4)
			return err
		}
		if _, err := w.Write([]byte{4}); err != nil {
			return err
		}
		_, err := w.Write(ip.To16())
		return err
	}
	if host == "" || len(host) > 255 {
		return errors.New("invalid SOCKS5 domain address")
	}
	if _, err := w.Write([]byte{3, byte(len(host))}); err != nil {
		return err
	}
	_, err := io.WriteString(w, host)
	return err
}

func readSOCKS5Reply(r io.Reader) (string, int, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return "", 0, err
	}
	if header[0] != 5 || header[2] != 0 {
		return "", 0, errors.New("invalid SOCKS5 reply header")
	}
	if header[1] != 0 {
		return "", 0, fmt.Errorf("SOCKS5 request failed with code %d", header[1])
	}
	var host string
	switch header[3] {
	case 1:
		address := make([]byte, 4)
		if _, err := io.ReadFull(r, address); err != nil {
			return "", 0, err
		}
		host = net.IP(address).String()
	case 4:
		address := make([]byte, 16)
		if _, err := io.ReadFull(r, address); err != nil {
			return "", 0, err
		}
		host = net.IP(address).String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return "", 0, err
		}
		if n[0] == 0 {
			return "", 0, errors.New("empty SOCKS5 domain reply")
		}
		address := make([]byte, int(n[0]))
		if _, err := io.ReadFull(r, address); err != nil {
			return "", 0, err
		}
		host = string(address)
	default:
		return "", 0, errors.New("unsupported SOCKS5 reply address type")
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return "", 0, err
	}
	return host, int(binary.BigEndian.Uint16(p[:])), nil
}

// SOCKS5UDPAssociation carries complete datagrams through an RFC 1928 relay.
type SOCKS5UDPAssociation struct {
	control net.Conn
	packet  net.Conn
	closed  chan struct{}
	once    sync.Once
	readMu  sync.Mutex
	writeMu sync.Mutex
	onClose func()
}

func (a *SOCKS5UDPAssociation) WriteTo(payload []byte, address string) error {
	if a == nil || a.packet == nil {
		return errors.New("SOCKS5 UDP association is closed")
	}
	frame, err := marshalSOCKSUDP(address, payload)
	if err != nil {
		return err
	}
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	_, err = a.packet.Write(frame)
	return err
}

func (a *SOCKS5UDPAssociation) Read(ctx context.Context) (UDPMessage, error) {
	if a == nil || a.packet == nil {
		return UDPMessage{}, errors.New("SOCKS5 UDP association is closed")
	}
	a.readMu.Lock()
	defer a.readMu.Unlock()
	if deadline, ok := ctx.Deadline(); ok {
		_ = a.packet.SetReadDeadline(deadline)
	}
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = a.packet.SetReadDeadline(time.Now()); close(callbackDone) })
	buffer := make([]byte, 65535)
	n, err := a.packet.Read(buffer)
	if !stop() {
		<-callbackDone
	}
	_ = a.packet.SetReadDeadline(time.Time{})
	if ctx.Err() != nil {
		return UDPMessage{}, ctx.Err()
	}
	if err != nil {
		return UDPMessage{}, err
	}
	address, payload, err := parseSOCKSUDP(buffer[:n])
	if err != nil {
		return UDPMessage{}, err
	}
	return UDPMessage{Address: address, Payload: payload}, nil
}

func (a *SOCKS5UDPAssociation) Close() error {
	if a == nil {
		return nil
	}
	var closeErr error
	a.once.Do(func() {
		close(a.closed)
		if a.packet != nil {
			closeErr = a.packet.Close()
		}
		if a.control != nil {
			_ = a.control.Close()
		}
		if a.onClose != nil {
			a.onClose()
		}
	})
	return closeErr
}
