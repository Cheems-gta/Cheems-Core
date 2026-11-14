package quictransport

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"sync"

	"github.com/quic-go/quic-go/quicvarint"
)

// UDPAssociation multiplexes one logical UDP flow over the session's QUIC
// datagrams. Its session ID is unique within the QUIC connection.
type UDPAssociation struct {
	session  *Hysteria2Session
	id       uint32
	input    chan UDPMessage
	closed   chan struct{}
	once     sync.Once
	mu       sync.Mutex
	packetID uint16
}

func (s *Hysteria2Session) OpenUDPAssociation() (*UDPAssociation, error) {
	if s == nil || s.Transport == nil || !s.UDPEnabled {
		return nil, errors.New("Hysteria 2 server did not enable UDP relay")
	}
	for attempts := 0; attempts < 4; attempts++ {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		id := binary.BigEndian.Uint32(b[:])
		if id == 0 {
			continue
		}
		a := &UDPAssociation{session: s, id: id, input: make(chan UDPMessage, 64), closed: make(chan struct{})}
		s.udpMu.Lock()
		if s.udpRoutes == nil {
			s.udpRoutes = make(map[uint32]chan UDPMessage)
		}
		if _, exists := s.udpRoutes[id]; !exists {
			s.udpRoutes[id] = a.input
			s.udpMu.Unlock()
			s.udpOnce.Do(func() { go s.readUDPRoutes() })
			return a, nil
		}
		s.udpMu.Unlock()
	}
	return nil, errors.New("could not allocate Hysteria 2 UDP session ID")
}

func (s *Hysteria2Session) readUDPRoutes() {
	ctx := s.Transport.connection.Context()
	for {
		m, err := s.ReceiveUDP(ctx)
		if err != nil {
			return
		}
		s.udpMu.Lock()
		route := s.udpRoutes[m.SessionID]
		s.udpMu.Unlock()
		if route != nil {
			select {
			case route <- m:
			default:
			}
		}
	}
}

func (a *UDPAssociation) WriteTo(payload []byte, address string) error {
	if a == nil || a.session == nil {
		return errors.New("UDP association is closed")
	}
	a.mu.Lock()
	a.packetID++
	id := a.packetID
	a.mu.Unlock()
	return a.session.SendUDP(a.session.Transport.connection.Context(), UDPMessage{SessionID: a.id, PacketID: id, Address: address, Payload: payload})
}

func (a *UDPAssociation) Read(ctx context.Context) (UDPMessage, error) {
	if a == nil {
		return UDPMessage{}, errors.New("UDP association is closed")
	}
	select {
	case <-ctx.Done():
		return UDPMessage{}, ctx.Err()
	case <-a.closed:
		return UDPMessage{}, errors.New("UDP association is closed")
	case m := <-a.input:
		return m, nil
	}
}

func (a *UDPAssociation) Close() error {
	if a == nil {
		return nil
	}
	a.once.Do(func() {
		close(a.closed)
		a.session.udpMu.Lock()
		delete(a.session.udpRoutes, a.id)
		a.session.udpMu.Unlock()
	})
	return nil
}

const (
	maxUDPAddressLength = 2048
	maxUDPMessageSize   = 4096
)

// UDPMessage is one unfragmented Hysteria 2 UDP datagram.
type UDPMessage struct {
	SessionID uint32
	PacketID  uint16
	Address   string
	Payload   []byte
}

func (m UDPMessage) MarshalBinary() ([]byte, error) {
	host, port, err := net.SplitHostPort(m.Address)
	if err != nil || host == "" {
		return nil, errors.New("invalid Hysteria 2 UDP destination")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return nil, errors.New("invalid Hysteria 2 UDP port")
	}
	if m.SessionID == 0 {
		return nil, errors.New("UDP session ID must be nonzero")
	}
	if len(m.Address) > maxUDPAddressLength || len(m.Payload) > maxUDPMessageSize {
		return nil, errors.New("Hysteria 2 UDP message exceeds protocol limits")
	}
	frame := make([]byte, 8, 8+quicvarint.Len(uint64(len(m.Address)))+len(m.Address)+len(m.Payload))
	binary.BigEndian.PutUint32(frame, m.SessionID)
	binary.BigEndian.PutUint16(frame[4:], m.PacketID)
	frame[6] = 0 // Fragment ID
	frame[7] = 1 // Fragment count: fragmentation is not advertised.
	frame = quicvarint.Append(frame, uint64(len(m.Address)))
	frame = append(frame, m.Address...)
	frame = append(frame, m.Payload...)
	return frame, nil
}

func ParseUDPMessage(frame []byte) (UDPMessage, error) {
	if len(frame) < 9 {
		return UDPMessage{}, errors.New("truncated Hysteria 2 UDP message")
	}
	sid := binary.BigEndian.Uint32(frame)
	if sid == 0 {
		return UDPMessage{}, errors.New("UDP session ID must be nonzero")
	}
	if frame[6] != 0 || frame[7] != 1 {
		return UDPMessage{}, errors.New("fragmented Hysteria 2 UDP messages are unsupported")
	}
	reader := bytes.NewReader(frame[8:])
	length, err := quicvarint.Read(reader)
	if err != nil || length == 0 || length > maxUDPAddressLength || length > uint64(reader.Len()) {
		return UDPMessage{}, errors.New("invalid Hysteria 2 UDP address length")
	}
	address := make([]byte, int(length))
	if _, err = reader.Read(address); err != nil {
		return UDPMessage{}, err
	}
	payload := make([]byte, reader.Len())
	if _, err = reader.Read(payload); err != nil {
		return UDPMessage{}, err
	}
	msg := UDPMessage{SessionID: sid, PacketID: binary.BigEndian.Uint16(frame[4:]), Address: string(address), Payload: payload}
	// Reuse marshal validation for destination and payload constraints.
	if _, err = msg.MarshalBinary(); err != nil {
		return UDPMessage{}, err
	}
	return msg, nil
}

// SendUDP sends one packet only after the server advertised UDP support.
func (s *Hysteria2Session) SendUDP(ctx context.Context, msg UDPMessage) error {
	if s == nil || s.Transport == nil || !s.UDPEnabled {
		return errors.New("Hysteria 2 server did not enable UDP relay")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	frame, err := msg.MarshalBinary()
	if err != nil {
		return err
	}
	return s.Transport.connection.SendDatagram(frame)
}

// ReceiveUDP waits for one complete QUIC datagram and validates its framing.
func (s *Hysteria2Session) ReceiveUDP(ctx context.Context) (UDPMessage, error) {
	if s == nil || s.Transport == nil || !s.UDPEnabled {
		return UDPMessage{}, errors.New("Hysteria 2 server did not enable UDP relay")
	}
	frame, err := s.Transport.connection.ReceiveDatagram(ctx)
	if err != nil {
		return UDPMessage{}, err
	}
	return ParseUDPMessage(frame)
}
