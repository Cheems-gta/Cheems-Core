package quictransport

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

type socks5TestNetwork struct{ protected atomic.Int32 }

func (n *socks5TestNetwork) Protect(int64) bool { n.protected.Add(1); return true }
func (*socks5TestNetwork) Resolve(host string) (string, error) {
	if host == "socks.test" {
		return "127.0.0.1", nil
	}
	return "", net.InvalidAddrError("unexpected host " + host)
}

func TestSOCKS5UDPAssociationAuthenticatesAndRelaysDatagrams(t *testing.T) {
	udpRelay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpRelay.Close()
	tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	serverDone := make(chan error, 1)
	go func() {
		control, acceptErr := tcpListener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer control.Close()
		var hello [3]byte
		if _, acceptErr = io.ReadFull(control, hello[:]); acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		if hello != [3]byte{5, 1, 2} {
			serverDone <- io.ErrUnexpectedEOF
			return
		}
		_, acceptErr = control.Write([]byte{5, 2})
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		var auth [2]byte
		if _, acceptErr = io.ReadFull(control, auth[:]); acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		username := make([]byte, int(auth[1]))
		if _, acceptErr = io.ReadFull(control, username); acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		var passLen [1]byte
		if _, acceptErr = io.ReadFull(control, passLen[:]); acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		password := make([]byte, int(passLen[0]))
		if _, acceptErr = io.ReadFull(control, password); acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		if auth[0] != 1 || string(username) != "user" || string(password) != "pass" {
			serverDone <- io.ErrUnexpectedEOF
			return
		}
		if _, acceptErr = control.Write([]byte{1, 0}); acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		var request [4]byte
		if _, acceptErr = io.ReadFull(control, request[:]); acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		if request != [4]byte{5, 3, 0, 1} {
			serverDone <- io.ErrUnexpectedEOF
			return
		}
		var addressAndPort [6]byte
		if _, acceptErr = io.ReadFull(control, addressAndPort[:]); acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		if addressAndPort != [6]byte{0, 0, 0, 0, 0, 0} {
			serverDone <- io.ErrUnexpectedEOF
			return
		}
		bound := udpRelay.LocalAddr().(*net.UDPAddr)
		reply := []byte{5, 0, 0, 1}
		reply = append(reply, bound.IP.To4()...)
		var port [2]byte
		binary.BigEndian.PutUint16(port[:], uint16(bound.Port))
		reply = append(reply, port[:]...)
		if _, acceptErr = control.Write(reply); acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		serverDone <- nil
		_, _ = io.Copy(io.Discard, control)
	}()

	network := &socks5TestNetwork{}
	client, err := NewSOCKS5Client(net.JoinHostPort("socks.test", strconv.Itoa(tcpListener.Addr().(*net.TCPAddr).Port)), "user", "pass", network, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	association, err := client.OpenUDPAssociation()
	if err != nil {
		t.Fatal(err)
	}
	defer association.Close()
	if err = <-serverDone; err != nil {
		t.Fatal(err)
	}

	want := []byte("dns query")
	if err = association.WriteTo(want, "resolver.example:53"); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 65535)
	_ = udpRelay.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, source, err := udpRelay.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	address, payload, err := parseSOCKSUDP(buffer[:n])
	if err != nil {
		t.Fatal(err)
	}
	if address != "resolver.example:53" || string(payload) != string(want) {
		t.Fatalf("received %s %q", address, payload)
	}
	response, err := marshalSOCKSUDP(address, []byte("dns reply"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = udpRelay.WriteToUDP(response, source); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, err := association.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Address != address || string(got.Payload) != "dns reply" {
		t.Fatalf("reply = %s %q", got.Address, got.Payload)
	}
	if network.protected.Load() < 2 {
		t.Fatalf("expected protected TCP and UDP sockets, got %d", network.protected.Load())
	}
}

func TestSOCKS5UDPAssociationCancellationClosesRead(t *testing.T) {
	association, err := (&SOCKS5UDPAssociation{}).Read(context.Background())
	if err == nil || association.Address != "" {
		t.Fatal("nil association read should fail")
	}
}

func TestSOCKS5ClientCloseClosesRegisteredUDPAssociations(t *testing.T) {
	client, err := NewSOCKS5Client("socks.test:1080", "", "", &socks5TestNetwork{}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	controlClient, controlServer := net.Pipe()
	defer controlServer.Close()
	packetClient, packetServer := net.Pipe()
	defer packetServer.Close()
	association := &SOCKS5UDPAssociation{control: controlClient, packet: packetClient, closed: make(chan struct{})}
	association.onClose = func() { client.removeAssociation(association) }
	if !client.registerAssociation(association) {
		t.Fatal("fresh SOCKS5 client rejected association")
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = packetServer.Write([]byte("x")); err == nil {
		t.Fatal("client close left the UDP packet socket open")
	}
	if err = client.Close(); err != nil {
		t.Fatalf("repeated close: %v", err)
	}
	if _, err = client.OpenTCP(context.Background(), "example.com", 443); err == nil {
		t.Fatal("closed SOCKS5 client accepted a new TCP connection")
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.associations) != 0 {
		t.Fatalf("closed client retained %d UDP associations", len(client.associations))
	}
}
