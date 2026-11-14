// Package mobilebridge exposes protected native transports and a gomobile API
// for the Android VPNService/TUN frontend.
package mobilebridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	quictransport "github.com/Cheems-gta/Cheems-Core/native/quic"
)

var (
	mu           sync.Mutex
	session      *quictransport.Hysteria2Session
	anyTLSClient *quictransport.AnyTLSClient
	vlessClient  *quictransport.VLESSClient
	vmessClient  *quictransport.VMessClient
	ss2022Client *quictransport.Shadowsocks2022Client
	socks5Client *quictransport.SOCKS5Client
	activeTCP    tcpBackend
	activeUDP    udpBackend
	server       *quictransport.SOCKS5Server
	starting     bool
	generation   uint64
	running      atomic.Bool
	lastError    string
	startCancel  context.CancelFunc
	startNetwork Network
)

type tcpBackend interface {
	OpenTCP(context.Context, string, int) (io.ReadWriteCloser, error)
}

type udpBackend interface {
	OpenUDPAssociation(string) (udpAssociation, error)
}

type udpAssociation interface {
	WriteTo([]byte, string) error
	Read(context.Context) (quictransport.UDPMessage, error)
	Close() error
}

type hysteriaUDPBackend struct {
	session *quictransport.Hysteria2Session
}

func (b hysteriaUDPBackend) OpenUDPAssociation(string) (udpAssociation, error) {
	return b.session.OpenUDPAssociation()
}

type socks5UDPBackend struct{ client *quictransport.SOCKS5Client }

func (b socks5UDPBackend) OpenUDPAssociation(string) (udpAssociation, error) {
	return b.client.OpenUDPAssociation()
}

type vmessUDPBackend struct{ client *quictransport.VMessClient }

func (b vmessUDPBackend) OpenUDPAssociation(destination string) (udpAssociation, error) {
	return b.client.OpenUDPAssociation(destination)
}

type shadowsocks2022UDPBackend struct {
	client *quictransport.Shadowsocks2022Client
}

func (b shadowsocks2022UDPBackend) OpenUDPAssociation(string) (udpAssociation, error) {
	return b.client.OpenUDPAssociation()
}

// Start authenticates and opens a local TCP-only SOCKS5 listener.
// Must be called from an Android background thread.
// Network is implemented by the Android VPN service using its physical network.
type Network interface {
	Protect(fd int64) bool
	Resolve(host string) (string, error)
}

func Start(host string, port int, sni string, password string, localPort int, localSecret string, allowUnverifiedTLS bool, customCAPEM string, certificateSHA256 string) error {
	return start(host, port, sni, password, localPort, localSecret, allowUnverifiedTLS, customCAPEM, certificateSHA256, nil)
}

// StartWithNetwork requires upstream socket protection; rejection fails startup.
func StartWithNetwork(host string, port int, sni string, password string, localPort int, localSecret string, allowUnverifiedTLS bool, customCAPEM string, certificateSHA256 string, network Network) error {
	if network == nil {
		return errors.New("physical network callback required")
	}
	return start(host, port, sni, password, localPort, localSecret, allowUnverifiedTLS, customCAPEM, certificateSHA256, network)
}

func start(host string, port int, sni string, password string, localPort int, localSecret string, allowUnverifiedTLS bool, customCAPEM string, certificateSHA256 string, network Network) error {
	if host == "" || port < 1 || port > 65535 || localPort < 1 || localPort > 65535 {
		return errors.New("invalid server or local port")
	}
	if password == "" {
		return errors.New("Hysteria 2 password required")
	}
	if len(localSecret) < 24 || len(localSecret) > 255 {
		return errors.New("local SOCKS5 secret required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	mu.Lock()
	if starting || server != nil {
		mu.Unlock()
		return errors.New("Hysteria 2 is already starting or running")
	}
	starting = true
	startCancel = cancel
	startGeneration := generation
	mu.Unlock()

	newSession, err := quictransport.DialHysteria2(ctx, quictransport.Hysteria2Config{
		Address:            net.JoinHostPort(host, strconv.Itoa(port)),
		ServerName:         sni,
		Password:           password,
		Timeout:            15 * time.Second,
		AllowUnverifiedTLS: allowUnverifiedTLS,
		TrustedCAPEM:       customCAPEM,
		CertificateSHA256:  certificateSHA256,
		Network:            network,
	})
	if err != nil {
		recordFailure(startGeneration, err)
		return err
	}
	newServer, err := quictransport.ListenSOCKS5(newSession, fmt.Sprintf("127.0.0.1:%d", localPort), localSecret)
	if err != nil {
		_ = newSession.Close()
		recordFailure(startGeneration, err)
		return err
	}
	mu.Lock()
	if generation == startGeneration {
		starting = false
		startCancel = nil
	}
	if generation != startGeneration {
		mu.Unlock()
		_ = newServer.Close()
		_ = newSession.Close()
		return errors.New("Hysteria 2 startup canceled")
	}
	session = newSession
	anyTLSClient = nil
	vlessClient = nil
	vmessClient = nil
	ss2022Client = nil
	socks5Client = nil
	activeTCP = newSession
	if newSession.UDPEnabled {
		activeUDP = hysteriaUDPBackend{session: newSession}
	} else {
		activeUDP = nil
	}
	server = newServer
	startNetwork = network
	running.Store(true)
	lastError = ""
	mu.Unlock()
	go func() {
		if err := newServer.Serve(); err != nil {
			mu.Lock()
			if server == newServer {
				server = nil
				session = nil
				activeTCP = nil
				activeUDP = nil
				running.Store(false)
				lastError = "SOCKS5 listener stopped unexpectedly"
				mu.Unlock()
				_ = newSession.Close()
				return
			}
			mu.Unlock()
		}
	}()
	// A local listening socket is not proof the remote QUIC session is alive.
	// Invalidate the native state when the peer closes the underlying tunnel.
	go func() {
		<-newSession.Transport.Done()
		mu.Lock()
		if server != newServer {
			mu.Unlock()
			return
		}
		server = nil
		session = nil
		activeTCP = nil
		activeUDP = nil
		running.Store(false)
		lastError = "Hysteria 2 QUIC connection closed"
		mu.Unlock()
		_ = newServer.Close()
	}()
	return nil
}

// StartAnyTLSWithNetwork creates the AnyTLS client, protected local SOCKS
// bridge, and TCP backend used by the Android VPN TUN stack.
func StartAnyTLSWithNetwork(host string, port int, sni string, password string, localPort int, localSecret string, allowUnverifiedTLS bool, customCAPEM string, certificateSHA256 string, network Network) error {
	if host == "" || port < 1 || port > 65535 || localPort < 1 || localPort > 65535 {
		return errors.New("invalid server or local port")
	}
	if password == "" || len(localSecret) < 24 || len(localSecret) > 255 || network == nil {
		return errors.New("AnyTLS password, local secret, and protected network callback required")
	}
	clientCtx, cancel := context.WithCancel(context.Background())
	mu.Lock()
	if starting || server != nil {
		mu.Unlock()
		cancel()
		return errors.New("a native proxy is already starting or running")
	}
	starting = true
	startCancel = cancel
	startGeneration := generation
	mu.Unlock()

	client, err := quictransport.NewAnyTLSClient(clientCtx, quictransport.AnyTLSConfig{
		Address: net.JoinHostPort(host, strconv.Itoa(port)), ServerName: sni,
		Password: password, Network: network, TrustedCAPEM: customCAPEM,
		CertificateSHA256: certificateSHA256, AllowUnverifiedTLS: allowUnverifiedTLS,
	})
	if err != nil {
		cancel()
		recordFailure(startGeneration, err)
		return err
	}
	newServer, err := quictransport.ListenSOCKS5WithDialer(fmt.Sprintf("127.0.0.1:%d", localPort), localSecret, client.OpenTCP)
	if err != nil {
		_ = client.Close()
		cancel()
		recordFailure(startGeneration, err)
		return err
	}
	mu.Lock()
	if generation == startGeneration {
		starting = false
		startCancel = nil
	}
	if generation != startGeneration {
		mu.Unlock()
		_ = newServer.Close()
		_ = client.Close()
		cancel()
		return errors.New("AnyTLS startup canceled")
	}
	session = nil
	vlessClient = nil
	vmessClient = nil
	ss2022Client = nil
	socks5Client = nil
	anyTLSClient = client
	activeTCP = client
	activeUDP = nil
	server = newServer
	startNetwork = network
	running.Store(true)
	lastError = ""
	mu.Unlock()
	go func() {
		if serveErr := newServer.Serve(); serveErr != nil {
			mu.Lock()
			if server == newServer {
				server = nil
				anyTLSClient = nil
				activeTCP = nil
				activeUDP = nil
				running.Store(false)
				lastError = "AnyTLS local SOCKS5 listener stopped unexpectedly"
				mu.Unlock()
				_ = client.Close()
				cancel()
				return
			}
			mu.Unlock()
		}
	}()
	return nil
}

// StartVLESSWithNetwork starts the explicitly supported VLESS TCP+TLS adapter.
func StartVLESSWithNetwork(host string, port int, sni string, userUUID string, localPort int, localSecret string, allowUnverifiedTLS bool, customCAPEM string, certificateSHA256 string, network Network) error {
	if host == "" || port < 1 || port > 65535 || localPort < 1 || localPort > 65535 {
		return errors.New("invalid server or local port")
	}
	if userUUID == "" || len(localSecret) < 24 || len(localSecret) > 255 || network == nil {
		return errors.New("VLESS UUID, local secret, and protected network callback required")
	}
	mu.Lock()
	if starting || server != nil {
		mu.Unlock()
		return errors.New("a native proxy is already starting or running")
	}
	starting = true
	startGeneration := generation
	mu.Unlock()

	client, err := quictransport.NewVLESSClient(quictransport.VLESSConfig{
		Address: net.JoinHostPort(host, strconv.Itoa(port)), ServerName: sni,
		UUID: userUUID, Network: network, TrustedCAPEM: customCAPEM,
		CertificateSHA256: certificateSHA256, AllowUnverifiedTLS: allowUnverifiedTLS,
	})
	if err != nil {
		recordFailure(startGeneration, err)
		return err
	}
	newServer, err := quictransport.ListenSOCKS5WithDialer(fmt.Sprintf("127.0.0.1:%d", localPort), localSecret, client.OpenTCP)
	if err != nil {
		recordFailure(startGeneration, err)
		return err
	}
	mu.Lock()
	if generation == startGeneration {
		starting = false
		startCancel = nil
	}
	if generation != startGeneration {
		mu.Unlock()
		_ = newServer.Close()
		return errors.New("VLESS startup canceled")
	}
	session = nil
	anyTLSClient = nil
	vlessClient = client
	vmessClient = nil
	ss2022Client = nil
	socks5Client = nil
	activeTCP = client
	activeUDP = nil
	server = newServer
	startNetwork = network
	running.Store(true)
	lastError = ""
	mu.Unlock()
	go func() {
		if serveErr := newServer.Serve(); serveErr != nil {
			mu.Lock()
			if server == newServer {
				server = nil
				vlessClient = nil
				vmessClient = nil
				activeTCP = nil
				activeUDP = nil
				running.Store(false)
				lastError = "VLESS local SOCKS5 listener stopped unexpectedly"
				mu.Unlock()
				return
			}
			mu.Unlock()
		}
	}()
	return nil
}

// StartVMessWithNetwork starts the supported VMess TCP adapter with optional
// verified TLS. The importer rejects non-TCP transports and unsupported TLS options.
func StartVMessWithNetwork(host string, port int, sni string, userUUID string, security string, alterID int, tlsEnabled bool, localPort int, localSecret string, customCAPEM string, network Network) error {
	if host == "" || port < 1 || port > 65535 || localPort < 1 || localPort > 65535 {
		return errors.New("invalid server or local port")
	}
	if userUUID == "" || len(localSecret) < 24 || len(localSecret) > 255 || network == nil {
		return errors.New("VMess UUID, local secret, and protected network callback required")
	}
	mu.Lock()
	if starting || server != nil {
		mu.Unlock()
		return errors.New("a native proxy is already starting or running")
	}
	starting = true
	startGeneration := generation
	mu.Unlock()

	client, err := quictransport.NewVMessClient(quictransport.VMessConfig{
		Address: net.JoinHostPort(host, strconv.Itoa(port)), ServerName: sni,
		UserID: userUUID, Security: security, AlterID: alterID, TLS: tlsEnabled,
		Network: network, TrustedCAPEM: customCAPEM,
	})
	if err != nil {
		recordFailure(startGeneration, err)
		return err
	}
	newServer, err := quictransport.ListenSOCKS5WithDialer(fmt.Sprintf("127.0.0.1:%d", localPort), localSecret, client.OpenTCP)
	if err != nil {
		_ = client.Close()
		recordFailure(startGeneration, err)
		return err
	}
	mu.Lock()
	if generation == startGeneration {
		starting = false
		startCancel = nil
	}
	if generation != startGeneration {
		mu.Unlock()
		_ = newServer.Close()
		_ = client.Close()
		return errors.New("VMess startup canceled")
	}
	session = nil
	anyTLSClient = nil
	vlessClient = nil
	vmessClient = client
	ss2022Client = nil
	socks5Client = nil
	activeTCP = client
	activeUDP = vmessUDPBackend{client: client}
	server = newServer
	startNetwork = network
	running.Store(true)
	lastError = ""
	mu.Unlock()
	go func() {
		if serveErr := newServer.Serve(); serveErr != nil {
			mu.Lock()
			if server == newServer {
				server = nil
				vmessClient = nil
				ss2022Client = nil
				activeTCP = nil
				activeUDP = nil
				running.Store(false)
				lastError = "VMess local SOCKS5 listener stopped unexpectedly"
				mu.Unlock()
				_ = client.Close()
				return
			}
			mu.Unlock()
		}
	}()
	return nil
}

// StartShadowsocks2022WithNetwork starts the experimental SS2022 TCP/UDP adapter.
func StartShadowsocks2022WithNetwork(host string, port int, method string, psk string, localPort int, localSecret string, network Network) error {
	if host == "" || port < 1 || port > 65535 || localPort < 1 || localPort > 65535 {
		return errors.New("invalid server or local port")
	}
	if len(localSecret) < 24 || len(localSecret) > 255 || network == nil {
		return errors.New("local secret and protected network callback required")
	}
	mu.Lock()
	if starting || server != nil {
		mu.Unlock()
		return errors.New("a native proxy is already starting or running")
	}
	starting = true
	startGeneration := generation
	mu.Unlock()

	client, err := quictransport.NewShadowsocks2022Client(quictransport.Shadowsocks2022Config{
		Address: net.JoinHostPort(host, strconv.Itoa(port)), Method: method, Password: psk,
		Network: network,
	})
	if err != nil {
		recordFailure(startGeneration, err)
		return err
	}
	newServer, err := quictransport.ListenSOCKS5WithDialer(fmt.Sprintf("127.0.0.1:%d", localPort), localSecret, client.OpenTCP)
	if err != nil {
		_ = client.Close()
		recordFailure(startGeneration, err)
		return err
	}
	mu.Lock()
	if generation == startGeneration {
		starting = false
		startCancel = nil
	}
	if generation != startGeneration {
		mu.Unlock()
		_ = newServer.Close()
		_ = client.Close()
		return errors.New("Shadowsocks 2022 startup canceled")
	}
	session = nil
	anyTLSClient = nil
	vlessClient = nil
	vmessClient = nil
	ss2022Client = client
	socks5Client = nil
	activeTCP = client
	activeUDP = shadowsocks2022UDPBackend{client: client}
	server = newServer
	startNetwork = network
	running.Store(true)
	lastError = ""
	mu.Unlock()
	go func() {
		if serveErr := newServer.Serve(); serveErr != nil {
			mu.Lock()
			if server == newServer {
				server = nil
				ss2022Client = nil
				activeTCP = nil
				activeUDP = nil
				running.Store(false)
				lastError = "Shadowsocks 2022 local SOCKS5 listener stopped unexpectedly"
				mu.Unlock()
				_ = client.Close()
				return
			}
			mu.Unlock()
		}
	}()
	return nil
}

// StartSOCKS5WithNetwork enables SOCKS5 TCP and UDP traffic on the global TUN.
func StartSOCKS5WithNetwork(host string, port int, username string, password string, localPort int, localSecret string, network Network) error {
	if host == "" || port < 1 || port > 65535 || localPort < 1 || localPort > 65535 {
		return errors.New("invalid server or local port")
	}
	if len(localSecret) < 24 || len(localSecret) > 255 || network == nil {
		return errors.New("local secret and protected network callback required")
	}
	client, err := quictransport.NewSOCKS5Client(net.JoinHostPort(host, strconv.Itoa(port)), username, password, network, 10*time.Second)
	if err != nil {
		return err
	}
	mu.Lock()
	if starting || server != nil {
		mu.Unlock()
		return errors.New("a native proxy is already starting or running")
	}
	starting = true
	startGeneration := generation
	mu.Unlock()
	newServer, err := quictransport.ListenSOCKS5WithDialer(fmt.Sprintf("127.0.0.1:%d", localPort), localSecret, client.OpenTCP)
	if err != nil {
		recordFailure(startGeneration, err)
		return err
	}
	mu.Lock()
	if generation == startGeneration {
		starting = false
		startCancel = nil
	}
	if generation != startGeneration {
		mu.Unlock()
		_ = newServer.Close()
		return errors.New("SOCKS5 startup canceled")
	}
	session = nil
	anyTLSClient = nil
	vlessClient = nil
	vmessClient = nil
	socks5Client = client
	activeTCP = client
	activeUDP = socks5UDPBackend{client: client}
	server = newServer
	startNetwork = network
	running.Store(true)
	lastError = ""
	mu.Unlock()
	go func() {
		if serveErr := newServer.Serve(); serveErr != nil {
			mu.Lock()
			if server == newServer {
				server = nil
				socks5Client = nil
				activeTCP = nil
				activeUDP = nil
				running.Store(false)
				lastError = "SOCKS5 local bridge stopped unexpectedly"
				mu.Unlock()
				return
			}
			mu.Unlock()
		}
	}()
	return nil
}

func recordFailure(startGeneration uint64, err error) {
	mu.Lock()
	defer mu.Unlock()
	if generation == startGeneration {
		starting = false
		startCancel = nil
		lastError = err.Error()
	}
}

// Stop invalidates even an in-progress startup; never waits for network dial
// with the mutex held. Both calls are safe to repeat.
func Stop() {
	StopTunnel()
	mu.Lock()
	generation++
	starting = false
	cancel := startCancel
	startCancel = nil
	oldServer := server
	oldSession := session
	oldAnyTLS := anyTLSClient
	oldVLESS := vlessClient
	oldVMess := vmessClient
	oldSS2022 := ss2022Client
	oldSOCKS5 := socks5Client
	server = nil
	session = nil
	anyTLSClient = nil
	vlessClient = nil
	vmessClient = nil
	ss2022Client = nil
	socks5Client = nil
	activeTCP = nil
	activeUDP = nil
	startNetwork = nil
	running.Store(false)
	mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if oldServer != nil {
		_ = oldServer.Close()
	}
	if oldSession != nil {
		_ = oldSession.Close()
	}
	if oldAnyTLS != nil {
		_ = oldAnyTLS.Close()
	}
	if oldVLESS != nil {
		_ = oldVLESS.Close()
	}
	if oldVMess != nil {
		_ = oldVMess.Close()
	}
	if oldSS2022 != nil {
		_ = oldSS2022.Close()
	}
	if oldSOCKS5 != nil {
		_ = oldSOCKS5.Close()
	}
}

func IsRunning() bool { return running.Load() }

func LastError() string {
	mu.Lock()
	defer mu.Unlock()
	return lastError
}
