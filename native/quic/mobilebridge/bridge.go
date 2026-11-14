// Package mobilebridge exposes a gomobile API for the Android application.
// This is a loopback TCP proxy, not a system-wide Android VPNService.
package mobilebridge

import (
	"context"
	"errors"
	"fmt"
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
	server       *quictransport.SOCKS5Server
	starting     bool
	generation   uint64
	running      atomic.Bool
	lastError    string
	startCancel  context.CancelFunc
	startNetwork Network
)

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
		running.Store(false)
		lastError = "Hysteria 2 QUIC connection closed"
		mu.Unlock()
		_ = newServer.Close()
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
	server = nil
	session = nil
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
}

func IsRunning() bool { return running.Load() }

func LastError() string {
	mu.Lock()
	defer mu.Unlock()
	return lastError
}
