// Package quictransport provides QUIC transport and Hysteria 2 client adapters.
package quictransport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

type Config struct {
	Address    string
	ServerName string
	ALPN       string
	Timeout    time.Duration
}

type Transport struct {
	connection *quic.Conn
	packet     net.PacketConn
	closeOnce  sync.Once
	closeError error
}

func Dial(ctx context.Context, cfg Config) (*Transport, error) {
	host, port, err := net.SplitHostPort(cfg.Address)
	if err != nil || host == "" {
		return nil, errors.New("QUIC server address must be host:port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return nil, errors.New("invalid QUIC port")
	}
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	if cfg.ALPN == "" {
		return nil, errors.New("QUIC ALPN is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	c, err := quic.DialAddr(ctx, cfg.Address, &tls.Config{
		ServerName: cfg.ServerName, NextProtos: []string{cfg.ALPN},
		MinVersion: tls.VersionTLS13,
	}, &quic.Config{KeepAlivePeriod: 15 * time.Second, MaxIdleTimeout: 60 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("QUIC dial: %w", err)
	}
	return &Transport{connection: c}, nil
}

func (t *Transport) OpenStream(ctx context.Context) (io.ReadWriteCloser, error) {
	if t == nil || t.connection == nil {
		return nil, errors.New("QUIC connection not established")
	}
	return t.connection.OpenStreamSync(ctx)
}

func (t *Transport) Close() error {
	if t == nil || t.connection == nil {
		return nil
	}
	t.closeOnce.Do(func() {
		t.closeError = t.connection.CloseWithError(0, "client closing")
		if t.packet != nil {
			if err := t.packet.Close(); t.closeError == nil {
				t.closeError = err
			}
		}
	})
	return t.closeError
}

func (t *Transport) LocalAddr() net.Addr  { return t.connection.LocalAddr() }
func (t *Transport) RemoteAddr() net.Addr { return t.connection.RemoteAddr() }

// Done signals a closed QUIC connection, including remote disconnects.
// The UI must not mistake a still-listening local socket for a live tunnel.
func (t *Transport) Done() <-chan struct{} {
	if t == nil || t.connection == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return t.connection.Context().Done()
}
