package quictransport

import (
	"context"
	"errors"
	"github.com/gorilla/websocket"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// WebSocketConfig describes an ordinary RFC6455 transport without early data.
type WebSocketConfig struct{ Path, Host string }

func (c WebSocketConfig) validate() error {
	if c.Path != "" && !strings.HasPrefix(c.Path, "/") {
		return errors.New("WebSocket path must start with /")
	}
	if strings.ContainsAny(c.Host+c.Path, "\r\n") {
		return errors.New("invalid WebSocket host/path")
	}
	u, e := url.ParseRequestURI(c.Path)
	if c.Path != "" && (e != nil || u.IsAbs() || u.Host != "" || u.Fragment != "") {
		return errors.New("invalid WebSocket path")
	}
	return nil
}

// wrapWebSocket uses the already protected, optionally TLS-wrapped connection.
func wrapWebSocket(ctx context.Context, raw net.Conn, cfg WebSocketConfig) (net.Conn, error) {
	if e := cfg.validate(); e != nil {
		raw.Close()
		return nil, e
	}
	path := cfg.Path
	if path == "" {
		path = "/"
	}
	host := cfg.Host
	if host == "" {
		host = raw.RemoteAddr().String()
	}
	u, e := url.Parse("ws://" + host + path)
	if e != nil {
		raw.Close()
		return nil, e
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { raw.Close(); close(done) })
	ws, response, e := websocket.NewClient(raw, u, http.Header{}, 4096, 4096)
	if !stop() {
		<-done
	}
	if ctx.Err() != nil {
		raw.Close()
		return nil, ctx.Err()
	}
	if e != nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		raw.Close()
		return nil, e
	}
	ws.SetReadLimit(16 * 1024 * 1024)
	return &webSocketStream{Conn: raw, ws: ws}, nil
}

type webSocketStream struct {
	net.Conn
	ws              *websocket.Conn
	reader          io.Reader
	readMu, writeMu sync.Mutex
}

func (c *webSocketStream) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		if c.reader == nil {
			kind, r, e := c.ws.NextReader()
			if e != nil {
				return 0, e
			}
			if kind != websocket.BinaryMessage {
				return 0, errors.New("WebSocket proxy received a non-binary frame")
			}
			c.reader = r
		}
		n, e := c.reader.Read(p)
		if e == io.EOF {
			c.reader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, e
	}
}
func (c *webSocketStream) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if e := c.ws.WriteMessage(websocket.BinaryMessage, p); e != nil {
		return 0, e
	}
	return len(p), nil
}
func (c *webSocketStream) Close() error { return c.ws.Close() }
