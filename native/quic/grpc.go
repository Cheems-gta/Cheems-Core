package quictransport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sync"
)

// GRPCConfig implements the ordinary bidirectional Hunk/Tun transport, not TunMulti.
type GRPCConfig struct{ ServiceName, Authority string }

func (c GRPCConfig) validate() error {
	if !regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(c.ServiceName) {
		return errors.New("gRPC service name must contain letters, digits, dot, underscore or hyphen")
	}
	if c.Authority == "" {
		return errors.New("gRPC authority required")
	}
	u, e := url.Parse("https://" + c.Authority)
	if e != nil || u.Host != c.Authority || u.User != nil || u.Path != "" {
		return errors.New("invalid gRPC authority")
	}
	return nil
}
func wrapGRPC(raw net.Conn, cfg GRPCConfig) (net.Conn, error) {
	if e := cfg.validate(); e != nil {
		raw.Close()
		return nil, e
	}
	transport := &http2.Transport{}
	cc, e := transport.NewClientConn(raw)
	if e != nil {
		raw.Close()
		return nil, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	reader, writer := io.Pipe()
	c := &grpcStream{Conn: raw, cc: cc, writer: writer, cancel: cancel, response: make(chan grpcResponse, 1)}
	request := &http.Request{Method: "POST", URL: &url.URL{Scheme: "https", Host: cfg.Authority, Path: "/" + cfg.ServiceName + "/Tun"}, Host: cfg.Authority, Header: http.Header{"Content-Type": {"application/grpc"}, "Te": {"trailers"}}, Body: reader}
	go func() {
		r, e := cc.RoundTrip(request.WithContext(ctx))
		c.response <- grpcResponse{r, e}
		if e != nil {
			writer.CloseWithError(e)
		}
	}()
	return c, nil
}

type grpcResponse struct {
	response *http.Response
	err      error
}
type grpcStream struct {
	net.Conn
	cc              *http2.ClientConn
	writer          *io.PipeWriter
	cancel          context.CancelFunc
	response        chan grpcResponse
	body            *http.Response
	pending         []byte
	readMu, writeMu sync.Mutex
	once            sync.Once
}

func (c *grpcStream) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	total := 0
	for len(p) > 0 {
		size := len(p)
		if size > 65536 {
			size = 65536
		}
		data := p[:size]
		var v [10]byte
		n := binary.PutUvarint(v[:], uint64(size))
		message := append([]byte{10}, v[:n]...)
		message = append(message, data...)
		frame := make([]byte, 5)
		binary.BigEndian.PutUint32(frame[1:], uint32(len(message)))
		frame = append(frame, message...)
		if _, e := c.writer.Write(frame); e != nil {
			return total, e
		}
		total += size
		p = p[size:]
	}
	return total, nil
}
func (c *grpcStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.body == nil {
		r := <-c.response
		if r.err != nil {
			return 0, r.err
		}
		c.body = r.response
		if c.body.StatusCode != 200 || c.body.Header.Get("Content-Type") != "application/grpc" {
			c.body.Body.Close()
			return 0, errors.New("gRPC server rejected tunnel request")
		}
	}
	for len(c.pending) == 0 {
		var header [5]byte
		_, e := io.ReadFull(c.body.Body, header[:])
		if e != nil {
			if e == io.EOF && c.body.Trailer.Get("Grpc-Status") != "0" {
				return 0, fmt.Errorf("gRPC tunnel ended with status %q", c.body.Trailer.Get("Grpc-Status"))
			}
			return 0, e
		}
		size := binary.BigEndian.Uint32(header[1:])
		if header[0] != 0 || size > 16*1024*1024 {
			return 0, errors.New("unsupported or oversized gRPC message")
		}
		message := make([]byte, int(size))
		if _, e = io.ReadFull(c.body.Body, message); e != nil {
			return 0, e
		}
		if len(message) == 0 {
			continue
		}
		if message[0] != 10 {
			return 0, errors.New("invalid gRPC Hunk field")
		}
		reader := bytes.NewReader(message[1:])
		length, e := binary.ReadUvarint(reader)
		if e != nil || length != uint64(reader.Len()) {
			return 0, errors.New("invalid gRPC Hunk size")
		}
		c.pending = message[len(message)-reader.Len():]
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
func (c *grpcStream) Close() error {
	c.once.Do(func() { c.cancel(); c.writer.Close(); c.cc.Close(); c.Conn.Close() })
	return nil
}
