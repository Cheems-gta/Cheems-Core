package quictransport

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"math/big"
	"net"
	"strings"

	utls "github.com/metacubex/utls"
)

type anyTLSHandshakeConn interface {
	net.Conn
	HandshakeContext(context.Context) error
}

// These names match the commonly imported Clash client-fingerprint values.
// "random" selects a browser preset per connection; it is not traffic weighting.
func anyTLSHelloID(name string) (utls.ClientHelloID, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "none":
		return utls.HelloGolang, nil
	case "chrome":
		return utls.HelloChrome_Auto, nil
	case "firefox":
		return utls.HelloFirefox_Auto, nil
	case "safari":
		return utls.HelloSafari_Auto, nil
	case "ios":
		return utls.HelloIOS_Auto, nil
	case "android":
		return utls.HelloAndroid_11_OkHttp, nil
	case "edge":
		return utls.HelloEdge_Auto, nil
	case "360":
		return utls.Hello360_Auto, nil
	case "qq":
		return utls.HelloQQ_Auto, nil
	case "random":
		presets := []utls.ClientHelloID{utls.HelloChrome_Auto, utls.HelloFirefox_Auto, utls.HelloSafari_Auto}
		i, err := rand.Int(rand.Reader, big.NewInt(int64(len(presets))))
		if err != nil {
			return utls.ClientHelloID{}, err
		}
		return presets[i.Int64()], nil
	default:
		return utls.ClientHelloID{}, fmt.Errorf("unsupported AnyTLS client fingerprint %q", name)
	}
}

func anyTLSClientConn(raw net.Conn, config *tls.Config, fingerprint string) (anyTLSHandshakeConn, error) {
	hello, err := anyTLSHelloID(fingerprint)
	if err != nil {
		return nil, err
	}
	if hello == utls.HelloGolang {
		return tls.Client(raw, config), nil
	}
	uc := &utls.Config{
		ServerName: config.ServerName, RootCAs: config.RootCAs,
		MinVersion: config.MinVersion, InsecureSkipVerify: config.InsecureSkipVerify,
		NextProtos: config.NextProtos,
	}
	// The optional leaf pin stays effective in strict/native API callers.
	if config.VerifyConnection != nil {
		uc.VerifyConnection = func(s utls.ConnectionState) error {
			return config.VerifyConnection(tls.ConnectionState{
				PeerCertificates: s.PeerCertificates, VerifiedChains: s.VerifiedChains,
				ServerName: s.ServerName, NegotiatedProtocol: s.NegotiatedProtocol,
			})
		}
	}
	c := utls.UClient(raw, uc, hello)
	if len(config.NextProtos) != 0 {
		if err := c.BuildHandshakeState(); err != nil {
			return nil, err
		}
		found := false
		for _, extension := range c.Extensions {
			if alpn, ok := extension.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = append([]string(nil), config.NextProtos...)
				found = true
			}
		}
		if !found {
			c.Extensions = append(c.Extensions, &utls.ALPNExtension{AlpnProtocols: config.NextProtos})
		}
	}
	return c, nil
}
