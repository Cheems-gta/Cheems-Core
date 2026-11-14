package quictransport

import (
 "context"
 "crypto/tls"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/url"
 "strconv"
 "strings"
 "time"

 quic "github.com/quic-go/quic-go"
 "github.com/quic-go/quic-go/http3"
)

// Hysteria2Session owns an authenticated HTTP/3 control transport and a QUIC
// connection. It is not yet wired to the Android proxy Dialer.
type Hysteria2Session struct {
 Transport *Transport
 http3 *http3.Transport
}

type Hysteria2Config struct {
 Address string
 ServerName string
 Password string
 Timeout time.Duration
}

func DialHysteria2(ctx context.Context, cfg Hysteria2Config) (*Hysteria2Session,error) {
 if cfg.Password == "" { return nil,errors.New("Hysteria 2 password required") }
 host,port,err:=net.SplitHostPort(cfg.Address)
 if err!=nil || host=="" { return nil,errors.New("invalid Hysteria 2 address") }
 p,err:=strconv.Atoi(port)
 if err!=nil || p<1 || p>65535 { return nil,errors.New("invalid Hysteria 2 port") }
 if cfg.ServerName=="" { cfg.ServerName=host }
 if cfg.Timeout<=0 { cfg.Timeout=10*time.Second }
 ctx,cancel:=context.WithTimeout(ctx,cfg.Timeout)
 defer cancel()
 tlsConfig:=&tls.Config{ServerName:cfg.ServerName,NextProtos:[]string{"h3"},MinVersion:tls.VersionTLS13}
 conn,err:=quic.DialAddrEarly(ctx,cfg.Address,tlsConfig,&quic.Config{KeepAlivePeriod:15*time.Second,MaxIdleTimeout:60*time.Second})
 if err!=nil { return nil,fmt.Errorf("Hysteria 2 QUIC handshake: %w",err) }
 transport:=&Transport{connection:conn}
 h3:=&http3.Transport{
  TLSClientConfig:tlsConfig,
  Dial:func(context.Context,string,*tls.Config,*quic.Config)(quic.EarlyConnection,error){
   return conn,nil
  },
 }
 session:=&Hysteria2Session{Transport:transport,http3:h3}
 req,err:=AuthenticationRequest(ctx,cfg.ServerName,cfg.Password)
 if err!=nil { session.Close();return nil,err }
 resp,err:=h3.RoundTrip(req)
 if err!=nil { session.Close();return nil,fmt.Errorf("Hysteria 2 HTTP/3 authentication: %w",err) }
 if err=CheckAuthenticationResponse(resp);err!=nil { session.Close();return nil,err }
 return session,nil
}

// AuthenticationRequest builds a protocol-specific HTTP/3 authentication request.
// Caller must send it over the same QUIC connection used for proxy streams.
func AuthenticationRequest(ctx context.Context, serverName, password string) (*http.Request,error) {
 if password=="" { return nil,errors.New("Hysteria 2 password required") }
 if serverName=="" || strings.ContainsAny(serverName,"/\\\r\n") { return nil,errors.New("invalid server name") }
 u:=&url.URL{Scheme:"https",Host:serverName,Path:"/auth"}
 req,err:=http.NewRequestWithContext(ctx,http.MethodPost,u.String(),nil)
 if err!=nil { return nil,err }
 req.Header.Set("Hysteria-Auth",password)
 req.Header.Set("Hysteria-CC-RX","0")
 return req,nil
}

func CheckAuthenticationResponse(resp *http.Response) error {
 if resp==nil { return errors.New("missing Hysteria 2 authentication response") }
 if resp.Body!=nil { io.Copy(io.Discard,io.LimitReader(resp.Body,4096));resp.Body.Close() }
 if resp.StatusCode!=233 { return fmt.Errorf("Hysteria 2 authentication rejected (HTTP %d)",resp.StatusCode) }
 return nil
}

func (s *Hysteria2Session) Close() error {
 if s==nil { return nil }
 if s.http3!=nil { s.http3.Close() }
 if s.Transport!=nil { return s.Transport.Close() }
 return nil
}
