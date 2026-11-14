// Package mobilebridge exposes a minimal gomobile-compatible API to Android.
// The library is not an Android VPNService and supports only local SOCKS5 TCP.
package mobilebridge

import (
 "context"
 "errors"
 "fmt"
 "net"
 "strconv"
 "sync"
 "time"

 quictransport "github.com/Cheems-gta/Cheems-Core/native/quic"
)

var (
 mu sync.Mutex
 session *quictransport.Hysteria2Session
 server *quictransport.SOCKS5Server
 lastError string
)

// Start blocks until HTTP/3 authentication succeeds and the local SOCKS5
// listener is ready. It must run on an Android background thread.
func Start(host string, port int, sni string, password string, localPort int) error {
 mu.Lock()
 defer mu.Unlock()
 if server != nil { return errors.New("Hysteria 2 already started") }
 if host=="" || port<1 || port>65535 || localPort<1 || localPort>65535 {
  return errors.New("invalid server or local port")
 }
 ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second)
 defer cancel()
 s,err:=quictransport.DialHysteria2(ctx,quictransport.Hysteria2Config{
  Address:net.JoinHostPort(host,strconv.Itoa(port)),
  ServerName:sni,Password:password,Timeout:15*time.Second,
 })
 if err!=nil { lastError=err.Error();return err }
 listener,err:=quictransport.ListenSOCKS5(s,fmt.Sprintf("127.0.0.1:%d",localPort))
 if err!=nil { s.Close();lastError=err.Error();return err }
 session=s
 server=listener
 lastError=""
 go func(){_ = listener.Serve()}()
 return nil
}

func Stop() {
 mu.Lock()
 defer mu.Unlock()
 if server!=nil { _=server.Close();server=nil }
 if session!=nil { _=session.Close();session=nil }
}

func IsRunning() bool {
 mu.Lock();defer mu.Unlock()
 return server!=nil
}

func LastError() string {
 mu.Lock();defer mu.Unlock()
 return lastError
}
