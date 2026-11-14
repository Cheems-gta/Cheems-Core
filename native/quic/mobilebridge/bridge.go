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
 mu sync.Mutex
 session *quictransport.Hysteria2Session
 server *quictransport.SOCKS5Server
 starting bool
 generation uint64
 running atomic.Bool
 lastError string
)

// Start authenticates and opens a local TCP-only SOCKS5 listener.
// Must be called from an Android background thread.
func Start(host string,port int,sni string,password string,localPort int)error{
 if host=="" || port<1 || port>65535 || localPort<1 || localPort>65535{
  return errors.New("invalid server or local port")
 }
 if password==""{return errors.New("Hysteria 2 password required")}
 mu.Lock()
 if starting || server!=nil{
  mu.Unlock()
  return errors.New("Hysteria 2 is already starting or running")
 }
 starting=true
 startGeneration:=generation
 mu.Unlock()

 ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second)
 defer cancel()
 newSession,err:=quictransport.DialHysteria2(ctx,quictransport.Hysteria2Config{
  Address:net.JoinHostPort(host,strconv.Itoa(port)),
  ServerName:sni,
  Password:password,
  Timeout:15*time.Second,
 })
 if err!=nil{
  recordFailure(startGeneration,err)
  return err
 }
 newServer,err:=quictransport.ListenSOCKS5(newSession,fmt.Sprintf("127.0.0.1:%d",localPort))
 if err!=nil{
  _=newSession.Close()
  recordFailure(startGeneration,err)
  return err
 }
 mu.Lock()
 if generation==startGeneration{starting=false}
 if generation!=startGeneration{
  mu.Unlock()
  _=newServer.Close()
  _=newSession.Close()
  return errors.New("Hysteria 2 startup canceled")
 }
 session=newSession
 server=newServer
 running.Store(true)
 lastError=""
 mu.Unlock()
 go func(){
  if err:=newServer.Serve();err!=nil{
   mu.Lock()
   if server==newServer{
    server=nil
    session=nil
    running.Store(false)
    lastError="SOCKS5 listener stopped unexpectedly"
    mu.Unlock()
    _=newSession.Close()
    return
   }
   mu.Unlock()
  }
 }()
 return nil
}

func recordFailure(startGeneration uint64,err error){
 mu.Lock()
 defer mu.Unlock()
 if generation==startGeneration{
  starting=false
  lastError=err.Error()
 }
}

// Stop invalidates even an in-progress startup; never waits for network dial
// with the mutex held. Both calls are safe to repeat.
func Stop(){
 mu.Lock()
 generation++
 starting=false
 oldServer:=server
 oldSession:=session
 server=nil
 session=nil
 running.Store(false)
 mu.Unlock()
 if oldServer!=nil{_ = oldServer.Close()}
 if oldSession!=nil{_ = oldSession.Close()}
}

func IsRunning()bool{return running.Load()}

func LastError()string{
 mu.Lock()
 defer mu.Unlock()
 return lastError
}
