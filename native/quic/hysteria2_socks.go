package quictransport

import (
 "context"
 "encoding/binary"
 "errors"
 "fmt"
 "io"
 "net"
 "sync"
 "time"
)

// SOCKS5Server is a local TCP-only SOCKS5 endpoint backed by an authenticated
// Hysteria 2 session. UDP ASSOCIATE and username/password are not supported.
type SOCKS5Server struct {
 listener net.Listener
 session *Hysteria2Session
 closed chan struct{}
 once sync.Once
}

func ListenSOCKS5(session *Hysteria2Session, address string) (*SOCKS5Server,error) {
 if session==nil || session.Transport==nil { return nil,errors.New("Hysteria 2 authentication required") }
 host,_,err:=net.SplitHostPort(address)
 if err!=nil || (host!="127.0.0.1" && host!="::1" && host!="localhost") {
  return nil,errors.New("SOCKS5 listener must bind to loopback")
 }
 listener,err:=net.Listen("tcp",address)
 if err!=nil { return nil,err }
 return &SOCKS5Server{listener:listener,session:session,closed:make(chan struct{})},nil
}

func (s *SOCKS5Server) Addr() net.Addr { return s.listener.Addr() }
func (s *SOCKS5Server) Close() error {
 var err error
 s.once.Do(func(){close(s.closed);err=s.listener.Close()})
 return err
}

func (s *SOCKS5Server) Serve() error {
 for {
  c,err:=s.listener.Accept()
  if err!=nil {
   select {case <-s.closed:return nil;default:return err}
  }
  go s.handle(c)
 }
}

func (s *SOCKS5Server) handle(client net.Conn) {
 defer client.Close()
 client.SetDeadline(time.Now().Add(15*time.Second))
 var hello [2]byte
 if _,err:=io.ReadFull(client,hello[:]);err!=nil || hello[0]!=5 { return }
 if hello[1]==0 { return }
 methods:=make([]byte,int(hello[1]))
 if _,err:=io.ReadFull(client,methods);err!=nil { return }
 allowed:=false
 for _,m:=range methods {if m==0 {allowed=true}}
 if !allowed {client.Write([]byte{5,255});return}
 if _,err:=client.Write([]byte{5,0});err!=nil{return}
 var request [4]byte
 if _,err:=io.ReadFull(client,request[:]);err!=nil{return}
 if request[0]!=5 || request[1]!=1 || request[2]!=0 {
  client.Write([]byte{5,7,0,1,0,0,0,0,0,0});return
 }
 var host string
 switch request[3] {
 case 1:
  b:=make([]byte,4);if _,err:=io.ReadFull(client,b);err!=nil{return};host=net.IP(b).String()
 case 4:
  b:=make([]byte,16);if _,err:=io.ReadFull(client,b);err!=nil{return};host=net.IP(b).String()
 case 3:
  var n [1]byte;if _,err:=io.ReadFull(client,n[:]);err!=nil||n[0]==0{return}
  b:=make([]byte,int(n[0]));if _,err:=io.ReadFull(client,b);err!=nil{return};host=string(b)
 default:
  client.Write([]byte{5,8,0,1,0,0,0,0,0,0});return
 }
 var portBytes [2]byte
 if _,err:=io.ReadFull(client,portBytes[:]);err!=nil{return}
 port:=int(binary.BigEndian.Uint16(portBytes[:]))
 ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second)
 defer cancel()
 upstream,err:=s.session.OpenTCP(ctx,host,port)
 if err!=nil {
  client.Write([]byte{5,5,0,1,0,0,0,0,0,0});return
 }
 defer upstream.Close()
 if _,err:=client.Write([]byte{5,0,0,1,0,0,0,0,0,0});err!=nil{return}
 client.SetDeadline(time.Time{})
 done:=make(chan struct{})
 go func(){io.Copy(upstream,client);upstream.Close();close(done)}()
 _,_ = io.Copy(client,upstream)
 client.Close()
 <-done
}

func (s *SOCKS5Server) String() string {
 if s==nil || s.listener==nil {return "SOCKS5 (closed)"}
 return fmt.Sprintf("SOCKS5 listening at %s",s.listener.Addr())
}
