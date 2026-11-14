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

type tcpDialer func(context.Context,string,int)(io.ReadWriteCloser,error)

// SOCKS5Server forwards local TCP SOCKS5 CONNECT sessions over Hysteria 2.
// UDP ASSOCIATE and username/password are deliberately not advertised.
type SOCKS5Server struct {
 listener net.Listener
 dial tcpDialer
 closed chan struct{}
 once sync.Once
 clients sync.Map
}

func ListenSOCKS5(session *Hysteria2Session,address string)(*SOCKS5Server,error){
 if session==nil || session.Transport==nil{return nil,errors.New("Hysteria 2 authentication required")}
 return listenSOCKS5(address,session.OpenTCP)
}

// listenSOCKS5 accepts an injectable dialer to exercise the full SOCKS5
// handshake and data relay without requiring private subscription credentials.
func listenSOCKS5(address string,dial tcpDialer)(*SOCKS5Server,error){
 if dial==nil{return nil,errors.New("missing TCP dialer")}
 host,_,err:=net.SplitHostPort(address)
 if err!=nil || (host!="127.0.0.1" && host!="::1" && host!="localhost"){
  return nil,errors.New("SOCKS5 listener must bind to loopback")
 }
 listener,err:=net.Listen("tcp",address)
 if err!=nil{return nil,err}
 return &SOCKS5Server{listener:listener,dial:dial,closed:make(chan struct{})},nil
}

func(s *SOCKS5Server)Addr()net.Addr{return s.listener.Addr()}

func(s *SOCKS5Server)Close()error{
 var err error
 s.once.Do(func(){
  close(s.closed)
  err=s.listener.Close()
  s.clients.Range(func(k,_ any)bool{_ = k.(net.Conn).Close();return true})
 })
 return err
}

func(s *SOCKS5Server)Serve()error{
 for{
  client,err:=s.listener.Accept()
  if err!=nil{
   select{case <-s.closed:return nil;default:return err}
  }
  s.clients.Store(client,struct{}{})
  go s.handle(client)
 }
}

func(s *SOCKS5Server)handle(client net.Conn){
 defer func(){s.clients.Delete(client);client.Close()}()
 _=client.SetDeadline(time.Now().Add(15*time.Second))
 var hello [2]byte
 if _,err:=io.ReadFull(client,hello[:]);err!=nil || hello[0]!=5{return}
 if hello[1]==0{return}
 methods:=make([]byte,int(hello[1]))
 if _,err:=io.ReadFull(client,methods);err!=nil{return}
 allowed:=false
 for _,method:=range methods{if method==0{allowed=true}}
 if !allowed{_,_=client.Write([]byte{5,255});return}
 if _,err:=client.Write([]byte{5,0});err!=nil{return}

 var request [4]byte
 if _,err:=io.ReadFull(client,request[:]);err!=nil{return}
 if request[0]!=5 || request[2]!=0{return}
 if request[1]!=1{_,_=client.Write([]byte{5,7,0,1,0,0,0,0,0,0});return}
 var host string
 switch request[3]{
 case 1:
  b:=make([]byte,4)
  if _,err:=io.ReadFull(client,b);err!=nil{return}
  host=net.IP(b).String()
 case 4:
  b:=make([]byte,16)
  if _,err:=io.ReadFull(client,b);err!=nil{return}
  host=net.IP(b).String()
 case 3:
  var n [1]byte
  if _,err:=io.ReadFull(client,n[:]);err!=nil || n[0]==0{return}
  b:=make([]byte,int(n[0]))
  if _,err:=io.ReadFull(client,b);err!=nil{return}
  host=string(b)
 default:
  _,_=client.Write([]byte{5,8,0,1,0,0,0,0,0,0});return
 }
 var p [2]byte
 if _,err:=io.ReadFull(client,p[:]);err!=nil{return}
 port:=int(binary.BigEndian.Uint16(p[:]))

 ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second)
 defer cancel()
 upstream,err:=s.dial(ctx,host,port)
 if err!=nil{
  _,_=client.Write([]byte{5,5,0,1,0,0,0,0,0,0})
  return
 }
 defer upstream.Close()
 select{case <-s.closed:return;default:}
 if _,err:=client.Write([]byte{5,0,0,1,0,0,0,0,0,0});err!=nil{return}
 _=client.SetDeadline(time.Time{})

 done:=make(chan struct{})
 go func(){
  _,_=io.Copy(upstream,client)
  // A QUIC Stream's Close closes the write direction, preserving reads.
  if cw,ok:=upstream.(interface{CloseWrite()error});ok{_ = cw.CloseWrite()}else{_ = upstream.Close()}
  close(done)
 }()
 _,_=io.Copy(client,upstream)
 _=client.Close()
 <-done
}

func(s *SOCKS5Server)String()string{
 if s==nil || s.listener==nil{return "SOCKS5 (closed)"}
 return fmt.Sprintf("SOCKS5 listening at %s",s.listener.Addr())
}
