package quictransport

import (
 "context"
 "io"
 "net"
 "testing"
 "time"
)

func TestSOCKS5RelayEndToEnd(t *testing.T){
 called:=make(chan string,1)
 server,err:=listenSOCKS5("127.0.0.1:0",func(ctx context.Context,host string,port int)(io.ReadWriteCloser,error){
  called<-net.JoinHostPort(host,"443")
  local,remote:=net.Pipe()
  go func(){defer remote.Close();_,_=io.Copy(remote,remote)}()
  return local,nil
 })
 if err!=nil{t.Fatal(err)}
 defer server.Close()
 go func(){_ = server.Serve()}()
 conn,err:=net.DialTimeout("tcp",server.Addr().String(),time.Second)
 if err!=nil{t.Fatal(err)}
 defer conn.Close()
 _=conn.SetDeadline(time.Now().Add(3*time.Second))
 if _,err=conn.Write([]byte{5,1,0});err!=nil{t.Fatal(err)}
 greeting:=make([]byte,2)
 if _,err=io.ReadFull(conn,greeting);err!=nil{t.Fatal(err)}
 if greeting[0]!=5 || greeting[1]!=0{t.Fatalf("SOCKS greeting: %v",greeting)}
 request:=append([]byte{5,1,0,3,11},[]byte("example.com")...)
 request=append(request,1,187)
 if _,err=conn.Write(request);err!=nil{t.Fatal(err)}
 reply:=make([]byte,10)
 if _,err=io.ReadFull(conn,reply);err!=nil{t.Fatal(err)}
 if reply[1]!=0{t.Fatalf("SOCKS CONNECT failed: %v",reply)}
 select{case got:=<-called:if got!="example.com:443"{t.Fatalf("dial destination %q",got)}
 case <-time.After(time.Second):t.Fatal("dial not invoked")}
 if _,err=conn.Write([]byte("hello"));err!=nil{t.Fatal(err)}
 echoed:=make([]byte,5)
 if _,err=io.ReadFull(conn,echoed);err!=nil{t.Fatal(err)}
 if string(echoed)!="hello"{t.Fatalf("echo mismatch %q",echoed)}
}

func TestSOCKS5RejectsAuthentication(t *testing.T){
 server,err:=listenSOCKS5("127.0.0.1:0",func(context.Context,string,int)(io.ReadWriteCloser,error){
  t.Error("unexpected TCP dial")
  return nil,io.EOF
 })
 if err!=nil{t.Fatal(err)}
 defer server.Close()
 go func(){_ = server.Serve()}()
 conn,err:=net.Dial("tcp",server.Addr().String())
 if err!=nil{t.Fatal(err)}
 defer conn.Close()
 _=conn.SetDeadline(time.Now().Add(time.Second))
 if _,err=conn.Write([]byte{5,1,2});err!=nil{t.Fatal(err)}
 result:=make([]byte,2)
 if _,err=io.ReadFull(conn,result);err!=nil{t.Fatal(err)}
 if result[0]!=5 || result[1]!=255{t.Fatalf("expected no acceptable auth method: %v",result)}
}

func TestSOCKS5NeverBindsPublicInterface(t *testing.T){
 _,err:=listenSOCKS5("0.0.0.0:0",func(context.Context,string,int)(io.ReadWriteCloser,error){return nil,nil})
 if err==nil{t.Fatal("must reject public interface")}
}
