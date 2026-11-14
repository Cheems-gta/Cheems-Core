package quictransport

import (
 "context"
 "crypto/rand"
 "errors"
 "fmt"
 "io"
 "net"
 "strconv"
 "strings"
 "time"

 "github.com/quic-go/quic-go/quicvarint"
)

const (
 tcpRequestID = 0x401
 maxAddressLength = 2048
 maxMessageLength = 2048
 maxPaddingLength = 4096
)

// OpenTCP opens a Hysteria 2 TCP proxy stream on an authenticated session.
// It must never be called before successful HTTP/3 authentication.
func (s *Hysteria2Session) OpenTCP(ctx context.Context, host string, port int) (io.ReadWriteCloser,error) {
 if s==nil || s.Transport==nil { return nil,errors.New("Hysteria 2 session not authenticated") }
 if host=="" || strings.ContainsAny(host,"\r\n") || port<1 || port>65535 { return nil,errors.New("invalid TCP destination") }
 address:=net.JoinHostPort(host,strconv.Itoa(port))
 stream,err:=s.Transport.OpenStream(ctx)
 if err!=nil { return nil,err }
 // Opening a QUIC stream honors ctx, but stream reads do not. Bound the
 // connect acknowledgement explicitly so an unresponsive peer cannot hang
 // the Android startup/relay thread forever.
 deadline,hasDeadline:=ctx.Deadline()
 if !hasDeadline { deadline=time.Now().Add(15*time.Second) }
 if d,ok:=stream.(interface{SetDeadline(time.Time)error});ok {
  if err=d.SetDeadline(deadline);err!=nil { stream.Close();return nil,err }
 }
 if err=WriteTCPRequest(stream,address);err!=nil { stream.Close();return nil,err }
 if err=ReadTCPResponse(stream);err!=nil { stream.Close();return nil,err }
 if d,ok:=stream.(interface{SetDeadline(time.Time)error});ok {
  if err=d.SetDeadline(time.Time{});err!=nil { stream.Close();return nil,err }
 }
 return stream,nil
}

func WriteTCPRequest(w io.Writer,address string) error {
 if len(address)==0 || len(address)>maxAddressLength { return errors.New("invalid TCP address length") }
 padding:=make([]byte,64)
 if _,err:=rand.Read(padding);err!=nil { return err }
 frame:=make([]byte,0,16+len(address)+len(padding))
 frame=quicvarint.Append(frame,tcpRequestID)
 frame=quicvarint.Append(frame,uint64(len(address)))
 frame=append(frame,address...)
 frame=quicvarint.Append(frame,uint64(len(padding)))
 frame=append(frame,padding...)
 for len(frame)>0 {
  n,err:=w.Write(frame)
  if err!=nil { return err }
  if n<=0 { return io.ErrShortWrite }
  frame=frame[n:]
 }
 return nil
}

// unbufferedVarintReader prevents a buffered wrapper from reading ahead into\n// the application payload that follows the Hysteria 2 response frame.\ntype unbufferedVarintReader struct { io.Reader }\nfunc (r unbufferedVarintReader) ReadByte() (byte,error) {\n var b [1]byte\n _,err:=io.ReadFull(r.Reader,b[:])\n return b[0],err\n}\n\nfunc ReadTCPResponse(r io.Reader) error {\n reader:=unbufferedVarintReader{r}
 var status [1]byte
 if _,err:=io.ReadFull(reader,status[:]);err!=nil { return err }
 msgLen,err:=quicvarint.Read(reader)
 if err!=nil { return err }
 if msgLen>maxMessageLength { return errors.New("Hysteria 2 response message too large") }
 msg:=make([]byte,int(msgLen))
 if _,err=io.ReadFull(reader,msg);err!=nil { return err }
 padLen,err:=quicvarint.Read(reader)
 if err!=nil { return err }
 if padLen>maxPaddingLength { return errors.New("Hysteria 2 response padding too large") }
 if _,err=io.CopyN(io.Discard,reader,int64(padLen));err!=nil { return err }
 if status[0]!=0 { return fmt.Errorf("Hysteria 2 TCP connect rejected: %s",string(msg)) }
 return nil
}
