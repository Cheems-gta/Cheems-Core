package quictransport

import (
 "bytes"
 "context"
 "io"
 "testing"

 "github.com/quic-go/quic-go/quicvarint"
)

func TestTCPRequestWireFormat(t *testing.T) {
 var b bytes.Buffer
 if err:=WriteTCPRequest(&b,"example.com:443");err!=nil { t.Fatal(err) }
 reader:=quicvarint.NewReader(&b)
 typ,err:=quicvarint.Read(reader)
 if err!=nil || typ!=0x401 { t.Fatalf("request type %d: %v",typ,err) }
 n,err:=quicvarint.Read(reader)
 if err!=nil { t.Fatal(err) }
 addr:=make([]byte,n)
 if _,err=io.ReadFull(&b,addr);err!=nil { t.Fatal(err) }
 if string(addr)!="example.com:443" { t.Fatalf("address %q",addr) }
 paddingLen,err:=quicvarint.Read(reader)
 if err!=nil || paddingLen!=64 { t.Fatalf("padding length %d: %v",paddingLen,err) }
 if b.Len()!=int(paddingLen) { t.Fatalf("padding remaining %d",b.Len()) }
}
func TestTCPResponseSuccessPreservesPayload(t *testing.T) {
 var b bytes.Buffer
 b.WriteByte(0)
 b.Write(quicvarint.Append(nil,0))
 b.Write(quicvarint.Append(nil,2))
 b.Write([]byte{1,2})
 b.WriteString("hello")
 if err:=ReadTCPResponse(&b);err!=nil { t.Fatal(err) }
 if b.String()!="hello" { t.Fatalf("payload lost: %q",b.String()) }
}
func TestTCPResponseRejectsError(t *testing.T) {
 var b bytes.Buffer
 b.WriteByte(1)
 b.Write(quicvarint.Append(nil,4))
 b.WriteString("nope")
 b.Write(quicvarint.Append(nil,0))
 if err:=ReadTCPResponse(&b);err==nil { t.Fatal("expected rejection") }
}
func TestTCPResponseRejectsOversizedPadding(t *testing.T) {
 var b bytes.Buffer
 b.WriteByte(0)
 b.Write(quicvarint.Append(nil,0))
 b.Write(quicvarint.Append(nil,4097))
 if err:=ReadTCPResponse(&b);err==nil { t.Fatal("expected padding rejection") }
}
func TestTCPRequiresAuthenticatedSession(t *testing.T) {
 var session *Hysteria2Session
 if _,err:=session.OpenTCP(context.Background(),"example.com",443);err==nil { t.Fatal("expected authentication failure") }
}
