package quictransport

import (
 "context"
 "io"
 "net/http"
 "strings"
 "testing"
)

func TestAuthenticationRequest(t *testing.T) {
 req,err:=AuthenticationRequest(context.Background(),"edge.example.com","test-secret")
 if err!=nil { t.Fatal(err) }
 if req.Method!=http.MethodPost || req.URL.Path!="/auth" || req.URL.Scheme!="https" { t.Fatalf("unexpected auth request: %s %s",req.Method,req.URL) }
 if req.Header.Get("Hysteria-Auth")!="test-secret" { t.Fatal("missing authentication header") }
 if req.Header.Get("Hysteria-CC-RX")!="0" { t.Fatal("missing congestion control receive header") }
 if len(req.Header.Get("Hysteria-Padding"))<256 { t.Fatal("missing authentication padding") }
}
func TestAuthenticationRejectsMissingPassword(t *testing.T) {
 _,err:=AuthenticationRequest(context.Background(),"edge.example.com","")
 if err==nil { t.Fatal("expected error") }
}
func TestAuthenticationStatus(t *testing.T) {
 for _,tc:=range []struct{status int;ok bool}{{233,true},{200,false},{401,false},{403,false}} {
  resp:=&http.Response{StatusCode:tc.status,Body:io.NopCloser(strings.NewReader(""))}
  err:=CheckAuthenticationResponse(resp)
  if (err==nil)!=tc.ok { t.Errorf("status %d: error %v",tc.status,err) }
 }
}
func TestNoUnauthenticatedSession(t *testing.T) {
 _,err:=DialHysteria2(context.Background(),Hysteria2Config{Address:"localhost:443",Password:""})
 if err==nil { t.Fatal("expected missing credential error") }
}

type authenticationBodySpy struct {
  readCalled bool
  closed bool
}

func (b *authenticationBodySpy) Read(p []byte) (int,error) {
  b.readCalled=true
  return 0,io.ErrNoProgress
}
func (b *authenticationBodySpy) Close() error {
  b.closed=true
  return nil
}

func TestAuthenticationResponseNeverWaitsForBodyEOF(t *testing.T) {
  // Real HTTP/3 servers can keep their stream open after sending 233.
  // Protocol authentication depends on status headers, not body EOF.
  for _,status:=range []int{233,403} {
    body:=&authenticationBodySpy{}
    response:=&http.Response{StatusCode:status,Body:body}
    err:=CheckAuthenticationResponse(response)
    if (err==nil)!=(status==233) {
      t.Fatalf("unexpected authentication outcome %d: %v",status,err)
    }
    if body.readCalled {t.Fatal("response handler attempted to read the auth body")}
    if !body.closed {t.Fatal("response body was not closed")}
  }
}
