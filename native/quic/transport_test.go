package quictransport

import (
 "context"
 "testing"
)

func TestRejectsInvalidAddress(t *testing.T) {
 _,err:=Dial(context.Background(),Config{Address:"invalid",ALPN:"h3"})
 if err==nil { t.Fatal("expected invalid address error") }
}
func TestRejectsMissingALPN(t *testing.T) {
 _,err:=Dial(context.Background(),Config{Address:"localhost:443"})
 if err==nil { t.Fatal("expected ALPN error") }
}
func TestRejectsInvalidPort(t *testing.T) {
 _,err:=Dial(context.Background(),Config{Address:"localhost:0",ALPN:"h3"})
 if err==nil { t.Fatal("expected invalid port error") }
}
