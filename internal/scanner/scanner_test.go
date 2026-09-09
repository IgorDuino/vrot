package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/example/vhostscan/internal/model"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSNI(t *testing.T) {
	x := model.Target{Scheme: "https", OriginalSNI: "edge.example"}
	if SNI(model.Probe{Target: x, VHost: "internal.example", Mode: model.ModeHost}) != "edge.example" {
		t.Fatal()
	}
	if SNI(model.Probe{Target: x, VHost: "internal.example", Mode: model.ModeSNI}) != "internal.example" {
		t.Fatal()
	}
}
func TestGenerateCountAndCancel(t *testing.T) {
	ts := []model.Target{{Scheme: "https", ConnectHost: "1.1.1.1", Port: 443}}
	n := 0
	for range Generate(context.Background(), ts, []string{"a", "b"}, []model.Mode{model.ModeHost, model.ModeSNI}) {
		n++
	}
	if n != 4 {
		t.Fatal(n)
	}
	httpTarget := []model.Target{{Scheme: "http", ConnectHost: "127.0.0.1", Port: 80}}
	if got := Count(httpTarget, []string{"a", "b"}, []model.Mode{model.ModeHost, model.ModeSNI}); got != 2 {
		t.Fatalf("HTTP duplicate count = %d", got)
	}
}
func TestExplicitDestinationHostAndSNI(t *testing.T) {
	var gotSNI, gotHost string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		fmt.Fprint(w, "<title>internal</title>")
	}))
	srv.StartTLS()
	defer srv.Close()
	srv.TLS.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) { gotSNI = h.ServerName; return nil, nil }
	h, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	var port int
	fmt.Sscan(p, &port)
	s := New(Config{Timeout: time.Second})
	f, e := s.Probe(context.Background(), model.Probe{Target: model.Target{Scheme: "https", ConnectHost: h, Port: port}, VHost: "does-not-resolve.invalid", Mode: model.ModeSNI})
	if e != nil {
		t.Fatal(e)
	}
	if gotSNI != "does-not-resolve.invalid" || gotHost != "does-not-resolve.invalid" || f.Title != "internal" {
		t.Fatalf("sni=%q host=%q f=%+v", gotSNI, gotHost, f)
	}
}
func BenchmarkGenerate(b *testing.B) {
	ts := make([]model.Target, 100)
	vs := make([]string, 10000)
	for i := range ts {
		ts[i] = model.Target{Scheme: "https", ConnectHost: "127.0.0.1", Port: 443}
	}
	for i := range vs {
		vs[i] = fmt.Sprintf("v%d.invalid", i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx, c := context.WithCancel(context.Background())
		ch := Generate(ctx, ts, vs, []model.Mode{model.ModeHost, model.ModeSNI})
		for j := 0; j < 1000; j++ {
			<-ch
		}
		c()
	}
}
