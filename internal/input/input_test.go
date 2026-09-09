package input

import "testing"

func TestTarget(t *testing.T) {
	x, e := Target("203.0.113.10,edge.example.com")
	if e != nil || x.ConnectHost != "203.0.113.10" || x.OriginalSNI != "edge.example.com" || x.Port != 443 {
		t.Fatalf("%+v %v", x, e)
	}
	x, e = Target("http://[::1]:8080")
	if e != nil || x.ConnectHost != "::1" || x.Port != 8080 || x.OriginalSNI != "" {
		t.Fatalf("%+v %v", x, e)
	}
}
func TestVHost(t *testing.T) {
	x, e := VHost("HTTPS://Grafana.Internal.Example/path")
	if e != nil || x != "grafana.internal.example" {
		t.Fatalf("%q %v", x, e)
	}
	if _, e = VHost("a.example:8443"); e == nil {
		t.Fatal("wanted port error")
	}
}
