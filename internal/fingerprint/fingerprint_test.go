package fingerprint

import (
	"github.com/igorduino/vrot/internal/model"
	"testing"
)

func TestCompare(t *testing.T) {
	b := model.Fingerprint{StatusCode: 403, ContentLength: 100, BodyHash: "a", Title: "Forbidden", ContentType: "text/html"}
	if c, _ := Compare(b, []model.Fingerprint{b}); c != "match" {
		t.Fatal(c)
	}
	g := b
	g.BodyHash = "dynamic"
	g.ContentLength = 103
	if c, _ := Compare(g, []model.Fingerprint{b}); c != "similar" {
		t.Fatal(c)
	}
	g.Title = "Jenkins"
	if c, _ := Compare(g, []model.Fingerprint{b}); c != "different" {
		t.Fatal(c)
	}
}
