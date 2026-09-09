package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"html"
	"regexp"
	"strings"

	"github.com/example/vhostscan/internal/model"
)

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
var spaceRE = regexp.MustCompile(`\s+`)

func Body(body []byte) (hash, title string) {
	norm := spaceRE.ReplaceAllString(strings.TrimSpace(string(body)), " ")
	s := sha256.Sum256([]byte(norm))
	hash = hex.EncodeToString(s[:])
	if m := titleRE.FindStringSubmatch(string(body)); len(m) > 1 {
		title = strings.TrimSpace(html.UnescapeString(spaceRE.ReplaceAllString(m[1], " ")))
		if len(title) > 200 {
			title = title[:200]
		}
	}
	return
}

func Compare(got model.Fingerprint, bases []model.Fingerprint) (string, model.Fingerprint) {
	if len(bases) == 0 {
		return "different", model.Fingerprint{}
	}
	best := bases[0]
	for _, b := range bases {
		if got.StatusCode == b.StatusCode && got.BodyHash == b.BodyHash && got.Location == b.Location && got.CertificateHash == b.CertificateHash {
			return "match", b
		}
		if got.StatusCode == b.StatusCode && got.Title == b.Title && got.Location == b.Location && got.ContentType == b.ContentType {
			d := got.ContentLength - b.ContentLength
			if d < 0 {
				d = -d
			}
			max := got.ContentLength
			if b.ContentLength > max {
				max = b.ContentLength
			}
			if max == 0 || float64(d)/float64(max) <= .05 {
				return "similar", b
			}
		}
	}
	return "different", best
}
