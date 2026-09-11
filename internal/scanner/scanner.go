package scanner

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/igorduino/vrot/internal/fingerprint"
	"github.com/igorduino/vrot/internal/model"
)

type Config struct {
	Concurrency     int
	Timeout         time.Duration
	MaxBody         int64
	VerifyTLS       bool
	Path, UserAgent string
	RateLimit       int
}
type Scanner struct{ cfg Config }

func New(c Config) *Scanner {
	if c.Concurrency < 1 {
		c.Concurrency = 50
	}
	if c.MaxBody < 1 {
		c.MaxBody = 512 << 10
	}
	if c.Path == "" {
		c.Path = "/"
	}
	return &Scanner{c}
}

func SNI(p model.Probe) string {
	if p.Target.Scheme != "https" {
		return ""
	}
	if p.Mode == model.ModeSNI {
		return p.VHost
	}
	return p.Target.OriginalSNI
}

func (s *Scanner) Probe(ctx context.Context, p model.Probe) (model.Fingerprint, error) {
	dialer := &net.Dialer{Timeout: s.cfg.Timeout}
	tr := &http.Transport{DisableCompression: true, DisableKeepAlives: true, ForceAttemptHTTP2: false, TLSHandshakeTimeout: s.cfg.Timeout, ResponseHeaderTimeout: s.cfg.Timeout}
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, p.Target.Address())
	}
	tr.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		c, e := dialer.DialContext(ctx, network, p.Target.Address())
		if e != nil {
			return nil, e
		}
		t := tls.Client(c, &tls.Config{ServerName: SNI(p), InsecureSkipVerify: !s.cfg.VerifyTLS, MinVersion: tls.VersionTLS12})
		if e = t.HandshakeContext(ctx); e != nil {
			c.Close()
			return nil, e
		}
		return t, nil
	}
	client := &http.Client{Transport: tr, Timeout: s.cfg.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	u := &url.URL{Scheme: p.Target.Scheme, Host: p.Target.Address(), Path: s.cfg.Path}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if e != nil {
		return model.Fingerprint{}, e
	}
	req.Host = p.VHost
	req.Header.Set("User-Agent", s.cfg.UserAgent)
	resp, e := client.Do(req)
	if e != nil {
		return model.Fingerprint{}, e
	}
	defer resp.Body.Close()
	body, e := io.ReadAll(io.LimitReader(resp.Body, s.cfg.MaxBody))
	if e != nil {
		return model.Fingerprint{}, e
	}
	h, title := fingerprint.Body(body)
	f := model.Fingerprint{StatusCode: resp.StatusCode, ContentLength: int64(len(body)), BodyHash: h, Title: title, Location: resp.Header.Get("Location"), ContentType: resp.Header.Get("Content-Type"), Server: resp.Header.Get("Server")}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		cert := resp.TLS.PeerCertificates[0]
		sum := sha256.Sum256(cert.Raw)
		f.CertificateHash = hex.EncodeToString(sum[:])
		f.CertificateNames = append([]string{cert.Subject.CommonName}, cert.DNSNames...)
	}
	return f, nil
}

func Generate(ctx context.Context, targets []model.Target, vhosts []string, modes []model.Mode) <-chan model.Probe {
	ch := make(chan model.Probe)
	go func() {
		defer close(ch)
		for _, t := range targets {
			for _, v := range vhosts {
				last := ""
				for _, m := range modes {
					sni := SNI(model.Probe{Target: t, VHost: v, Mode: m})
					key := sni + "\x00" + v
					if key == last {
						continue
					}
					last = key
					select {
					case ch <- model.Probe{Target: t, VHost: v, Mode: m}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
	return ch
}

// Count returns the exact number Generate will emit, including its semantic
// de-duplication when two requested modes produce the same SNI/Host tuple.
func Count(targets []model.Target, vhosts []string, modes []model.Mode) int64 {
	var n int64
	for _, t := range targets {
		for _, v := range vhosts {
			last := ""
			for _, m := range modes {
				key := SNI(model.Probe{Target: t, VHost: v, Mode: m}) + "\x00" + v
				if key != last {
					n++
					last = key
				}
			}
		}
	}
	return n
}

func (s *Scanner) Run(ctx context.Context, jobs <-chan model.Probe, fn func(model.Probe, model.Fingerprint, error)) {
	var wg sync.WaitGroup
	var tick <-chan time.Time
	if s.cfg.RateLimit > 0 {
		t := time.NewTicker(time.Second / time.Duration(s.cfg.RateLimit))
		defer t.Stop()
		tick = t.C
	}
	for i := 0; i < s.cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				if tick != nil {
					select {
					case <-tick:
					case <-ctx.Done():
						return
					}
				}
				f, e := s.Probe(ctx, p)
				fn(p, f, e)
			}
		}()
	}
	wg.Wait()
}

func ControlName(i int) string {
	return fmt.Sprintf("vrot-%d-%d.invalid", time.Now().UnixNano(), i)
}
