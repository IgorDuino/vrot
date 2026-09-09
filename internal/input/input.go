package input

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/example/vhostscan/internal/model"
)

func Target(raw string) (model.Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return model.Target{}, fmt.Errorf("empty target")
	}
	parts := strings.SplitN(raw, ",", 2)
	endpoint := parts[0]
	if !strings.Contains(endpoint, "://") {
		endpoint = "https://" + endpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" {
		return model.Target{}, fmt.Errorf("invalid target %q", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return model.Target{}, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	port := 443
	if u.Scheme == "http" {
		port = 80
	}
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return model.Target{}, fmt.Errorf("invalid port in %q", raw)
		}
	}
	host := strings.ToLower(u.Hostname())
	original := host
	sni := host
	if net.ParseIP(host) != nil {
		original, sni = "", ""
	}
	if len(parts) == 2 {
		sni = strings.TrimSpace(strings.TrimSuffix(strings.ToLower(parts[1]), "."))
		original = sni
	}
	return model.Target{Scheme: u.Scheme, ConnectHost: host, Port: port, OriginalHost: original, OriginalSNI: sni, Raw: raw}, nil
}

func VHost(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "#") {
		return "", nil
	}
	if !strings.Contains(s, "://") {
		s = "//" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("invalid vhost %q", raw)
	}
	if u.Port() != "" {
		return "", fmt.Errorf("vhost ports are not supported: %q", raw)
	}
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if net.ParseIP(h) != nil {
		return "", fmt.Errorf("vhost must be a hostname: %q", raw)
	}
	return h, nil
}

func Lines(r interface{ Read([]byte) (int, error) }, parse func(string) (string, error)) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), 1024*1024)
	for sc.Scan() {
		v, e := parse(sc.Text())
		if e != nil {
			return nil, e
		}
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out, sc.Err()
}
