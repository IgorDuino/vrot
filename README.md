# vhostscan

`vhostscan` finds virtual hosts unintentionally reachable through an external
HTTP(S) reverse proxy. It scans a supplied target × known-vhost matrix; it is
not a DNS brute-forcer, crawler, or generic Host-header-injection tester.

```text
                 external target
                       |
                       v
              203.0.113.10:443
                 /           \
                /             \
       original SNI       candidate SNI
             |                  |
             +--------+---------+
                      |
             Host: candidate
                      |
                      v
                response diff
```

## The important distinction

Every probe controls three independent values:

1. **TCP destination** is always the external target.
2. **TLS SNI** is either the external target's hostname (`host` mode) or the
   candidate (`sni` mode).
3. **HTTP Host** is always the candidate.

Candidate DNS is therefore never used to select the connection destination.
For an HTTPS IP target, original SNI is deliberately empty. To associate an IP
with a public SNI, use `203.0.113.10,edge.example.com` in the target input.
Bare targets mean HTTPS on port 443; explicit `http://` selects HTTP.

## Install and use

```bash
go install github.com/example/vhostscan/cmd/vhostscan@latest

# both routing modes (default)
vhostscan -l public.txt -w internal-vhosts.txt
# original SNI + candidate Host only
vhostscan -l public.txt -w internal-vhosts.txt -mode host
# candidate SNI + candidate Host, while still dialing the public target
vhostscan -l public.txt -w internal-vhosts.txt -mode sni
# stdin targets and JSONL findings
cat public.txt | vhostscan -w internal-vhosts.txt -json
# repeat direct targets
vhostscan -u 203.0.113.10 -u https://edge.example.com:8443 -w vhosts.txt
# inspect suppressed and error results
vhostscan -l public.txt -w vhosts.txt -show-all -json
# bounded high-throughput scan
vhostscan -l public.txt -w vhosts.txt -c 200 -rate-limit 1000
```

Typical compact output is streamed immediately:

```text
https://203.0.113.10:443   grafana.internal.example         sni  200    8412  Grafana
https://edge.example.com:443 jenkins.internal.example       host 403    3121  Jenkins
```

## Baseline filtering

For every target and routing mode, three random `.invalid` hosts are requested
before candidate scanning. A deterministic fingerprint compares status, bounded
body length and normalized SHA-256, title, redirect, selected headers, and the
leaf certificate. Exact matches and structurally identical responses within a
5% length tolerance are suppressed by default. Use `-show-similar` or
`-show-all` to inspect them, and tune controls with `-baseline-samples`.

Bodies are capped at 512 KiB, compression is disabled, redirects are not
followed, certificates are accepted by default (but still fingerprinted), and
all work has an overall timeout. Use `-verify-tls` when normal PKI verification
is desired. Progress and the summary go only to stderr; `-silent` disables both.

## Development

```bash
go test ./...
go test -race ./...
go vet ./...
go test -bench=. ./internal/scanner
```
