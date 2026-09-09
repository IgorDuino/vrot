package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/example/vhostscan/internal/fingerprint"
	in "github.com/example/vhostscan/internal/input"
	"github.com/example/vhostscan/internal/model"
	"github.com/example/vhostscan/internal/scanner"
)

type stringsFlag []string

func (s *stringsFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "vhostscan:", err)
		os.Exit(1)
	}
}
func run() error {
	var urls stringsFlag
	var list, wordlist, mode string
	var concurrency, rate, samples int
	var timeout time.Duration
	var maxBody int64
	var jsonOut, silent, noProgress, showAll, showSimilar, verify bool
	flag.Var(&urls, "u", "target (repeatable)")
	flag.StringVar(&list, "l", "", "target file")
	flag.StringVar(&wordlist, "w", "", "vhost file (required)")
	flag.StringVar(&mode, "mode", "both", "host, sni, or both")
	flag.IntVar(&concurrency, "c", 50, "concurrent requests")
	flag.IntVar(&rate, "rate-limit", 0, "global requests/second (0 unlimited)")
	flag.IntVar(&samples, "baseline-samples", 3, "random-host controls per target/mode")
	flag.DurationVar(&timeout, "timeout", 5*time.Second, "request timeout")
	flag.Int64Var(&maxBody, "max-body-size", 512<<10, "maximum response bytes")
	flag.BoolVar(&jsonOut, "json", false, "write JSONL")
	flag.BoolVar(&silent, "silent", false, "disable progress and summary")
	flag.BoolVar(&noProgress, "no-progress", false, "disable progress")
	flag.BoolVar(&showAll, "show-all", false, "emit every result and errors")
	flag.BoolVar(&showSimilar, "show-similar", false, "also emit similar results")
	flag.BoolVar(&verify, "verify-tls", false, "verify TLS certificates")
	flag.Parse()
	if wordlist == "" {
		return fmt.Errorf("-w is required")
	}
	if samples < 1 {
		return fmt.Errorf("baseline-samples must be positive")
	}
	modes := []model.Mode{model.ModeHost, model.ModeSNI}
	if mode == "host" {
		modes = modes[:1]
	} else if mode == "sni" {
		modes = modes[1:]
	} else if mode != "both" {
		return fmt.Errorf("invalid mode %q", mode)
	}
	vf, e := os.Open(wordlist)
	if e != nil {
		return e
	}
	vhosts, e := in.Lines(vf, in.VHost)
	vf.Close()
	if e != nil {
		return e
	}
	if len(vhosts) == 0 {
		return fmt.Errorf("no vhosts")
	}
	var raw []string
	raw = append(raw, urls...)
	if list != "" {
		f, e := os.Open(list)
		if e != nil {
			return e
		}
		raw = append(raw, readRaw(f)...)
		f.Close()
	} else if len(raw) == 0 {
		st, _ := os.Stdin.Stat()
		if st.Mode()&os.ModeCharDevice == 0 {
			raw = append(raw, readRaw(os.Stdin)...)
		}
	}
	seen := map[string]bool{}
	var targets []model.Target
	for _, r := range raw {
		t, e := in.Target(r)
		if e != nil {
			return e
		}
		k := t.Display() + "|" + t.OriginalSNI
		if !seen[k] {
			seen[k] = true
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		return fmt.Errorf("no targets (use -u, -l, or stdin)")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	sc := scanner.New(scanner.Config{Concurrency: concurrency, Timeout: timeout, MaxBody: maxBody, VerifyTLS: verify, Path: "/", UserAgent: "vhostscan/1.0", RateLimit: rate})
	baselines := map[string][]model.Fingerprint{}
	for _, t := range targets {
		for _, m := range modes {
			key := t.Display() + "|" + string(m)
			for i := 0; i < samples; i++ {
				v := scanner.ControlName(i)
				f, e := sc.Probe(ctx, model.Probe{Target: t, VHost: v, Mode: m})
				if e == nil {
					baselines[key] = append(baselines[key], f)
				}
			}
		}
	}
	start := time.Now()
	var done, findings, errors atomic.Int64
	var outMu sync.Mutex
	total := scanner.Count(targets, vhosts, modes)
	progress := !silent && !noProgress && isTerminal(os.Stderr)
	stop := make(chan struct{})
	if progress {
		go func() {
			tk := time.NewTicker(500 * time.Millisecond)
			defer tk.Stop()
			for {
				select {
				case <-tk.C:
					d := done.Load()
					fmt.Fprintf(os.Stderr, "\r[%3d%%] %d / %d | %.0f req/s | findings %d | errors %d", 100*d/max(total, 1), d, total, float64(d)/time.Since(start).Seconds(), findings.Load(), errors.Load())
				case <-stop:
					return
				}
			}
		}()
	}
	sc.Run(ctx, scanner.Generate(ctx, targets, vhosts, modes), func(p model.Probe, f model.Fingerprint, e error) {
		done.Add(1)
		r := model.Result{Target: p.Target.Display(), VHost: p.VHost, Mode: p.Mode, Fingerprint: f}
		if e != nil {
			errors.Add(1)
			r.Error = e.Error()
			if !showAll {
				return
			}
		} else {
			class, b := fingerprint.Compare(f, baselines[p.Target.Display()+"|"+string(p.Mode)])
			r.Classification = class
			r.BaselineStatus = b.StatusCode
			r.BaselineLength = b.ContentLength
			if class == "different" {
				findings.Add(1)
			}
			if !showAll && class != "different" && !(showSimilar && class == "similar") {
				return
			}
		}
		outMu.Lock()
		defer outMu.Unlock()
		if jsonOut {
			_ = json.NewEncoder(os.Stdout).Encode(r)
		} else {
			fmt.Printf("%-28s %-32s %-4s %3d %7d  %s", r.Target, r.VHost, r.Mode, r.StatusCode, r.ContentLength, sanitize(r.Title))
			if r.Location != "" {
				fmt.Printf(" -> %s", sanitize(r.Location))
			}
			if r.Error != "" {
				fmt.Printf(" error=%s", sanitize(r.Error))
			}
			fmt.Println()
		}
	})
	if progress {
		close(stop)
		fmt.Fprintln(os.Stderr)
	}
	if !silent {
		d := time.Since(start)
		fmt.Fprintf(os.Stderr, "Targets: %d | VHosts: %d | Completed: %d | Interesting: %d | Errors: %d | Duration: %s | Rate: %.0f req/s\n", len(targets), len(vhosts), done.Load(), findings.Load(), errors.Load(), d.Round(time.Millisecond), float64(done.Load())/max(d.Seconds(), .001))
	}
	return nil
}
func readRaw(r io.Reader) []string {
	var x []string
	s := bufio.NewScanner(r)
	for s.Scan() {
		v := strings.TrimSpace(s.Text())
		if v != "" && !strings.HasPrefix(v, "#") {
			x = append(x, v)
		}
	}
	return x
}
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r != 127 {
			b.WriteRune(r)
		}
	}
	return b.String()
}
func isTerminal(f *os.File) bool {
	s, e := f.Stat()
	return e == nil && s.Mode()&os.ModeCharDevice != 0
}
func max[T int64 | float64](a, b T) T {
	if a > b {
		return a
	}
	return b
}
