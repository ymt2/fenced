package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestSplitDoubleDash(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantPre []string
		wantCmd []string
	}{
		{
			name:    "no double dash treats all args as command",
			args:    []string{"claude", "foo"},
			wantPre: nil,
			wantCmd: []string{"claude", "foo"},
		},
		{
			name:    "double dash at start",
			args:    []string{"--", "claude"},
			wantPre: []string{},
			wantCmd: []string{"claude"},
		},
		{
			name:    "flags before double dash",
			args:    []string{"--fence-verbose", "--", "claude", "--help"},
			wantPre: []string{"--fence-verbose"},
			wantCmd: []string{"claude", "--help"},
		},
		{
			name:    "empty after double dash",
			args:    []string{"-m", "--"},
			wantPre: []string{"-m"},
			wantCmd: []string{},
		},
		{
			name:    "empty args",
			args:    nil,
			wantPre: nil,
			wantCmd: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pre, cmd := splitDoubleDash(tt.args)
			if !reflect.DeepEqual(pre, tt.wantPre) {
				t.Errorf("pre = %#v, want %#v", pre, tt.wantPre)
			}
			if !reflect.DeepEqual(cmd, tt.wantCmd) {
				t.Errorf("cmd = %#v, want %#v", cmd, tt.wantCmd)
			}
		})
	}
}

func TestDynamicSocketsIncludesGnuPG(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	gnupg := filepath.Join(home, ".gnupg")
	if err := os.Mkdir(gnupg, 0o700); err != nil {
		t.Fatal(err)
	}
	wantSockets := []string{
		filepath.Join(gnupg, "S.gpg-agent"),
		filepath.Join(gnupg, "S.gpg-agent.ssh"),
		filepath.Join(gnupg, "S.scdaemon"),
		filepath.Join(gnupg, "S.dirmngr"),
		filepath.Join(gnupg, "S.keyboxd"),
	}
	for _, s := range wantSockets {
		if err := os.WriteFile(s, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Decoy: non-matching file in $HOME/.gnupg should not be picked up.
	decoy := filepath.Join(gnupg, "pubring.kbx")
	if err := os.WriteFile(decoy, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	got := dynamicSockets()
	for _, want := range wantSockets {
		if !slices.Contains(got, want) {
			t.Errorf("dynamicSockets() missing %q; got %#v", want, got)
		}
	}
	if slices.Contains(got, decoy) {
		t.Errorf("dynamicSockets() unexpectedly contains decoy %q", decoy)
	}
}

func TestParseViolation(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantOp      string
		wantDetails string
	}{
		{
			name:        "network-outbound is captured with details",
			line:        "2026-05-27 12:34:56.789 Df  kernel[0:abc] Sandbox: curl(12345) deny(1) network-outbound /private/tmp/sock",
			wantOp:      "network-outbound",
			wantDetails: "/private/tmp/sock",
		},
		{
			name:        "file-read-data is captured with path",
			line:        "2026-05-27 12:34:56.789 Df  kernel[0:abc] Sandbox: cat(12345) deny(1) file-read-data /etc/passwd",
			wantOp:      "file-read-data",
			wantDetails: "/etc/passwd",
		},
		{
			name: "/dev/tty noise filtered",
			line: "2026-05-27 12:34:56.789 Df  kernel[0:abc] Sandbox: zsh(12345) deny(1) file-write-data /dev/ttys001",
		},
		{
			name: "mDNSResponder noise filtered",
			line: "2026-05-27 12:34:56.789 Df  kernel[0:abc] Sandbox: curl(12345) deny(1) network-outbound /var/run/mDNSResponder",
		},
		{
			name: "file-ioctl is not counted",
			line: "2026-05-27 12:34:56.789 Df  kernel[0:abc] Sandbox: ls(12345) deny(1) file-ioctl /dev/random",
		},
		{
			name: "duplicate report header is ignored",
			line: "2026-05-27 12:34:56.789 Df  kernel[0:abc] Sandbox: curl(12345) deny(1) network-outbound /var/run/ (duplicate report)",
		},
		{
			name: "log stream banner is ignored",
			line: "Filtering the log data using \"eventMessage ENDSWITH \\\"_abc123def_SBX\\\"\"",
		},
		{
			name: "CMD64 sentinel is ignored",
			line: "CMD64_aGVsbG8=_END_abc123def_SBX",
		},
		{
			name: "non-sandbox line is ignored",
			line: "kernel: some unrelated log line",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op, details := parseViolation(tt.line)
			if op != tt.wantOp || details != tt.wantDetails {
				t.Errorf("parseViolation(%q) = (%q, %q), want (%q, %q)",
					tt.line, op, details, tt.wantOp, tt.wantDetails)
			}
		})
	}
}

func TestSessionSuffixPatternExtractsFromWrappedCommand(t *testing.T) {
	wrapped := `sandbox-exec -p '(version 1)(deny default (with message "CMD64_aGVsbG8=_END_abc123def_SBX"))' -- sh -c 'echo hi'`
	got := sessionSuffixPattern.FindString(wrapped)
	if got != "_abc123def_SBX" {
		t.Errorf("sessionSuffixPattern.FindString = %q, want %q", got, "_abc123def_SBX")
	}
}

func TestSandboxStatsPrintSummary(t *testing.T) {
	s := &sandboxStats{counts: map[string]map[string]int{
		"network-outbound": {
			"example.com:443": 2,
			"other.test:80":   1,
		},
		"file-read-data": {
			"/etc/shadow":                  3,
			"/Users/ymt2/.aws/credentials": 2,
		},
		"mach-lookup": {
			"com.apple.coresymbolicationd": 1,
		},
	}}
	var buf bytes.Buffer
	s.printSummary(&buf)
	out := buf.String()

	if !strings.Contains(out, "9 blocked operations") {
		t.Errorf("missing total in summary: %q", out)
	}
	// Operations sorted by total desc: file-read-data (5) > network-outbound (3) > mach-lookup (1).
	wantOrder := []string{"file-read-data", "network-outbound", "mach-lookup"}
	prev := -1
	for _, op := range wantOrder {
		idx := strings.Index(out, op)
		if idx < 0 {
			t.Errorf("summary missing %q: %q", op, out)
			continue
		}
		if idx < prev {
			t.Errorf("summary order wrong for %q (idx=%d, prev=%d): %q", op, idx, prev, out)
		}
		prev = idx
	}
	for _, want := range []string{"/etc/shadow", "/Users/ymt2/.aws/credentials", "example.com:443"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing detail %q: %q", want, out)
		}
	}
	// Detail counts use the ×N prefix.
	if !strings.Contains(out, "×3") || !strings.Contains(out, "×2") {
		t.Errorf("summary missing detail counts: %q", out)
	}
}

func TestSandboxStatsPrintSummaryTruncatesHighCardinality(t *testing.T) {
	byDetail := map[string]int{}
	for i := 0; i < detailsPerOperation+5; i++ {
		byDetail[fmt.Sprintf("/path/variant-%02d", i)] = 1
	}
	s := &sandboxStats{counts: map[string]map[string]int{
		"file-read-data": byDetail,
	}}
	var buf bytes.Buffer
	s.printSummary(&buf)
	out := buf.String()

	if !strings.Contains(out, "+5 more (5 events)") {
		t.Errorf("expected truncation footer, got %q", out)
	}
	if got := strings.Count(out, "×1"); got != detailsPerOperation {
		t.Errorf("expected exactly %d detail rows, got %d in %q", detailsPerOperation, got, out)
	}
}

func TestSandboxStatsPrintSummaryEmpty(t *testing.T) {
	s := &sandboxStats{counts: map[string]map[string]int{}}
	var buf bytes.Buffer
	s.printSummary(&buf)
	if !strings.Contains(buf.String(), "no sandbox violations recorded") {
		t.Errorf("expected empty-state message, got %q", buf.String())
	}
}
