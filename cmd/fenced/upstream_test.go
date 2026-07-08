package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestMirroredFenceInternals pins the fence internals that fenced mirrors
// (sessionSuffixPattern, violationPattern, and the CMD64 log tag handled by
// parseViolation). It reads the fence module's source out of the local
// module cache so that a dependency bump changing any of these constructs
// fails CI — Renovate merges fence updates automatically, so this is the
// only tripwire — instead of silently breaking the violation stats.
func TestMirroredFenceInternals(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/fencesandbox/fence").Output()
	if err != nil {
		t.Fatalf("locating fence module source: %v", err)
	}
	moduleDir := strings.TrimSpace(string(out))
	if moduleDir == "" {
		t.Fatal("go list -m returned an empty dir for the fence module")
	}
	readSource := func(rel string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(moduleDir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("reading fence source: %v", err)
		}
		return string(data)
	}
	macos := readSource("internal/sandbox/macos.go")
	monitor := readSource("internal/sandbox/monitor.go")

	t.Run("session suffix construction", func(t *testing.T) {
		// Mirrored by sessionSuffixPattern (main.go): _[0-9a-f]{9}_SBX.
		re := regexp.MustCompile(`"_"\s*\+\s*hex\.EncodeToString\(\w+\)\[:9\]\s*\+\s*"_SBX"`)
		if !re.MatchString(macos) {
			t.Error(`fence macos.go no longer builds the session suffix as "_" + hex.EncodeToString(...)[:9] + "_SBX"; re-derive sessionSuffixPattern in main.go and update this pin`)
		}
	})

	t.Run("log tag embeds the session suffix", func(t *testing.T) {
		// startSandboxStats recovers the suffix from the wrapped command via
		// this tag, and parseViolation drops the CMD64_ sentinel lines.
		re := regexp.MustCompile(`"CMD64_"\s*\+\s*EncodeSandboxedCommand\([\w.]+\)\s*\+\s*"_END"\s*\+\s*sessionSuffix`)
		if !re.MatchString(macos) {
			t.Error(`fence macos.go no longer embeds "CMD64_" + command + "_END" + sessionSuffix in the profile; update startSandboxStats/parseViolation in main.go and this pin`)
		}
	})

	t.Run("violation pattern", func(t *testing.T) {
		// Mirrored by violationPattern (main.go), which drops the process
		// name/pid captures and keeps operation + details.
		want := "violationPattern = regexp.MustCompile(`Sandbox: (\\w+)\\((\\d+)\\) deny\\(\\d+\\) (\\S+)(.*)`)"
		if !strings.Contains(monitor, want) {
			t.Error("fence monitor.go violationPattern changed; re-derive violationPattern in main.go and update this pin")
		}
	})
}
