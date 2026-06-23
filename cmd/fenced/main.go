package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fencesandbox/fence/pkg/fence"
	shellquote "github.com/kballard/go-shellquote"
)

func main() {
	if !fence.IsSupported() {
		log.Fatal("sandboxing not supported on this platform")
	}

	preArgs, cmdArgs := splitDoubleDash(os.Args[1:])

	fs := flag.NewFlagSet("fenced", flag.ExitOnError)
	verbose := fs.Bool("fence-verbose", false, "forward fence library noise to stderr instead of discarding it")
	if err := fs.Parse(preArgs); err != nil {
		log.Fatal(err)
	}
	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "usage: fenced [--fence-verbose] -- <command> [args...]")
		os.Exit(2)
	}

	origStderr, drainDone, err := redirectStderrToPipe(*verbose)
	if err != nil {
		log.Fatal(err)
	}
	// Helper re-execs spawned by fence inherit our env. Point their fencelog
	// at /dev/null so their noise does not land on the child's stderr.
	os.Setenv("FENCE_LOG_FILE", os.DevNull)

	cfg, err := fence.LoadConfigResolved(fence.ResolveDefaultConfigPath())
	if err != nil {
		log.Fatal(err)
	}
	if cfg == nil {
		cfg = fence.DefaultConfig()
	}

	// Resolve sockets dynamically and append them.
	cfg.Network.AllowUnixSockets = append(
		cfg.Network.AllowUnixSockets,
		dynamicSockets()...,
	)

	manager := fence.NewManager(cfg, false, true)
	defer manager.Cleanup()
	if err := manager.Initialize(); err != nil {
		log.Fatal(err)
	}

	wrapped, err := manager.WrapCommand(shellquote.Join(cmdArgs...))
	if err != nil {
		log.Fatal(err)
	}

	stats := startSandboxStats(wrapped, origStderr)

	cmd := exec.Command("sh", "-c", wrapped)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, origStderr
	runErr := cmd.Run()

	stats.stop()

	// Close fd 2 (our pipe write end) so the drain goroutine reaches EOF and
	// returns before we print the summary on origStderr.
	_ = syscall.Close(int(os.Stderr.Fd()))
	<-drainDone

	stats.printSummary(origStderr)

	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		log.Fatal(runErr)
	}
}

// splitDoubleDash splits args around "--". When "--" is absent, all args are returned as cmd.
func splitDoubleDash(args []string) (pre, cmd []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return nil, args
}

func dynamicSockets() []string {
	var out []string

	// SSH agent (from env)
	if s := os.Getenv("SSH_AUTH_SOCK"); s != "" {
		out = append(out, s)
	}

	// All launchd sockets (guards against path changes after a reboot)
	if matches, _ := filepath.Glob("/private/var/run/com.apple.launchd.*/Listeners"); matches != nil {
		out = append(out, matches...)
	}

	// GnuPG agent / scdaemon / dirmngr sockets
	if matches, _ := filepath.Glob(os.ExpandEnv("$HOME/.gnupg/S.*")); matches != nil {
		out = append(out, matches...)
	}

	// Git fsmonitor (the cwd repo + its worktrees)
	if matches, _ := filepath.Glob(".git/fsmonitor--daemon.ipc"); matches != nil {
		out = append(out, mustAbs(matches)...)
	}
	if matches, _ := filepath.Glob(".git/worktrees/*/fsmonitor--daemon.ipc"); matches != nil {
		out = append(out, mustAbs(matches)...)
	}

	return out
}

func mustAbs(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if abs, err := filepath.Abs(p); err == nil {
			out = append(out, abs)
		}
	}
	return out
}

// redirectStderrToPipe captures fd 2 so the fence library's init-time
// stderr binding writes into a pipe we own. The returned file is the
// original stderr, preserved for the child command and for our own
// user-facing output. drainDone closes once the goroutine consuming the
// pipe sees EOF, which happens after the caller closes fd 2.
func redirectStderrToPipe(verbose bool) (origStderr *os.File, drainDone <-chan struct{}, err error) {
	origFd, err := syscall.Dup(int(os.Stderr.Fd()))
	if err != nil {
		return nil, nil, err
	}
	origStderr = os.NewFile(uintptr(origFd), "/dev/stderr")
	// fenced's own log should reach the user, so point it back at the original stderr.
	log.SetOutput(origStderr)

	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		_ = origStderr.Close()
		return nil, nil, err
	}
	if err := syscall.Dup2(int(pipeW.Fd()), int(os.Stderr.Fd())); err != nil {
		_ = pipeR.Close()
		_ = pipeW.Close()
		_ = origStderr.Close()
		return nil, nil, err
	}
	// fd 2 now holds the pipe's write end, so this reference can be closed.
	_ = pipeW.Close()

	var sink io.Writer = io.Discard
	if verbose {
		sink = origStderr
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(sink, pipeR)
		_ = pipeR.Close()
		close(done)
	}()
	return origStderr, done, nil
}

// sessionSuffixPattern matches the per-invocation tag fence embeds in
// macOS sandbox profiles (see fencesandbox/fence internal/sandbox/macos.go).
var sessionSuffixPattern = regexp.MustCompile(`_[0-9a-f]{9}_SBX`)

// sandboxStats accumulates blocked-operation counts via the macOS unified
// log stream. On platforms other than macOS, or when the session suffix
// can not be recovered, it degrades to a no-op stub.
type sandboxStats struct {
	cancel context.CancelFunc
	cmd    *exec.Cmd
	done   chan struct{}

	mu sync.Mutex
	// counts[operation][details] = occurrences. Details is the trailing
	// path/host/service captured from the sandbox log line.
	counts map[string]map[string]int
}

func startSandboxStats(wrappedCommand string, origStderr io.Writer) *sandboxStats {
	s := &sandboxStats{counts: map[string]map[string]int{}}
	if runtime.GOOS != "darwin" {
		return s
	}
	suffix := sessionSuffixPattern.FindString(wrappedCommand)
	if suffix == "" {
		fmt.Fprintln(origStderr, "fenced: could not determine sandbox session suffix; stats disabled")
		return s
	}

	ctx, cancel := context.WithCancel(context.Background())
	predicate := fmt.Sprintf(`eventMessage ENDSWITH "%s"`, suffix)
	cmd := exec.CommandContext(
		ctx, "log", "stream",
		"--predicate", predicate,
		"--style", "compact",
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		fmt.Fprintf(origStderr, "fenced: log stream attach failed: %v\n", err)
		return s
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		cancel()
		fmt.Fprintf(origStderr, "fenced: log stream start failed: %v\n", err)
		return s
	}
	s.cancel = cancel
	s.cmd = cmd
	s.done = make(chan struct{})

	go func() {
		defer close(s.done)
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			op, details := parseViolation(scanner.Text())
			if op == "" {
				continue
			}
			s.mu.Lock()
			byDetail := s.counts[op]
			if byDetail == nil {
				byDetail = map[string]int{}
				s.counts[op] = byDetail
			}
			byDetail[details]++
			s.mu.Unlock()
		}
	}()

	// Wait so events that fire before the log stream finishes attaching are not missed.
	time.Sleep(100 * time.Millisecond)
	return s
}

func (s *sandboxStats) stop() {
	if s == nil || s.cancel == nil {
		return
	}
	// Give the log stream a moment to deliver events from right after the child exits.
	time.Sleep(500 * time.Millisecond)
	s.cancel()
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_ = s.cmd.Wait()
	}
	if s.done != nil {
		<-s.done
	}
}

// detailsPerOperation caps the per-operation detail list so a tight loop
// hitting many unique paths cannot drown the summary. Excess entries are
// rolled into a trailing "... +N more" line so the total stays honest.
const detailsPerOperation = 10

func (s *sandboxStats) printSummary(w io.Writer) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.counts) == 0 {
		fmt.Fprintln(w, "fenced: no sandbox violations recorded")
		return
	}

	type opTotal struct {
		op    string
		total int
	}
	ops := make([]opTotal, 0, len(s.counts))
	grand := 0
	for op, byDetail := range s.counts {
		t := 0
		for _, n := range byDetail {
			t += n
		}
		ops = append(ops, opTotal{op, t})
		grand += t
	}
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].total != ops[j].total {
			return ops[i].total > ops[j].total
		}
		return ops[i].op < ops[j].op
	})

	opWidth := 0
	for _, o := range ops {
		if len(o.op) > opWidth {
			opWidth = len(o.op)
		}
	}

	fmt.Fprintf(w, "fenced: %d blocked operations\n", grand)
	for _, o := range ops {
		fmt.Fprintf(w, "  %-*s : %d\n", opWidth, o.op, o.total)
		printDetails(w, s.counts[o.op])
	}
}

func printDetails(w io.Writer, byDetail map[string]int) {
	type entry struct {
		detail string
		count  int
	}
	entries := make([]entry, 0, len(byDetail))
	for d, n := range byDetail {
		entries = append(entries, entry{d, n})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].count != entries[j].count {
			return entries[i].count > entries[j].count
		}
		return entries[i].detail < entries[j].detail
	})

	shown := entries
	hiddenVariants, hiddenEvents := 0, 0
	if len(entries) > detailsPerOperation {
		shown = entries[:detailsPerOperation]
		for _, e := range entries[detailsPerOperation:] {
			hiddenVariants++
			hiddenEvents += e.count
		}
	}
	for _, e := range shown {
		label := e.detail
		if label == "" {
			label = "(no detail)"
		}
		fmt.Fprintf(w, "    ×%-3d %s\n", e.count, truncateForSummary(label, 100))
	}
	if hiddenVariants > 0 {
		fmt.Fprintf(w, "    ... +%d more (%d events)\n", hiddenVariants, hiddenEvents)
	}
}

func truncateForSummary(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// violationPattern matches sandbox denial lines emitted by macOS
// `log stream --style compact`. Mirrors fencesandbox/fence
// internal/sandbox/monitor.go violationPattern, but we capture the
// operation and the trailing details separately so we can filter noise
// from foundational paths like /dev/tty.
var violationPattern = regexp.MustCompile(`Sandbox: \w+\(\d+\) deny\(\d+\) (\S+)(.*)`)

// parseViolation extracts the operation name and the trailing details
// (typically a path, host:port, or mach-service name) from a sandbox
// denial log line. Returns ("", "") when the line should be ignored.
func parseViolation(line string) (op, details string) {
	if strings.HasPrefix(line, "Filtering") || strings.HasPrefix(line, "Timestamp") {
		return "", ""
	}
	if strings.Contains(line, "duplicate report") {
		return "", ""
	}
	if strings.HasPrefix(line, "CMD64_") {
		return "", ""
	}
	m := violationPattern.FindStringSubmatch(line)
	if m == nil {
		return "", ""
	}
	op = m[1]
	details = strings.TrimSpace(m[2])
	if !relevantSandboxOperation(op) || isNoisyViolation(details) {
		return "", ""
	}
	return op, details
}

func relevantSandboxOperation(op string) bool {
	switch {
	case strings.HasPrefix(op, "network-"),
		strings.HasPrefix(op, "file-read"),
		strings.HasPrefix(op, "file-write"),
		strings.HasPrefix(op, "mach-"):
		return true
	}
	return false
}

func isNoisyViolation(details string) bool {
	switch {
	case strings.HasPrefix(details, "/dev/tty"),
		strings.HasPrefix(details, "/dev/pts"),
		strings.HasPrefix(details, "/private/var/run/syslog"),
		strings.Contains(details, "mDNSResponder"):
		return true
	}
	return false
}
