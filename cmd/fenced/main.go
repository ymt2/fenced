package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/Use-Tusk/fence/pkg/fence"
	shellquote "github.com/kballard/go-shellquote"
)

func main() {
	if !fence.IsSupported() {
		log.Fatal("sandboxing not supported on this platform")
	}

	cmdArgs := afterDoubleDash(os.Args[1:])
	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "usage: fenced [...] -- <command> [args...]")
		os.Exit(2)
	}

	abs, err := filepath.Abs("/tmp/fence.log")
	if err != nil {
		log.Fatal(err)
	}
	os.Setenv("FENCE_LOG_FILE", abs)

	// 既存の ~/.config/fence/fence.json を読む
	cfg, err := fence.LoadConfigResolved(fence.ResolveDefaultConfigPath())
	if err != nil {
		log.Fatal(err)
	}
	if cfg == nil {
		cfg = fence.DefaultConfig()
	}

	// 動的に socket を解決して上乗せ
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

	cmd := exec.Command("sh", "-c", wrapped)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		log.Fatal(err)
	}
}

// "--" 以降だけ取り出す。"--" が無ければ全引数を返す。
func afterDoubleDash(args []string) []string {
	for i, a := range args {
		if a == "--" {
			return args[i+1:]
		}
	}
	return args
}

func dynamicSockets() []string {
	var out []string

	// SSH agent (env から)
	if s := os.Getenv("SSH_AUTH_SOCK"); s != "" {
		out = append(out, s)
	}

	// launchd の socket を全部 (re-boot 後の path 変動対策)
	if matches, _ := filepath.Glob("/private/var/run/com.apple.launchd.*/Listeners"); matches != nil {
		out = append(out, matches...)
	}

	// Git fsmonitor (cwd の repo + worktree)
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
