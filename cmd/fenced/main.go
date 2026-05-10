package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

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

	logPath, err := filepath.Abs("/tmp/fence.log")
	if err != nil {
		log.Fatal(err)
	}
	os.Setenv("FENCE_LOG_FILE", logPath)

	// fence ライブラリ内の fencelog は init 時に os.Stderr (fd 2) を捕捉して
	// そこへ書き込むため、env var だけでは抑止できない。fd 2 をログファイルに
	// 差し替え、元の stderr は子プロセス用に取っておく。
	origStderrFd, err := syscall.Dup(int(os.Stderr.Fd()))
	if err != nil {
		log.Fatal(err)
	}
	origStderr := os.NewFile(uintptr(origStderrFd), "/dev/stderr")

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()
	if err := syscall.Dup2(int(logFile.Fd()), int(os.Stderr.Fd())); err != nil {
		log.Fatal(err)
	}
	// fenced 自身のエラーはユーザに見せたいのでログ出力を元の stderr に戻す。
	log.SetOutput(origStderr)

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
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, origStderr
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
