# fenced

`fenced` is a thin wrapper around [Use-Tusk/fence](https://github.com/Use-Tusk/fence)
that sandboxes a command using your existing fence configuration, transparently
allows the local sockets a typical dev shell needs, and prints a summary of what
the sandbox blocked when the command exits.

It is meant for wrapping long-running, network-and-filesystem-hungry tools (e.g.
agents, build scripts) where you want fence's protection without hand-maintaining
every `allow` rule and without fence's verbose logging on your terminal.

## What it does

- Loads your resolved fence config from `~/.config/fence/fence.json` (or
  `fence.jsonc`); falls back to fence's default (block all network) when none
  exists.
- Adds commonly-needed Unix sockets to the allow list at runtime so they survive
  reboots and path changes:
  - `$SSH_AUTH_SOCK` (SSH agent)
  - `launchd` listener sockets under `/private/var/run/com.apple.launchd.*`
  - GnuPG agent / scdaemon / dirmngr sockets under `~/.gnupg/S.*`
  - Git fsmonitor sockets for the current repo and its worktrees
- Captures the fence library's init-time stderr noise into a pipe and discards
  it by default (pass `--fence-verbose` to forward it to stderr instead).
- On macOS, tails the unified log for this session's sandbox denials and prints
  an operation-by-operation summary — with the offending paths/hosts — when the
  wrapped command exits.

## Install

```sh
make install   # builds to $HOME/.local/bin/fenced
```

Or build locally:

```sh
make build     # builds to ./bin/fenced
```

Requires Go (see `go.mod` for the version) and a platform fence supports
(macOS / Linux).

## Usage

```sh
fenced [--fence-verbose] -- <command> [args...]
```

Everything after `--` is the command to run inside the sandbox.

```sh
fenced -- claude
fenced -- npm test
fenced --fence-verbose -- ./build.sh
```

The wrapped command's stdin/stdout/stderr are passed through unchanged, and
`fenced` exits with the command's exit code.

### Flags

| Flag | Description |
| --- | --- |
| `--fence-verbose` | Forward the fence library's diagnostic output to stderr instead of discarding it. |

## Exit summary

When the command finishes, `fenced` prints a summary of blocked operations to
stderr (macOS only). Counts are grouped by sandbox operation, and within each
operation the offending paths/hosts are de-duplicated and listed by frequency:

```
fenced: 9 blocked operations
  file-read-data    : 5
    ×3   /etc/shadow
    ×2   /Users/you/.aws/credentials
  network-outbound  : 3
    ×2   example.com:443
    ×1   other.test:80
  mach-lookup       : 1
    ×1   com.apple.coresymbolicationd
```

This is handy for tightening your fence config: anything important showing up
here is a candidate for an explicit `allow` rule.

Notes:

- Only `network-*`, `file-read*`, `file-write*`, and `mach-*` operations are
  counted; noisy system paths (`/dev/tty*`, `mDNSResponder`, syslog) are filtered
  out.
- Each operation lists at most 10 distinct targets; the rest collapse into a
  `... +N more (M events)` line.
- Stats rely on the macOS unified log (`log stream`). On other platforms the
  summary is skipped.

## Development

```sh
make check   # gofumpt + go fix + vet + test (clean tree)
make ci      # compile + check
make test    # go test -race ./...
```

`gofumpt` is pinned via a `go.mod` tool directive, and a lefthook pre-commit hook
runs `go fix`.
