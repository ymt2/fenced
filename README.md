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

## Recipe: agent-browser

[agent-browser](https://www.npmjs.com/package/agent-browser) drives Chrome over
CDP through a background daemon. Two things trip it up under the sandbox:

- **Chrome can't launch inside.** It needs mach service registration (Crashpad),
  writes under `~/Library/Application Support/Google/Chrome`, and to bind its own
  `SingletonSocket` — none of which the sandbox grants. Chrome must run
  **outside** `fenced`.
- **The daemon can't bind its control socket by default.** Binding an AF_UNIX
  socket requires its path to be in fence's `allowUnixSockets`; the daemon's
  `~/.agent-browser/*.sock` isn't there out of the box, so the bind is denied.
  (`allowLocalBinding` only covers TCP loopback ports, not Unix sockets.)

The working split: run Chrome **outside** the sandbox with a debugging port, run
agent-browser (daemon + CLI) **inside**, and let the daemon attach to Chrome over
loopback CDP (loopback outbound is allowed).

**1. Allow the daemon's socket in `~/.config/fence/fence.json`:**

```jsonc
{
  "network": {
    "allowUnixSockets": [
      "~/.agent-browser"        // NOT "~/.agent-browser/**" — see note
    ]
  },
  "filesystem": {
    "allowWrite": [
      "~/.agent-browser/**"     // daemon state + the socket file
    ]
  }
}
```

> **Glob gotcha:** an `allowUnixSockets` entry becomes a literal Seatbelt
> `(subpath ...)` — globs are **not** expanded — so pass the bare directory
> (`~/.agent-browser`), which matches every socket beneath it. `filesystem`
> rules *are* glob-aware, so `~/.agent-browser/**` is correct there.

**2. Start Chrome outside the sandbox** with remote debugging:

```sh
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --remote-debugging-port=9222 \
  --user-data-dir="$HOME/.cache/agent-browser-chrome" \
  --no-first-run --no-default-browser-check &
```

**3. Run agent-browser inside `fenced`, attaching to that Chrome:**

```sh
export AGENT_BROWSER_CDP=9222     # attach to the running Chrome instead of launching one
fenced -- agent-browser open https://example.com
fenced -- agent-browser snapshot -i
```

Pass `--cdp 9222` per command instead of the env var if you prefer. Avoid the
`connect` subcommand here — it starts a daemon that tries to launch its own
Chrome, which the sandbox blocks.

> **Security note:** because Chrome runs outside the sandbox, page traffic is
> **not** subject to fence's `allowedDomains`. The sandbox still confines the
> agent-browser process inside it (it only reaches Chrome over loopback), but
> browsing itself escapes the network policy.

## Development

```sh
make check   # gofumpt + go fix + vet + test (clean tree)
make ci      # compile + check
make test    # go test -race ./...
```

`gofumpt` is pinned via a `go.mod` tool directive, and a lefthook pre-commit hook
runs `go fix`.
