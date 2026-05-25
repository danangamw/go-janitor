# go-janitor

Docker maintenance & security audit CLI. Cleans up Docker garbage and audits running containers for CVEs — via Unix socket, no HTTP server needed.

## Features

- **Trash Collector** — removes dangling images, stopped containers (by age), orphaned volumes, and unused networks. Reports disk freed.
- **Security Auditor** — parallel Trivy scan of all running container images with deduplication, cache, and configurable severity threshold.
- **Reporter** — structured JSON logging via `slog`, file export, Slack/Discord webhook with exponential-backoff retry.
- **Dry-run mode** — full simulation with identical log output, labelled `[DRY-RUN]`.
- **Graceful shutdown** — SIGTERM/SIGINT cancels via context; in-flight deletions finish cleanly.

## Requirements

- Go 1.24+
- Docker socket accessible at `/var/run/docker.sock`
- [Trivy](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) (for `scan` / `run` commands)

## Install

```bash
# via install script (no Go required — downloads pre-built binary)
curl -sSf https://raw.githubusercontent.com/danangamw/go-janitor/main/scripts/install.sh | bash

# or download a specific version
curl -sSf https://raw.githubusercontent.com/danangamw/go-janitor/main/scripts/install.sh | bash -s v0.1.0
```

Or grab a binary directly from the [Releases page](https://github.com/danangamw/go-janitor/releases).

**Build from source** (requires Go 1.24+):

```bash
make build && make install

# or via go install
go install github.com/danangamw/go-janitor/cmd/janitor@latest
```

## Usage

```
go-janitor [command] [flags]

Commands:
  clean     Run Docker Trash Collector
  scan      Run Security Auditor
  run       Run both sequentially (default)
  version   Print version info

Flags:
  --dry-run           Simulate without executing (default: false)
  --max-age duration  Max age of stopped containers (default: 48h)
  --severity string   Trivy severity threshold (default: "CRITICAL,HIGH")
  --concurrency int   Max parallel scan goroutines (default: 5)
  --output string     Output format: text or json (default: "text")
  --output-file string Path for JSON report export
  --webhook string    Slack/Discord webhook URL
  --socket string     Docker Unix socket path (default: "/var/run/docker.sock")
  --log-level string  Log level: debug/info/warn/error (default: "info")
  --config string     Path to YAML config file
```

### Examples

```bash
# Dry-run full pipeline
go-janitor run --dry-run

# Clean only containers older than 24h
go-janitor clean --max-age 24h

# Scan with only CRITICAL CVEs, send alert to Slack
go-janitor scan --severity CRITICAL --webhook https://hooks.slack.com/...

# Export JSON report
go-janitor run --output json --output-file /tmp/report.json

# Use config file
cp janitor.yaml.example janitor.yaml
go-janitor run --config janitor.yaml
```

## Config file (YAML)

```yaml
max_age: 72h
concurrency: 3
severity: CRITICAL,HIGH
webhook: https://hooks.slack.com/services/xxx
log_level: info
```

Priority: `CLI flag > JANITOR_* env var > config file > default`

## Build

```bash
make build          # host OS/arch
make build-all      # linux/amd64 + linux/arm64
make test           # -race -cover
make lint           # golangci-lint
make docker         # multi-stage image
```

## Exit Codes

| Code | Meaning                            |
| ---- | ---------------------------------- |
| 0    | Success / dry-run                  |
| 1    | Total failure                      |
| 2    | Partial failure (some scan errors) |

## License

MIT
