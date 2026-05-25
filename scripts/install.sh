#!/usr/bin/env bash
set -euo pipefail

REPO="github.com/danangamw/go-janitor/cmd/janitor"
BINARY="janitor"
VERSION="${1:-latest}"

printf '\033[1;36m==> Installing go-janitor@%s\033[0m\n' "$VERSION"

# Check go is available
if ! command -v go &>/dev/null; then
  printf '\033[1;31merror:\033[0m Go is not installed or not in PATH.\n' >&2
  exit 1
fi

printf '    Downloading and compiling (this may take a moment)...\n'

if go install "${REPO}@${VERSION}" 2>&1 | grep -v '^$'; then
  :
fi

# Resolve install path
GOBIN="${GOBIN:-$(go env GOPATH)/bin}"
BINARY_PATH="${GOBIN}/${BINARY}"

if [[ ! -x "$BINARY_PATH" ]]; then
  printf '\033[1;31merror:\033[0m binary not found at %s\n' "$BINARY_PATH" >&2
  exit 1
fi

INSTALLED_VERSION=$("$BINARY_PATH" version 2>/dev/null || echo "unknown")

printf '\033[1;32m==> Done!\033[0m %s\n' "$INSTALLED_VERSION"
printf '    Binary: %s\n' "$BINARY_PATH"
printf '\n    Run: %s --help\n' "$BINARY"
