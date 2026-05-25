#!/usr/bin/env bash
set -euo pipefail

REPO="danangamw/go-janitor"
BINARY="go-janitor"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${1:-latest}"

# ── helpers ────────────────────────────────────────────────────────────────────
info()  { printf '\033[1;36m==> %s\033[0m\n' "$*"; }
ok()    { printf '\033[1;32m==> %s\033[0m\n' "$*"; }
err()   { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
need()  { command -v "$1" &>/dev/null || err "'$1' is required but not installed. Install it and retry."; }

# ── detect OS & arch ───────────────────────────────────────────────────────────
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) err "Unsupported architecture: $ARCH" ;;
esac
case "$OS" in
  linux|darwin) ;;
  *) err "Unsupported OS: $OS" ;;
esac

need curl
need tar

# ── resolve version ────────────────────────────────────────────────────────────
info "Installing ${BINARY}@${VERSION}"

if [[ "$VERSION" == "latest" ]]; then
  printf '    Fetching latest release...\n'
  VERSION="$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
  [[ -n "$VERSION" ]] || err "Could not determine latest version from GitHub API."
fi

# ── download & install ─────────────────────────────────────────────────────────
TARBALL="${BINARY}_${OS}_${ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"

printf '    Downloading %s (%s/%s)...\n' "$VERSION" "$OS" "$ARCH"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

curl -sSfL "$DOWNLOAD_URL" -o "${TMP}/${TARBALL}" \
  || err "Download failed. Check that release ${VERSION} exists:\n  https://github.com/${REPO}/releases"

tar -xzf "${TMP}/${TARBALL}" -C "$TMP"

BINARY_PATH="${TMP}/${BINARY}"
[[ -f "$BINARY_PATH" ]] || err "Binary '${BINARY}' not found in archive."

printf '    Installing to %s (may need sudo)...\n' "$INSTALL_DIR"
if [[ -w "$INSTALL_DIR" ]]; then
  install -m 0755 "$BINARY_PATH" "${INSTALL_DIR}/${BINARY}"
else
  sudo install -m 0755 "$BINARY_PATH" "${INSTALL_DIR}/${BINARY}"
fi

# ── verify ─────────────────────────────────────────────────────────────────────
INSTALLED_VERSION=$("${INSTALL_DIR}/${BINARY}" version 2>/dev/null || echo "unknown")

ok "Done! ${INSTALLED_VERSION}"
printf '    Binary: %s/%s\n' "$INSTALL_DIR" "$BINARY"
printf '\n    Run: %s --help\n' "$BINARY"
