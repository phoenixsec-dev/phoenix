#!/usr/bin/env sh
set -eu

REPO="phoenixsec-dev/phoenix"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${PHOENIX_VERSION:-latest}" # e.g. v0.10.2 or "latest"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: required command not found: $1" >&2
    exit 1
  }
}

need_cmd curl
need_cmd tar

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux) OS="linux" ;;
  Darwin) OS="darwin" ;;
  *)
    echo "error: unsupported OS: $OS (supported: Linux, Darwin)" >&2
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *)
    echo "error: unsupported arch: $ARCH (supported: amd64, arm64)" >&2
    exit 1
    ;;
esac

if [ "$VERSION" = "latest" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  if [ -z "$VERSION" ]; then
    echo "error: failed to resolve latest version from GitHub API" >&2
    exit 1
  fi
fi

ARCHIVE="phoenix_${VERSION}_${OS}_${ARCH}.tar.gz"
BASE_URL="https://github.com/$REPO/releases/download/$VERSION"
TMPDIR="$(mktemp -d)"
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT INT TERM

echo "Downloading $ARCHIVE ..."
curl -fsSL "$BASE_URL/$ARCHIVE" -o "$TMPDIR/$ARCHIVE"
curl -fsSL "$BASE_URL/checksums.txt" -o "$TMPDIR/checksums.txt"

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$TMPDIR" && grep " $ARCHIVE\$" checksums.txt | sha256sum -c -)
elif command -v shasum >/dev/null 2>&1; then
  EXPECTED="$(grep " $ARCHIVE\$" "$TMPDIR/checksums.txt" | awk '{print $1}')"
  ACTUAL="$(shasum -a 256 "$TMPDIR/$ARCHIVE" | awk '{print $1}')"
  [ "$EXPECTED" = "$ACTUAL" ] || {
    echo "error: checksum verification failed" >&2
    exit 1
  }
else
  echo "warning: no sha256 checksum tool found; skipping verification" >&2
fi

tar -xzf "$TMPDIR/$ARCHIVE" -C "$TMPDIR"

if [ ! -w "$INSTALL_DIR" ]; then
  INSTALL_DIR="${HOME}/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi

install -m 0755 "$TMPDIR/phoenix" "$INSTALL_DIR/phoenix"
install -m 0755 "$TMPDIR/phoenix-server" "$INSTALL_DIR/phoenix-server"

echo "Installed:"
echo "  $INSTALL_DIR/phoenix"
echo "  $INSTALL_DIR/phoenix-server"

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    echo "note: $INSTALL_DIR is not in PATH"
    ;;
esac
