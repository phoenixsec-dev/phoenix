#!/usr/bin/env sh
# Phoenix installer: downloads the phoenix + phoenix-server release binaries
# for this OS/arch, verifies them against the release checksums.txt, and
# installs them.
#
#   curl -fsSL https://raw.githubusercontent.com/phoenixsec-dev/phoenix/main/scripts/install.sh | sh
#
# Environment:
#   PHOENIX_VERSION   release tag to install, e.g. v0.17.0 (default: latest)
#   INSTALL_DIR       target directory (default: /usr/local/bin, falling back
#                     to ~/.local/bin when /usr/local/bin is not writable)
#   PHOENIX_BASE_URL  download directory holding the archives + checksums.txt
#                     (default: the GitHub release for PHOENIX_VERSION). Used
#                     for mirrors and for testing against a local
#                     `goreleaser release --snapshot` build.
set -eu

REPO="phoenixsec-dev/phoenix"
VERSION="${PHOENIX_VERSION:-latest}"

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

# GoReleaser strips the leading "v" from the tag in archive names:
# tag v0.17.0 ships phoenix_0.17.0_linux_amd64.tar.gz.
ARCHIVE="phoenix_${VERSION#v}_${OS}_${ARCH}.tar.gz"
BASE_URL="${PHOENIX_BASE_URL:-https://github.com/$REPO/releases/download/$VERSION}"
TMPDIR="$(mktemp -d)"
cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT INT TERM

echo "Downloading $ARCHIVE ($VERSION) ..."
curl -fsSL "$BASE_URL/$ARCHIVE" -o "$TMPDIR/$ARCHIVE"
curl -fsSL "$BASE_URL/checksums.txt" -o "$TMPDIR/checksums.txt"

# Refuse to install anything we could not verify. This is a secrets manager;
# an unverified binary is not an acceptable fallback.
EXPECTED="$(grep " $ARCHIVE\$" "$TMPDIR/checksums.txt" | awk '{print $1}')"
if [ -z "$EXPECTED" ]; then
  echo "error: $ARCHIVE is not listed in checksums.txt" >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL="$(sha256sum "$TMPDIR/$ARCHIVE" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  ACTUAL="$(shasum -a 256 "$TMPDIR/$ARCHIVE" | awk '{print $1}')"
else
  echo "error: need sha256sum or shasum to verify the download" >&2
  exit 1
fi
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "error: checksum verification failed for $ARCHIVE" >&2
  exit 1
fi
echo "Checksum OK"

tar -xzf "$TMPDIR/$ARCHIVE" -C "$TMPDIR"

# Only fall back to ~/.local/bin when the caller did not pick a directory.
# An explicit INSTALL_DIR that is not writable is an error, not a hint.
if [ -n "${INSTALL_DIR:-}" ]; then
  mkdir -p "$INSTALL_DIR"
else
  INSTALL_DIR="/usr/local/bin"
  if [ ! -w "$INSTALL_DIR" ]; then
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "$INSTALL_DIR"
  fi
fi

install -m 0755 "$TMPDIR/phoenix" "$INSTALL_DIR/phoenix"
install -m 0755 "$TMPDIR/phoenix-server" "$INSTALL_DIR/phoenix-server"

echo "Installed:"
echo "  $INSTALL_DIR/phoenix"
echo "  $INSTALL_DIR/phoenix-server"

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *)
    echo "note: $INSTALL_DIR is not in PATH; add it before running the commands below"
    ;;
esac

echo
echo "Next: phoenix-server --init ~/.phoenix"
echo "Quickstart: https://github.com/$REPO/blob/main/docs/quickstart.md"
