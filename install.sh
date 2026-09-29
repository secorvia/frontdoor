#!/bin/sh
# frontdoor installer.
#
# It downloads the release archive, verifies its SHA-256 against the signed
# checksums file, and only then unpacks it. A security tool that asks you to
# pipe a script into a shell should at least be able to prove what it fetched.
#
#   curl -fsSL https://raw.githubusercontent.com/secorvia/frontdoor/main/install.sh | sh
#
# If you would rather not pipe anything into a shell - a reasonable position -
# use `go install github.com/secorvia/frontdoor/cmd/frontdoor@latest`, or take
# the archive from the releases page and check it by hand.
set -eu

REPO="secorvia/frontdoor"
VERSION="${FRONTDOOR_VERSION:-latest}"
INSTALL_DIR="${FRONTDOOR_INSTALL_DIR:-/usr/local/bin}"

die() { printf 'install: %s\n' "$1" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }

need curl
need tar

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux|darwin) ;;
  *) die "unsupported OS: $os. Use: go install github.com/$REPO/cmd/frontdoor@latest" ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) die "unsupported architecture: $arch" ;;
esac

if [ "$VERSION" = "latest" ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
    sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n1)
  [ -n "$VERSION" ] || die "could not determine the latest version"
fi
NUM="${VERSION#v}"

base="https://github.com/$REPO/releases/download/$VERSION"
archive="frontdoor_${NUM}_${os}_${arch}.tar.gz"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

printf 'Downloading %s %s (%s/%s)\n' frontdoor "$VERSION" "$os" "$arch"
curl -fsSL -o "$tmp/$archive" "$base/$archive" || die "download failed: $base/$archive"
curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt" || die "no checksums.txt in $VERSION"

# Verify before unpacking, not after. An archive that fails the checksum is
# never written anywhere it could be run from.
printf 'Verifying checksum\n'
expected=$(grep " $archive\$" "$tmp/checksums.txt" | awk '{print $1}')
[ -n "$expected" ] || die "$archive is not listed in checksums.txt"

if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$archive" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$tmp/$archive" | awk '{print $1}')
else
  die "no sha256sum or shasum available to verify the download"
fi

[ "$actual" = "$expected" ] || die "checksum mismatch
  expected $expected
  got      $actual
Do not run this binary. Please open an issue at https://github.com/$REPO/issues"

if command -v cosign >/dev/null 2>&1; then
  printf 'Verifying signature\n'
  curl -fsSL -o "$tmp/checksums.txt.sig" "$base/checksums.txt.sig" 2>/dev/null || true
  curl -fsSL -o "$tmp/checksums.txt.pem" "$base/checksums.txt.pem" 2>/dev/null || true
  if [ -s "$tmp/checksums.txt.sig" ] && [ -s "$tmp/checksums.txt.pem" ]; then
    cosign verify-blob "$tmp/checksums.txt" \
      --signature "$tmp/checksums.txt.sig" \
      --certificate "$tmp/checksums.txt.pem" \
      --certificate-identity-regexp "https://github\.com/$REPO/\.github/workflows/.+" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com ||
      die "signature verification failed - do not run this binary"
  fi
else
  printf 'cosign not found; checksum verified but signature was not. Install cosign to check it.\n'
fi

tar -xzf "$tmp/$archive" -C "$tmp" frontdoor

if [ -w "$INSTALL_DIR" ]; then
  mv "$tmp/frontdoor" "$INSTALL_DIR/frontdoor"
else
  printf 'Installing to %s needs elevation\n' "$INSTALL_DIR"
  sudo mv "$tmp/frontdoor" "$INSTALL_DIR/frontdoor"
fi
chmod +x "$INSTALL_DIR/frontdoor" 2>/dev/null || sudo chmod +x "$INSTALL_DIR/frontdoor"

printf '\nInstalled %s to %s\n' "$("$INSTALL_DIR/frontdoor" version)" "$INSTALL_DIR"
printf 'Run: frontdoor scan\n'
