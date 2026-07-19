#!/bin/sh
# rvuln0-scan installer — downloads the latest release binary from GitHub
set -eu

REPO="grave0x/rvuln0-scan"
BIN="rvuln0-scan"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Detect platform
OS="$(uname -s)"
ARCH="$(uname -m)"
case "${OS}" in
    Linux)  PLATFORM="linux" ;;
    Darwin) PLATFORM="macos" ;;
    *)      echo "Unsupported OS: ${OS}"; exit 1 ;;
esac

# Find latest release tag
echo "Fetching latest release from ${REPO}..."
LATEST="$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)"
if [ -z "${LATEST}" ]; then
    echo "Could not find latest release. Is ${REPO} accessible?"
    exit 1
fi
echo "Latest release: ${LATEST}"

# Download binary
URL="https://github.com/${REPO}/releases/download/${LATEST}/${BIN}"
echo "Downloading ${URL}..."
curl -sL "${URL}" -o "/tmp/${BIN}"
chmod +x "/tmp/${BIN}"

# Install
echo "Installing to ${INSTALL_DIR}/${BIN}..."
mv "/tmp/${BIN}" "${INSTALL_DIR}/${BIN}"

echo "Installed ${BIN} ${LATEST} to ${INSTALL_DIR}/${BIN}"
echo "Run: ${BIN} --help"
