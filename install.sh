#!/usr/bin/env bash
set -e

REPO="${REPO:-VLOD-ZDOV/vless-extractor}"
BINARY="vless-extract"
URL="https://github.com/${REPO}/releases/latest/download/${BINARY}"

echo "[*] Installing ${BINARY} from ${REPO}..."

# Destination directory
if [ "$EUID" -eq 0 ]; then
    DEST="/usr/local/bin"
    SUDO=""
elif [ -w "/usr/local/bin" ]; then
    DEST="/usr/local/bin"
    SUDO=""
elif command -v sudo >/dev/null 2>&1; then
    DEST="/usr/local/bin"
    SUDO="sudo"
else
    DEST="${HOME}/.local/bin"
    SUDO=""
    mkdir -p "${DEST}"
fi

TMP_FILE="$(mktemp)"
trap 'rm -f "${TMP_FILE}"' EXIT

echo "[*] Downloading ${URL}..."
curl -fsSL "${URL}" -o "${TMP_FILE}"
chmod +x "${TMP_FILE}"

if [ -n "${SUDO}" ]; then
    echo "[*] Installing to ${DEST}/${BINARY} (sudo)..."
    ${SUDO} install -m 755 "${TMP_FILE}" "${DEST}/${BINARY}"
else
    echo "[*] Installing to ${DEST}/${BINARY}..."
    install -m 755 "${TMP_FILE}" "${DEST}/${BINARY}"
fi

echo "[+] Successfully installed ${BINARY} to ${DEST}/${BINARY}"
if ! command -v "${BINARY}" >/dev/null 2>&1; then
    echo "[!] Note: Make sure ${DEST} is in your PATH."
fi
