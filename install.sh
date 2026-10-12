#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${ROOT_DIR}/.venv"
PYTHON_BIN="${PYTHON_BIN:-python3}"

print_python_help() {
  echo "    Install Python 3 and ensure '${PYTHON_BIN}' is on PATH."
  echo "    Ubuntu/Debian: sudo apt update && sudo apt install -y python3 python3-venv"
  echo "    RHEL/Fedora:   sudo dnf install -y python3"
  echo "    macOS:         brew install python"
}

print_npm_help() {
  echo "    Install Node.js and npm (needed to build the frontend), then rerun this script."
  echo "    Ubuntu/Debian: sudo apt update && sudo apt install -y nodejs npm"
  echo "    RHEL/Fedora:   sudo dnf install -y nodejs npm"
  echo "    macOS:         brew install node"
}

cd "${ROOT_DIR}"

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  echo "[!] Python not found: ${PYTHON_BIN}"
  print_python_help
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "[!] npm not found"
  print_npm_help
  exit 1
fi

if [[ ! -d "${VENV_DIR}" ]]; then
  echo "[i] Creating virtual environment"
  "${PYTHON_BIN}" -m venv "${VENV_DIR}"
fi

echo "[i] Installing Python dependencies"
"${VENV_DIR}/bin/python" -m pip install --upgrade pip
"${VENV_DIR}/bin/pip" install -r requirements.txt

echo "[i] Installing frontend dependencies and building UI"
npm --prefix frontend install
npm --prefix frontend run build

echo "[i] Ensuring output directory exists"
mkdir -p output

echo
echo "[✓] Install complete"
echo "    Run: python SprayCan.py"
