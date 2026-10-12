#!/usr/bin/env python3
"""
SprayCan installer — creates a venv, installs Python and frontend dependencies.
Run with: python install.py
"""

import os
import platform
import shutil
import subprocess
import sys

MIN_PYTHON = (3, 9)
MIN_NODE = (18, 0)
VENV_DIR = ".venv"
IS_WINDOWS = os.name == "nt"


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _p(msg=""):
    print(msg)


def fail(msg):
    _p()
    for line in msg.splitlines():
        _p("  [!] %s" % line)
    _p()
    sys.exit(1)


def step(msg):
    _p("  [→] %s" % msg)


def ok(msg):
    _p("  [✓] %s" % msg)


def warn(msg):
    _p("  [!] %s" % msg)


# ---------------------------------------------------------------------------
# Python version check
# ---------------------------------------------------------------------------

if sys.version_info < MIN_PYTHON:
    fail(
        "Python %d.%d or newer is required (you have %d.%d).\n"
        "Download the latest Python from https://python.org/downloads/"
        % (MIN_PYTHON[0], MIN_PYTHON[1], sys.version_info.major, sys.version_info.minor)
    )


# ---------------------------------------------------------------------------
# Resolve paths relative to this script, not cwd
# ---------------------------------------------------------------------------

ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT)

VENV_BIN = os.path.join(ROOT, VENV_DIR, "Scripts" if IS_WINDOWS else "bin")
venv_python = os.path.join(VENV_BIN, "python.exe" if IS_WINDOWS else "python")
req_file = os.path.join(ROOT, "requirements.txt")

_p()
_p("  SprayCan — Installer")
_p("  " + "-" * 40)
_p("  Platform : %s %s" % (platform.system(), platform.release()))
_p("  Python   : %s" % sys.version.split()[0])
_p()


# ---------------------------------------------------------------------------
# Create venv
# ---------------------------------------------------------------------------

venv_ready = os.path.isdir(VENV_DIR) and os.path.isfile(venv_python)

if venv_ready:
    step("Virtual environment already exists — skipping creation")
else:
    if os.path.isdir(VENV_DIR):
        step("Incomplete virtual environment found — recreating")
        shutil.rmtree(VENV_DIR)

    step("Creating virtual environment in %s/" % VENV_DIR)
    result = subprocess.run(
        [sys.executable, "-m", "venv", VENV_DIR],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        err = (result.stderr or "").strip()
        msg = "Failed to create virtual environment."
        if err:
            msg += "\n  %s" % err
        if IS_WINDOWS:
            msg += (
                "\n  Ensure Python was installed with the 'venv' feature enabled."
                "\n  Re-run the Python installer, select Modify, and enable pip/venv."
            )
        elif sys.platform == "darwin":
            msg += (
                "\n  Try reinstalling Python via https://python.org/downloads/ or:"
                "\n    brew install python@%d.%d"
                % (sys.version_info.major, sys.version_info.minor)
            )
        else:
            # Ubuntu / Debian: venv ships as a separate apt package per Python version
            msg += (
                "\n  On Ubuntu/Debian, install the venv package for your Python version:"
                "\n    sudo apt install python%d.%d-venv"
                % (sys.version_info.major, sys.version_info.minor)
            )
        fail(msg)

    if not os.path.isfile(venv_python):
        fail(
            "Virtual environment was created but the Python binary is missing at:\n"
            "  %s\n"
            "This may indicate a corrupted Python installation." % venv_python
        )

ok("Virtual environment ready")


# ---------------------------------------------------------------------------
# Upgrade pip
# ---------------------------------------------------------------------------

step("Upgrading pip")
result = subprocess.run(
    [venv_python, "-m", "pip", "install", "--upgrade", "pip", "-q"],
    capture_output=True,
    text=True,
)
if result.returncode != 0:
    warn("pip upgrade failed — continuing with existing pip version")


# ---------------------------------------------------------------------------
# Install Python dependencies
# ---------------------------------------------------------------------------

if not os.path.isfile(req_file):
    fail("requirements.txt not found at:\n  %s" % req_file)

step("Installing Python dependencies from requirements.txt")
result = subprocess.run(
    [venv_python, "-m", "pip", "install", "-r", req_file, "-q"],
    stderr=subprocess.PIPE,
    text=True,
)
if result.returncode != 0:
    err = (result.stderr or "").strip() or "(no details)"
    hint = ""
    if sys.platform == "darwin":
        hint = "\n  On macOS you may need Xcode tools first: xcode-select --install"
    fail(
        "Dependency installation failed:\n"
        "  %s\n\n"
        "  Check your internet connection and try again.%s" % (err, hint)
    )

ok("Python dependencies installed")


# ---------------------------------------------------------------------------
# Frontend — npm install + build
# ---------------------------------------------------------------------------

frontend_dir = os.path.join(ROOT, "frontend")
frontend_dist = os.path.join(frontend_dir, "dist")


def _run_npm(*args):
    """Run npm in the frontend directory.
    Uses shell=True on Windows so npm.cmd is resolved via PATHEXT."""
    return subprocess.run(
        ["npm"] + list(args),
        cwd=frontend_dir,
        capture_output=True,
        text=True,
        shell=IS_WINDOWS,
    )


def _npm_err(result):
    """Return the first 15 lines of npm error output for display."""
    raw = (result.stderr or result.stdout or "").strip()
    lines = raw.splitlines()[:15]
    return "\n      ".join(lines) if lines else "(no details)"


npm = shutil.which("npm") or (shutil.which("npm.cmd") if IS_WINDOWS else None)

if npm:
    # Warn if Node.js is older than MIN_NODE
    node_bin = shutil.which("node") or (shutil.which("node.exe") if IS_WINDOWS else None)
    if node_bin:
        try:
            ver_str = subprocess.check_output(
                [node_bin, "--version"], text=True, stderr=subprocess.DEVNULL
            ).strip()
            parts = ver_str.lstrip("v").split(".")
            node_ver = (int(parts[0]), int(parts[1] if len(parts) > 1 else "0"))
            if node_ver < MIN_NODE:
                warn(
                    "Node.js %s detected — v%d+ is recommended. "
                    "Download from https://nodejs.org/" % (ver_str, MIN_NODE[0])
                )
        except Exception:
            pass

    step("Installing frontend dependencies")
    result = _run_npm("install")
    if result.returncode != 0:
        warn("npm install failed — checking for pre-built frontend")
        _p("      %s" % _npm_err(result))
        if not os.path.isdir(frontend_dist):
            fail(
                "npm install failed and no pre-built frontend/dist/ exists.\n"
                "  Resolve the npm error above and re-run the installer."
            )
    else:
        step("Building frontend")
        result = _run_npm("run", "build")
        if result.returncode != 0:
            warn("Frontend build failed — checking for pre-built frontend")
            _p("      %s" % _npm_err(result))
            if not os.path.isdir(frontend_dist):
                fail(
                    "Frontend build failed and no pre-built dist/ exists.\n"
                    "  Resolve the build error above and re-run the installer."
                )
        else:
            ok("Frontend built")

else:
    if os.path.isdir(frontend_dist):
        step("npm not found — using pre-built frontend (fine for end users)")
    else:
        _p()
        _p("  [!] npm not found and no pre-built frontend/dist/ exists.")
        _p("      Install Node.js from https://nodejs.org/ and re-run this installer.")
        if sys.platform == "darwin":
            _p("      With Homebrew:    brew install node")
        elif not IS_WINDOWS:
            _p("      On Ubuntu/Debian: sudo apt install nodejs npm")
        _p()
        sys.exit(1)


# ---------------------------------------------------------------------------
# Create runtime directories
# ---------------------------------------------------------------------------

for rel_path in ["output"]:
    dirpath = os.path.join(ROOT, rel_path)
    if not os.path.isdir(dirpath):
        step("Creating %s/" % rel_path)
        os.makedirs(dirpath, exist_ok=True)


# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

_p()
_p("  " + "=" * 40)
_p("  [✓] Installation complete")
_p()
_p("  To start SprayCan:")
_p("      python SprayCan.py")
_p()
