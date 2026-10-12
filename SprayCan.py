#!/usr/bin/env python3

import os
import sys

# Re-exec under the project venv if we're not already running inside it.
_ROOT = os.path.dirname(os.path.abspath(__file__))
_VENV_PYTHON = os.path.join(
    _ROOT, ".venv", "Scripts" if os.name == "nt" else "bin",
    "python.exe" if os.name == "nt" else "python",
)
if os.path.isfile(_VENV_PYTHON) and os.path.abspath(sys.executable) != os.path.abspath(_VENV_PYTHON):
    os.execv(_VENV_PYTHON, [_VENV_PYTHON] + sys.argv)

import argparse
import threading
import time
import webbrowser

try:
    import uvicorn
except ImportError as e:
    print("")
    print("  [!] Missing dependency: %s" % e)
    print("  [!] Have you run the installer?")
    print("")
    print("      python install.py")
    print("")
    sys.exit(1)

VERSION = "0.80"

_BOLD = "\033[1m"
_RESET = "\033[0m"

BANNER = (
    _BOLD
    + """
  ████████████████████████████████████████████████████
  ██  MODE 1 (default) : UI Mode                     ██
  ██    Starts Canvas and opens your browser.         ██
  ██                                                  ██
  ██  MODE 2 : Blind Mode  [ --blind ]               ██
  ██    Starts Canvas, NO browser. Server URL shown.  ██
  ██                                                  ██
  ██  MODE 3 : Headless Mode  [ --headless ]         ██
  ██    Runs scans from the command line, no Canvas.  ██
  ████████████████████████████████████████████████████
"""
    + _RESET
    + """
  SprayCan v{version} — Remember to shake well before use.
""".format(version=VERSION)
)


class _HelpFormatter(argparse.RawDescriptionHelpFormatter):
    pass


def _open_browser(url: str, delay: float = 1.2):
    time.sleep(delay)
    webbrowser.open(url)


def main():
    parser = argparse.ArgumentParser(
        description=BANNER,
        formatter_class=_HelpFormatter,
    )
    parser.add_argument(
        "--blind",
        action="store_true",
        help="Start server without launching browser (headless / SSH use)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("SPRAYCAN_SERVER_PORT", 8787)),
        help="Port to listen on (default: 8787)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1)",
    )

    from util.headless import add_headless_arguments
    add_headless_arguments(parser)

    args = parser.parse_args()

    if args.headless or args.list_scans:
        from util.headless import run_headless
        try:
            sys.exit(run_headless(args, version=VERSION))
        except KeyboardInterrupt:
            print("\n  [!] Interrupted.")
            sys.exit(130)

    url = "http://%s:%d" % (args.host, args.port)

    print("\n  ⛫💨  SprayCan v%s — Canvas starting..." % VERSION)
    print("  [i] Server: %s" % url)

    if not args.blind:
        t = threading.Thread(target=_open_browser, args=(url,), daemon=True)
        t.start()

    uvicorn.run(
        "server.server:app",
        host=args.host,
        port=args.port,
        reload=False,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
