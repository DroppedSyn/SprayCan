"""Headless CLI scan runner — run scans from the command line without Canvas.

Invoked via SprayCan.py --headless (see add_headless_arguments/run_headless).
Browser-mode auth is intentionally not offered here — it requires a local
browser on this machine, which defeats the point of running headless.
"""

import os
import time

import util.console as console
import util.tokenizer as tokenizer
from Objects.Core import Core
from util.paths import PROJECT_ROOT

DROPLETS_DIR = os.path.join(PROJECT_ROOT, "Droplets")

_AUTH_MODE_TO_SCAN_CONTEXT = {
    "sp": "sp",
    "token": "token",
    "device-code": "device_code",
}


def add_headless_arguments(parser):
    group = parser.add_argument_group(
        "Headless mode (run scans from the command line, no Canvas)"
    )
    group.add_argument(
        "--headless",
        action="store_true",
        help="Run scans directly from the command line and exit — does not start Canvas.",
    )
    group.add_argument(
        "--tenant",
        type=str,
        default=None,
        help="Tenant ID to scan (required with --headless).",
    )
    group.add_argument(
        "--auth-mode",
        choices=["sp", "token", "device-code"],
        default=None,
        help="Authentication method (required with --headless). Browser mode is not available headless.",
    )
    group.add_argument("--sp-client-id", type=str, default=None, help="Service principal client ID (sp mode).")
    group.add_argument(
        "--sp-client-secret",
        type=str,
        default=None,
        help="Service principal client secret (sp mode). Falls back to SPRAYCAN_SP_CLIENT_SECRET env var.",
    )
    group.add_argument(
        "--graph-token",
        type=str,
        default=None,
        help="Raw Graph access token (token mode). Falls back to SPRAYCAN_GRAPH_TOKEN env var.",
    )
    group.add_argument(
        "--arm-token",
        type=str,
        default=None,
        help="Raw ARM access token (token mode). Falls back to SPRAYCAN_ARM_TOKEN env var.",
    )
    group.add_argument(
        "--scan",
        action="append",
        dest="scans",
        default=None,
        metavar="NAME_OR_NUMBER",
        help='Scan to run, repeatable: a number from --list-scans, "all", or an exact '
        'droplet name, e.g. --scan 3 --scan 7, or --scan "Scan: PIM State Checks".',
    )
    group.add_argument(
        "--all-scans",
        action="store_true",
        help="Run every catalogued scan droplet. Equivalent to --scan all.",
    )
    group.add_argument(
        "--list-scans",
        action="store_true",
        help="List available scans, numbered for use with --scan, and exit — no tenant/auth required.",
    )
    return parser


def _get_scan_catalogue(core):
    """Scan-type droplets in the same stable order used for --list-scans numbering
    and numeric --scan lookups — sorted by name so numbers stay consistent across
    separate invocations as long as the droplet set hasn't changed."""
    scans = [d for d in core.droplets if getattr(d, "droplet_type", None) == "scan"]
    return sorted(scans, key=lambda d: getattr(d, "droplet_name", ""))


def _list_scans():
    core = Core(DROPLETS_DIR)
    catalogue = _get_scan_catalogue(core)
    width = len(str(len(catalogue)))
    print("\n  Available scans:\n")
    for i, droplet in enumerate(catalogue, start=1):
        print("    %s  %s" % (str(i).rjust(width), getattr(droplet, "droplet_name", "")))
    print('\n  Use --scan <number> (repeatable), --scan all, or --all-scans.\n')


def _resolve_secret(cli_value, env_var):
    if cli_value:
        return cli_value
    return os.environ.get(env_var, "").strip() or None


def _authenticate(tenant_id, auth_mode, args):
    if auth_mode == "sp":
        client_id = args.sp_client_id
        client_secret = _resolve_secret(args.sp_client_secret, "SPRAYCAN_SP_CLIENT_SECRET")
        if not client_id or not client_secret:
            console.error(
                "[!] --auth-mode sp requires --sp-client-id and --sp-client-secret "
                "(or SPRAYCAN_SP_CLIENT_SECRET)."
            )
            return False
        tokenizer.store_sp_credential(tenant_id, client_id, client_secret)
        try:
            tokenizer.get_graph_token_sp(tenant_id)
        except Exception as exc:
            tokenizer.clear_sp_credential(tenant_id)
            console.error("[!] SP authentication failed: %s" % exc)
            return False
        console.success("[✓] Authenticated via Service Principal.")
        return True

    if auth_mode == "token":
        graph_token = _resolve_secret(args.graph_token, "SPRAYCAN_GRAPH_TOKEN")
        arm_token = _resolve_secret(args.arm_token, "SPRAYCAN_ARM_TOKEN")
        if not graph_token and not arm_token:
            console.error(
                "[!] --auth-mode token requires --graph-token and/or --arm-token "
                "(or SPRAYCAN_GRAPH_TOKEN / SPRAYCAN_ARM_TOKEN)."
            )
            return False
        if graph_token:
            tokenizer.store_access_token(tenant_id, "graph", graph_token)
        if arm_token:
            tokenizer.store_access_token(tenant_id, "arm", arm_token)
        console.success("[✓] Token(s) registered.")
        return True

    if auth_mode == "device-code":
        result = tokenizer.begin_device_code_login(tenant_id)
        if result["status"] == "error":
            console.error("[!] Could not start device code sign-in: %s" % result.get("error"))
            return False
        print("\n  [i] Go to %s" % result["verificationUri"])
        print("  [i] Enter code: %s\n" % result["userCode"])
        console.info("[i] Waiting for you to complete sign-in...")
        while True:
            session = tokenizer.get_device_code_session(tenant_id)
            status = session.get("status")
            if status == "success":
                console.success("[✓] Signed in.")
                return True
            if status == "error":
                console.error("[!] Device code sign-in failed: %s" % session.get("error"))
                return False
            time.sleep(2)

    console.error("[!] Unknown auth mode: %s" % auth_mode)
    return False


def run_headless(args, version="") -> int:
    if args.list_scans:
        _list_scans()
        return 0

    if not args.tenant:
        console.error("[!] --headless requires --tenant.")
        return 2
    if not args.auth_mode:
        console.error("[!] --headless requires --auth-mode {sp,token,device-code}.")
        return 2
    if args.all_scans and args.scans:
        console.error("[!] --all-scans and --scan are mutually exclusive.")
        return 2
    if not args.all_scans and not args.scans:
        console.error("[!] Specify --scan (number, name, or 'all' — repeatable) or --all-scans.")
        return 2

    core = Core(DROPLETS_DIR)
    catalogue = _get_scan_catalogue(core)
    droplet_map = {getattr(d, "droplet_name", ""): d for d in core.droplets}

    wants_all = args.all_scans or any(s.strip().lower() == "all" for s in (args.scans or []))

    if wants_all:
        queue = catalogue
        if not queue:
            console.error("[!] No scan droplets found.")
            return 1
    else:
        queue = []
        for raw in args.scans:
            value = raw.strip()
            if value.isdigit():
                index = int(value)
                if not (1 <= index <= len(catalogue)):
                    console.error(
                        "[!] Invalid scan number: %s (valid range: 1-%d, see --list-scans)"
                        % (value, len(catalogue))
                    )
                    return 2
                queue.append(catalogue[index - 1])
                continue
            droplet = droplet_map.get(value)
            if droplet is None:
                console.error("[!] Unknown scan: %s (see --list-scans)" % value)
                return 2
            queue.append(droplet)

    if not _authenticate(args.tenant, args.auth_mode, args):
        return 1

    # Only set (and persist to settings.json) once auth has actually succeeded — a failed
    # attempt shouldn't silently repoint Canvas's "current tenant" at an unauthenticated tenant.
    tokenizer.set_scan_context(args.tenant, _AUTH_MODE_TO_SCAN_CONTEXT[args.auth_mode])

    print("\n  ⛫💨  SprayCan %s— headless run" % (("v%s " % version) if version else ""))
    print("  [i] Tenant: %s" % args.tenant)
    print("  [i] Auth mode: %s" % args.auth_mode)
    print("  [i] Queue: %d scan(s)\n" % len(queue))

    failed = []
    for droplet in queue:
        name = getattr(droplet, "droplet_name", droplet.__class__.__name__)
        try:
            core.run_droplet(droplet)
        except KeyboardInterrupt:
            raise
        except Exception:
            # run_droplet() already printed the error and error-log path.
            failed.append(name)

    print()
    if failed:
        console.error("[!] %d of %d scan(s) failed:" % (len(failed), len(queue)))
        for name in failed:
            console.error("    - %s" % name)
        return 1

    console.success("[✓] All %d scan(s) completed." % len(queue))
    return 0
