import base64
import json
import threading
import uuid

import azure.identity
from azure.identity import CredentialUnavailableError
import requests

import util.console as console
import util.settings as settings

# Default client ID used for refresh token exchange (Microsoft Azure PowerShell public client)
DEFAULT_REFRESH_CLIENT_ID = "1950a258-227b-4e31-a9cf-717495945fc2"

# Timeout (seconds) given to the user to complete browser auth flow in web mode.
_WEB_AUTH_TIMEOUT = 120

ARM_BASEURL = 'https://management.azure.com'
ARM_CLASSIC_BASEURL = 'https://management.core.windows.net/'
GRAPH_BASEURL = 'https://graph.microsoft.com'
DEFAULT_SCOPE = '.default'

browser_credential = azure.identity.InteractiveBrowserCredential(
    additionally_allowed_tenants=['*'],
)


def build_device_code_credential():
    return azure.identity.DeviceCodeCredential(
        tenant_id=get_current_tenant_id(),
        additionally_allowed_tenants=['*'],
        cache_persistence_options=azure.identity.TokenCachePersistenceOptions(
            name="spraycan",
            allow_unencrypted_storage=True,
        ),
    )


# ---------------------------------------------------------------------------
# Device code auth — web-safe, no local browser required on the SprayCan host.
# DeviceCodeCredential.get_token() blocks for up to ~15 minutes waiting for the
# user to complete sign-in elsewhere, so it runs in a background thread; the
# thread's prompt_callback fills in the session dict as soon as the code is
# issued (a couple seconds), letting the request handler return immediately
# while polling for completion happens via get_device_code_session().
# ---------------------------------------------------------------------------

_device_code_sessions: dict = {}  # tenant_id -> session dict


def _run_device_code_flow(tenant_id: str, session_id: str):
    session = _device_code_sessions.get(tenant_id)
    if session is None or session.get("id") != session_id:
        return  # superseded by a retry before this thread even started

    def _on_prompt(verification_uri, user_code, expires_on):
        session["verificationUri"] = verification_uri
        session["userCode"] = user_code
        session["expiresOn"] = expires_on.isoformat()
        session["codeReady"].set()

    def _is_current():
        # An abandoned attempt (e.g. one that timed out waiting for its code) that succeeds
        # late shouldn't clobber the tokens from a newer attempt the user actually completed.
        current = _device_code_sessions.get(tenant_id)
        return current is not None and current.get("id") == session_id

    try:
        credential = azure.identity.DeviceCodeCredential(
            tenant_id=tenant_id,
            additionally_allowed_tenants=["*"],
            prompt_callback=_on_prompt,
        )
        # Graph first — this is the call that actually issues the device code and blocks for
        # the user to complete sign-in. Store it as soon as it succeeds: a user with Graph
        # consent but no Azure RBAC role on any subscription (a common split) shouldn't be
        # locked out of Device Code sign-in entirely just because the ARM fetch below fails.
        graph_token = credential.get_token(f"{GRAPH_BASEURL}/{DEFAULT_SCOPE}", tenant_id=tenant_id).token
        if _is_current():
            store_access_token(tenant_id, "graph", graph_token)

        # Reuses the same credential instance so MSAL's cache makes this silent — no second code.
        try:
            arm_token = credential.get_token(f"{ARM_BASEURL}/{DEFAULT_SCOPE}", tenant_id=tenant_id).token
        except Exception:
            arm_token = None
        if arm_token and _is_current():
            store_access_token(tenant_id, "arm", arm_token)

        session["status"] = "success"
    except Exception as exc:
        session["status"] = "error"
        session["error"] = str(exc)
    finally:
        session["codeReady"].set()


def begin_device_code_login(tenant_id: str) -> dict:
    """Starts a device code flow in the background; returns the code info once issued."""
    session_id = uuid.uuid4().hex
    session = {
        "id": session_id,
        "status": "pending",
        "codeReady": threading.Event(),
        "verificationUri": None,
        "userCode": None,
        "expiresOn": None,
        "error": None,
    }
    _device_code_sessions[tenant_id] = session

    thread = threading.Thread(target=_run_device_code_flow, args=(tenant_id, session_id), daemon=True)
    thread.start()

    if not session["codeReady"].wait(timeout=30):
        return {"status": "error", "error": "Timed out starting device code sign-in."}
    if session["status"] == "error":
        return {"status": "error", "error": session["error"]}
    if session["status"] == "success":
        return {"status": "success"}
    return {
        "status": "pending",
        "verificationUri": session["verificationUri"],
        "userCode": session["userCode"],
        "expiresOn": session["expiresOn"],
    }


def get_device_code_session(tenant_id: str) -> dict:
    return _device_code_sessions.get(tenant_id, {"status": "error", "error": "No device code session for tenant."})


def get_token_for_scope(scope):
    try:
        return browser_credential.get_token(scope, tenant_id=get_current_tenant_id(), timeout=30).token
    except CredentialUnavailableError:
        console.info("[i] Browser auth unavailable, falling back to device code.")
        return build_device_code_credential().get_token(scope, timeout=30).token


# ---------------------------------------------------------------------------
# Scan auth context — set via set_scan_context() before each scan run.
# Routes get_arm_token()/get_graph_token() to the right credential type.
#
# Thread-local by design: the server calls set_scan_context() from inside the
# worker thread that's about to run a droplet (server.py's _run_scan_in_thread),
# not from the main event-loop thread. A cancelled scan's droplet thread can't
# be force-killed and may keep running in the background (see server.py's
# cancel endpoint) — thread-local storage means that orphaned thread keeps
# reading its OWN tenant/auth context even if a newer scan for a different
# tenant starts concurrently on another thread; a shared global would let the
# newer scan's context silently leak into the orphaned one's credential calls.
# ---------------------------------------------------------------------------

_scan_context = threading.local()
_stored_access_tokens: dict = {}  # tenant_id -> {"graph": token, "arm": token}


def set_scan_context(tenant_id: str, auth_mode: str):
    """Called from the worker thread that's about to run a droplet, so each
    concurrently-executing thread has its own isolated view of which tenant/mode
    it's serving."""
    _scan_context.auth_mode = auth_mode
    _scan_context.tenant_id = tenant_id
    settings.set_current_tenant_id(tenant_id)


def _get_scan_auth_mode() -> str:
    return getattr(_scan_context, "auth_mode", "none")


def _get_scan_tenant_id() -> str:
    return getattr(_scan_context, "tenant_id", "")


def store_access_token(tenant_id: str, token_type: str, token_value: str):
    """Persist a raw access token so token-mode scans can use it."""
    if tenant_id not in _stored_access_tokens:
        _stored_access_tokens[tenant_id] = {}
    if token_type in ("graph", "graph_access_token", "unknown_jwt"):
        _stored_access_tokens[tenant_id]["graph"] = token_value
    elif token_type in ("arm", "arm_access_token"):
        _stored_access_tokens[tenant_id]["arm"] = token_value


def clear_stored_access_tokens(tenant_id: str):
    """Drop any Token/Device Code tokens held for this tenant (called on logout so a
    stale token from one auth mode can't silently leak into a different one)."""
    _stored_access_tokens.pop(tenant_id, None)


def clear_device_code_session(tenant_id: str):
    _device_code_sessions.pop(tenant_id, None)


def get_arm_token():
    auth_mode = _get_scan_auth_mode()
    tid = _get_scan_tenant_id() or settings.get_current_tenant_id()
    if auth_mode == "sp":
        return get_arm_token_sp(tid)
    if auth_mode in ("token", "device_code"):
        tok = _stored_access_tokens.get(tid, {}).get("arm")
        if tok:
            return tok
        raise RuntimeError(
            "No ARM access token for tenant %s — re-authenticate (Token, Device Code, or SP)." % tid
        )
    # browser mode — web-safe, no input() fallback
    return get_arm_token_web(tid)


def get_graph_token():
    auth_mode = _get_scan_auth_mode()
    tid = _get_scan_tenant_id() or settings.get_current_tenant_id()
    if auth_mode == "sp":
        return get_graph_token_sp(tid)
    if auth_mode in ("token", "device_code"):
        tok = _stored_access_tokens.get(tid, {}).get("graph")
        if tok:
            return tok
        raise RuntimeError(
            "No Graph access token for tenant %s — re-authenticate (Token, Device Code, or SP)." % tid
        )
    # browser mode — web-safe, no input() fallback
    return get_graph_token_web(tid)

def set_new_tenant_id():
    valid_uuid = False
    tenant_id = None
    while not valid_uuid:
        tenant_id = console.prompt('[i] Please provide Tenant ID to log into: ')
        valid_uuid = validate_tennant_id(tenant_id)
    if tenant_id is not None:
        write_tenant_id_to_cache(tenant_id)
        return tenant_id
    else:
        console.error("[!] How did you get here?")
        exit(1)

def validate_tennant_id(tenant_id):
    try:
        # check for validity of Uuid
        throwaway_uuid_obj = uuid.UUID(tenant_id, version=4)
    except ValueError:
        console.error("[!] \"%s\" is not a valid tenant id. Please try again." % tenant_id)
        return False
    return True

def get_current_tenant_id():
    # When a scan is running, return the scan's tenant rather than reading settings.json —
    # concurrent auth flows can update settings mid-scan and misdirect output files.
    scan_tenant_id = _get_scan_tenant_id()
    if scan_tenant_id:
        return scan_tenant_id
    tenant_id = settings.get_current_tenant_id()
    if tenant_id:
        return tenant_id
    return set_new_tenant_id()


def write_tenant_id_to_cache(tenant_id):
    settings.set_current_tenant_id(tenant_id)
    return tenant_id


# ---------------------------------------------------------------------------
# Web-safe auth — no input(), no DeviceCode fallback.
# These are called from FastAPI request handlers (async context).
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Token classification and refresh exchange
# ---------------------------------------------------------------------------

def classify_token(token: str) -> str:
    """Classify a raw token string.

    Returns one of:
      arm_access_token   — JWT with management.azure.com audience
      graph_access_token — JWT with graph.microsoft.com audience
      unknown_jwt        — JWT with unrecognised audience
      likely_refresh_token — opaque string (not a JWT)
    """
    parts = token.strip().split(".")
    if len(parts) == 3:
        try:
            payload = parts[1]
            payload += "=" * (4 - len(payload) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload))
            aud = str(claims.get("aud", ""))
            if "management.azure.com" in aud:
                return "arm_access_token"
            if "graph.microsoft.com" in aud:
                return "graph_access_token"
            return "unknown_jwt"
        except Exception:
            pass
    return "likely_refresh_token"


def exchange_refresh_token(
    tenant_id: str,
    refresh_token: str,
    client_id: str = DEFAULT_REFRESH_CLIENT_ID,
    scope: str = f"{GRAPH_BASEURL}/{DEFAULT_SCOPE}",
) -> dict:
    """Exchange a refresh token for a new access token.

    Returns the full token response dict including the new access_token,
    refresh_token (rotated), and expires_in. Raises RuntimeError on failure.
    """
    url = "https://login.microsoftonline.com/%s/oauth2/v2.0/token" % tenant_id
    resp = requests.post(url, data={
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "scope": scope,
    }, timeout=30)
    result = resp.json()
    if "error" in result:
        raise RuntimeError("%s: %s" % (
            result.get("error"),
            result.get("error_description", "Token exchange failed"),
        ))
    return result


# ---------------------------------------------------------------------------
# Service Principal auth — in-memory credentials, per-tenant
# ---------------------------------------------------------------------------

_sp_credentials: dict = {}  # tenant_id -> ClientSecretCredential


def store_sp_credential(tenant_id: str, client_id: str, client_secret: str):
    """Build and cache a ClientSecretCredential for this tenant."""
    cred = azure.identity.ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )
    _sp_credentials[tenant_id] = cred
    return cred


def clear_sp_credential(tenant_id: str):
    _sp_credentials.pop(tenant_id, None)


def get_graph_token_sp(tenant_id: str) -> str:
    """Return a Graph token using the cached SP credential. Raises RuntimeError on failure."""
    cred = _sp_credentials.get(tenant_id)
    if not cred:
        raise RuntimeError("No SP credential registered for tenant %s" % tenant_id)
    try:
        return cred.get_token(f"{GRAPH_BASEURL}/{DEFAULT_SCOPE}").token
    except Exception as exc:
        raise RuntimeError("SP auth failed: %s" % exc) from exc


def get_arm_token_sp(tenant_id: str) -> str:
    """Return an ARM token using the cached SP credential. Raises RuntimeError on failure."""
    cred = _sp_credentials.get(tenant_id)
    if not cred:
        raise RuntimeError("No SP credential registered for tenant %s" % tenant_id)
    try:
        return cred.get_token(f"{ARM_BASEURL}/{DEFAULT_SCOPE}").token
    except Exception as exc:
        raise RuntimeError("SP auth failed: %s" % exc) from exc


def get_graph_token_web(tenant_id=None):
    """Return a Graph access token without any interactive CLI prompts.

    Uses the cached browser credential if a valid token already exists.
    Opens a browser window otherwise. Never calls input().
    Raises RuntimeError on failure.
    """
    tid = tenant_id or settings.get_current_tenant_id()
    try:
        return browser_credential.get_token(
            f"{GRAPH_BASEURL}/{DEFAULT_SCOPE}",
            tenant_id=tid,
            timeout=_WEB_AUTH_TIMEOUT,
        ).token
    except Exception as exc:
        raise RuntimeError("Browser auth failed: %s" % exc) from exc


def get_arm_token_web(tenant_id=None):
    """Return an ARM access token without any interactive CLI prompts."""
    tid = tenant_id or settings.get_current_tenant_id()
    try:
        return browser_credential.get_token(
            f"{ARM_BASEURL}/{DEFAULT_SCOPE}",
            tenant_id=tid,
            timeout=_WEB_AUTH_TIMEOUT,
        ).token
    except Exception as exc:
        raise RuntimeError("Browser auth failed: %s" % exc) from exc


def reset_browser_credential():
    """Replace the browser credential with a fresh in-memory instance (logout)."""
    global browser_credential
    browser_credential = azure.identity.InteractiveBrowserCredential(
        additionally_allowed_tenants=["*"],
    )
