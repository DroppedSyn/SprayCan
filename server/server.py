import asyncio
import base64
import json
import os
import queue as _queue_mod
import re
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

# Project root is two levels up from server/server.py
sys.path.insert(0, str(Path(__file__).parent.parent))

import util.scan_events as _scan_events
import util.settings as _settings
import util.tokenizer as _tokenizer
from Objects.Core import Core as _Core

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
    from fastapi.staticfiles import StaticFiles
    from pydantic import BaseModel
except ImportError as e:
    print("")
    print("  [!] Missing dependency: %s" % e)
    print("  [!] Have you run the installer?")
    print("")
    print("      python install.py")
    print("")
    sys.exit(1)

ROOT_DIR = Path(__file__).parent.parent
OUTPUT_DIR = ROOT_DIR / "output"
DIST_DIR = ROOT_DIR / "frontend" / "dist"

_droplets: list = []

_scan_state: dict = {
    "running": False,
    "queue": [],
    "current_index": -1,
    "total": 0,
    "scan_name": None,
    "tenant_id": None,
    "started_at": None,
    "error": None,
    "task": None,  # asyncio.Task ref prevents GC mid-run
}
_scan_run_counter = 0  # bumped per run — see util/scan_events.py's generation tagging


@asynccontextmanager
async def _lifespan(app: FastAPI):
    global _droplets
    try:
        core = _Core(str(ROOT_DIR / "Droplets"))
        _RUNNABLE_TYPES = {"scan", "util"}
        _droplets = [d for d in core.droplets if getattr(d, "droplet_type", None) in _RUNNABLE_TYPES]
        print("  [+] Loaded %d scan droplet(s)" % len(_droplets), flush=True)
    except Exception as exc:
        print("  [!] Could not load droplets: %s" % exc, flush=True)
    print("\033[32m  [✓] Canvas started\033[0m", flush=True)
    yield


app = FastAPI(title="SprayCan Canvas", lifespan=_lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:4173",
        "http://127.0.0.1:4173",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Helpers — ported from server/index.mjs
# ---------------------------------------------------------------------------

def _parse_finding_filename(name: str) -> dict:
    match = re.match(r'^([^.]+)\.(.+)\.json$', name, re.IGNORECASE)
    epoch_ms = None
    if match and match.group(1).isdigit():
        epoch_ms = int(match.group(1))
    scan_type = match.group(2) if match else re.sub(r'\.json$', '', name, flags=re.IGNORECASE)
    return {
        "name": name,
        "epochMs": epoch_ms,
        "tenantId": "unknown",
        "dateKey": "unknown",
        "scanType": scan_type,
        "isAggregate": scan_type == "all_scans",
    }


def _format_date_key(value) -> str:
    if value is None:
        return "unknown"
    try:
        if isinstance(value, str):
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        elif isinstance(value, datetime):
            dt = value
        else:
            return "unknown"
        year = str(dt.year)[-2:]
        month = str(dt.month).zfill(2)
        day = str(dt.day).zfill(2)
        return f"{year}_{month}_{day}"
    except (ValueError, AttributeError):
        return "unknown"


def _format_date_key_from_epoch(epoch_ms: int) -> str:
    try:
        dt = datetime.fromtimestamp(epoch_ms / 1000)  # local time so date grouping matches the user's clock
        return _format_date_key(dt)
    except (ValueError, OSError, OverflowError):
        return "unknown"


def _normalize_findings_payload(payload, fallback_scan_name: str = "findings") -> dict:
    if not isinstance(payload, dict):
        payload = {}
    result = dict(payload)
    result["tenant_id"] = payload.get("tenant_id") or "unknown"
    result["generated_at_utc"] = payload.get("generated_at_utc") or None
    result["scan_name"] = payload.get("scan_name") or fallback_scan_name
    findings = payload.get("findings")
    result["findings"] = findings if isinstance(findings, list) else []
    return result


def _count_findings_by_severity(findings: list) -> dict:
    counts: dict = {}
    for f in findings:
        if isinstance(f, dict):
            sev = f.get("severity") or "info"
            counts[sev] = counts.get(sev, 0) + 1
    return counts


def _build_file_metadata(name: str, payload) -> dict:
    parsed = _parse_finding_filename(name)
    normalized = _normalize_findings_payload(payload, parsed["scanType"])
    scan_type = normalized["scan_name"] or parsed["scanType"]
    epoch_ms = parsed["epochMs"]
    date_key = (
        _format_date_key_from_epoch(epoch_ms)
        if epoch_ms is not None
        else _format_date_key(normalized["generated_at_utc"])
    )
    return {
        "name": name,
        "tenantId": normalized["tenant_id"] or "unknown",
        "dateKey": date_key,
        "scanType": scan_type,
        "isAggregate": scan_type == "all_scans",
        "tenantName": normalized.get("tenant_name") or None,
        "generatedAtUtc": normalized["generated_at_utc"],
        "epochMs": epoch_ms,
        "findingCounts": _count_findings_by_severity(normalized["findings"]),
    }


def _load_findings_file_path(file_path: Path) -> dict:
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path.name}")
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_findings_file(file_name: str) -> dict:
    """Load a findings file by name, searching all tenant subdirectories."""
    safe_name = os.path.basename(file_name)
    if OUTPUT_DIR.exists():
        for tenant_dir in OUTPUT_DIR.iterdir():
            if not tenant_dir.is_dir():
                continue
            candidate = tenant_dir / safe_name
            if candidate.exists():
                return _load_findings_file_path(candidate)
    raise FileNotFoundError(f"File not found: {safe_name}")


def _list_finding_files() -> list:
    if not OUTPUT_DIR.exists():
        return []
    result = []
    for entry in OUTPUT_DIR.iterdir():
        if not entry.is_dir():
            continue
        tenant_id = entry.name
        for file_entry in entry.iterdir():
            if not file_entry.is_file() or not file_entry.name.endswith(".json"):
                continue
            try:
                payload = _load_findings_file_path(file_entry)
            except Exception:
                payload = None
            meta = _build_file_metadata(file_entry.name, payload)
            meta["tenantId"] = tenant_id
            meta["filePath"] = str(file_entry.relative_to(ROOT_DIR))
            result.append(meta)
    result.sort(key=lambda f: f.get("epochMs") or 0, reverse=True)
    return result


def _get_latest_aggregate_file(files: list):
    def sort_key(f):
        if f.get("epochMs") is not None:
            return f["epochMs"]
        utc = f.get("generatedAtUtc")
        if utc:
            try:
                return datetime.fromisoformat(utc.replace("Z", "+00:00")).timestamp() * 1000
            except ValueError:
                pass
        return 0

    sorted_files = sorted(files, key=sort_key, reverse=True)
    aggregate = next((f for f in sorted_files if f.get("isAggregate")), None)
    return aggregate or (sorted_files[0] if sorted_files else None)


def _update_tenant_name(tenant_id: str, tenant_name: str):
    if not tenant_id or tenant_id == "unknown":
        raise ValueError("Cannot update tenant name for unknown tenant id")
    tenant_dir = OUTPUT_DIR / tenant_id
    if not tenant_dir.exists():
        return
    for file_entry in tenant_dir.iterdir():
        if not file_entry.is_file() or not file_entry.name.endswith(".json"):
            continue
        payload = _load_findings_file_path(file_entry)
        normalized = _normalize_findings_payload(payload, _parse_finding_filename(file_entry.name)["scanType"])
        normalized["tenant_id"] = tenant_id
        if tenant_name:
            normalized["tenant_name"] = tenant_name
        else:
            normalized.pop("tenant_name", None)
        with open(file_entry, "w", encoding="utf-8") as f:
            json.dump(normalized, f, indent=2)


# ---------------------------------------------------------------------------
# API routes — registered before the SPA catch-all
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health():
    return {"ok": True}


@app.get("/api/files")
async def get_files():
    return _list_finding_files()


# /api/findings/latest MUST be registered before /api/findings/{file_name}
@app.get("/api/findings/latest")
async def get_latest_findings():
    files = _list_finding_files()
    if not files:
        raise HTTPException(status_code=404, detail="No findings files found")
    latest = _get_latest_aggregate_file(files)
    if not latest:
        raise HTTPException(status_code=404, detail="No findings files found")
    try:
        findings = _load_findings_file(latest["name"])
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="No findings files found")
    return {"file": latest["name"], "findings": findings}


@app.get("/api/findings/{file_name:path}")
async def get_findings(file_name: str):
    try:
        findings = _load_findings_file(file_name)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File not found")
    return {"file": file_name, "findings": findings}


@app.delete("/api/findings/{file_name:path}")
async def delete_findings(file_name: str, tenantId: str = ""):
    safe_name = os.path.basename(file_name)
    safe_tenant = os.path.basename(tenantId.strip())
    if not safe_name or not safe_tenant:
        raise HTTPException(status_code=400, detail="tenant ID and file name required")
    try:
        candidate = (OUTPUT_DIR / safe_tenant / safe_name).resolve()
        candidate.relative_to(OUTPUT_DIR.resolve())
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid path")
    if not candidate.exists() or not candidate.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    candidate.unlink()
    return {"ok": True, "files": _list_finding_files()}


class TenantUpdate(BaseModel):
    tenantName: str = ""


@app.post("/api/tenants/{tenant_id:path}")
async def update_tenant(tenant_id: str, body: TenantUpdate):
    try:
        _update_tenant_name(tenant_id, body.tenantName.strip())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _settings.upsert_tenant(tenant_id, body.tenantName.strip())
    files = _list_finding_files()
    return {"ok": True, "files": files, "tenants": _build_tenant_list(files)}


# ---------------------------------------------------------------------------
# Auth state — in-memory per-tenant, reset on server restart
# Note: the MSAL credential cache is shared on disk across tenants.
# These flags track the server session state only.
# ---------------------------------------------------------------------------

_auth_states: dict = {}
_token_sessions: dict = {}  # tenant_id -> {accessToken, refreshToken, tokenType, expiresIn}


def _default_auth_state(tenant_id: str) -> dict:
    return {
        "authMode": "none",
        "isAuthenticated": False,
        "tenantId": tenant_id,
        "tokenType": None,
        "spClientId": None,
        "tokenExpiresAt": None,
    }


def _get_auth_state(tenant_id: str) -> dict:
    if tenant_id not in _auth_states:
        _auth_states[tenant_id] = _default_auth_state(tenant_id)
    return _auth_states[tenant_id]


def _decode_jwt_payload(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        payload += "=" * (4 - len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def _build_tenant_list(files: list) -> list:
    """Merge registered tenants with tenants discovered from output files."""
    registered = {t["id"]: t["name"] for t in _settings.get_tenants()}

    # Count files per tenant
    file_counts: dict = {}
    for f in files:
        tid = f.get("tenantId", "unknown")
        if tid and tid != "unknown":
            file_counts[tid] = file_counts.get(tid, 0) + 1

    all_tenant_ids = set(registered.keys()) | set(file_counts.keys())
    result = []
    for tid in all_tenant_ids:
        auth = _auth_states.get(tid, {})
        result.append({
            "id": tid,
            "name": registered.get(tid, ""),
            "isRegistered": tid in registered,
            "fileCount": file_counts.get(tid, 0),
            "isAuthenticated": auth.get("isAuthenticated", False),
        })

    result.sort(key=lambda t: (not t["isRegistered"], t["name"] or t["id"]))
    return result


# ---------------------------------------------------------------------------
# Tenant endpoints
# ---------------------------------------------------------------------------

@app.get("/api/tenants")
async def get_tenants():
    files = _list_finding_files()
    return _build_tenant_list(files)


class TenantRegisterBody(BaseModel):
    id: str
    name: str = ""


@app.post("/api/tenants")
async def register_tenant(body: TenantRegisterBody):
    tenant_id = body.id.strip()
    if not tenant_id:
        raise HTTPException(status_code=400, detail={"error": "tenant_id_required"})
    _settings.upsert_tenant(tenant_id, body.name.strip())
    files = _list_finding_files()
    return {"ok": True, "tenants": _build_tenant_list(files)}


@app.delete("/api/tenants/{tenant_id:path}")
async def delete_tenant(tenant_id: str):
    tenant_id = tenant_id.strip()
    if not tenant_id:
        raise HTTPException(status_code=400, detail={"error": "tenant_id_required"})
    # Deregister only — output/<tenant_id>/ findings are left untouched, so a tenant
    # that still has files reappears as "discovered" (matches unregistered-but-scanned
    # tenants elsewhere in _build_tenant_list).
    _settings.remove_tenant(tenant_id)
    if _settings.get_current_tenant_id() == tenant_id:
        _settings.set_current_tenant_id(None)
    _tokenizer.clear_sp_credential(tenant_id)
    _tokenizer.clear_stored_access_tokens(tenant_id)
    _tokenizer.clear_device_code_session(tenant_id)
    _auth_states.pop(tenant_id, None)
    _token_sessions.pop(tenant_id, None)
    files = _list_finding_files()
    return {"ok": True, "tenants": _build_tenant_list(files)}


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

@app.get("/api/auth/status")
async def auth_status(tenantId: str = ""):
    if not tenantId:
        return _default_auth_state("")
    return _get_auth_state(tenantId)


class BrowserAuthBody(BaseModel):
    tenantId: str = ""


@app.post("/api/auth/browser")
async def auth_browser(body: BrowserAuthBody):
    tenant_id = body.tenantId.strip()
    if not tenant_id:
        raise HTTPException(status_code=400, detail={"error": "tenant_required"})
    try:
        token = await asyncio.to_thread(_tokenizer.get_graph_token_web, tenant_id)
    except Exception as exc:
        raise HTTPException(status_code=401, detail={"error": "auth_failed", "detail": str(exc)})

    claims = _decode_jwt_payload(token)
    resolved_tenant_id = claims.get("tid") or tenant_id
    _settings.set_current_tenant_id(resolved_tenant_id)

    state = _get_auth_state(resolved_tenant_id)
    state.update({
        "authMode": "browser",
        "isAuthenticated": True,
        "tenantId": resolved_tenant_id,
        "tokenType": None,
        "spClientId": None,
        "tokenExpiresAt": None,
    })
    return state


class DeviceCodeStartBody(BaseModel):
    tenantId: str = ""


@app.post("/api/auth/device-code/start")
async def auth_device_code_start(body: DeviceCodeStartBody):
    tenant_id = body.tenantId.strip()
    if not tenant_id:
        raise HTTPException(status_code=400, detail={"error": "tenant_required"})

    result = await asyncio.to_thread(_tokenizer.begin_device_code_login, tenant_id)
    if result["status"] == "error":
        raise HTTPException(status_code=401, detail={"error": "device_code_failed", "detail": result["error"]})
    return result


@app.get("/api/auth/device-code/status")
async def auth_device_code_status(tenantId: str = ""):
    tenant_id = tenantId.strip()
    if not tenant_id:
        raise HTTPException(status_code=400, detail={"error": "tenant_required"})

    session = _tokenizer.get_device_code_session(tenant_id)
    status = session.get("status")

    if status == "pending":
        return {"status": "pending"}

    if status == "success":
        state = _get_auth_state(tenant_id)
        state.update({
            "authMode": "device_code",
            "isAuthenticated": True,
            "tenantId": tenant_id,
            "tokenType": None,
            "spClientId": None,
            "tokenExpiresAt": None,
        })
        return {"status": "success", "authState": state}

    return {"status": "error", "error": session.get("error") or "Device code sign-in failed."}


class SPAuthBody(BaseModel):
    tenantId: str = ""
    clientId: str = ""
    clientSecret: str = ""


@app.post("/api/auth/sp")
async def auth_sp(body: SPAuthBody):
    tenant_id = body.tenantId.strip()
    client_id = body.clientId.strip()
    client_secret = body.clientSecret.strip()

    if not tenant_id:
        raise HTTPException(status_code=400, detail={"error": "tenant_required"})
    if not client_id or not client_secret:
        raise HTTPException(status_code=400, detail={"error": "credentials_required"})

    # Store credential first, then validate with a test token request
    _tokenizer.store_sp_credential(tenant_id, client_id, client_secret)
    try:
        await asyncio.to_thread(_tokenizer.get_graph_token_sp, tenant_id)
    except Exception as exc:
        _tokenizer.clear_sp_credential(tenant_id)
        raise HTTPException(status_code=401, detail={"error": "auth_failed", "detail": str(exc)})

    state = _get_auth_state(tenant_id)
    state.update({
        "authMode": "sp",
        "isAuthenticated": True,
        "tenantId": tenant_id,
        "spClientId": client_id[:8] + "…",
        "tokenType": None,
        "tokenExpiresAt": None,
    })
    return state


class TokenAuthBody(BaseModel):
    tenantId: str = ""
    token: str = ""
    clientId: str = ""
    scopeHint: str = "graph"  # "graph" or "arm"


@app.post("/api/auth/token")
async def auth_token(body: TokenAuthBody):
    raw_token = body.token.strip()
    tenant_id = body.tenantId.strip()
    client_id = body.clientId.strip() or _tokenizer.DEFAULT_REFRESH_CLIENT_ID
    scope_hint = body.scopeHint.strip().lower()

    if not raw_token:
        raise HTTPException(status_code=400, detail={"error": "token_required"})

    token_type = _tokenizer.classify_token(raw_token)

    if token_type == "likely_refresh_token":
        if not tenant_id:
            raise HTTPException(status_code=400, detail={
                "error": "tenant_required",
                "detail": "Tenant ID is required to exchange a refresh token.",
            })
        scope = (
            f"{_tokenizer.ARM_BASEURL}/{_tokenizer.DEFAULT_SCOPE}"
            if scope_hint == "arm"
            else f"{_tokenizer.GRAPH_BASEURL}/{_tokenizer.DEFAULT_SCOPE}"
        )
        try:
            result = await asyncio.to_thread(
                _tokenizer.exchange_refresh_token, tenant_id, raw_token, client_id, scope
            )
        except Exception as exc:
            raise HTTPException(status_code=401, detail={
                "error": "token_exchange_failed",
                "detail": str(exc),
            })
        access_token = result.get("access_token")
        _token_sessions[tenant_id] = {
            "tokenType": token_type,
            "accessToken": access_token,
            "refreshToken": result.get("refresh_token", raw_token),
            "expiresIn": result.get("expires_in"),
        }
        if access_token:
            _tokenizer.store_access_token(tenant_id, scope_hint, access_token)
    else:
        # Access token — extract tenant from JWT tid claim
        claims = _decode_jwt_payload(raw_token)
        resolved_tenant_id = claims.get("tid") or tenant_id
        if resolved_tenant_id:
            tenant_id = resolved_tenant_id
        _token_sessions[tenant_id or "unknown"] = {
            "tokenType": token_type,
            "accessToken": raw_token,
            "refreshToken": None,
            "expiresIn": None,
        }
        _tokenizer.store_access_token(tenant_id or "unknown", token_type, raw_token)

    state = _get_auth_state(tenant_id)
    state.update({
        "authMode": "token",
        "isAuthenticated": True,
        "tenantId": tenant_id,
        "tokenType": token_type,
        "spClientId": None,
        "tokenExpiresAt": None,
    })
    return state


class LogoutBody(BaseModel):
    tenantId: str = ""


@app.post("/api/auth/logout")
async def auth_logout(body: LogoutBody):
    tenant_id = body.tenantId.strip()
    _tokenizer.clear_sp_credential(tenant_id)
    _tokenizer.reset_browser_credential()
    _tokenizer.clear_stored_access_tokens(tenant_id)
    _tokenizer.clear_device_code_session(tenant_id)
    _token_sessions.pop(tenant_id, None)
    if tenant_id and tenant_id in _auth_states:
        _auth_states[tenant_id] = _default_auth_state(tenant_id)
        return _auth_states[tenant_id]
    return _default_auth_state(tenant_id)


# ---------------------------------------------------------------------------
# Scan endpoints
# ---------------------------------------------------------------------------

@app.get("/api/scans")
async def get_scans():
    return [
        {
            "name": getattr(d, "droplet_name", ""),
            "type": getattr(d, "droplet_type", ""),
            "description": getattr(d, "droplet_description", None) or "",
        }
        for d in _droplets
    ]


class RunScanBody(BaseModel):
    scanQueue: list[str]
    tenantId: str


class VerbosityBody(BaseModel):
    verbosity: str


@app.get("/api/settings/verbosity")
async def get_verbosity():
    return {"verbosity": _settings.get_verbosity()}


@app.post("/api/settings/verbosity")
async def set_verbosity(body: VerbosityBody):
    try:
        _settings.set_verbosity(body.verbosity)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": str(exc)})
    return {"verbosity": _settings.get_verbosity()}


class FrontDoorProbePayloadBody(BaseModel):
    enabled: bool


@app.get("/api/settings/front-door-probe-payload")
async def get_front_door_probe_payload():
    return {"enabled": _settings.get_front_door_probe_payload()}


@app.post("/api/settings/front-door-probe-payload")
async def set_front_door_probe_payload(body: FrontDoorProbePayloadBody):
    _settings.set_front_door_probe_payload(body.enabled)
    return {"enabled": _settings.get_front_door_probe_payload()}


def _run_scan_in_thread(scan_name: str, tenant_id: str, auth_mode: str, generation: int):
    # Set from inside the worker thread itself (not the caller) so this thread's tenant/auth
    # context is isolated via thread-local storage — see util/tokenizer.py's _scan_context.
    _tokenizer.set_scan_context(tenant_id, auth_mode)
    # Same reasoning for scan_events: if this run gets cancelled, this thread keeps running
    # (can't force-kill a Python thread) — tag it so its output doesn't bleed into whatever
    # newer run is now considered "current".
    _scan_events.set_thread_generation(generation)
    core = _Core(str(ROOT_DIR / "Droplets"))
    target = next(
        (d for d in core.droplets if getattr(d, "droplet_name", None) == scan_name),
        None,
    )
    if target is None:
        raise ValueError("Scan not found: %s" % scan_name)
    core.run_droplet(target)


REFRESH_GRAPH_PERMISSIONS_SCAN = "Refresh and update Graph Permissions"


def _start_scan_run(scan_queue: list, tenant_id: str, droplet_map: dict = None):
    """Shared by /api/scans/run and the dedicated maintenance endpoints below.
    `droplet_map` gates against the drag-and-drop catalogue when supplied — pass None for a
    fixed, developer-controlled scan_queue that isn't user-supplied catalogue input."""
    global _scan_run_counter
    if not scan_queue:
        raise HTTPException(status_code=400, detail={"error": "queue_empty"})
    if _scan_state["running"]:
        raise HTTPException(status_code=409, detail={"error": "scan_in_progress"})

    if droplet_map is not None:
        for name in scan_queue:
            if name not in droplet_map:
                raise HTTPException(status_code=404, detail={"error": "scan_not_found", "name": name})

    auth = _get_auth_state(tenant_id)
    if not auth.get("isAuthenticated"):
        raise HTTPException(status_code=401, detail={"error": "auth_required"})

    auth_mode = auth.get("authMode", "none")

    _scan_run_counter += 1
    generation = _scan_run_counter
    _scan_events.set_current_generation(generation)
    _scan_events.clear()

    _scan_state.update({
        "running": True,
        "queue": scan_queue,
        "current_index": -1,
        "total": len(scan_queue),
        "scan_name": None,
        "tenant_id": tenant_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "error": None,
    })

    async def _run():
        failed_scans = []
        total = len(scan_queue)
        try:
            for i, scan_name in enumerate(scan_queue):
                _scan_state["current_index"] = i
                _scan_state["scan_name"] = scan_name
                _scan_events.emit("queue_start", json.dumps({"index": i, "total": total, "name": scan_name}))
                try:
                    await asyncio.to_thread(_run_scan_in_thread, scan_name, tenant_id, auth_mode, generation)
                    _scan_events.emit("queue_done", json.dumps({"index": i, "name": scan_name}))
                except Exception as exc:
                    failed_scans.append(scan_name)
                    _scan_state["error"] = str(exc)
                    _scan_events.emit("scan_error", "[!] %s failed: %s" % (scan_name, exc))
            _scan_events.emit("complete", "")
        except asyncio.CancelledError:
            _scan_events.emit("cancelled", "")
        finally:
            _scan_state["running"] = False

    task = asyncio.create_task(_run())
    _scan_state["task"] = task
    return {"ok": True, "queue": scan_queue}


@app.post("/api/scans/run")
async def run_scan(body: RunScanBody):
    scan_queue = [name.strip() for name in body.scanQueue if name.strip()]
    tenant_id = body.tenantId.strip()
    droplet_map = {getattr(d, "droplet_name", ""): d for d in _droplets}
    return _start_scan_run(scan_queue, tenant_id, droplet_map)


class RefreshGraphPermissionsBody(BaseModel):
    tenantId: str = ""


@app.post("/api/scans/refresh-graph-permissions")
async def refresh_graph_permissions(body: RefreshGraphPermissionsBody):
    tenant_id = body.tenantId.strip()
    return _start_scan_run([REFRESH_GRAPH_PERMISSIONS_SCAN], tenant_id)


@app.post("/api/scans/cancel")
async def cancel_scan():
    if not _scan_state["running"]:
        raise HTTPException(status_code=409, detail={"error": "no_scan_running"})
    task = _scan_state.get("task")
    if task and not task.done():
        task.cancel()
    return {"ok": True}


@app.get("/api/scans/status")
async def scan_status():
    async def _stream():
        loop = asyncio.get_running_loop()
        last_sent = loop.time()
        KEEPALIVE_INTERVAL = 15.0
        while True:
            try:
                event = _scan_events.get_nowait()
                yield "data: %s\n\n" % json.dumps(event)
                last_sent = loop.time()
                if event.get("type") in ("complete", "error", "cancelled"):
                    return
            except _queue_mod.Empty:
                if not _scan_state["running"]:
                    # Scan finished — drain any events that arrived just before running=False
                    await asyncio.sleep(0.05)
                    while True:
                        try:
                            event = _scan_events.get_nowait()
                            yield "data: %s\n\n" % json.dumps(event)
                            if event.get("type") in ("complete", "error", "cancelled"):
                                return
                        except _queue_mod.Empty:
                            # No terminal event arrived — synthesise one so the
                            # client always gets a clean close, not an onerror.
                            if _scan_state.get("error"):
                                yield "data: %s\n\n" % json.dumps({"type": "error", "text": _scan_state["error"]})
                            else:
                                yield "data: %s\n\n" % json.dumps({"type": "complete", "text": _scan_state.get("scan_name", "")})
                            return
                now = loop.time()
                if now - last_sent >= KEEPALIVE_INTERVAL:
                    yield ": ping\n\n"
                    last_sent = now
                await asyncio.sleep(0.05)

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ---------------------------------------------------------------------------
# CSV download — serves files from output/ by relative path
# ---------------------------------------------------------------------------

@app.get("/api/csv")
async def download_csv(path: str = ""):
    if not path:
        raise HTTPException(status_code=400, detail="path required")
    try:
        candidate = (OUTPUT_DIR / path).resolve()
        candidate.relative_to(OUTPUT_DIR.resolve())
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid path")
    if not candidate.exists() or not candidate.is_file():
        raise HTTPException(status_code=404, detail="file not found")
    return FileResponse(
        str(candidate),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="%s"' % candidate.name},
    )


# ---------------------------------------------------------------------------
# SPA — serve pre-built React frontend from frontend/dist/
# Registered last so all /api/* routes take priority
# ---------------------------------------------------------------------------

if DIST_DIR.exists() and (DIST_DIR / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(DIST_DIR / "assets")), name="assets")


@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    if not DIST_DIR.exists():
        return JSONResponse(
            status_code=503,
            content={"error": "Frontend not built. Run: python install.py"},
        )
    # Serve specific static files that exist in dist root (favicon, manifest, etc.)
    # Resolve and verify containment to prevent path traversal (e.g. ../../server.py).
    if full_path:
        try:
            candidate = (DIST_DIR / full_path).resolve()
            candidate.relative_to(DIST_DIR.resolve())
            if candidate.is_file():
                return FileResponse(str(candidate))
        except ValueError:
            pass  # path escapes dist/ — fall through to index.html
    index = DIST_DIR / "index.html"
    if not index.exists():
        return JSONResponse(
            status_code=503,
            content={"error": "Frontend not built. Run: python install.py"},
        )
    return FileResponse(str(index))
