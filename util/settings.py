import json
import os
import threading

from util.paths import PROJECT_ROOT

SETTINGS_FILE = os.path.join(PROJECT_ROOT, "settings.json")
LEGACY_TENANT_CACHE_FILE = os.path.join(PROJECT_ROOT, "tenant_id_cache.json")
DEFAULT_SETTINGS = {
    "tenant_id": None,
    "verbosity": "normal",
    "tenants": [],
    "front_door_probe_payload": False,
}
VALID_VERBOSITY_MODES = {"quiet", "normal", "debug"}

# Guards every read-modify-write cycle below. server.py runs droplets in worker threads that
# each touch settings.json (set_scan_context -> set_current_tenant_id) concurrently with the
# main thread's own settings writes (tenant register/rename/delete, verbosity). Without this,
# a read racing another thread's write can observe a just-truncated/empty file (a bare open(…,
# "w") truncates before writing) and silently fall back to DEFAULT_SETTINGS below — if that
# corrupted snapshot is then itself saved, it permanently wipes real data.
_lock = threading.Lock()


def get_settings_file_path():
    return SETTINGS_FILE


def _load_settings_locked():
    settings = dict(DEFAULT_SETTINGS)

    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as settings_file:
                loaded_settings = json.load(settings_file)
                if isinstance(loaded_settings, dict):
                    settings.update(loaded_settings)
        except (OSError, ValueError):
            pass
    elif os.path.exists(LEGACY_TENANT_CACHE_FILE):
        try:
            with open(LEGACY_TENANT_CACHE_FILE, "r", encoding="utf-8") as legacy_file:
                legacy_settings = json.load(legacy_file)
                if isinstance(legacy_settings, dict) and legacy_settings.get("tenant_id"):
                    settings["tenant_id"] = legacy_settings["tenant_id"]
                    _save_settings_locked(settings)
        except (OSError, ValueError):
            pass

    if settings.get("verbosity") not in VALID_VERBOSITY_MODES:
        settings["verbosity"] = DEFAULT_SETTINGS["verbosity"]

    return settings


def _save_settings_locked(settings):
    merged_settings = dict(DEFAULT_SETTINGS)
    merged_settings.update(settings or {})
    if merged_settings.get("verbosity") not in VALID_VERBOSITY_MODES:
        merged_settings["verbosity"] = DEFAULT_SETTINGS["verbosity"]

    # Write to a temp file and atomically rename it over the target — os.replace() is atomic
    # on POSIX and Windows, so any reader (even one outside this process/lock) always sees
    # either the complete old file or the complete new one, never a truncated one.
    tmp_path = "%s.tmp-%d" % (SETTINGS_FILE, os.getpid())
    with open(tmp_path, "w", encoding="utf-8") as settings_file:
        json.dump(merged_settings, settings_file, indent=4)
    os.replace(tmp_path, SETTINGS_FILE)

    return merged_settings


def load_settings():
    with _lock:
        return _load_settings_locked()


def save_settings(settings):
    with _lock:
        return _save_settings_locked(settings)


def get_setting(key, default=None):
    with _lock:
        return _load_settings_locked().get(key, default)


def set_setting(key, value):
    with _lock:
        settings = _load_settings_locked()
        settings[key] = value
        return _save_settings_locked(settings)


def get_tenants():
    """Return registered tenants list: [{id, name}]"""
    return get_setting("tenants", [])


def upsert_tenant(tenant_id: str, name: str = ""):
    """Register or rename a tenant in the registry."""
    with _lock:
        settings = _load_settings_locked()
        tenants = settings.get("tenants", [])
        for tenant in tenants:
            if tenant["id"] == tenant_id:
                tenant["name"] = name
                break
        else:
            tenants.append({"id": tenant_id, "name": name})
        settings["tenants"] = tenants
        _save_settings_locked(settings)
        return tenants


def remove_tenant(tenant_id: str):
    """Remove a tenant from the registry."""
    with _lock:
        settings = _load_settings_locked()
        tenants = [t for t in settings.get("tenants", []) if t["id"] != tenant_id]
        settings["tenants"] = tenants
        _save_settings_locked(settings)
        return tenants


def get_current_tenant_id():
    return get_setting("tenant_id")


def set_current_tenant_id(tenant_id):
    return set_setting("tenant_id", tenant_id)


def get_verbosity():
    return get_setting("verbosity", DEFAULT_SETTINGS["verbosity"])


def set_verbosity(mode):
    normalized_mode = str(mode or "").strip().lower()
    if normalized_mode not in VALID_VERBOSITY_MODES:
        raise ValueError("Invalid verbosity mode: %s" % mode)
    return set_setting("verbosity", normalized_mode)


def get_front_door_probe_payload():
    # Off by default: this sends an XSS-looking test string straight at customer-owned
    # production origins, which is far more likely than a plain reachability probe to trip
    # a WAF/IDS and get the scanning IP flagged or blocked. Opt-in only.
    return bool(get_setting("front_door_probe_payload", DEFAULT_SETTINGS["front_door_probe_payload"]))


def set_front_door_probe_payload(enabled):
    return set_setting("front_door_probe_payload", bool(enabled))
