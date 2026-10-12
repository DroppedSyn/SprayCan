import json
import re

from Objects.Core import make_finding, make_object

# ──────────────────────────────────────────────────────────────────────────────
# Rule module for the Logic / Function App scanner droplet.
#
# Rules come in two flavours, registered in the lists at the bottom of this file:
#
#   SCAN_RULES       — per-record functions: (record, droplet_name) → [Finding]
#                      Called once per collected app. Use for findings that are
#                      inherently per-resource (e.g. embedded credentials where
#                      the matched snippets differ app-to-app).
#
#   BATCH_SCAN_RULES — batch functions: (records, droplet_name) → [Finding]
#                      Receive the full list of collected apps at once and emit
#                      one consolidated finding per check. Use for findings where
#                      a single "table of all affected apps" card is more useful
#                      than N individual cards.
# ──────────────────────────────────────────────────────────────────────────────


# ── Credential detection ──────────────────────────────────────────────────────

# Key-name substrings that warrant a closer look at the associated value.
SECRET_PATTERNS = [
    "password",
    "secret",
    "client_secret",
    "connectionstring",
    "connection_string",
    "accountkey",
    "accesskey",
    "api_key",
    "apikey",
    "token",
    "sas",
    "authorization",
]

# Regex patterns run against raw text blobs (JSON strings, env vars, etc.) to
# catch connection strings and bearer tokens that would not surface via
# key-name matching alone.
RAW_SECRET_VALUE_PATTERNS = [
    re.compile(r"defaultendpointsprotocol=.*?accountkey=", re.IGNORECASE),
    re.compile(r"sharedaccesssignature=", re.IGNORECASE),
    re.compile(r"accountkey=", re.IGNORECASE),
    re.compile(r"clientsecret[\s\"':=]+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
    re.compile(r"authorization[\s\"':=]+bearer\s+[A-Za-z0-9._~+/=-]{12,}", re.IGNORECASE),
]


# ── Finding / evidence helpers ────────────────────────────────────────────────

def build_parent_object(record):
    attrs = {}
    if record.get("platform") == "functionApp":
        attrs["client_cert_mode"] = record.get("client_cert_mode")
    return make_object(record["platform"], record.get("id"), record.get("name"), **attrs)


def build_base_evidence(record):
    evidence = {
        "platform": record.get("platform"),
        "resource_name": record.get("name"),
        "resource_id": record.get("id"),
        "subscription_name": record.get("subscription_name"),
        "resource_group": record.get("resource_group"),
        "region": record.get("region"),
    }
    if record.get("platform") == "functionApp":
        evidence.update(
            {
                "https_only": record.get("https_only"),
                "http_version": record.get("http_version"),
                "minimum_inbound_tls_version": record.get("minimum_inbound_tls_version"),
                "client_certificate_mode": record.get("client_cert_mode"),
            }
        )
    return evidence


def build_trigger_object(trigger):
    return make_object(
        "trigger",
        trigger.get("id") or trigger.get("name"),
        trigger.get("name"),
        trigger_type=trigger.get("type"),
        trigger_kind=trigger.get("kind"),
        auth_mode=trigger.get("auth_mode"),
        externally_accessible=trigger.get("external_access"),
    )


# ── Secret value filtering ────────────────────────────────────────────────────

def normalize_secret_value(value):
    if isinstance(value, str):
        return value.strip()
    return value


def is_benign_secret_value(value):
    """
    Returns True if the value is a placeholder, reference, or identifier rather
    than a real credential. Filters are ordered cheapest-first.
    """
    value = normalize_secret_value(value)

    if value in (None, "", [], {}, False):
        return True

    if isinstance(value, str):
        lowered = value.lower()

        if lowered in {"null", "none", "n/a", "redacted"}:
            return True

        # Logic App / ARM workflow expressions — @parameters('x'), @variables('y'), etc.
        if value.startswith("@"):
            return True

        # ARM template parameter references — [parameters('x')], [variables('y')]
        if value.startswith("[") and value.endswith("]"):
            return True

        # Azure Key Vault managed secret reference
        if "@microsoft.keyvault(" in lowered:
            return True

        # Shell / CI variable placeholders — ${VAR}, $(VAR)
        if value.startswith("${") or value.startswith("$("):
            return True

        # ARM resource IDs are identifiers, not credentials
        if value.startswith("/subscriptions/"):
            return True

        # Field names echoed as values (config keys that mirror the property name)
        if lowered.endswith("_connection_string"):
            return True
        if lowered.endswith("_secret"):
            return True
        if lowered.endswith("_password"):
            return True
        if lowered.endswith("_token"):
            return True
        if lowered.endswith("_key"):
            return True

    return False


def looks_like_real_secret_value(value):
    """
    Heuristic: returns True if the value looks like a real credential rather than
    a name, reference, or innocuous string.

    Positive signals: known connection-string markers, or a string that is at
    least 24 characters long, contains a digit, and is not all letters (all-alpha
    strings are usually human-readable names, not generated secrets).
    """
    value = normalize_secret_value(value)
    if is_benign_secret_value(value):
        return False

    if isinstance(value, str):
        lowered = value.lower()
        if any(marker in lowered for marker in ("accountkey=", "sharedaccesssignature=", "defaultendpointsprotocol=", "endpointsuffix=")):
            return True
        if len(value) >= 24 and not value.isalpha() and any(c.isdigit() for c in value):
            return True
        return False

    # Numeric values under a secret-pattern key are always worth flagging.
    return isinstance(value, (int, float))


def walk_sensitive_fields(value, source, path=""):
    """
    Recursively walks a parsed JSON structure, collecting fields whose name
    matches a SECRET_PATTERN and whose value passes looks_like_real_secret_value.
    Returns a list of match dicts: {pattern, source, path, snippet}.
    """
    matches = []

    if isinstance(value, dict):
        for key, nested_value in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            key_lower = str(key).lower()

            if any(pattern in key_lower for pattern in SECRET_PATTERNS):
                if looks_like_real_secret_value(nested_value):
                    matches.append(
                        {
                            "pattern": key_lower,
                            "source": source,
                            "path": child_path,
                            "snippet": str(normalize_secret_value(nested_value))[:180],
                        }
                    )

            matches.extend(walk_sensitive_fields(nested_value, source, child_path))

    elif isinstance(value, list):
        for index, nested_value in enumerate(value):
            child_path = f"{path}[{index}]" if path else f"[{index}]"
            matches.extend(walk_sensitive_fields(nested_value, source, child_path))

    return matches


def build_raw_secret_matches(chunk):
    """
    Runs RAW_SECRET_VALUE_PATTERNS against the raw text content of a blob.
    Catches connection strings and tokens that live in flat string values rather
    than structured JSON keys (e.g. an env var set to a full connection string).
    """
    matches = []
    content = chunk.get("content", "")
    for pattern in RAW_SECRET_VALUE_PATTERNS:
        match = pattern.search(content)
        if not match:
            continue
        snippet = match.group(0).replace("\n", " ").strip()
        matches.append(
            {
                "pattern": pattern.pattern,
                "source": chunk.get("source"),
                "path": "raw_text",
                "snippet": snippet[:180],
            }
        )
    return matches


# ── Trigger reachability ──────────────────────────────────────────────────────

def _evaluate_reachable_trigger(record, trigger):
    """
    Compound check — returns (row_severity, notes) or None if the trigger should
    not appear in the reachable-trigger table.

    Severity matrix:
      HIGH  — anonymous auth,   no IP restrictions
      LOW   — anonymous auth,   IP-restricted
      LOW   — SAS/auth-gated,   no IP restrictions
      INFO  — SAS/auth-gated,   IP-restricted
      None  — client cert active on a Function App (transport-layer auth present)
      None  — EasyAuth enabled on a Function App (platform-level token auth present)

    Logic Apps do not support client certificate authentication so that check is
    skipped for them entirely.
    """
    if not trigger.get("is_http") or not trigger.get("external_access"):
        return None

    # Function App-only checks (Logic Apps support neither client certs nor EasyAuth).
    if record.get("platform") == "functionApp":
        client_cert_mode = (record.get("client_cert_mode") or "").lower()
        if client_cert_mode not in ("disabled", "", "unknown"):
            return None
        # EasyAuth enforces token-based authentication at the platform level,
        # before the function code runs. A True value means the app is protected
        # regardless of the trigger's authLevel binding setting.
        if record.get("easyauth_enabled") is True:
            return None

    is_anonymous = (trigger.get("auth_mode") or "").lower() == "anonymous"
    ip_restricted = trigger.get("ip_restricted", False)

    if is_anonymous and not ip_restricted:
        return "high", "Anonymous, no IP restrictions"
    if is_anonymous and ip_restricted:
        return "low", "Anonymous, IP-restricted"
    if not is_anonymous and not ip_restricted:
        return "low", "SAS/auth-gated, no IP restrictions"
    return "info", "SAS/auth-gated, IP-restricted"


def scan_reachable_http_triggers_batch(records, droplet_name):
    """
    Consolidates all externally reachable HTTP triggers across Logic Apps and
    Function Apps into a single finding with a sortable trigger-level table.
    The finding severity reflects the worst row present.
    """
    rows = []

    for record in records:
        for trigger in record.get("triggers", []):
            result = _evaluate_reachable_trigger(record, trigger)
            if result is None:
                continue

            row_severity, notes = result
            rows.append({
                "app_name": record.get("name"),
                "platform": record.get("platform"),
                "subscription": record.get("subscription_name"),
                "resource_group": record.get("resource_group"),
                "trigger_name": trigger.get("name"),
                "auth_mode": trigger.get("auth_mode"),
                "ip_restricted": trigger.get("ip_restricted", False),
                "row_severity": row_severity,
                "notes": notes,
            })

    if not rows:
        return []

    _sev_order = {"high": 0, "low": 1, "info": 2}
    rows.sort(key=lambda r: _sev_order.get(r["row_severity"], 3))
    if any(r["row_severity"] == "high" for r in rows):
        overall_severity = "high"
    elif any(r["row_severity"] == "low" for r in rows):
        overall_severity = "low"
    else:
        overall_severity = "info"
    high_count = sum(1 for r in rows if r["row_severity"] == "high")

    return [
        make_finding(
            title="Publicly Reachable HTTP Triggers",
            desc=(
                "One or more Logic Apps or Function Apps expose HTTP/HTTPS triggers that are externally accessible, "
                "accept anonymous requests, and have client certificate authentication disabled. "
                "Apps with no IP restrictions are high severity; apps with IP allowlists are low severity."
            ),
            severity=overall_severity,
            confidence="medium",
            objects=[],
            evidence=[{"type": "trigger_table", "rows": rows}],
            rec=(
                "For each listed trigger: remove public exposure where not required, enable client certificate "
                "authentication, or restrict access via IP allowlists. High-severity entries should be treated "
                "as unauthenticated public endpoints until remediated."
            ),
            meta={
                "scan": droplet_name,
                "trigger_count": len(rows),
                "high_count": high_count,
            },
        )
    ]


def build_secret_matches(record):
    """Combines structured field-walk and raw-text regex matches for a record."""
    matches = []
    for chunk in record.get("text_blobs", []):
        content = chunk.get("content", "")
        try:
            structured_content = json.loads(content)
        except (TypeError, ValueError):
            structured_content = None

        if structured_content is not None:
            matches.extend(walk_sensitive_fields(structured_content, chunk.get("source")))

        matches.extend(build_raw_secret_matches(chunk))
    return matches


def scan_possible_credentials(record, droplet_name):
    """
    Per-record rule. Emits a finding for each app that contains keyword or
    pattern matches suggesting embedded credentials. Deliberately kept as a
    per-record rule (not batch) because the matched snippets are unique per app
    and must travel with their source resource.
    """
    matches = build_secret_matches(record)
    if not matches:
        return []

    unique_matches = []
    seen = set()
    for match in matches:
        key = (match["pattern"], match["source"], match["snippet"])
        if key in seen:
            continue
        seen.add(key)
        unique_matches.append(match)

    return [
        make_finding(
            title="Possible Embedded Credential Material",
            desc=(
                "The collected Logic App or Function App definition/configuration contains keywords or snippets "
                "that may indicate embedded credentials, secrets, tokens, or connection material."
            ),
            severity="medium",
            confidence="low",
            objects=[build_parent_object(record)],
            evidence=[build_base_evidence(record)] + unique_matches[:20],
            rec=(
                "Review the referenced definitions/configuration and move any embedded credentials to approved "
                "secret stores such as Key Vault or managed identity-based access."
            ),
            meta={
                "scan": droplet_name,
                "platform": record.get("platform"),
                "resource_id": record.get("id"),
                "match_count": len(unique_matches),
            },
        )
    ]


def parse_http_version(record):
    try:
        return float(str(record.get("http_version")))
    except (TypeError, ValueError):
        return None


def parse_tls_version(record):
    try:
        return float(str(record.get("minimum_inbound_tls_version")))
    except (TypeError, ValueError):
        return None


# ── Batch finding helpers ─────────────────────────────────────────────────────
#
# Batch rules emit a single consolidated finding containing:
#   - an app_table evidence item (rendered as a table in the UI)
#   - a paste_output string in meta (markdown table for Jira / Word reports)

def _app_row(record, extra=None):
    """Builds a standard app-table row from a record, with optional extra columns."""
    row = {
        "App Name": record.get("name") or "—",
        "Subscription": record.get("subscription_name") or "—",
        "Resource Group": record.get("resource_group") or "—",
        "Region": record.get("region") or "—",
    }
    if extra:
        row.update(extra)
    return row


def _build_markdown_table(columns, rows):
    """Renders a column-aligned markdown pipe table from a list of row dicts."""
    widths = {col: len(col) for col in columns}
    for row in rows:
        for col in columns:
            widths[col] = max(widths[col], len(str(row.get(col) or "—")))
    header = "| " + " | ".join(col.ljust(widths[col]) for col in columns) + " |"
    sep = "| " + " | ".join("-" * widths[col] for col in columns) + " |"
    lines = [header, sep]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(col) or "—").ljust(widths[col]) for col in columns) + " |")
    return "\n".join(lines)


def _build_paste_output(title, desc, severity, columns, rows, rec):
    """
    Assembles a self-contained markdown block — title, severity, description,
    table, and recommendation — ready to paste into a Jira ticket or Word report.
    """
    return "\n".join([
        "## %s" % title,
        "**Severity:** %s" % severity.capitalize(),
        "",
        desc,
        "",
        _build_markdown_table(columns, rows),
        "",
        "**Recommendation:** %s" % rec,
    ])


def _app_table_evidence(columns, rows):
    """Wraps columns and rows into an app_table evidence item for the UI renderer."""
    return {"type": "app_table", "columns": columns, "rows": rows}


_STANDARD_APP_COLS = ["App Name", "Subscription", "Resource Group", "Region"]


# ── Batch scan rules ──────────────────────────────────────────────────────────

def scan_function_app_easyauth_batch(records, droplet_name):
    """Flags publicly accessible Function Apps that have EasyAuth disabled."""
    rows = []
    for record in records:
        if record.get("platform") != "functionApp":
            continue
        if not record.get("public_access"):
            continue
        if record.get("easyauth_enabled") is not False:
            continue
        rows.append(_app_row(record))
    if not rows:
        return []
    title = "Function App EasyAuth Not Enabled"
    desc = (
        "The following publicly accessible Function Apps do not have Azure App Service Authentication "
        "(EasyAuth) enabled. Without EasyAuth the apps receive unauthenticated requests directly "
        "and must implement authentication at the application layer."
    )
    rec = (
        "Enable Azure App Service Authentication (EasyAuth) for each listed app if it should require "
        "authenticated callers. If unauthenticated access is intentional, confirm that application-layer "
        "authentication is in place and document the decision."
    )
    severity = "medium"
    return [make_finding(
        title=title,
        desc=desc,
        severity=severity,
        confidence="medium",
        objects=[],
        evidence=[_app_table_evidence(_STANDARD_APP_COLS, rows)],
        rec=rec,
        meta={
            "scan": droplet_name,
            "affected_count": len(rows),
            "paste_output": _build_paste_output(title, desc, severity, _STANDARD_APP_COLS, rows, rec),
        },
    )]


def scan_function_app_cors_batch(records, droplet_name):
    """Flags Function Apps whose CORS policy allows requests from any origin (*)."""
    rows = []
    for record in records:
        if record.get("platform") != "functionApp":
            continue
        if "*" not in (record.get("cors_allowed_origins") or []):
            continue
        rows.append(_app_row(record))
    if not rows:
        return []
    title = "Function App CORS Wildcard Configured"
    desc = (
        "The following Function Apps have a CORS policy that allows requests from any origin (\"*\"). "
        "This permits cross-origin JavaScript from any domain to make requests to the app's endpoints, "
        "which can be exploited if the app relies on cookies or session tokens for authentication."
    )
    rec = (
        "Replace the wildcard CORS entry with an explicit allowlist of trusted origins. "
        "If broad access is intentional, confirm the apps do not rely on cookie-based auth "
        "that could be hijacked via cross-origin requests."
    )
    severity = "medium"
    return [make_finding(
        title=title,
        desc=desc,
        severity=severity,
        confidence="high",
        objects=[],
        evidence=[_app_table_evidence(_STANDARD_APP_COLS, rows)],
        rec=rec,
        meta={
            "scan": droplet_name,
            "affected_count": len(rows),
            "paste_output": _build_paste_output(title, desc, severity, _STANDARD_APP_COLS, rows, rec),
        },
    )]


def scan_function_app_http_allowed_batch(records, droplet_name):
    """Flags Function Apps that do not enforce HTTPS-only access."""
    rows = []
    for record in records:
        if record.get("platform") != "functionApp":
            continue
        if record.get("https_only") is not False:
            continue
        rows.append(_app_row(record))
    if not rows:
        return []
    title = "Function App Allows HTTP"
    desc = (
        "The following Function Apps do not enforce HTTPS-only access, "
        "allowing inbound requests over unencrypted HTTP."
    )
    rec = "Enable HTTPS Only on each listed app so inbound requests over plain HTTP are rejected."
    severity = "high"
    return [make_finding(
        title=title,
        desc=desc,
        severity=severity,
        confidence="high",
        objects=[],
        evidence=[_app_table_evidence(_STANDARD_APP_COLS, rows)],
        rec=rec,
        meta={
            "scan": droplet_name,
            "affected_count": len(rows),
            "paste_output": _build_paste_output(title, desc, severity, _STANDARD_APP_COLS, rows, rec),
        },
    )]


def scan_function_app_http2_batch(records, droplet_name):
    """Flags Function Apps running on HTTP/1.1 when HTTP/2 is available."""
    cols = ["App Name", "HTTP Version", "Subscription", "Resource Group", "Region"]
    rows = []
    for record in records:
        if record.get("platform") != "functionApp":
            continue
        v = parse_http_version(record)
        if v is None or v >= 2.0:
            continue
        rows.append(_app_row(record, {"HTTP Version": record.get("http_version") or "1.1"}))
    if not rows:
        return []
    title = "Function App Does Not Use HTTP/2"
    desc = "The following Function Apps are not configured to use HTTP/2."
    rec = "Enable HTTP/2 for each listed app unless there is a documented compatibility reason not to."
    severity = "low"
    return [make_finding(
        title=title,
        desc=desc,
        severity=severity,
        confidence="high",
        objects=[],
        evidence=[_app_table_evidence(cols, rows)],
        rec=rec,
        meta={
            "scan": droplet_name,
            "affected_count": len(rows),
            "paste_output": _build_paste_output(title, desc, severity, cols, rows, rec),
        },
    )]


def scan_function_app_tls_batch(records, droplet_name):
    """Flags Function Apps whose minimum inbound TLS version is below 1.2."""
    cols = ["App Name", "Min TLS Version", "Subscription", "Resource Group", "Region"]
    rows = []
    for record in records:
        if record.get("platform") != "functionApp":
            continue
        v = parse_tls_version(record)
        if v is None or v >= 1.2:
            continue
        rows.append(_app_row(record, {"Min TLS Version": record.get("minimum_inbound_tls_version") or "?"}))
    if not rows:
        return []
    title = "Function App Minimum TLS Version Below 1.2"
    desc = "The following Function Apps allow inbound TLS versions below 1.2."
    rec = "Set the minimum inbound TLS version to 1.2 or later on each listed app."
    severity = "high"
    return [make_finding(
        title=title,
        desc=desc,
        severity=severity,
        confidence="high",
        objects=[],
        evidence=[_app_table_evidence(cols, rows)],
        rec=rec,
        meta={
            "scan": droplet_name,
            "affected_count": len(rows),
            "paste_output": _build_paste_output(title, desc, severity, cols, rows, rec),
        },
    )]


def scan_logic_app_non_anonymous_exposed_batch(records, droplet_name):
    """
    Flags Logic Apps with SAS-authenticated HTTP triggers that are exposed to the
    internet without an IP allowlist. While SAS tokens provide some protection,
    the endpoint remains reachable by anyone who can obtain or guess the token.
    """
    cols = ["App Name", "Exposed Triggers", "Subscription", "Resource Group", "Region"]
    rows = []
    for record in records:
        if record.get("platform") != "logicApp":
            continue
        exposed = [
            t for t in record.get("triggers", [])
            if t.get("is_http")
            and t.get("external_access")
            and (t.get("auth_mode") or "").lower() != "anonymous"
            and not t.get("ip_restricted", False)
        ]
        if not exposed:
            continue
        rows.append(_app_row(record, {"Exposed Triggers": len(exposed)}))
    if not rows:
        return []
    title = "Logic App HTTP Trigger Exposed Without IP Restrictions"
    desc = (
        "The following Logic Apps expose HTTP triggers that are externally accessible with no IP "
        "access restrictions. While the triggers require caller authentication (e.g. a SAS token), "
        "anyone on the internet can attempt to invoke them."
    )
    rec = (
        "Add IP allowlist restrictions to each listed app's "
        "accessControl.triggers.allowedCallerIpAddresses configuration to limit callers "
        "to known IP ranges. Review whether these triggers need to be internet-accessible."
    )
    severity = "low"
    return [make_finding(
        title=title,
        desc=desc,
        severity=severity,
        confidence="medium",
        objects=[],
        evidence=[_app_table_evidence(cols, rows)],
        rec=rec,
        meta={
            "scan": droplet_name,
            "affected_count": len(rows),
            "paste_output": _build_paste_output(title, desc, severity, cols, rows, rec),
        },
    )]


# ── Rule registries ───────────────────────────────────────────────────────────
#
# The droplet calls each SCAN_RULES function once per record and each
# BATCH_SCAN_RULES function once with the full record list.
# Add new rules to whichever list fits the finding's granularity.

SCAN_RULES = [
    scan_possible_credentials,          # per-record: evidence is unique per app
]

BATCH_SCAN_RULES = [
    scan_reachable_http_triggers_batch,         # trigger-level table across all apps
    scan_function_app_easyauth_batch,
    scan_function_app_cors_batch,
    scan_function_app_http_allowed_batch,
    scan_function_app_http2_batch,
    scan_function_app_tls_batch,
    scan_logic_app_non_anonymous_exposed_batch,
]
