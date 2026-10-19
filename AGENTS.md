# AGENTS.md — building SprayCan droplets with a coding agent

This file is for AI coding agents (Codex, Antigravity, Claude Code, Cursor, Copilot, …) and the
people driving them. It holds everything needed to **add a new scan module ("droplet") and have it
show up in Canvas** without exploring the codebase first. The signatures and behaviours below are
checked against the code; trust them and only open the files named here when you need more.

Humans: the README's [Extensibility](README.md#extensibility--writing-your-own-droplet) section
covers the same ground in prose.

## Ground rules

- **Read-only.** Droplets only *read* from Microsoft Graph and Azure Resource Manager (GET, plus POST
  for query APIs such as Resource Graph). Never create, change or delete anything in a tenant.
- **No live traffic to targets** beyond Graph/ARM unless the droplet's description says so, it is
  opt-in, and it sends `User-Agent: util.version.USER_AGENT` (see `find_exposed_front_door_origins.py`).
- **No real data in the repo:** no tenant/object IDs, tokens, secrets, hostnames, client names or
  saved findings in code, comments, tests or docs. Use `00000000-0000-0000-0000-000000000000` and
  `contoso` style placeholders. Never commit `output/`, `settings.json` or `.pptx`/`.potx` files.
- **Python 3.9+**: no `match`, no `X | Y` type unions, no 3.10+ stdlib APIs.
- **No new dependencies** unless unavoidable (`requirements.txt` is installed by `install.py`).
- **Never handle credentials.** Get tokens from `util.tokenizer`; never log or write them.
- **One file per droplet** in `Droplets/`. Shared logic goes in `util/` or `ScanRules/`, never in
  `Droplets/`: every `.py` file there is imported at startup.

## Repo map (only what droplet work touches)

| Path | What it is |
|---|---|
| `Droplets/*.py` | One droplet per file. Auto-discovered (subfolders included) |
| `Objects/Core.py` | Loader (`Core`), `make_finding`, `make_object`, `choose_severity`, `check_pagination`, `write_findings_to_disk`, `write_json_payload_to_disk`, `load_graph_permissions_from_disk` |
| `Objects/Finding.py` | `Finding` class; `to_dict()` gives the JSON schema below |
| `util/http_client.py` | HTTP wrapper with retry and throttling. Use it, not `requests` |
| `util/tokenizer.py` | `get_graph_token()`, `get_arm_token()`, `get_current_tenant_id()` |
| `util/status.py` | `set_phase(text)`: the live progress line in Canvas and the terminal |
| `util/console.py` | `debug/info/success/warn/error(text)`: log lines streamed to Canvas |
| `util/error_logger.py` | `log_current_exception(context=...)`: writes a traceback to `content/logs/` |
| `util/settings.py` | Persisted settings (`settings.json`); scan-time toggles live here |
| `util/version.py` | `VERSION`, `USER_AGENT`, the only version source |
| `ScanRules/` | Rule modules imported by droplets (e.g. `logic_app_scan_rules.py`) |
| `frontend/src/components/FindingDetailPane.jsx` | Finding detail view: `renderEvidence()` per-scan branches |
| `frontend/src/lib/findings.js` | `summarizeFinding()` (list card) and `detailFacts()` (fact tiles), per-scan branches |
| `frontend/dist/` | Built Canvas bundle, **committed**. Rebuild after any frontend change |

Good reference droplets: `find_dangling_app_reg_URLs.py` (small, Graph),
`find_risky_nsg_rules.py` (ARM, subscriptions, rich evidence), `find_exposed_front_door_origins.py`
(`app_table` evidence, settings toggle, live probe), `export_aztop_resource_overviews.py`
(metrics view, CSV export).

## The droplet contract

`Objects/Core.py` walks `Droplets/`, imports every `.py`, and calls `Droplet(file_path)` for any
module-level class named `Droplet`. A file that fails to import or construct is skipped with a
warning.

```python
class Droplet:
    droplet_name = "Scan: <Unique Name>"   # identifier everywhere (see "Naming" below)
    droplet_type = "scan"                   # "scan" | "util" | "settings" | "test"
    droplet_path = None
    droplet_description = "...\n\nRequires\n  Graph : <Permission>"   # shown in Canvas

    def __init__(self, droplet_path):       # cheap, no network: runs on every catalogue load
        self.droplet_path = droplet_path

    def run(self):                          # do the work, write output, return findings list
        ...
```

| `droplet_type` | Canvas | Headless `--scan` / `--all-scans` |
|---|---|---|
| `scan` | Scans list | Yes |
| `util` | Exports & Utilities list | No |
| `settings`, `test` | Not listed | No |

- `run()` takes no arguments. Tenant and auth are already set up when it runs.
- **Raise on failure.** The runner catches the exception, logs a traceback to `content/logs/`, marks
  the scan failed in Canvas and carries on with the next queued scan. Don't swallow errors and
  return an empty list: that reads as "nothing found".
- Write output exactly once, with `write_findings_to_disk(findings, source_name=self.droplet_name)`,
  and `return findings`. Returning `[]` with nothing written is fine when there is nothing to report.
- Canvas reads the catalogue at startup (restart `SprayCan.py` after adding a droplet). Each run
  re-imports the file, so edits to an existing droplet need no restart. Headless picks up new files
  immediately.

### Naming (important)

`droplet_name` is the headless `--scan` name, the Canvas queue label, part of the output filename
and `meta.scan`. Canvas also picks per-scan layouts by **substring match** on it. Avoid these
substrings unless you want that layout:

`T0 Groups`, `Service Principals`, `Dynamic Groups`, `Dangling app-reg`, `NSG Inbound`,
`Logic and Function App Review`, `Resource Review`, `Front Door Origin Exposure`

Also avoid `Model ` and `Model_`: files with those in the name open in the network topology viewer.
Use the `Scan: ` prefix for scans and `Util: ` for utilities, and keep names stable, since saved
output and scripts refer to them.

## Template

Copy this, rename, and fill in the `TODO`s. It covers Graph, ARM and both paging styles.

```python
import util.console as console
import util.http_client as http_client
import util.status as status
import util.tokenizer as tokenizer
from Objects.Core import check_pagination, make_finding, make_object, write_findings_to_disk

GRAPH = "https://graph.microsoft.com"
ARM = "https://management.azure.com"


class Droplet:
    droplet_name = "Scan: TODO Unique Name"
    droplet_type = "scan"
    droplet_path = None
    droplet_description = (
        "TODO: one or two lines on what this finds and why it matters.\n"
        "\n"
        "Requires\n"
        "  Graph : TODO.Read.All\n"
        "  ARM   : Reader on subscriptions"
    )

    def __init__(self, droplet_path):
        self.droplet_path = droplet_path

    # -- data access ---------------------------------------------------------

    def get_all(self, url, token):
        """GET a Graph or ARM collection and follow every page. Raises on HTTP errors."""
        response = http_client.get(url, headers={"Authorization": "Bearer %s" % token})
        if response.status_code != 200:
            raise RuntimeError("HTTP %s from %s" % (response.status_code, url.split("?")[0]))
        body = response.json()
        return check_pagination(token, body, body.get("value", []))

    def get_subscriptions(self, arm_token):
        return self.get_all("%s/subscriptions?api-version=2022-12-01" % ARM, arm_token)

    # -- analysis ------------------------------------------------------------

    def build_finding(self, item):
        return make_finding(
            title="TODO: short, specific title",
            desc="TODO: what is wrong, in one or two sentences.",
            severity="medium",                  # critical | high | medium | low | info
            confidence="high",                  # high | medium | low
            objects=[make_object("TODO_type", item.get("id"), item.get("displayName"))],
            evidence=[{"TODO_field": item.get("TODO")}],
            rec="TODO: how to fix it.",
            meta={"scan": self.droplet_name},  # required: Canvas labels findings with it
        )

    # -- entry point ---------------------------------------------------------

    def run(self):
        status.set_phase("Collecting TODO")
        graph_token = tokenizer.get_graph_token()
        items = self.get_all("%s/v1.0/TODO?$select=id,displayName" % GRAPH, graph_token)

        status.set_phase("Analysing %d item(s)" % len(items))
        findings = [self.build_finding(item) for item in items if True]  # TODO: the real test

        console.info("[i] %d finding(s)" % len(findings))
        write_findings_to_disk(findings, source_name=self.droplet_name)
        return findings
```

## Helper reference

**`util.http_client`**: `get(url, *, headers=None, **kw)`, `post(url, *, headers=None, **kw)`,
`request(method, url, *, headers=None, max_retries=10, timeout=30, **kw)` (extra kwargs go to
`requests`, e.g. `json=`, `params=`).

- It retries 429/5xx and connection errors with backoff, honours `Retry-After`, and slows down when
  ARM's remaining-request headers run low.
- It **returns the response on 4xx and on a final 5xx**. Always check `status_code`. 403 usually
  means a missing permission: say which one in the error.
- `get_json(url, headers=...)` parses the body with no status check, so prefer `get` + check.

**`util.tokenizer`**: `get_graph_token()`, `get_arm_token()`. They work in every auth mode (browser,
device code, service principal, pasted token) and raise `RuntimeError` when no token is available.
Fetch them inside `run()`, never in `__init__`. `get_current_tenant_id()` returns the active tenant.

**`Objects.Core`**:

- `check_pagination(token, body, items)` follows Graph `@odata.nextLink` and ARM `nextLink`,
  appending each page's `value` to `items`, and returns the list. It doesn't check page status codes.
- `make_object(kind, obj_id=None, name=None, **attrs)` returns `{"type", "id", "name", **attrs}`.
- `make_finding(title, desc="", severity="info", confidence="medium", objects=None, evidence=None,
  rec="", meta=None)` returns a `Finding` with a fresh UUID `id`.
- `choose_severity(values, mapping, default="info")` gives the highest severity among
  `mapping[value]`. Use `choose_severity(sevs, {s: s for s in sevs})` for a plain list of severities.
- `write_findings_to_disk(findings, output_file=None, source_name=None)` writes
  `output/<tenant>/<epoch_ms>.<sanitised name>.json` and returns the path.
- `write_json_payload_to_disk(payload, source_name=...)` writes a non-finding payload. Canvas opens
  one with a top-level `subscriptions` list in the network topology viewer.
- `load_graph_permissions_from_disk()` returns the Graph permission catalogue (`graph_permissions.json`).

**`util.status.set_phase(text)`**: short present-tense progress ("Collecting subscriptions",
"Subscription 3/12: Prod"). **`util.console`**: prefix convention `[i]` info, `[+]` found, `[!]`
warning or error, `[↳]` detail. `debug` only shows in verbose mode.

**Resource Graph** (KQL across subscriptions): POST
`https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01` with
`{"subscriptions": [...], "query": "...", "options": {"$top": 1000, "$skipToken": ...}}`. See
`resource_graph_query()` in `export_external_attack_surface_overview.py` for paging.

## Output schema

```json
{
  "tenant_id": "...", "generated_at_utc": "...", "scan_name": "<droplet_name>",
  "findings": [{
    "id": "uuid", "title": "...", "desc": "...",
    "severity": "critical|high|medium|low|info", "confidence": "high|medium|low",
    "objects":  [{"type": "...", "id": "...", "name": "...", "...": "..."}],
    "evidence": [{"...": "..."}],
    "rec": "...",
    "meta": {"scan": "<droplet_name>", "...": "..."}
  }]
}
```

- **One finding per problem instance** (per app, per NSG, per role assignment) is the norm. Group
  many small rows into one finding with an `app_table` (below) when a per-item finding would flood
  the list.
- `severity` drives colour, sorting and the sidebar filter. Use `info` for inventory or summaries.
- Keep evidence values JSON-serialisable (no `set`, `datetime` or `bytes`).

## Plugging into Canvas

A new droplet renders in Canvas with **no frontend work**: title, severity, description,
recommendation, a generic fact grid, the `meta` block and raw-JSON evidence. These conventions
upgrade the view, still with no frontend change:

| You emit | Canvas shows |
|---|---|
| `meta["scan"] = self.droplet_name` | Scan label on the finding (otherwise "Unknown scan") |
| evidence item `{"type": "app_table", "columns": ["Name", "Region"], "rows": [{"Name": "a", "Region": "x"}]}` | A table with an **Export CSV** button. Row keys must match the column labels exactly. Cell values must be scalars: join lists into strings in Python. Empty `rows` renders nothing |
| objects of type `group`, `servicePrincipal`, `application`, `logicApp`, `functionApp`, `trigger` | "Primary Objects" panel (type, id, name) |
| objects of type `role` / `permission` / `assignment` | Dedicated role, permission and assignment lists |
| objects of any other type | "Other Objects" panel as JSON |
| `meta["metrics"] = [{"category": str, "total": int, "checks": [{"label": str, "bad": int, "total": int, "info": bool}]}]` | Colour-coded metrics view in place of the description. `info: True` marks a check that isn't a problem |
| `meta["csv_paths"] = ["<tenant>/csv/<run>/file.csv"]` (relative to `output/`) | CSV download links. **Only shown together with `meta["metrics"]`** |
| `meta["paste_output"] = "text"` | A collapsible copy-paste block |

Only go further if the defaults genuinely don't work:

- **Custom list card or fact tiles:** add a branch keyed on your name to `summarizeFinding()` and/or
  `detailFacts()` in `frontend/src/lib/findings.js`.
- **Custom evidence layout:** add a branch to `renderEvidence()` in
  `frontend/src/components/FindingDetailPane.jsx`, before the generic fallback at the end. Copy an
  existing branch. `renderKeyValueTable([[label, value], ...])` and
  `renderAppTable(columns, rows, filename)` are the building blocks.
- **Scan-time option** (a checkbox shown when your scan is queued): see `SCAN_TOGGLES` in
  `frontend/src/components/ScanPage.jsx`. Its comment lists the steps: a getter/setter in
  `util/settings.py`, a GET/POST `/api/settings/<slug>` endpoint in `server/server.py`, and the entry.
- After any frontend change: `cd frontend && npm run build`, then commit `frontend/src/` **and**
  `frontend/dist/`. Hard-reload the browser (Ctrl+Shift+R).

## Testing

**Without a tenant (do this first).** Stub the network and run the droplet against fixtures shaped
like real API responses. Save this as a scratch file outside the repo and run it from the repo
root:

```python
import importlib.util, json, sys, types
sys.path.insert(0, ".")

def load(path):
    spec = importlib.util.spec_from_file_location("droplet_under_test", path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

module = load("Droplets/<your_file>.py")

FIXTURES = {  # URL prefix -> JSON body. Use placeholder IDs only.
    "https://graph.microsoft.com/v1.0/TODO": {"value": [{"id": "00000000-0000-0000-0000-000000000001", "displayName": "contoso-app"}]},
}

def fake_get(url, *, headers=None, **kwargs):
    for prefix, body in FIXTURES.items():
        if url.startswith(prefix):
            return types.SimpleNamespace(status_code=200, content=json.dumps(body).encode(), json=lambda b=body: b, headers={})
    return types.SimpleNamespace(status_code=404, content=b"{}", json=lambda: {}, headers={})

written = {}
module.http_client.get = fake_get                       # patch the module the droplet imported
module.tokenizer.get_graph_token = lambda: "test-token"
module.tokenizer.get_arm_token = lambda: "test-token"
module.write_findings_to_disk = lambda findings, **kw: written.setdefault("findings", findings)

findings = module.Droplet("Droplets/<your_file>.py").run()
print(json.dumps([f.to_dict() for f in findings], indent=2))
```

Check the severities, that `meta.scan` is set and that the evidence is JSON-serialisable. Cover the
edge cases: empty collections, missing optional properties, 403 responses and multiple pages.

**Against a tenant you're authorised to test:**

```bash
python -m py_compile Droplets/<your_file>.py
python SprayCan.py --list-scans
python SprayCan.py --headless --tenant <tenant-id> --auth-mode device-code --scan "<droplet_name>"
python SprayCan.py            # Canvas: restart, run it, open the output, check it reads well
```

## Pull request checklist

- [ ] One new file in `Droplets/`. Name follows the naming rules and collides with no layout substring
- [ ] `droplet_description` ends with a `Requires` block (Graph permissions / ARM roles)
- [ ] Read-only API use. HTTP via `util.http_client`, tokens via `util.tokenizer`, status codes checked
- [ ] Errors raise. `write_findings_to_disk(..., source_name=self.droplet_name)` and `return findings`
- [ ] `meta["scan"]` set. Severities from the allowed set. Evidence is JSON-serialisable
- [ ] Offline fixture test passes. Real-tenant run checked in Canvas
- [ ] README: add the scan to **What It Does** and a row to the scan table, keeping the table in
      `--list-scans` order (Python's default sort of names: uppercase sorts before lowercase) and
      renumbering the rows below it
- [ ] Frontend touched? `npm run build` and `frontend/dist/` committed
- [ ] No real tenant data, tokens, saved findings or presentations in the diff
