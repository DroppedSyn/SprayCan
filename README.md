# SprayCan

SprayCan is a local Azure / Entra reconnaissance and findings tool.

It uses small scan modules called **droplets** to query Microsoft Graph and Azure Resource Manager, then emits structured findings as JSON. Those findings are reviewed in **Canvas** — a local React web UI included in this repo. Scans can be run from Canvas or from the command line ([Headless Mode](#headless-mode)).

## What It Does

Current scan coverage:

- Dangling app registration redirect URIs
- Entra ID tenant state checks
- PIM state checks
- Risky agent identities
- Groups with privileged Entra ID or Azure RBAC roles
- Risky dynamic groups
- Risky service principals with privilege escalation permissions
- NSG inbound rule analysis
- Logic App and Function App security review
- Azure network topology modelling
- External attack surface overview
- Azure resource security overviews (storage, app services, key vaults, etc.)
- Azure Front Door origin exposure (origins reachable directly, bypassing the Front Door WAF)

Scan droplets (runnable from Canvas or headless):

| # | Droplet name | Needs | What it checks |
|---|---|---|---|
| 1 | `Scan: Dangling app-reg URLS` | Graph | App registration redirect URIs / reply URLs whose domains no longer resolve (OAuth code hijack) |
| 2 | `Scan: Entra ID State Checks` | Graph | Tenant-wide Entra ID weak defaults: app registration / tenant creation by non-admins, guest roles and invitations, self-service sign-up, cross-tenant B2B defaults |
| 3 | `Scan: External Resource Review` | ARM | Internet-facing Azure resources across subscriptions; flags public endpoints needing network exposure review |
| 4 | `Scan: Find Risky NSG Inbound Rules` | ARM | NSG inbound rules allowing any source (0.0.0.0/0 / Internet) to sensitive or broad port ranges, with affected NICs and subnets |
| 5 | `Scan: Find T0 Groups with Entra ID and Azure RBAC roles` | Graph + ARM | Security groups holding Tier 0 directory roles or high-privilege Azure RBAC roles (nested membership expanded) |
| 6 | `Scan: Find risky Agent Identities` | Graph + ARM | AI agent / agentic workload identities with agent-inappropriate Graph permissions or high-privilege roles |
| 7 | `Scan: Find risky Dynamic Groups` | Graph | Dynamic groups with role/RBAC assignments whose membership rules use user-modifiable attributes |
| 8 | `Scan: Find risky Service Principals` | Graph (+ ARM optional) | Service principals with privileged Graph application permissions, correlated with Logic App managed identities |
| 9 | `Scan: Front Door Origin Exposure` | ARM | Front Door Standard/Premium origins (App Service, slots, SCM/Kudu, APIM) reachable directly, plus WAF policy gaps |
| 10 | `Scan: Logic and Function App Review` | ARM | Logic App / Function App misconfigurations: unauthenticated HTTP triggers, insecure connector patterns, rule-based findings |
| 11 | `Scan: PIM State Checks` | Graph + ARM | PIM coverage for Entra roles and Azure RBAC: permanent active assignments on high-privilege roles, missing eligibility config |
| 12 | `Scan: Resource Review (All)` | ARM | Configuration export and security metrics for common resource types (VMs, web apps, storage, databases, Key Vaults, registries, ...) to CSV |

**Needs:** *Graph* = a Microsoft Graph token (with the scan's Graph permissions); *ARM* = an Azure
Resource Manager token with Reader on the subscriptions to cover. `Scan: Find risky Service
Principals` uses ARM only to correlate with Logic App managed identities.

Non-scan droplets (not runnable headless):

- `Util: Model Azure Network` — JSON snapshot of network topology (VNets, subnets, peerings, NSGs,
  route tables, NICs). Listed in Canvas under **Exports & Utilities**; output opens in the network viewer.
- `Refresh and update Graph Permissions` — refreshes `graph_permissions.json`; run from its own
  button on the Scans page.
- `Settings: Set tenant ID`, `Settings: Set verbosity mode` — legacy settings droplets, not listed in
  Canvas (Canvas manages tenants and verbosity itself).
- `Example Module: Print Spinner Doodle` — minimal example droplet (type `test`, not listed anywhere).

### Front Door Origin Exposure — live traffic

Unlike the other scans, `Scan: Front Door Origin Exposure` sends live HTTP requests:

- **Always on:** one lightweight, unretried `GET /` per origin, slot, and SCM host, using the
  User-Agent `mnemonic-origin-audit/1.0`, to confirm config-based verdicts against live reachability.
- **Opt-in payload probe (off by default):** sends an XSS-style test string to each origin *and* its
  public Front Door domain to prove a WAF bypass. Enable it with the checkbox that appears on the
  Scans page when this scan is queued, or set `"front_door_probe_payload": true` in `settings.json`.
  This doubles request volume and is far more likely to trip a WAF/IDS and get the scanning IP
  flagged or blocked.

APIM verdicts use the global policy only, so an `x-azure-fdid` check that exists only at API/product
level reads as EXPOSED and needs manual confirmation. Classic Front Door (`Microsoft.Network/frontdoors`)
is flagged but not analyzed. Requires Reader on the subscriptions.

Each scan produces `Finding` objects with a common structure:

- `id`, `title`, `desc`, `severity`, `confidence`
- `objects`, `evidence`, `rec`, `meta`

## Project Layout

```text
SprayCan.py              Launcher — UI, blind, and headless modes (the only CLI entry point)
install.py               Cross-platform installer (Windows / macOS / Linux)
install.sh               Alternative bash installer (Unix only)
install.bat              Alternative batch installer (Windows only)
Droplets/                Scan, settings, and utility droplets
ScanRules/               Rule definitions used by droplets (e.g. Logic App rules)
Objects/                 Core Finding model and droplet runner
util/                    Auth (tokenizer), settings, headless runner, console/status helpers
server/                  Local FastAPI backend for Canvas
frontend/                Canvas React UI (pre-built into frontend/dist/)
output/                  Exported findings JSON and CSVs (tenant-scoped subdirectories)
content/logs/            Droplet error logs (gitignored)
```

## Requirements

- **Python 3.9+**
- **Node.js 18+** and `npm` (only needed to rebuild the frontend; a pre-built `dist/` is committed)

## Install

```bash
python install.py
```

This works on Windows, macOS, and Linux without any pre-setup. It will:

- create `.venv/` with the correct Python
- install Python dependencies from `requirements.txt`
- install and build the frontend (if `npm` is available, otherwise uses the pre-built `dist/`)
- create `output/` if it does not exist

If the venv step fails, the installer prints a platform-specific fix:

| Platform | Common fix |
|---|---|
| Ubuntu/Debian | `sudo apt install python3.X-venv` |
| macOS | `brew install python@3.X` |
| Windows | Re-run the Python installer → Modify → enable pip/venv |

Unix alternative using the bash installer:

```bash
bash install.sh
```

## Running SprayCan

`SprayCan.py` is the only command-line entry point. It has three modes:

| Mode | Command | Behaviour |
|---|---|---|
| UI (default) | `python SprayCan.py` | Starts Canvas and opens `http://127.0.0.1:8787` in your browser |
| Blind | `python SprayCan.py --blind` | Starts Canvas without opening a browser and prints the server URL (SSH / remote use) |
| Headless | `python SprayCan.py --headless ...` | Runs scans from the command line and exits; Canvas never starts |

No venv activation needed — SprayCan re-execs itself under `.venv` automatically if needed.

Server options (UI and blind modes; ignored in headless mode):

```
--blind          Start server without opening a browser (SSH / remote use)
--port PORT      Port to listen on (default: 8787, or SPRAYCAN_SERVER_PORT)
--host HOST      Host to bind to (default: 127.0.0.1)
```

```bash
SPRAYCAN_SERVER_PORT=8811 python SprayCan.py
```

`python SprayCan.py --help` prints every option.

## Headless Mode

Run scans directly from the command line — no Canvas, no browser, scriptable for
cron/CI. Browser-mode auth isn't offered here since it requires a local browser,
which defeats the point of running headless; use SP, Token, or Device Code instead.

### Walkthrough

**1. Install once** (if you haven't already):

```bash
python install.py
```

**2. See which scans are available.** This needs no tenant or credentials:

```bash
python SprayCan.py --list-scans
```

```text
  Available scans:

     1  Scan: Dangling app-reg URLS
     2  Scan: Entra ID State Checks
     ...
     9  Scan: Front Door Origin Exposure
     ...
    12  Scan: Resource Review (All)

  Use --scan <number> (repeatable), --scan all, or --all-scans.
```

**3. Pick how to authenticate.** Every headless run needs `--tenant <tenant-id>` and
`--auth-mode`:

| You have... | Use | You also pass |
|---|---|---|
| An app registration with a client secret | `--auth-mode sp` | `--sp-client-id`, `--sp-client-secret` (or `SPRAYCAN_SP_CLIENT_SECRET`) |
| An `az` CLI login, or tokens from elsewhere | `--auth-mode token` | `--graph-token` and/or `--arm-token` (or their env vars) |
| A user account and any browser, anywhere | `--auth-mode device-code` | nothing — sign in when prompted |

Check the **Needs** column in the [scan table](#what-it-does): some scans need a Graph token,
some an ARM token, some both. SP mode gets both automatically (the SP still needs the Graph
permissions and Reader role). Device code signs in for Graph, then fetches the ARM token silently
from the same sign-in. If that ARM fetch fails, Graph scans still run and ARM scans fail.

**4. Run one or more scans.** Combine `--headless`, the auth options, and one or more `--scan`.
Each `--scan` takes either the **number** shown by `--list-scans` or the **exact scan name**. In
the list above, `Scan: Entra ID State Checks` is number 2, so these two commands are equivalent:

```bash
# By number from --list-scans: quick for interactive use
python SprayCan.py --headless --tenant 00000000-0000-0000-0000-000000000000 \
  --auth-mode device-code --scan 2

# By exact name: stable in scripts, since numbers shift when scans are added or renamed
python SprayCan.py --headless --tenant 00000000-0000-0000-0000-000000000000 \
  --auth-mode device-code --scan "Scan: Entra ID State Checks"
```

Numbers and names can be mixed (`--scan 2 --scan "Scan: PIM State Checks"`), and `--scan all`
or `--all-scans` runs everything.

```text
  [i] Go to https://microsoft.com/devicelogin
  [i] Enter code: ABCD1234

  [i] Waiting for you to complete sign-in...
  [✓] Signed in.

  ⛫💨  SprayCan v0.80 — headless run
  [i] Tenant: 00000000-0000-0000-0000-000000000000
  [i] Auth mode: device-code
  [i] Queue: 1 scan(s)
  ...
  [✓] Scan complete: Scan: Entra ID State Checks

  [✓] All 1 scan(s) completed.
```

**5. Review the results.** Findings land in `output/<tenant-id>/<epoch_ms>.<scan_name>.json`
(plus CSVs under `output/<tenant-id>/csv/` for table-producing scans). Open them in Canvas with
`python SprayCan.py` (or `--blind` on a remote box), or process the JSON directly. Check the exit
code (`echo $?`) in scripts — `0` means every scan succeeded.

### Example commands

**Service principal**

```bash
# A single scan, by name (recommended for scripts — names don't shift, numbers can)
python SprayCan.py --headless --tenant <tenant-id> --auth-mode sp \
  --sp-client-id <client-id> --sp-client-secret <secret> \
  --scan "Scan: PIM State Checks"

# Several scans by number, from --list-scans
python SprayCan.py --headless --tenant <tenant-id> --auth-mode sp \
  --sp-client-id <client-id> --sp-client-secret <secret> \
  --scan 2 --scan 5 --scan 8

# Keep the secret off the command line (shell history, process list): prompt for it instead
read -rsp "SP secret: " SPRAYCAN_SP_CLIENT_SECRET && export SPRAYCAN_SP_CLIENT_SECRET
python SprayCan.py --headless --tenant <tenant-id> --auth-mode sp \
  --sp-client-id <client-id> --all-scans
```

**Tokens from the Azure CLI**

```bash
az login --tenant <tenant-id>
export SPRAYCAN_GRAPH_TOKEN=$(az account get-access-token --resource-type ms-graph --query accessToken -o tsv)
export SPRAYCAN_ARM_TOKEN=$(az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv)

# Everything
python SprayCan.py --headless --tenant <tenant-id> --auth-mode token --all-scans

# ARM-only scans need only the ARM token
python SprayCan.py --headless --tenant <tenant-id> --auth-mode token \
  --scan "Scan: Find Risky NSG Inbound Rules" --scan "Scan: Front Door Origin Exposure"
```

`az` tokens are short-lived (typically about an hour) and SprayCan can't refresh them, so re-run
the `export` lines before each session, and prefer SP mode for long `--all-scans` runs.

PowerShell equivalent for the token variables:

```powershell
$env:SPRAYCAN_GRAPH_TOKEN = az account get-access-token --resource-type ms-graph --query accessToken -o tsv
$env:SPRAYCAN_ARM_TOKEN   = az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv
python SprayCan.py --headless --tenant <tenant-id> --auth-mode token --all-scans
```

**Device code**

```bash
# Identity-focused scans, signing in from your own laptop/phone while SprayCan runs on a remote box
python SprayCan.py --headless --tenant <tenant-id> --auth-mode device-code \
  --scan "Scan: Entra ID State Checks" \
  --scan "Scan: Find T0 Groups with Entra ID and Azure RBAC roles" \
  --scan "Scan: Find risky Service Principals"

# Everything
python SprayCan.py --headless --tenant <tenant-id> --auth-mode device-code --scan all
```

**Scheduled / CI run**

```bash
#!/usr/bin/env bash
# Nightly full scan. Expects TENANT_ID, SP_CLIENT_ID and SPRAYCAN_SP_CLIENT_SECRET
# from the CI secret store.
python SprayCan.py --headless --tenant "$TENANT_ID" --auth-mode sp \
  --sp-client-id "$SP_CLIENT_ID" --all-scans
rc=$?
[ $rc -ne 0 ] && echo "SprayCan headless run failed (exit $rc)" >&2
exit $rc
```

### Options

```
--list-scans                 List scans, numbered for --scan, and exit (no tenant/auth needed)
--headless                   Run scans from the command line and exit
--tenant ID                  Tenant ID to scan (required)
--auth-mode MODE             sp | token | device-code (required)
--sp-client-id ID            Service principal client ID (sp mode)
--sp-client-secret SECRET    SP client secret (sp mode)       env: SPRAYCAN_SP_CLIENT_SECRET
--graph-token TOKEN          Raw Graph access token (token mode) env: SPRAYCAN_GRAPH_TOKEN
--arm-token TOKEN            Raw ARM access token (token mode)   env: SPRAYCAN_ARM_TOKEN
--scan NAME_OR_NUMBER        Scan to run; repeatable (number, exact name, or "all")
--all-scans                  Run every scan droplet (same as --scan all)
```

### Auth modes

- **`sp`** — requires `--sp-client-id` and `--sp-client-secret` (or `SPRAYCAN_SP_CLIENT_SECRET`).
  The credential is validated by fetching a Graph token before any scan runs.
- **`token`** — requires `--graph-token` and/or `--arm-token` (or their env vars). Either one alone
  is accepted; scans needing the missing API will fail.
- **`device-code`** — prints a verification URL and code, then waits until sign-in completes or
  the code expires (Microsoft's limit, about 15 minutes), when the run exits with `1`. Ctrl+C to abort.

### Selecting scans

- `--scan` accepts a number from `--list-scans`, the literal `all`, or an exact, case-sensitive
  droplet name — all repeatable and mixable (e.g. `--scan 2 --scan "Scan: PIM State Checks"`).
- Numbers come from scans sorted by name, so they shift when a scan droplet is added or renamed —
  use names in scripts.
- `--all-scans` / `--scan all` run every scan droplet only (see the table above); settings and
  utility droplets such as `Util: Model Azure Network` can't be run headless.
- `--all-scans` and `--scan` can't be combined.

### Behaviour

- Arguments and scan names are validated first, then authentication, then the queue runs in order.
  A failing scan is logged (with an error-log path under `content/logs/`) and the rest still run.
- Exit codes: `0` all scans succeeded · `1` auth failed, a scan failed, or no scans were found ·
  `2` usage error or unknown scan · `130` interrupted (Ctrl+C).
- Findings are written to `output/<tenant_id>/` exactly as they are from Canvas, so they show up
  in Canvas next time it's opened. To review them on a different machine, see
  [Portability](#portability-transferring-findings-to-another-install).
- After successful authentication, the tenant is saved to `settings.json` as Canvas's current tenant.

### Not available from the CLI

- Verbosity and the Front Door payload probe are read from `settings.json` only (`verbosity`,
  `front_door_probe_payload`) — set them in Canvas or edit the file.
- No options for output location or format.
- `install.py` / `install.sh` / `install.bat` take no command-line arguments.

## Authentication

In Canvas, authentication is handled in the Auth panel on the Scans page, against Microsoft Graph
and Azure Resource Manager. Four modes are available (headless mode offers all but Browser; see
[Auth modes](#auth-modes)):

- **Browser** — interactive Microsoft sign-in via a local browser opened on the machine running
  SprayCan. Only works when you're at the same machine SprayCan runs on.
- **Device Code** — sign in from any browser, on any device — no local browser required on the
  SprayCan host. Click Start, then open the shown URL and enter the code from wherever you have a
  browser (your own PC, phone, etc.), even if SprayCan itself is running on a headless/remote box.
- **SP** — a service principal client ID + secret (Graph application permissions must already be
  consented by an admin in the target tenant).
- **Token** — paste a raw access token or refresh token directly (headless token mode accepts
  access tokens only).

The authenticated token is scoped to the selected tenant. Tenant registrations are cached in
`settings.json`.

## Running Scans

Open Canvas, select or register a tenant, then go to the **Scans** tab.

- Drag scan droplets into the queue and reorder them as needed
- Click **Run** to execute the queue in sequence
- Progress streams live to the output panel
- Completed findings appear in the sidebar under **Scans** automatically

To run scans from the terminal, use [Headless Mode](#headless-mode).

## Output Files

Findings are written to tenant-scoped subdirectories:

```text
output/<tenant_id>/<epoch_ms>.<scan_name>.json
```

Example:

```text
output/a1b2c3d4-0000-0000-0000-000000000000/1743932195123.Scan__Find_T0_Groups_with_Entra_ID_and_Azure_RBAC_roles.json
```

Scans that produce tables (`Scan: Resource Review (All)`, `Scan: External Resource Review`,
`Scan: Front Door Origin Exposure`) also write CSVs to:

```text
output/<tenant_id>/csv/<epoch_seconds>_<scan_label>/*.csv
```

- Each scan run writes its own file, whether started from Canvas or headless
- Tenant ID and generation time are stored in the JSON payload
- Canvas reads these files and groups them by date, tenant, and scan

## Portability: transferring findings to another install

Findings are plain files, so moving them between SprayCan installs is just copying folders. A
common pattern is to **scan headless on one machine** (a jump box, a CI runner, a client
environment) and **review in Canvas on another**.

### How Canvas finds results

Canvas has no import step and no database. Each time the browser asks for the file list, the
server scans `output/` from scratch:

- It looks at **every subfolder of `output/`** and treats the **folder name as the tenant ID**.
  Every `*.json` file inside that folder is listed under that tenant.
- **Files placed directly in `output/` (not in a tenant subfolder) are ignored.** So are
  subfolders inside a tenant folder (such as `csv/`); only CSV downloads use those.
- The file name `<epoch_ms>.<scan_name>.json` gives the run's date for grouping in the sidebar.
  If the name doesn't start with an epoch, the date comes from `generated_at_utc` inside the file.
- A tenant that has files but isn't registered on this install still appears in the tenant
  list, as a discovered tenant. You don't need to register it or sign in to browse its findings.
- A file that isn't valid JSON is still listed, but with no findings.

### What to copy

Copy the **whole tenant folder**, `output/<tenant_id>/`, including its `csv/` subfolder:

```text
output/<tenant_id>/
├── <epoch_ms>.<scan_name>.json      ← findings (one per scan run)
├── <epoch_ms>.<scan_name>.json
└── csv/<epoch>_<scan_label>/*.csv   ← CSV exports, used by Canvas download buttons
```

- **Keep the folder name exactly as the tenant ID.** It's how Canvas groups the files.
- **Keep the file names unchanged.** They carry the run date.
- **Include `csv/` if you want the CSV download buttons to work.** The links are stored as
  paths under `output/` (e.g. `<tenant_id>/csv/...`), so the CSVs must sit at the same relative
  path on the new install. The findings themselves still display without them.
- The `Util: Model Azure Network` snapshot is a JSON file in the same folder, so it moves the
  same way.
- **Don't copy `settings.json`.** It holds that install's tenant registrations and current
  tenant, not findings. No credentials or tokens are ever written to `output/`, so nothing secret
  travels with it except the findings themselves.

### Step by step: headless scan → another install

**1. On the scanning machine,** run headless as usual. Findings go to `output/<tenant_id>/`.

```bash
python SprayCan.py --headless --tenant <tenant-id> --auth-mode sp \
  --sp-client-id <client-id> --all-scans
```

**2. Package the tenant folder** (run from the SprayCan directory):

```bash
# Linux / macOS
tar czf spraycan-<tenant-id>.tgz -C output <tenant-id>
```

```powershell
# Windows (PowerShell)
Compress-Archive -Path output\<tenant-id> -DestinationPath spraycan-<tenant-id>.zip
```

**3. Move the archive** to the reviewing machine (scp, file share, and so on). It contains a
full scan of the tenant's security posture, so handle it as sensitive client data.

**4. On the reviewing install, extract it into `output/`** so you end up with
`output/<tenant-id>/...`:

```bash
# Linux / macOS
tar xzf spraycan-<tenant-id>.tgz -C /path/to/SprayCan/output
```

```powershell
# Windows (PowerShell)
Expand-Archive spraycan-<tenant-id>.zip -DestinationPath C:\path\to\SprayCan\output
```

If `output/<tenant-id>/` already exists, the new files simply sit alongside the existing ones.
Scan files have unique epoch-based names, so nothing is overwritten.

**5. Open Canvas and reload the page.** With Canvas already running, refresh the browser tab:
Canvas fetches the file list when the page loads (and after a scan it ran finishes), not
continuously. No server restart is needed. With Canvas not running, just start it with
`python SprayCan.py`. The tenant appears in the tenant selector with its findings.

### Good to know

- **Renaming a tenant in Canvas edits the files.** It writes a `tenant_name` field into every
  findings file in that tenant's folder. Rename after copying if you want the original files
  left untouched.
- **Removing a tenant in Canvas doesn't delete its files.** It only deregisters the tenant, so
  a tenant with files reappears as discovered. To remove imported results, delete the files
  (from Canvas or on disk).
- **Hand-made or edited files work too,** as long as they follow the findings format
  (`tenant_id`, `generated_at_utc`, `scan_name`, `findings: [...]`) and sit in a tenant folder.
- **The same flow works between two Canvas installs, or from Canvas to headless.** Any install's
  `output/` folder is portable in the same way.

## Canvas

Canvas is the local web UI for reviewing SprayCan findings.

Features:

- Multi-tenant support with tenant selector and rename
- Scan queue with drag-and-drop ordering and live progress streaming
- Findings browser with severity filter and free-text search
- Finding detail view with evidence, recommendations, and primary objects
- Security metrics view for resource overview findings (colour-coded by severity %)
- Azure network topology viewer
- CSV download for metric findings, plus client-side CSV export for any table
- Dark / light mode

Canvas runs entirely locally. It is not a deployed web app.

## Extensibility — writing your own droplet

Droplets are plain Python files, and adding one is deliberately low-effort: **drop a file into
`Droplets/` and it shows up in Canvas and headless mode. No registration, no UI work, and no
changes to the server or frontend are required.**

### How droplets are discovered

- On load, `Objects/Core.py` walks `Droplets/` (subfolders included), imports every `.py` file, and
  instantiates any module-level class named `Droplet`, passing it the file's path.
- A file that fails to import or construct is skipped with a warning; it doesn't break the others.
- Each droplet's `droplet_type` decides where it appears:

| `droplet_type` | Canvas | Headless (`--scan`, `--all-scans`) |
|---|---|---|
| `"scan"` | **Scans** list in the queue builder | Yes |
| `"util"` | **Exports & Utilities** list in the queue builder | No |
| `"settings"`, `"test"` | Not listed | No |

### Minimum contract

A droplet needs a class called `Droplet` with:

- `droplet_name` — the display name, and also the identifier used by `--scan "<name>"`, the Canvas
  queue, output filenames, and the frontend's per-scan rendering. Keep it unique and stable; the
  `Scan: ...` prefix is the convention for scans.
- `droplet_type` — see the table above.
- `droplet_description` (optional but recommended) — shown in Canvas. End it with a `Requires` block
  listing Graph permissions / ARM roles, like the existing droplets.
- `__init__(self, droplet_path)` — store the path; keep it cheap (no network calls), since every
  droplet is instantiated whenever the catalogue loads.
- `run(self)` — does the work, writes its output with `write_findings_to_disk(...)`, and returns the
  findings list. Raising an exception is fine: the runner logs it to `content/logs/`, marks the scan
  failed, and moves on to the next one in the queue.

### A complete example

```python
# Droplets/find_guest_users.py
import util.console as console
import util.http_client as http_client
import util.status as status
import util.tokenizer as tokenizer
from Objects.Core import check_pagination, make_finding, make_object, write_findings_to_disk


class Droplet:
    droplet_name = "Scan: Find Guest Users"
    droplet_type = "scan"
    droplet_path = None
    droplet_description = (
        "Lists guest (B2B) user accounts in the tenant.\n"
        "\n"
        "Requires\n"
        "  Graph : User.Read.All"
    )

    def __init__(self, droplet_path):
        self.droplet_path = droplet_path

    def run(self):
        status.set_phase("Collecting guest users")
        token = tokenizer.get_graph_token()  # works in every auth mode (Browser, Device Code, SP, Token)
        url = "https://graph.microsoft.com/v1.0/users?$filter=userType eq 'Guest'&$select=id,displayName,mail"
        response = http_client.get(url, headers={"Authorization": "Bearer %s" % token})
        if response.status_code != 200:
            raise RuntimeError("Graph returned HTTP %s" % response.status_code)
        body = response.json()
        guests = check_pagination(token, body, body.get("value", []))

        findings = [
            make_finding(
                title="Guest user: %s" % (guest.get("displayName") or guest.get("mail")),
                desc="Guest account `%s` exists in the tenant." % guest.get("mail"),
                severity="low",
                confidence="high",
                objects=[make_object("user", guest.get("id"), guest.get("displayName"), mail=guest.get("mail"))],
                rec="Review whether this guest still needs access.",
                meta={"scan": self.droplet_name},
            )
            for guest in guests
        ]
        console.info("[i] Found %d guest user(s)." % len(findings))
        write_findings_to_disk(findings, source_name=self.droplet_name)
        return findings
```

Save the file and it's ready to use:

- **Headless:** immediately — `python SprayCan.py --list-scans` shows it, and
  `--scan "Scan: Find Guest Users"` runs it.
- **Canvas:** restart `SprayCan.py` once so the new droplet appears in the catalogue (it's read at
  startup). After that, edits to the droplet's code take effect on the next run without a restart,
  because each run re-imports it.

### Building blocks

| Helper | Use it for |
|---|---|
| `tokenizer.get_graph_token()` / `tokenizer.get_arm_token()` | A token for the current tenant and auth mode — never handle credentials yourself |
| `http_client.get/post/get_json` | HTTP with retry, `Retry-After` backoff and ARM throttling handling built in. Returns the response even on error, so check `status_code` |
| `check_pagination(token, body, items)` | Follows Graph `@odata.nextLink` and ARM `nextLink` paging |
| `make_finding(...)` / `make_object(kind, id, name, **extra)` | Build findings and the objects they reference |
| `write_findings_to_disk(findings, source_name=...)` | Writes `output/<tenant>/<epoch_ms>.<name>.json`, which Canvas picks up |
| `write_json_payload_to_disk(payload, source_name=...)` | Writes a non-finding JSON payload (e.g. the network model) |
| `status.set_phase(...)`, `console.info/warn/error/debug(...)` | Progress and log lines, streamed live to Canvas's output panel and the terminal |
| `util.settings` | Read persisted settings from `settings.json` |

Look at the existing droplets in `Droplets/` for fuller patterns (Resource Graph queries,
subscription enumeration, CSV export).

### Findings in Canvas — what you get for free

Every finding renders in Canvas with no frontend changes: title, severity, description,
recommendation, confidence, and the `meta` block. A few conventions improve the default view:

- **Set `meta["scan"] = self.droplet_name`.** Canvas uses it to label the finding's scan; without it
  the finding shows "Unknown scan".
- **`severity`** must be one of `critical`, `high`, `medium`, `low`, `info` (used for colouring and
  filtering).
- **`objects`** whose `type` isn't one Canvas already knows about appear under **Other Objects** as JSON.
- **`evidence`** items are shown as raw JSON by default.
- **Summary metrics:** put `meta["metrics"] = [{"category": ..., "total": N, "checks": [{"label": ...,
  "bad": n, "total": N}]}]` on a finding and Canvas renders the colour-coded metrics view instead of the
  description. Add `"info": True` to a check that isn't a problem, so it isn't coloured as bad.
- **Downloads:** `meta["csv_paths"]` (paths relative to `output/`) adds CSV download buttons, and
  `meta["paste_output"]` adds a collapsible copy-paste text block.

### When you do need UI work (optional)

Only for presentation beyond the defaults. Any frontend change means rebuilding the bundle
(`cd frontend && npm run build`) and committing `frontend/dist/`.

- **Custom evidence rendering:** add a branch to `renderEvidence()` in
  `frontend/src/components/FindingDetailPane.jsx`, keyed on your droplet's name
  (`scan.includes("...")`). The existing branches are the templates. For example, the Front Door branch
  renders `{"type": "app_table", "columns": [...], "rows": [...]}` evidence as a table with CSV export
  with `renderAppTable()`, so reusing that evidence shape gets you a table with a few lines of code.
- **A scan-time option** (a checkbox on the Scans page shown only when your scan is queued, like the
  Front Door payload probe): add a getter/setter in `util/settings.py`, a GET/POST
  `/api/settings/<slug>` endpoint in `server/server.py` returning `{"enabled": bool}`, and an entry in
  `SCAN_TOGGLES` in `frontend/src/components/ScanPage.jsx`. That array's comment lists the steps. The
  droplet reads the setting at the start of `run()`; headless runs use whatever is saved in
  `settings.json`.
- **A whole new view** (like the network topology viewer) is real frontend work. Most droplets don't
  need one.

## Typical Workflow

1. Run `python install.py` once after cloning.
2. Run `python SprayCan.py` — Canvas opens in your browser.
3. Register a tenant ID and authenticate in the Auth panel on the Scans page.
4. Queue and run the scans you need.
5. Review findings by date, tenant, severity, and scan type in the Findings panel.

Headless alternative: run `python SprayCan.py --list-scans`, then `python SprayCan.py --headless ...`
(see [Headless Mode](#headless-mode)), and open Canvas afterwards to review the results.

## Notes

- All execution is local and findings stay on your machine. SprayCan only talks to Microsoft Graph /
  ARM, except `Scan: Front Door Origin Exposure`, which also sends live HTTP requests to discovered
  origins (see above).
- `output/`, `content/logs/`, `settings.json`, `tenant_id_cache.json`, `graph_permissions.json`, `.venv/`, and
  frontend dependencies are gitignored.
- The pre-built `frontend/dist/` is committed so end users do not need Node.js installed.
