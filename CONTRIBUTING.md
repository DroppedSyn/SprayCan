# Contributing to SprayCan

Thanks for helping out. New scan modules (droplets) are the most valuable contribution, and adding
one is usually a single Python file.

## Ground rules

- **Only test against tenants you're authorised to assess.** Never include real tenant IDs,
  object IDs, tokens, secrets, findings or client names in code, comments, issues or pull requests.
  Use placeholders such as `00000000-0000-0000-0000-000000000000`.
- **Security issues go through [SECURITY.md](SECURITY.md)**, not public issues.
- By submitting a contribution, you agree it's licensed under the project's
  [Apache License 2.0](LICENSE) (section 5). No separate CLA is needed.

## Development setup

```bash
git clone https://github.com/DroppedSyn/SprayCan.git
cd SprayCan
python install.py          # creates .venv, installs Python deps, builds the frontend if npm exists
python SprayCan.py         # Canvas on http://127.0.0.1:8787
```

- Python 3.9+. Node.js 18+ is only needed if you change the frontend.
- Frontend dev server with hot reload: run `python SprayCan.py --blind` for the backend, then
  `cd frontend && npm run dev`. Vite serves on http://127.0.0.1:4173 and proxies `/api` to the
  backend on port 8787 (or `SPRAYCAN_SERVER_PORT`).

## Writing a droplet

Start with the README's [Extensibility](README.md#extensibility--writing-your-own-droplet)
section. It has the contract, a complete working example and the helper table. If you work with a
coding agent, have it read [AGENTS.md](AGENTS.md) first: it's the same material condensed for agents,
plus a template, an offline test harness and a PR checklist. In short:

1. Add `Droplets/<your_scan>.py` with a `class Droplet` defining `droplet_name`, `droplet_type`,
   `droplet_description`, `__init__(self, droplet_path)` and `run(self)`.
2. Test it headless: `python SprayCan.py --list-scans`, then
   `python SprayCan.py --headless --tenant <id> --auth-mode device-code --scan "<droplet_name>"`.
3. Restart Canvas once and check the findings render sensibly.

### Conventions

- **Name scans `Scan: …` and keep the name stable.** It's the identifier for `--scan`, the Canvas
  queue, output file names and frontend rendering.
- **Set `meta["scan"] = self.droplet_name`** on every finding.
- **Use the five severities:** `critical`, `high`, `medium`, `low`, `info`.
- **Document permissions** in a `Requires` block at the end of `droplet_description`: the Graph
  permissions and ARM roles the scan needs.
- **Go through `tokenizer` and `http_client`** for tokens, retries, throttling and pagination. No
  hand-rolled auth or raw `requests` calls to Graph / ARM.
- **Fail loudly** on unexpected API errors. The runner logs the exception and continues with the
  next scan.
- **Anything beyond Graph / ARM calls is opt-in.** If a droplet sends traffic to other hosts,
  document it in the description and README, use `util.version.USER_AGENT`, and keep anything
  intrusive off by default.
- **Keep `__init__` cheap.** Every droplet is instantiated whenever the catalogue loads.

## Frontend changes

Canvas is a React 18 + Vite app in `frontend/`. The built bundle in `frontend/dist/` is committed so
users don't need Node.js, so:

```bash
cd frontend && npm run build
```

and **commit the updated `frontend/dist/`** together with your source changes.

## Pull requests

- Keep each PR focused: one droplet or one fix.
- Describe what it does, which permissions it needs, and how you tested it (headless and/or Canvas).
- Update the README when you add a scan (scan table and **Needs** column) or change CLI behaviour.
- Don't commit generated or local files: `output/`, `settings.json`, `.venv/`, logs, or anything
  else in `.gitignore`.
- Versions are bumped in `util/version.py` (the single source of truth) by the maintainer at release
  time, so you don't need to touch it.
