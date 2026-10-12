# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems in SprayCan itself.

Report them privately through GitHub instead: go to the repository's **Security** tab and choose
**Report a vulnerability**. Include:

- what the issue is and where it lives (file, endpoint, droplet)
- steps to reproduce, or a proof of concept
- the SprayCan version (`python SprayCan.py --help` prints it) and your OS
- the impact as you see it

SprayCan is maintained on a best-effort basis. You can expect an acknowledgement, a discussion of
the fix, and credit in the release notes if you'd like it. Please give a reasonable window for a
fix before disclosing publicly.

## Supported versions

Only the latest release on `main` receives security fixes.

## Scope

**In scope:** vulnerabilities in SprayCan's own code, for example:

- the local Canvas server (`server/server.py`) and its API
- handling of tokens, credentials and service-principal secrets
- path traversal or file access through findings and CSV endpoints
- the installers and the launcher
- a droplet sending traffic it doesn't document

**Out of scope:**

- misconfigurations SprayCan *finds* in an Azure / Entra tenant (that's the tool working)
- vulnerabilities in Microsoft Graph, Azure Resource Manager or other upstream services
- issues that need an attacker who already controls your user account or machine
- running the server on a non-loopback address (see below), which is unsupported

## Security model: what to know as a user

- **The Canvas API has no authentication.** It's designed to bind to `127.0.0.1` (the
  default). Anyone who can reach the port can start scans with your authenticated session and read
  every finding. **Don't run it with `--host 0.0.0.0`** or on a shared or untrusted host. For
  remote use, keep the default and use an SSH tunnel: `ssh -L 8787:127.0.0.1:8787 <host>`.
- **Credentials.** Tokens and service-principal credentials are kept in process memory and are
  gone when SprayCan exits. One exception: if Browser sign-in can't open a browser, it falls back
  to a device-code credential with a persistent MSAL token cache (named `spraycan`) in your OS user
  profile, and that cache may be stored unencrypted on platforms without a keyring.
- **Findings are sensitive.** `output/` holds a detailed picture of a tenant's security posture.
  Treat it, and any archive of it, as confidential client data. It's gitignored for that reason.
- **Live traffic.** Most scans only call Microsoft Graph and ARM. `Scan: Front Door Origin
  Exposure` also sends HTTP requests to the origins it discovers, identified by the User-Agent
  `SprayCan/<version> (+https://github.com/DroppedSyn/SprayCan)`. Its payload probe, which sends an
  XSS-style test string, is off by default.
