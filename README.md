# Snyk Platform Health Check

A read-only script that calls the Snyk REST and V1 APIs to verify your platform is
configured properly, and prints a YES / NO / ERR report grouped into **Platform**,
**Group-level**, and **Org-level** checks.

It follows the Snyk account model **Tenant → Group → Org**: it resolves one tenant
(prompting if you can access several), then checks only the groups and orgs that
belong to that tenant.

The script is **safe to run against production** — every API call is a `GET`,
nothing is created, modified, or deleted. It always exits `0` (it's a report, not a
CI gate); a non-zero exit means the script itself failed to run.

---

## 1. Prerequisites — install `uv`

[`uv`](https://docs.astral.sh/uv/) manages the Python version and dependencies for
you. The script declares its own dependencies inline (PEP 723), so you do **not**
need to create a virtualenv or `pip install` anything.

**macOS / Linux**
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

**Homebrew (macOS)**
```bash
brew install uv
```

**Windows (PowerShell)**
```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Verify:
```bash
uv --version
```

That's all the setup required. The first `uv run` will automatically download a
compatible Python (>= 3.12) and install the script's dependencies (`httpx`, `rich`)
into an isolated, cached environment.

---

## 2. Get a Snyk API token

The script needs a token with Tenant Admin User that provides **group-level visibility** (it starts from
`GET /groups`). A token scoped to a single org will return no groups.

- **Personal token** — Snyk → avatar → **Account settings** → **General → API Token** --> Key (click to show the key)

---

## 3. Configure environment variables

| Variable | Required | Description |
|---|---|---|
| `SNYK_TOKEN` | **Yes** | API key or OAuth bearer token |
| `SNYK_TENANT_ID` | No | Pre-select a tenant (skips the interactive prompt; required for non-interactive/CI runs when you can access more than one tenant) |
| `SNYK_API_BASE` | No | API base URL. Defaults to `https://api.snyk.io` (US). Use your region's base otherwise |
| `SNYK_DEBUG` | No | Set to `1` to print every non-200 API response (and per-check diagnostics) — useful when a check is unexpectedly NO/ERR |

**Regional API bases:**

| Region | `SNYK_API_BASE` |
|---|---|
| US (default) | `https://api.snyk.io` |
| EU | `https://api.eu.snyk.io` |
| AU | `https://api.au.snyk.io` |

Example:
```bash
export SNYK_TOKEN="your-token-here"
# export SNYK_API_BASE="https://api.eu.snyk.io"                  # optional, non-US
```

---

## 4. Run the script

```bash
uv run snyk_healthcheck.py
```

`uv` resolves the inline dependencies and runs it. If you can access multiple
tenants, you'll be prompted to pick one.

### Debug mode

If a check is unexpectedly NO or ERR, re-run with debug to see the raw API
responses behind each call:
```bash
SNYK_DEBUG=1 uv run snyk_healthcheck.py
```

---

## 5. Troubleshooting

### TLS certificate error (`invalid peer certificate: UnknownIssuer`)

If `uv` fails while resolving dependencies with an error like:

```
error: Request failed after 3 retries
  Caused by: invalid peer certificate: UnknownIssuer
```

this is almost always a **corporate proxy / VPN** (Zscaler, Netskope, etc.)
intercepting TLS with a CA that `uv`'s bundled trust store doesn't recognize.

**Fix — tell `uv` to use the operating system's trust store:**
```bash
uv run --native-tls snyk_healthcheck.py
```

If `--native-tls` alone isn't enough, point `uv` at your corporate CA bundle
explicitly (ask IT for the `.pem`, or export it from the OS keychain):
```bash
# macOS — export the system roots once:
security find-certificate -a -p /Library/Keychains/System.keychain > ~/corp-ca.pem

export SSL_CERT_FILE=~/corp-ca.pem
export UV_NATIVE_TLS=1
uv run --native-tls snyk_healthcheck.py
```

You can make native TLS the default for the session so you don't have to pass the
flag each time:
```bash
export UV_NATIVE_TLS=1
uv run snyk_healthcheck.py
```

> Note: `--native-tls` only affects how `uv` downloads dependencies. The script's
> own API calls go out over `httpx`, which uses its own trust store and is
> unaffected by this flag. If the proxy also intercepts `api.snyk.io`, the
> `API Reachable` check may report a certificate error — in that case the proxy CA
> needs to be trusted system-wide.

### Dependencies already cached — run offline

Once the dependencies have been downloaded once, you can skip the network entirely
(handy if the TLS issue is intermittent):
```bash
uv run --offline snyk_healthcheck.py
```

### `Groups Configured` is ERR / no groups found

- The token lacks group-level access — use a token or service account with group
  visibility.
- You're pointed at the wrong region — set `SNYK_API_BASE` to your tenant's region.

### Multiple tenants in a non-interactive shell

If you can access more than one tenant and run in CI (no TTY), the script can't
prompt. Set `SNYK_TENANT_ID` to choose one.

---

## 6. Reading the report

- Output is split into **Platform**, **Group-Level Checks**, and **Org-Level Checks**
  sections, each with its own table and a `yes · no · err` subtotal, plus an overall
  summary line.
- **Status** column:
  - `YES` — the configuration item is present / enabled for at least one Group or Org
  - `NO` — not present / not enabled for all Groups or Org
  - `ERR` — the API call genuinely failedand response with Errors (auth, 4xx, 5xx, network) — not the same as NO
- The **Detail** column names the orgs involved. To keep lines readable it lists up to **3 Orgs or Groups** per check (`+N more`); re-run with `SNYK_DEBUG=1` to see full data.

---

## 7. Maintaining the script

API endpoints and versions are defined as constants at the top of
`snyk_healthcheck.py` (the `EP_*` paths and `REST_VERSION*` values). If Snyk changes
a path or version, update it there — no other code changes are needed.
