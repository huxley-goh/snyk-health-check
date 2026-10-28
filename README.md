# Snyk Platform Health Check

A read-only script that calls the Snyk REST and V1 APIs to verify your platform is
configured properly, and prints a YES / NO / ERR report grouped into **Platform**,
**Group-level**, and **Org-level** checks.

It follows the Snyk account model **Tenant → Group → Org**: it resolves one tenant
(prompting if you can access several), then one group within that tenant (prompting
if it has several), and checks only the orgs that belong to that group.

The script is **safe to run against production** — every API call is a `GET`,
nothing is created, modified, or deleted. It always exits `0` (it's a report, not a
CI gate); a non-zero exit means the script itself failed to run.

---

## ⚠️ IMPORTANT — please read before relying on the results

This script performs **surface-level checks only**. For org-level checks, a feature
is reported as enabled (`YES`) when it is configured for **at least one** org within
the selected Group — **it does not mean every org in the Group has that feature
enabled**, and the result does **not** represent the full state of all orgs.

The purpose of this report is to give a **general indication** of whether you have
adopted certain recommended features, and that they are in use **to some extent**.
It is a fast way to spot likely gaps so you can take **targeted action** and
**accelerate the overall health-check process** — not a definitive audit.

**At the end of the day, you must log in to your Snyk portal to identify and
investigate the actual gaps** before drawing conclusions or making changes. Treat
this output as a starting point, not the final word.

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
| `SNYK_GROUP_ID` | No | Pre-select a group (skips the interactive prompt; required for non-interactive/CI runs when the tenant has more than one group) |
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
tenants, you'll be prompted to pick one; then, if the tenant has more than one
group, you'll be prompted to pick a group to check.

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

Newer `uv` releases deprecate `--native-tls` in favour of `--system-certs`; use that
flag if you see the deprecation warning. It also needs `SSL_CERT_FILE` pointing at the
exported CA bundle (above) when your proxy CA isn't in the system trust store.

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

### A feature shows `NO` / `N/A` but it is enabled in the Snyk portal

Applies to **Snyk Agent Fix**, **OS Reachability**, **Snyk Secrets** and
**Universal Broker for OS**. Agent Fix, Reachability and Secrets are read **per org**
(there is no group-level endpoint for them); the Detail column says why:

| Detail shows | Meaning |
|---|---|
| `on 37/40 orgs; off: OrgA, OrgB` | Genuinely off in those orgs. Group rollups need **every** org on. |
| `flag not returned by API` / status `N/A` | The API answered but does not include the setting, so its state is unknown (not "off"). Verify in the portal. |
| `HTTP 403 x40` / `HTTP 404 x40` | The call was refused or the endpoint isn't served to the token/tenant — **not** "off". |
| `ERR` with `HTTP 5xx` | A real API failure — re-run. |

Known API limitations (confirmed against the live API):

- **Snyk Agent Fix** — `GET /orgs/{id}/settings/sast` returns only `sast_enabled`; the
  `autofix_enabled` field is never returned at any API version, so the check reports `N/A`
  unless Snyk starts returning it.
- **OS Reachability / Snyk Secrets** — the published specs list these as beta-only, but the
  live API serves them at the GA version and returns 404 for `~beta`. The script tries the GA
  version first and falls back to `~beta`.
- **Universal Broker for OS** — read from `GET /groups/{id}/settings/opensource/broker`
  (`data.enabled`). It was confirmed to match the portal toggle for a group where it is off.

For the raw per-org values, re-run with `SNYK_DEBUG=1`; each feature check then prints
a line such as `DEBUG os_reachability id=<org-id> HTTP 200 -> True`.

### `Groups Configured` is ERR / no groups found

- The token lacks group-level access — use a token or service account with group
  visibility.
- You're pointed at the wrong region — set `SNYK_API_BASE` to your tenant's region.

### Multiple tenants or groups in a non-interactive shell

If you can access more than one tenant and run in CI (no TTY), the script can't
prompt. Set `SNYK_TENANT_ID` to choose one. Likewise, if the selected tenant has
more than one group, set `SNYK_GROUP_ID` to choose the group to check.

---

## 6. Reading the report

- Output is split into **Platform**, **Group-Level Checks**, and **Org-Level Checks**
  sections, each with its own table and a `yes · no · err` subtotal, plus an overall
  summary line.
- **Status** column:
  - `YES` — the configuration item is present / enabled for at least one Group or Org
  - `NO` — not present / not enabled for all Groups or Org
  - `ERR` — the API call genuinely failedand response with Errors (auth, 4xx, 5xx, network) — not the same as NO
    A failed call is never reported as `NO`: if an org or group could not be read (for example HTTP 403
    or 500), the row shows `ERR` and the Detail names the HTTP status, because an API failure is not
    evidence that a setting is off.
  - `N/A` — the setting **cannot be read from the Snyk API** (it is simply not returned), so the script
    makes no claim either way. Check it in the Snyk portal. `N/A` rows are not counted as configured or
    not configured in the overall score.
- The **Detail** column names the orgs involved. To keep lines readable it lists up
  to **3 Orgs or Groups** per check, followed by `+N more` when there are others.

> **Note — the 3-org limit is display-only.** The names shown in the Detail column
> are a readable sample, **not** the total. Every check still evaluates **all** orgs
> in the selected group; the `YES` / `NO` / `ERR` status always reflects the full
> set. The `+N more` suffix tells you how many additional orgs matched beyond the
> three listed (e.g. `with PR checks: A, B, C +5 more` means **8** orgs qualified,
> not 3).

---

## 7. Maintaining the script

API endpoints and versions are defined as constants at the top of
`snyk_healthcheck.py` (the `EP_*` paths and `REST_VERSION*` values). If Snyk changes
a path or version, update it there — no other code changes are needed.

**REST first.** The script uses the Snyk REST API wherever one exists, and falls back
to V1 only where the API specs expose no REST equivalent. The V1 calls that remain
are: org integrations, integration settings (PR checks / fix PRs / auto dependency
upgrade / PR code and secrets tests), org ignore settings, org notification
settings, and org entitlements. When Snyk adds REST equivalents, switch these over.

**Pagination.** REST list endpoints return only 10 items per page by default. The
script requests 100 per page and follows every `links.next` page, so tenants, groups,
orgs, service accounts and projects are never silently truncated.

**Scan freshness.** Only Open Source and Code (SAST) projects are assessed. Container, IaC and
Snyk Secrets projects are excluded (`EXCLUDED_SCAN_TYPES` in the script), and deactivated projects
(`status: inactive`) are skipped since they are intentionally not scanned; the Detail column notes
how many were skipped. The stale/fresh decision was checked against Snyk's own `lastTestedDate`
on a live tenant and agreed on every sampled project.
