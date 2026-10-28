# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "httpx>=0.27",
#   "rich>=13",
# ]
# ///

"""
Snyk Platform Health Check
Run with: uv run snyk_healthcheck.py

Account model: Tenant → Group → Org. The script resolves one tenant
(prompting if several are accessible), then one group within that tenant
(prompting if several exist), and checks only the orgs that belong to
that group.

Required env vars:
  SNYK_TOKEN     — API key or OAuth bearer token

Optional:
  SNYK_TENANT_ID — pre-select a tenant (skips the prompt; useful for CI)
  SNYK_GROUP_ID  — pre-select a group  (skips the prompt; useful for CI)
  SNYK_API_BASE  — defaults to https://api.snyk.io
  BROKER_URL     — if set, broker connectivity is checked
"""

import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse, parse_qs

import httpx
from rich.console import Console
from rich.table import Table
from rich import box

# ── API Endpoints ──────────────────────────────────────────────────────────────
# Update paths here if Snyk changes their API structure.

REST_VERSION                 = "2024-10-15"
REST_VERSION_BETA            = "2024-10-15~beta"   # opensource settings is beta-only
# The published specs list the opensource + secrets org settings as beta-only, but the
# live API serves them at the GA version and returns 404 for the "~beta" spelling.
# Try GA first and fall back to beta so tenants/regions that lag behind still work.
REST_VERSIONS_OS_SETTINGS    = [REST_VERSION, REST_VERSION_BETA]
REST_VERSIONS_SECRETS        = [REST_VERSION, REST_VERSION_BETA]
REST_VERSION_PROJECTS        = "2024-05-31"        # projects endpoint GA version
REST_VERSION_SAST            = "2023-06-22"        # sast settings endpoint GA version
REST_VERSION_AUDIT           = "2024-04-29"        # audit_logs/search endpoint GA version
REST_VERSION_GROUPS          = "2023-01-30~beta"   # /groups, /groups/{id}, sso_connections are beta-only
REST_VERSIONS_SSO            = [REST_VERSION, REST_VERSION_GROUPS]   # GA first, then the beta pin

# Snyk REST list endpoints require limit to be >= 10 and a multiple of 10.
REST_MIN_LIMIT               = 10

EP_OPENAPI                   = "/openapi"
EP_TENANTS                   = "/tenants"
EP_GROUPS                    = "/groups"
EP_GROUP                     = "/groups/{group_id}"
EP_GROUP_ORGS                = "/groups/{group_id}/orgs"
EP_GROUP_SERVICE_ACCOUNTS    = "/groups/{group_id}/service_accounts"     # REST (note underscore)
EP_GROUP_AUDIT_LOGS          = "/groups/{group_id}/audit_logs/search"    # REST (underscore)
EP_GROUP_SSO_CONNECTIONS     = "/groups/{group_id}/sso_connections"      # REST
EP_GROUP_MEMBERSHIPS         = "/groups/{group_id}/memberships"          # REST
EP_GROUP_OS_BROKER           = "/groups/{group_id}/settings/opensource/broker"  # REST (GA)
EP_ORG_INTEGRATIONS          = "/org/{org_id}/integrations"
EP_ORG_INTEGRATION_SETTINGS  = "/org/{org_id}/integrations/{int_id}/settings"
EP_ORG_NOTIFICATION_SETTINGS = "/org/{org_id}/notification-settings"
EP_ORG_ENTITLEMENTS          = "/org/{org_id}/entitlements"             # V1
EP_ORG_SETTINGS              = "/org/{org_id}/settings"                 # V1
EP_ORG_SERVICE_ACCOUNTS      = "/orgs/{org_id}/service_accounts"        # REST
EP_ORG_BROKER_CONNECTIONS    = "/orgs/{org_id}/brokers/connections"     # REST (Universal Broker)
EP_ORG_SAST_SETTINGS         = "/orgs/{org_id}/settings/sast"           # REST
EP_ORG_SECRETS_SETTINGS      = "/orgs/{org_id}/settings/secrets"        # REST (beta)
EP_ORG_OPENSOURCE_SETTINGS   = "/orgs/{org_id}/settings/opensource"     # REST (beta)
EP_ORG_PROJECTS              = "/orgs/{org_id}/projects"
EP_ORG_TARGETS               = "/orgs/{org_id}/targets"                  # REST

# Project origins that represent a CI/CLI import (vs SCM).
CLI_ORIGINS = ["cli"]

SCM_ORIGINS = [
    "github", "github-enterprise", "gitlab", "gitlab-enterprise",
    "bitbucket-cloud", "bitbucket-server", "azure-repos",
]

SCM_TYPES = set(SCM_ORIGINS)

# Target `source_types` values that represent a repository SCM integration
# (GitHub / GitLab / Bitbucket / Azure DevOps and their app variants).
SCM_SOURCE_TYPES = [
    "github", "github-enterprise", "github-cloud-app", "github-server-app",
    "gitlab",
    "bitbucket-cloud", "bitbucket-server", "bitbucket-connect-app",
    "azure-repos",
]

# Project `type` values to EXCLUDE from scan-freshness (container, IaC and Secrets scans).
# Everything else (package managers + "sast") counts as Open Source or Code Analysis.
# "secrets" is a separate product: on a live tenant it was 8 of the 9 projects flagged
# stale, which made the OSS/Code freshness check report NO for the wrong reason.
EXCLUDED_SCAN_TYPES = {
    "dockerfile", "deb", "apk", "linux", "rpm",                 # container
    "terraformconfig", "cloudformationconfig", "k8sconfig",
    "armconfig", "helmconfig", "cloudconfig", "iac",            # IaC
    "secrets",                                                  # Snyk Secrets
}

SCAN_FRESHNESS_DAYS = 14

# ── Config ─────────────────────────────────────────────────────────────────────

TOKEN         = os.environ.get("SNYK_TOKEN", "")
TENANT_ID_ENV = os.environ.get("SNYK_TENANT_ID", "")
GROUP_ID_ENV  = os.environ.get("SNYK_GROUP_ID", "")
API_BASE      = os.environ.get("SNYK_API_BASE", "https://api.snyk.io")
BROKER_URL    = os.environ.get("BROKER_URL", "")
DEBUG         = bool(os.environ.get("SNYK_DEBUG"))   # set to surface non-200 API responses

if not TOKEN:
    print("ERROR: Set SNYK_TOKEN env var.")
    sys.exit(1)

HEADERS = {
    "Authorization": f"token {TOKEN}",
    "Content-Type":  "application/json",
}

console = Console()

# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _debug(api: str, path: str, status: int, body: Any) -> None:
    """When SNYK_DEBUG is set, print non-200 responses to aid diagnosis."""
    if DEBUG and status != 200:
        snippet = str(body)[:160]
        console.print(f"[dim yellow]  DEBUG {api} {status} {path} — {snippet}[/dim yellow]")

def get_rest(path: str, params: dict | None = None) -> tuple[int, Any]:
    p = {"version": REST_VERSION, **(params or {})}
    try:
        r = httpx.get(f"{API_BASE}/rest{path}", headers=HEADERS, params=p, timeout=15)
        body = r.json() if r.content else {}
        _debug("REST", path, r.status_code, body)
        return r.status_code, body
    except Exception as exc:
        if DEBUG:
            console.print(f"[dim yellow]  DEBUG REST ERR {path} — {exc}[/dim yellow]")
        return 0, {"error": str(exc)}

# API policy: prefer REST. V1 is used only where the Snyk specs expose no REST
# equivalent — org integrations + integration (PR/fix/dep-upgrade) settings, org
# ignore settings, org notification settings, and org entitlements.

def get_v1(path: str) -> tuple[int, Any]:
    try:
        r = httpx.get(f"{API_BASE}/v1{path}", headers=HEADERS, timeout=15)
        body = r.json() if r.content else {}
        _debug("V1", path, r.status_code, body)
        return r.status_code, body
    except Exception as exc:
        if DEBUG:
            console.print(f"[dim yellow]  DEBUG V1 ERR {path} — {exc}[/dim yellow]")
        return 0, {"error": str(exc)}

# Per-run response cache so checks that need the same endpoint share one call.
# Transport failures / 429 / 5xx are never cached, so a later check can retry.
_response_cache: dict[tuple, tuple[int, Any]] = {}

def _cache_get(key: tuple, fetch) -> tuple[int, Any]:
    if key in _response_cache:
        return _response_cache[key]
    status, body = fetch()
    if not (status == 0 or status == 429 or status >= 500):
        _response_cache[key] = (status, body)
    return status, body

def get_rest_cached(path: str, params: dict | None = None) -> tuple[int, Any]:
    key = ("rest", path, tuple(sorted((params or {}).items())))
    return _cache_get(key, lambda: get_rest(path, params))

def get_v1_cached(path: str) -> tuple[int, Any]:
    return _cache_get(("v1", path), lambda: get_v1(path))

def get_rest_first_version(path: str, versions: list[str]) -> tuple[int, Any]:
    """GET `path`, trying each API version in turn while the answer is 404.

    A 404 on a versioned REST path means "that version is not served for this
    endpoint", so the next version is tried. Any other status (200, 403, 5xx, ...)
    is returned as-is; if every version 404s the last 404 is returned.
    """
    status, body = 404, {}
    for version in versions:
        status, body = get_rest_cached(path, params={"version": version})
        if status != 404:
            break
    return status, body

def _next_cursor(links: dict) -> str | None:
    """Extract the `starting_after` cursor from a REST `links.next` URL."""
    nxt = links.get("next") if isinstance(links, dict) else None
    if not nxt:
        return None
    return parse_qs(urlparse(nxt).query).get("starting_after", [None])[0]

def get_rest_all(path: str, params: dict | None = None) -> tuple[int, list]:
    """GET every page of a REST list endpoint and return (status, all `data` items).

    REST list endpoints default to 10 results per page, so a single call silently
    truncates larger collections. This requests 100 per page and follows
    `links.next`. If any page fails, that page's status is returned (with the
    items gathered so far) so callers can treat the result as an error.
    """
    items: list = []
    cursor = None
    for _ in range(50):  # safety cap: 50 pages * 100 = 5000 items
        p = {"limit": 100, **(params or {})}
        if cursor:
            p["starting_after"] = cursor
        status, body = get_rest(path, params=p)
        if status != 200:
            return status, items
        items.extend(body.get("data", []))
        cursor = _next_cursor(body.get("links", {}))
        if not cursor:
            break
    return 200, items

# ── Check result type ──────────────────────────────────────────────────────────
# Each check returns: (check_name, status, detail)
# status is one of: "YES", "NO", "ERROR", "NA" (setting not exposed by the API)

CheckResult = tuple[str, str, str]

# ── Discovery (Tenant → Group → Org) ────────────────────────────────────────────

def fetch_tenants() -> dict[str, str]:
    """Return {tenant_id: tenant_name} for every tenant the token can access."""
    status, items = get_rest_all(EP_TENANTS)
    if status != 200:
        return {}
    return {
        t["id"]: t.get("attributes", {}).get("name", t["id"])
        for t in items
        if "id" in t
    }

def select_tenant(tenants: dict[str, str]) -> tuple[str, str] | None:
    """Resolve the tenant to check.

    Env override wins; a single tenant is auto-selected; several prompt the user.
    Returns (tenant_id, tenant_name) or None if it cannot be resolved.
    """
    if TENANT_ID_ENV:
        if TENANT_ID_ENV in tenants:
            return TENANT_ID_ENV, tenants[TENANT_ID_ENV]
        console.print(f"[red]SNYK_TENANT_ID '{TENANT_ID_ENV}' is not among accessible tenants.[/red]")
        return None
    if not tenants:
        return None
    if len(tenants) == 1:
        return next(iter(tenants.items()))

    items = list(tenants.items())
    console.print("\n[bold]Multiple tenants accessible — select one:[/bold]")
    for i, (tid, tname) in enumerate(items, 1):
        console.print(f"  [cyan]{i}[/cyan]. {tname} [dim]({tid})[/dim]")
    if not sys.stdin.isatty():
        console.print("[red]Non-interactive shell — set SNYK_TENANT_ID to choose a tenant.[/red]")
        return None
    while True:
        try:
            choice = input("Enter number: ").strip()
        except EOFError:
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(items):
            return items[int(choice) - 1]
        console.print("[red]Invalid selection — try again.[/red]")

def select_group(groups: dict[str, str]) -> tuple[str, str] | None:
    """Resolve the group to check within the selected tenant.

    Env override wins; a single group is auto-selected; several prompt the user.
    Returns (group_id, group_name) or None if it cannot be resolved.
    """
    if GROUP_ID_ENV:
        if GROUP_ID_ENV in groups:
            return GROUP_ID_ENV, groups[GROUP_ID_ENV]
        console.print(f"[red]SNYK_GROUP_ID '{GROUP_ID_ENV}' is not among groups in this tenant.[/red]")
        return None
    if not groups:
        return None
    if len(groups) == 1:
        return next(iter(groups.items()))

    items = list(groups.items())
    console.print("\n[bold]Multiple groups in tenant — select one:[/bold]")
    for i, (gid, gname) in enumerate(items, 1):
        console.print(f"  [cyan]{i}[/cyan]. {gname} [dim]({gid})[/dim]")
    if not sys.stdin.isatty():
        console.print("[red]Non-interactive shell — set SNYK_GROUP_ID to choose a group.[/red]")
        return None
    while True:
        try:
            choice = input("Enter number: ").strip()
        except EOFError:
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(items):
            return items[int(choice) - 1]
        console.print("[red]Invalid selection — try again.[/red]")

def _group_tenant_id(group: dict) -> str | None:
    """Extract the tenant id a group belongs to from its relationships."""
    data = group.get("relationships", {}).get("tenant", {}).get("data") or {}
    return data.get("id")

def fetch_groups(tenant_id: str) -> dict[str, str]:
    """Return {group_id: group_name} for groups belonging to the given tenant.

    GET /groups lists all groups across all tenants (every page is fetched), so we
    filter client-side on each group's tenant relationship. The list payload omits
    that relationship, so fall back to the per-group detail endpoint.
    """
    status, items = get_rest_all(EP_GROUPS, params={"version": REST_VERSION_GROUPS})
    if status != 200:
        return {}
    groups: dict[str, str] = {}
    for g in items:
        gid = g.get("id")
        if not gid:
            continue
        g_tenant = _group_tenant_id(g)
        if g_tenant is None:
            d_status, d_body = get_rest(EP_GROUP.format(group_id=gid),
                                        params={"version": REST_VERSION_GROUPS})
            if d_status == 200:
                g_tenant = _group_tenant_id(d_body.get("data", {}))
        if g_tenant == tenant_id:
            groups[gid] = g.get("attributes", {}).get("name", gid)
    return groups

def fetch_orgs(group_id: str) -> dict[str, str]:
    """Return {org_id: org_name} for every org in the given group (all pages)."""
    status, items = get_rest_all(EP_GROUP_ORGS.format(group_id=group_id))
    if status != 200:
        return {}
    return {
        o["id"]: o.get("attributes", {}).get("name", o["id"])
        for o in items
        if "id" in o
    }

# ── Individual checks ──────────────────────────────────────────────────────────

def _org_list(names: list[str], cap: int = 3) -> str:
    """Comma-join org names, capping long lists (max 3 per detail line)."""
    if len(names) <= cap:
        return ", ".join(names)
    return ", ".join(names[:cap]) + f" +{len(names) - cap} more"

def _grp(names: list[str]) -> str:
    """'Group: A' / 'Groups: A, B, C +2 more' — names the group(s) behind a YES."""
    return f"{'Group' if len(names) == 1 else 'Groups'}: {_org_list(names)}"

# An org-level yes/no lookup returns (answer, http_status). `answer` is None when the
# API call failed (non-200), so "could not read" is never mistaken for "no".
OrgProbe = tuple[bool | None, int]

def _probe(status: int, answer) -> OrgProbe:
    """(answer(), status) for a 200 response, else (None, status)."""
    return (bool(answer()), status) if status == 200 else (None, status)

def _any_org(name: str, orgs: dict[str, str], org_predicate,
             ok_word: str, none_detail: str) -> CheckResult:
    """Any-org rollup: YES if at least one org satisfies `org_predicate`.

    `org_predicate(org_id)` returns an OrgProbe. Names the passing orgs (and the
    failing ones) in the detail. If no org qualifies but some could not be read,
    the result is ERROR (not NO): an API failure is not evidence that nothing is set.
    """
    if not orgs:
        return name, "ERROR", "No orgs found"
    passing, failing, errors = [], [], []
    for org_id, org_name in orgs.items():
        answer, status = org_predicate(org_id)
        if answer is True:
            passing.append(org_name)
        elif answer is False:
            failing.append(org_name)
        else:
            errors.append((org_name, status))
    if passing:
        return name, "YES", f"{ok_word}: {_org_list(passing)}"
    if errors:
        rest = f"; not set in {len(failing)} other org(s)" if failing else ""
        return name, "ERROR", (f"Could not read {_org_list([n for n, _ in errors])} "
                               f"({_http_summary([st for _, st in errors])}){rest}")
    return name, "NO", f"{none_detail}: {_org_list(failing)}"

def check_api_reachability() -> CheckResult:
    status, body = get_rest(EP_OPENAPI)
    if status == 200:
        return "API Reachable", "YES", f"Connected to {API_BASE}"
    return "API Reachable", "ERROR", f"HTTP {status} — {body.get('error', 'unreachable')}"

def check_groups_exist(groups: dict[str, str]) -> CheckResult:
    """YES if at least one group was returned by the API."""
    if groups:
        names = ", ".join(groups.values())
        return "Groups Configured", "YES", f"{len(groups)} group(s) found — {names}"
    return "Groups Configured", "ERROR", "No groups returned — check token permissions"

def check_orgs_in_groups(groups: dict[str, str], orgs: dict[str, str],
                         group_orgs: dict[str, dict[str, str]] | None = None) -> CheckResult:
    """YES if at least one org exists in the selected group(s)."""
    if orgs:
        with_orgs = [name for gid, name in groups.items() if (group_orgs or {}).get(gid)] \
            or list(groups.values())
        return ("Orgs in Group", "YES",
                f"{len(orgs)} org(s) across {len(groups)} group(s) — {_grp(with_orgs)}")
    return "Orgs in Group", "NO", f"No orgs found across {len(groups)} group(s)"

def check_group_members(groups: dict[str, str]) -> CheckResult:
    """YES only if every group has at least 2 members.

    A group with a single member is a single point of failure for admin access,
    so any group below the threshold makes this NO.
    """
    if not groups:
        return "Group Members (>=2)", "ERROR", "No groups found"
    short, errors = [], 0
    for group_id, group_name in groups.items():
        status, body = get_rest(EP_GROUP_MEMBERSHIPS.format(group_id=group_id),
                                params={"limit": 100})
        if status != 200:
            errors += 1
            continue
        count = len(body.get("data", []))
        if count < 2:
            short.append(f"{group_name} ({count})")
    if short:
        return "Group Members (>=2)", "NO", f"{len(short)} group(s) below 2 members: {', '.join(short)}"
    if errors:
        return "Group Members (>=2)", "ERROR", f"Could not read memberships for {errors} group(s)"
    return ("Group Members (>=2)", "YES",
            f"All {len(groups)} group(s) have >=2 members — {_grp(list(groups.values()))}")

def _org_has_scm_integration(org_id: str) -> OrgProbe:
    """True if the org has at least one source-control integration configured."""
    status, body = get_v1_cached(EP_ORG_INTEGRATIONS.format(org_id=org_id))
    return _probe(status, lambda: isinstance(body, dict) and any(k in SCM_TYPES for k in body))

def check_scm_integrations(orgs: dict[str, str]) -> CheckResult:
    """YES if any org has at least one SCM integration (GitHub/GitLab/Bitbucket/Azure)."""
    return _any_org(
        "SCM Integration", orgs, _org_has_scm_integration,
        ok_word="with SCM integration",
        none_detail="No org has an SCM integration",
    )

def _org_working_scm_types(org_id: str) -> set[str] | None:
    """Return the SCM integration types that have actually imported & scanned
    repos in this org, or None on API error.

    `exclude_empty=true` (the API default) returns only targets that have at
    least one project — i.e. the integration successfully pulled and scanned a
    repo. That is the closest signal to "working" the API exposes; there is no
    integration connectivity/test endpoint.
    """
    status, body = get_rest(
        EP_ORG_TARGETS.format(org_id=org_id),
        params={"source_types": ",".join(SCM_SOURCE_TYPES),
                "exclude_empty": "true", "limit": 100},
    )
    if status != 200:
        return None
    types: set[str] = set()
    for t in body.get("data", []):
        itype = (t.get("relationships", {}).get("integration", {}).get("data", {})
                 .get("attributes", {}).get("integration_type"))
        if itype:
            types.add(itype)
    return types

def check_scm_integration_working(groups: dict[str, str],
                                  group_orgs: dict[str, dict[str, str]]) -> CheckResult:
    """YES if at least one group has a repository SCM integration that is
    actually working — i.e. has imported and scanned repos (non-empty targets).

    Integrations are org-level in Snyk (no group-level endpoint), so a group
    counts as working if any of its orgs has working SCM targets.
    """
    if not groups:
        return "SCM Integration Working", "ERROR", "No groups found"
    working_groups = 0
    working_names: list[str] = []
    types_seen: set[str] = set()
    errors = 0
    for group_id, group_name in groups.items():
        group_works = False
        for org_id in group_orgs.get(group_id, {}):
            types = _org_working_scm_types(org_id)
            if types is None:
                errors += 1
                continue
            if types:
                group_works = True
                types_seen.update(types)
        if group_works:
            working_groups += 1
            working_names.append(group_name)
    if working_groups:
        return ("SCM Integration Working", "YES",
                f"{working_groups}/{len(groups)} group(s) with live repos — "
                f"{', '.join(sorted(types_seen))} — {_grp(working_names)}")
    if errors and not types_seen:
        return "SCM Integration Working", "ERROR", "Could not read targets for any org"
    return "SCM Integration Working", "NO", "No imported/scanned repos in any group"

# Cache of SCM integration settings for ALL orgs (per unique org set), so the
# several PR-related checks share one integrations + settings sweep.
_scm_settings_cache: dict[frozenset, tuple] = {}

def _all_scm_integration_settings(orgs: dict[str, str]) -> tuple[list, int]:
    """Return ([(org_name, settings), ...], error_count) for every org that has
    a SCM integration. Memoized for the run."""
    key = frozenset(orgs)
    if key in _scm_settings_cache:
        return _scm_settings_cache[key]
    results, errors = [], 0
    for org_id, org_name in orgs.items():
        status, body = get_v1_cached(EP_ORG_INTEGRATIONS.format(org_id=org_id))
        if status != 200:
            errors += 1
            continue
        int_id = next((v for k, v in body.items() if k in SCM_TYPES), None)
        if not int_id:
            continue
        s_status, settings = get_v1(EP_ORG_INTEGRATION_SETTINGS.format(org_id=org_id, int_id=int_id))
        if s_status == 200:
            results.append((org_name, settings))
        else:
            errors += 1
    res = (results, errors)
    _scm_settings_cache[key] = res
    return res

def _pr_any_check(name: str, orgs: dict[str, str], predicate, ok_word: str, none_word: str) -> CheckResult:
    """Any-org PR setting check: YES if at least one org's SCM integration
    satisfies `predicate(settings)`."""
    results, errors = _all_scm_integration_settings(orgs)
    if not results:
        if errors:
            return name, "ERROR", "Could not read integration settings"
        return name, "NO", "No SCM integration found in any org"
    passing = [org for org, s in results if predicate(s)]
    failing = [org for org, s in results if not predicate(s)]
    if passing:
        return name, "YES", f"{ok_word}: {_org_list(passing)}"
    if errors:   # some orgs could not be read, so "disabled everywhere" is not proven
        return name, "ERROR", f"Could not read integration settings for {errors} org(s)"
    return name, "NO", f"{none_word}: {_org_list(failing)}"

def check_pr_checks(orgs: dict[str, str]) -> CheckResult:
    return _pr_any_check(
        "PR Checks Enabled", orgs,
        lambda s: s.get("pullRequestTestEnabled", False),
        ok_word="with PR checks", none_word="PR checks disabled in all SCM orgs")

def check_fix_prs(orgs: dict[str, str]) -> CheckResult:
    return _pr_any_check(
        "Fix PRs Enabled", orgs,
        lambda s: s.get("autoRemediationPrs", {}).get("freshPrsEnabled", False),
        ok_word="with fix PRs", none_word="Fix PRs disabled in all SCM orgs")

def check_pr_code_test(orgs: dict[str, str]) -> CheckResult:
    """PRs are tested with Snyk Code (SAST), not just open-source deps."""
    return _pr_any_check(
        "PR Code Test (SAST)", orgs,
        lambda s: s.get("pullRequestTestCodeEnabled", False),
        ok_word="with PR code test", none_word="PR code test disabled in all SCM orgs")

def check_pr_secrets_test(orgs: dict[str, str]) -> CheckResult:
    """PRs are tested with Snyk Secrets (field added to the V1 integration settings)."""
    return _pr_any_check(
        "PR Secrets Test", orgs,
        lambda s: s.get("pullRequestTestSecretsEnabled", False),
        ok_word="with PR secrets test", none_word="PR secrets test disabled in all SCM orgs")

# V1 integration-settings flags that make a PR check actually fail (block) the PR.
# `pullRequestFailOnAnyCodeIssues` (Snyk Code issues) is returned by the live API but is
# not in the published V1 spec, so it is read best-effort: absent simply counts as off.
PR_FAIL_FLAGS = ("pullRequestFailOnAnyVulns", "pullRequestFailOnlyForHighSeverity",
                 "pullRequestFailOnAnyCodeIssues")

def check_pr_fail_policy(orgs: dict[str, str]) -> CheckResult:
    """PR checks actually fail (block) on vulnerabilities or code issues, not
    informational only."""
    return _pr_any_check(
        "PR Fail Policy", orgs,
        lambda s: any(bool(s.get(flag)) for flag in PR_FAIL_FLAGS),
        ok_word="failing PRs on issues", none_word="No SCM org fails PRs on issues")

def check_auto_dep_upgrade(orgs: dict[str, str]) -> CheckResult:
    """Automatic dependency-upgrade PRs are enabled."""
    return _pr_any_check(
        "Auto Dependency Upgrade", orgs,
        lambda s: s.get("autoDepUpgradeEnabled", False),
        ok_word="with auto dep upgrade", none_word="Auto dep upgrade disabled in all SCM orgs")

def check_service_accounts(groups: dict[str, str]) -> CheckResult:
    """YES if at least one group has service accounts configured."""
    if not groups:
        return "Service Accounts", "ERROR", "No groups found"
    total = 0
    auth_types: set[str] = set()
    with_accounts: list[str] = []
    error_statuses: list[int] = []
    for group_id, group_name in groups.items():
        status, accounts = get_rest_all(EP_GROUP_SERVICE_ACCOUNTS.format(group_id=group_id))
        if status == 200:
            total += len(accounts)
            if accounts:
                with_accounts.append(group_name)
            auth_types.update(a.get("attributes", {}).get("auth_type", "?") for a in accounts)
        else:
            error_statuses.append(status)
    if total:
        return ("Service Accounts", "YES",
                f"{total} account(s) — {', '.join(sorted(auth_types))} — {_grp(with_accounts)}")
    if error_statuses:
        return "Service Accounts", "ERROR", f"Could not read service accounts ({_http_summary(error_statuses)})"
    return "Service Accounts", "NO", "None configured in any group"

def check_notification_settings(orgs: dict[str, str]) -> CheckResult:
    """YES if at least one org has at least one notification type enabled.

    The V1 response maps each notification type to an object such as
    {"enabled": true, "inherited": false}, so the flag is read from `enabled`.
    An org counts as active only if some type is explicitly enabled.
    """
    if not orgs:
        return "Notifications Configured", "ERROR", "No orgs found"
    active, disabled, errors = [], [], []
    for org_id, org_name in orgs.items():
        status, body = get_v1(EP_ORG_NOTIFICATION_SETTINGS.format(org_id=org_id))
        if status != 200 or not isinstance(body, dict):
            errors.append(org_name)
            continue
        if any(isinstance(v, dict) and v.get("enabled") is True for v in body.values()):
            active.append(org_name)
        else:
            disabled.append(org_name)
    if active:
        return "Notifications Configured", "YES", f"active: {_org_list(active)}"
    if disabled:
        return "Notifications Configured", "NO", f"disabled: {_org_list(disabled)}"
    return "Notifications Configured", "ERROR", f"Could not retrieve settings for: {_org_list(errors)}"

def check_recent_audit_activity(groups: dict[str, str]) -> CheckResult:
    """YES if any group has audit activity in the last 7 days.

    Events live under data.items[] (not data[]); the endpoint path uses an
    underscore (audit_logs) and is released at version 2024-04-29.
    """
    if not groups:
        return "Recent Audit Activity", "ERROR", "No groups found"
    since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    now   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    total = 0
    capped = False
    active_groups: list[str] = []
    error_statuses: list[int] = []
    for group_id, group_name in groups.items():
        status, body = get_rest(
            EP_GROUP_AUDIT_LOGS.format(group_id=group_id),
            params={"version": REST_VERSION_AUDIT, "from": since, "to": now, "size": 100},
        )
        if status == 200:
            n = len(body.get("data", {}).get("items", []))
            total += n
            if n:
                active_groups.append(group_name)
            capped = capped or n >= 100   # one page only: the true count may be higher
        else:
            error_statuses.append(status)
    if total:
        return ("Recent Audit Activity", "YES",
                f"{total}{'+' if capped else ''} event(s) in last 7 days — {_grp(active_groups)}")
    if error_statuses:
        return "Recent Audit Activity", "ERROR", f"Could not read audit logs ({_http_summary(error_statuses)})"
    return "Recent Audit Activity", "NO", "No events in last 7 days"

def _org_has_origin(org_id: str, origins: list[str]) -> OrgProbe:
    """True if the org has at least one project with one of the given origins."""
    status, body = get_rest(
        EP_ORG_PROJECTS.format(org_id=org_id),
        params={"version": REST_VERSION_PROJECTS,
                "origins": ",".join(origins), "limit": REST_MIN_LIMIT},
    )
    return _probe(status, lambda: len(body.get("data", [])) > 0)

def _org_has_project(org_id: str) -> OrgProbe:
    """True if the org has at least one project imported."""
    status, body = get_rest(
        EP_ORG_PROJECTS.format(org_id=org_id),
        params={"version": REST_VERSION_PROJECTS, "limit": REST_MIN_LIMIT},
    )
    return _probe(status, lambda: len(body.get("data", [])) > 0)

def check_projects_exist(orgs: dict[str, str]) -> CheckResult:
    """YES if any org has at least one project imported."""
    return _any_org(
        "Projects (>=1/org)", orgs, _org_has_project,
        ok_word="with >=1 project",
        none_detail="No org has any projects imported",
    )

def check_project_origin_mix(orgs: dict[str, str]) -> CheckResult:
    """YES if, across all orgs, there is at least one SCM-origin project AND at
    least one CLI/CI-origin project (they need not be in the same org)."""
    if not orgs:
        return "Project Origin Mix (SCM+CLI)", "ERROR", "No orgs found"
    scm_orgs, cli_orgs, error_statuses = [], [], []
    for oid, n in orgs.items():
        for origins, bucket in ((SCM_ORIGINS, scm_orgs), (CLI_ORIGINS, cli_orgs)):
            answer, status = _org_has_origin(oid, origins)
            if answer:
                bucket.append(n)
            elif answer is None:
                error_statuses.append(status)
    if scm_orgs and cli_orgs:
        return "Project Origin Mix (SCM+CLI)", "YES", \
            f"SCM: {_org_list(scm_orgs)}  |  CLI: {_org_list(cli_orgs)}"
    missing = [label for label, present in (("SCM", scm_orgs), ("CLI", cli_orgs)) if not present]
    if error_statuses:   # a failed lookup could be hiding the missing origin
        return ("Project Origin Mix (SCM+CLI)", "ERROR",
                f"Could not read projects ({_http_summary(error_statuses)}); "
                f"no {', '.join(missing)} origin project found in the orgs that could be read")
    return "Project Origin Mix (SCM+CLI)", "NO", f"No {', '.join(missing)} origin project(s) in any org"

def _parse_dt(value: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp (handles a trailing 'Z')."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

def _fetch_org_projects(org_id: str, extra_params: dict) -> list[dict] | None:
    """Fetch all projects for an org (following pagination). None on API error."""
    status, items = get_rest_all(
        EP_ORG_PROJECTS.format(org_id=org_id),
        params={"version": REST_VERSION_PROJECTS, **extra_params},
    )
    return items if status == 200 else None

def _check_scan_freshness(name: str, orgs: dict[str, str], origins: list[str]) -> CheckResult:
    """YES if every Open Source / Code Analysis project from the given origins
    was last tested within the last 14 days; NO if any is stale.

    Container, IaC and Secrets scans are excluded, as are deactivated projects
    (attributes.status == "inactive"), which are intentionally not scanned.
    Last-tested time is the newer of meta.latest_issue_counts.updated_at and
    meta.cli_monitored_at (the latter is only set for CLI-monitored projects).
    """
    if not orgs:
        return name, "ERROR", "No orgs found"
    cutoff = datetime.now(timezone.utc) - timedelta(days=SCAN_FRESHNESS_DAYS)
    checked = stale = inactive = 0
    checked_orgs, stale_orgs = [], []
    api_error = False
    for org_id, org_name in orgs.items():
        projects = _fetch_org_projects(
            org_id, {"meta.latest_issue_counts": "true", "origins": ",".join(origins)}
        )
        if projects is None:
            api_error = True
            continue
        org_checked = org_stale = 0
        for proj in projects:
            attrs = proj.get("attributes", {})
            if attrs.get("type") in EXCLUDED_SCAN_TYPES:
                continue
            if attrs.get("status") == "inactive":
                inactive += 1
                continue
            checked += 1
            org_checked += 1
            meta = proj.get("meta", {})
            counts = meta.get("latest_issue_counts") or {}
            stamps = [_parse_dt(counts.get("updated_at")), _parse_dt(meta.get("cli_monitored_at"))]
            tested = max((s for s in stamps if s), default=None)
            if tested is None or tested < cutoff:
                stale += 1
                org_stale += 1
        if org_checked:
            checked_orgs.append(org_name)
        if org_stale:
            stale_orgs.append(org_name)
    skipped = f" ({inactive} inactive skipped)" if inactive else ""
    if checked == 0:
        if api_error:
            return name, "ERROR", "Could not retrieve projects"
        return name, "YES", f"No active OSS/Code projects to assess{skipped}"
    if stale:
        return name, "NO", f"{stale}/{checked} project(s) stale in: {_org_list(stale_orgs)}{skipped}"
    if api_error:   # fresh where readable, but some orgs could not be read at all
        return name, "ERROR", (f"{checked} project(s) fresh, but some orgs could not be read "
                               f"({_org_list(checked_orgs)}){skipped}")
    return name, "YES", f"All {checked} project(s) fresh in: {_org_list(checked_orgs)}{skipped}"

def check_scm_scan_freshness(orgs: dict[str, str]) -> CheckResult:
    return _check_scan_freshness("SCM Scans (<=14d)", orgs, SCM_ORIGINS)

def check_cli_scan_freshness(orgs: dict[str, str]) -> CheckResult:
    return _check_scan_freshness("CLI Scans (<=14d)", orgs, CLI_ORIGINS)

def check_sso_configured(groups: dict[str, str]) -> CheckResult:
    """YES if at least one group has a SSO/SAML connection configured."""
    if not groups:
        return "SSO Configured", "ERROR", "No groups found"
    matches: dict[str, int] = {}  # group_name -> connection count
    error_statuses: list[int] = []
    for group_id, group_name in groups.items():
        status, body = get_rest_first_version(
            EP_GROUP_SSO_CONNECTIONS.format(group_id=group_id), REST_VERSIONS_SSO)
        if status == 200:
            count = len(body.get("data", []))
            if count:
                matches[group_name] = count
        else:
            error_statuses.append(status)
    if matches:
        return ("SSO Configured", "YES",
                f"{len(matches)}/{len(groups)} group(s) with SSO — {_grp(list(matches))}")
    if error_statuses:   # a failed call is not proof that SSO is absent
        return "SSO Configured", "ERROR", f"Could not read SSO connections ({_http_summary(error_statuses)})"
    return "SSO Configured", "NO", f"None across {len(groups)} group(s)"

def check_sast_enabled(orgs: dict[str, str]) -> CheckResult:
    """YES if at least one org has Snyk Code (SAST) enabled."""
    if not orgs:
        return "Snyk Code (SAST)", "ERROR", "No orgs found"
    enabled, disabled = [], []
    error_statuses: list[int] = []
    for org_id, org_name in orgs.items():
        status, body = get_rest_cached(EP_ORG_SAST_SETTINGS.format(org_id=org_id),
                                       params={"version": REST_VERSION_SAST})
        if status != 200:
            error_statuses.append(status)
            continue
        on = body.get("data", {}).get("attributes", {}).get("sast_enabled")
        (enabled if on else disabled).append(org_name)
    if enabled:
        return "Snyk Code (SAST)", "YES", f"enabled: {_org_list(enabled)}"
    if error_statuses:
        return "Snyk Code (SAST)", "ERROR", f"Could not read SAST settings ({_http_summary(error_statuses)})"
    return "Snyk Code (SAST)", "NO", f"Not enabled: {_org_list(disabled)}"

# Org-level feature state: True (on), False (off), "unavailable" (feature not
# entitled/present — e.g. 403/404), "unreported" (HTTP 200 but the API leaves the
# flag out of the response, so the real state cannot be read — NOT the same as off),
# or "error" (real API/transport failure).
# Each lookup also returns the HTTP status so a NO can be explained, not guessed.
FeatureState = bool | str
OrgState = tuple[FeatureState, int]

def _is_transient(status: int) -> bool:
    """A status that reflects a real API/transport failure, not 'feature absent'."""
    return status == 0 or status == 401 or status == 429 or status >= 500

def _debug_state(label: str, org_id: str, status: int, state: FeatureState) -> None:
    """When SNYK_DEBUG is set, show what each org returned for a feature check."""
    if DEBUG:
        console.print(f"[dim cyan]  DEBUG {label} id={org_id} HTTP {status} -> {state}[/dim cyan]")

def _agent_fix_state(org_id: str) -> OrgState:
    status, body = get_rest_cached(EP_ORG_SAST_SETTINGS.format(org_id=org_id),
                                   params={"version": REST_VERSION_SAST})
    if status == 200:
        # Verified against the live API: /settings/sast returns only `sast_enabled`
        # (at every API version, including newer/beta) and never `autofix_enabled`.
        # A missing flag is therefore "unreported", not "off".
        flag = body.get("data", {}).get("attributes", {}).get("autofix_enabled")
        state: FeatureState = bool(flag) if flag is not None else "unreported"
    else:
        state = "error" if _is_transient(status) else "unavailable"
    _debug_state("agent_fix", org_id, status, state)
    return state, status

def _os_reachability_state(org_id: str) -> OrgState:
    status, body = get_rest_first_version(
        EP_ORG_OPENSOURCE_SETTINGS.format(org_id=org_id), REST_VERSIONS_OS_SETTINGS)
    if status == 200:
        flag = (body.get("data", {}).get("attributes", {}).get("reachability") or {}).get("enabled")
        state: FeatureState = bool(flag) if flag is not None else "unreported"
    else:
        state = "error" if _is_transient(status) else "unavailable"
    _debug_state("os_reachability", org_id, status, state)
    return state, status

def _http_summary(statuses: list[int]) -> str:
    """'HTTP 403 x5, HTTP 404 x1' from a list of status codes."""
    counts: dict[int, int] = {}
    for st in statuses:
        counts[st] = counts.get(st, 0) + 1
    return ", ".join(f"HTTP {st} x{n}" for st, n in sorted(counts.items()))

def _explain_group(group_name: str, orgs: dict[str, str],
                   results: dict[str, OrgState]) -> str:
    """One-line reason for a group's result: how many orgs are on, which are off,
    and which returned an HTTP failure / 'feature unavailable' status."""
    on = sum(1 for s, _ in results.values() if s is True)
    off = [orgs[o] for o, (s, _) in results.items() if s is False]
    bad = [st for s, st in results.values() if s in ("error", "unavailable")]
    unreported = sum(1 for s, _ in results.values() if s == "unreported")
    parts = [f"on {on}/{len(results)} orgs"]
    if off:
        parts.append(f"off: {_org_list(off)}")
    if unreported:
        parts.append(f"flag not returned by API in {unreported} org(s)")
    if bad:
        parts.append(_http_summary(bad))
    return f"{group_name} ({'; '.join(parts)})"

def _group_feature_check(name: str, groups: dict[str, str],
                         group_orgs: dict[str, dict[str, str]],
                         org_state) -> CheckResult:
    """Group-level rollup of an org-scoped feature toggle.

    `org_state(org_id)` returns (state, http_status) where state is True/False,
    "unavailable" (feature not entitled/present), or "error" (real API failure).
    Per group:
      - any org explicitly OFF, or no org has it on (all unavailable) -> not enabled
      - every reporting org ON (unavailable orgs skipped)             -> enabled
      - could not determine due only to real API errors               -> error
    The check is NO if any group is not enabled, ERROR only if the sole obstacle
    is real API errors, else YES. "Feature simply not enabled" reads as NO, not ERR.
    The Detail column says how many orgs are on, which are off, and any HTTP
    statuses seen, so a NO can be traced to its cause.
    """
    if not groups:
        return name, "ERROR", "No groups found"
    failing, errored, unverifiable = [], [], []
    enabled_groups: list[str] = []
    for group_id, group_name in groups.items():
        orgs = group_orgs.get(group_id, {})
        results = {o: org_state(o) for o in orgs}
        states = [s for s, _ in results.values()]
        votes = [s for s in states if isinstance(s, bool)]
        if any(v is False for v in votes):
            failing.append(_explain_group(group_name, orgs, results))   # explicitly off in some org
        elif votes:
            enabled_groups.append(group_name)                            # all reporting orgs are on
        elif any(s == "error" for s in states):
            errored.append(_explain_group(group_name, orgs, results))   # couldn't determine (real error)
        elif any(s == "unreported" for s in states):
            unverifiable.append(group_name)                              # API never reports the flag
        else:
            failing.append(_explain_group(group_name, orgs, results))   # not enabled / available anywhere
    if failing:
        return name, "NO", f"Not enabled in Group level: {'; '.join(failing)}"
    if errored:
        return name, "ERROR", f"API error querying: {'; '.join(errored)}"
    if unverifiable:
        return name, "NA", (f"Not verifiable via API — setting not returned for: "
                            f"{', '.join(unverifiable)}. Check it in the Snyk portal")
    return name, "YES", f"Enabled in {len(enabled_groups)} group level — {_grp(enabled_groups)}"

def check_agent_fix(groups: dict[str, str], group_orgs: dict[str, dict[str, str]]) -> CheckResult:
    return _group_feature_check("Snyk Agent Fix", groups, group_orgs, _agent_fix_state)

def check_os_reachability(groups: dict[str, str], group_orgs: dict[str, dict[str, str]]) -> CheckResult:
    return _group_feature_check("OS Reachability", groups, group_orgs, _os_reachability_state)

def check_os_broker_group(groups: dict[str, str]) -> CheckResult:
    """YES if "Universal Broker for Snyk Open Source" is enabled for every group.

    REST: GET /groups/{id}/settings/opensource/broker (GA). The spec returns the
    flag as `data.enabled` (not under `attributes`); both shapes are accepted.
    """
    name = "Universal Broker for OS"
    if not groups:
        return name, "ERROR", "No groups found"
    enabled, off, errors = [], [], []
    unavailable: list[tuple[str, int]] = []
    for group_id, group_name in groups.items():
        status, body = get_rest_cached(EP_GROUP_OS_BROKER.format(group_id=group_id))
        data = body.get("data") if isinstance(body, dict) else None
        if status == 200 and isinstance(data, dict):
            flag = data.get("enabled", (data.get("attributes") or {}).get("enabled"))
            (enabled if flag else off).append(group_name)
            _debug_state("os_broker", group_id, status, bool(flag))
        elif _is_transient(status):
            errors.append(group_name)
            _debug_state("os_broker", group_id, status, "error")
        else:
            unavailable.append((group_name, status))
            _debug_state("os_broker", group_id, status, "unavailable")
    if off or unavailable:
        parts = []
        if off:
            parts.append(f"off: {', '.join(off)}")
        if unavailable:
            parts.append(f"endpoint unavailable ({_http_summary([st for _, st in unavailable])}): "
                         f"{', '.join(n for n, _ in unavailable)}")
        return name, "NO", "Not enabled in Group level — " + "; ".join(parts)
    if errors:
        return name, "ERROR", f"API error querying: {', '.join(errors)}"
    return name, "YES", f"Enabled in {len(enabled)} group level — {_grp(enabled)}"

def check_secrets_enabled(orgs: dict[str, str]) -> CheckResult:
    """YES if at least one org has Snyk Secrets enabled (REST, beta endpoint).

    NO when the setting is off or the endpoint is unavailable to the org
    (403/404); ERROR only when no org could be read due to real API failures.
    The Detail column separates "off" from "HTTP 4xx" so the two can be told apart.
    """
    name = "Snyk Secrets"
    if not orgs:
        return name, "ERROR", "No orgs found"
    enabled, off, errors = [], [], []
    unavailable: list[tuple[str, int]] = []
    for org_id, org_name in orgs.items():
        status, body = get_rest_first_version(
            EP_ORG_SECRETS_SETTINGS.format(org_id=org_id), REST_VERSIONS_SECRETS)
        if status == 200:
            on = bool(body.get("data", {}).get("attributes", {}).get("secrets_enabled"))
            (enabled if on else off).append(org_name)
            _debug_state("secrets", org_id, status, on)
        elif _is_transient(status):
            errors.append(org_name)
            _debug_state("secrets", org_id, status, "error")
        else:
            unavailable.append((org_name, status))
            _debug_state("secrets", org_id, status, "unavailable")
    if enabled:
        return name, "YES", f"enabled in {len(enabled)}/{len(orgs)} org(s): {_org_list(enabled)}"
    if off or unavailable:
        parts = []
        if off:
            parts.append(f"off: {_org_list(off)}")
        if unavailable:
            parts.append(f"endpoint unavailable ({_http_summary([st for _, st in unavailable])}): "
                         f"{_org_list([n for n, _ in unavailable])}")
        return name, "NO", "Not enabled — " + "; ".join(parts)
    return name, "ERROR", f"Could not retrieve settings for: {_org_list(errors)}"

def check_entitlements(orgs: dict[str, str]) -> CheckResult:
    """YES if any org has feature entitlements enabled."""
    if not orgs:
        return "Entitlements", "ERROR", "No orgs found"
    have, none_ = [], []
    error_statuses: list[int] = []
    for org_id, org_name in orgs.items():
        status, body = get_v1(EP_ORG_ENTITLEMENTS.format(org_id=org_id))
        if status != 200:
            error_statuses.append(status)
            continue
        any_on = isinstance(body, dict) and any(v is True for v in body.values())
        (have if any_on else none_).append(org_name)
    if have:
        return "Entitlements", "YES", f"with entitlements: {_org_list(have)}"
    if error_statuses:
        return "Entitlements", "ERROR", f"Could not read entitlements ({_http_summary(error_statuses)})"
    return "Entitlements", "NO", f"No entitlements in: {_org_list(none_)}"

def _org_ignore_workflow_on(org_id: str) -> OrgProbe:
    """True if the org has the Ignore Approval Workflow enabled."""
    status, body = get_v1_cached(EP_ORG_SETTINGS.format(org_id=org_id))
    return _probe(status, lambda: isinstance(body, dict)
                  and (body.get("ignores") or {}).get("approvalWorkflowEnabled"))

def check_ignore_approval_workflow(orgs: dict[str, str]) -> CheckResult:
    """YES if any org has the Ignore Approval Workflow enabled."""
    return _any_org(
        "Ignore Approval Workflow", orgs, _org_ignore_workflow_on,
        ok_word="with approval workflow",
        none_detail="Not enabled in any org",
    )

def _org_ignore_reason_required(org_id: str) -> OrgProbe:
    """True if the org requires a reason to ignore an issue (ignores.reasonRequired)."""
    status, body = get_v1_cached(EP_ORG_SETTINGS.format(org_id=org_id))
    return _probe(status, lambda: isinstance(body, dict)
                  and (body.get("ignores") or {}).get("reasonRequired"))

def check_ignore_reason_required(orgs: dict[str, str]) -> CheckResult:
    """YES if any org requires a reason when ignoring an issue."""
    return _any_org(
        "Ignore Reason Required", orgs, _org_ignore_reason_required,
        ok_word="requiring an ignore reason",
        none_detail="No org requires an ignore reason",
    )

def _org_has_service_account(org_id: str) -> OrgProbe:
    """True if the org has at least one service account."""
    status, body = get_rest(EP_ORG_SERVICE_ACCOUNTS.format(org_id=org_id), params={"limit": 10})
    return _probe(status, lambda: len(body.get("data", [])) > 0)

def check_org_service_accounts(orgs: dict[str, str]) -> CheckResult:
    """YES if any org has at least one service account."""
    return _any_org(
        "Org Service Accounts", orgs, _org_has_service_account,
        ok_word="with service account(s)",
        none_detail="No org has a service account",
    )

def _org_has_broker_connection(org_id: str) -> OrgProbe:
    """True if the org has a configured Universal Broker connection.

    A connection with a deployment_id is a configured Universal Broker
    integration. The API exposes no connection health/error field, so
    "installed/configured" is the only signal — runtime connectivity is not
    reported by the API.
    """
    status, body = get_rest(EP_ORG_BROKER_CONNECTIONS.format(org_id=org_id),
                            params={"limit": 100})
    return _probe(status, lambda: any(
        c.get("attributes", {}).get("deployment_id") for c in body.get("data", [])
    ))

def check_broker_integration(orgs: dict[str, str]) -> CheckResult:
    """YES if at least one org has a Universal Broker connection; NO if none do."""
    return _any_org(
        "Broker Integration", orgs, _org_has_broker_connection,
        ok_word="with a Universal Broker connection",
        none_detail="No org has a Universal Broker connection",
    )

def check_broker() -> CheckResult | None:
    if not BROKER_URL:
        return None
    try:
        r = httpx.get(f"{BROKER_URL}/systemcheck", timeout=10)
        body = r.json()
        if r.status_code == 200 and body.get("ok"):
            return "Broker Connectivity", "YES", f"Broker healthy at {BROKER_URL}"
        return "Broker Connectivity", "NO", f"Broker returned ok=false — {body}"
    except Exception as exc:
        return "Broker Connectivity", "ERROR", f"Could not reach broker: {exc}"

# ── Runner ─────────────────────────────────────────────────────────────────────

def resolve_tenant() -> tuple[str, str]:
    """Resolve the tenant to check, or exit if none can be determined."""
    console.print("  [dim]Discovering tenants...[/dim]")
    tenants = fetch_tenants()
    selected = select_tenant(tenants)
    if not selected:
        console.print(
            "[bold red]ERROR:[/bold red] Could not resolve a tenant. "
            "Check the token's permissions, or set SNYK_TENANT_ID."
        )
        sys.exit(1)
    tenant_id, tenant_name = selected
    console.print(f"  [dim]Using tenant:[/dim] [bold]{tenant_name}[/bold] [dim]({tenant_id})[/dim]")
    return tenant_id, tenant_name

def resolve_group(tenant_id: str) -> tuple[str, str]:
    """Resolve the group to check within the tenant, or exit if none can be determined."""
    console.print("  [dim]Discovering groups in tenant...[/dim]")
    groups = fetch_groups(tenant_id)
    selected = select_group(groups)
    if not selected:
        console.print(
            "[bold red]ERROR:[/bold red] Could not resolve a group. "
            "Check the token's permissions, or set SNYK_GROUP_ID."
        )
        sys.exit(1)
    group_id, group_name = selected
    console.print(f"  [dim]Using group:[/dim] [bold]{group_name}[/bold] [dim]({group_id})[/dim]")
    return group_id, group_name

# A report section: (section_title, [CheckResult, ...])
Section = tuple[str, list[CheckResult]]

def run_all_checks(groups: dict[str, str]) -> list[Section]:
    # ── Platform ────────────────────────────────────────────────────────────────
    console.print("  [dim]Checking platform connectivity...[/dim]")
    platform = [check_api_reachability()]

    # ── Discovery (orgs in the selected group) ────────────────────────────────────
    console.print("  [dim]Discovering orgs in group...[/dim]")
    group_orgs: dict[str, dict[str, str]] = {}
    orgs: dict[str, str] = {}
    for group_id in groups:
        g_orgs = fetch_orgs(group_id)
        group_orgs[group_id] = g_orgs
        orgs.update(g_orgs)

    # ── Group-level checks (run first, in order) ──────────────────────────────────
    console.print("  [dim]Running group-level checks...[/dim]")
    group_checks = [
        check_groups_exist(groups),
        check_orgs_in_groups(groups, orgs, group_orgs),
        check_group_members(groups),
        check_sso_configured(groups),
        check_service_accounts(groups),
        check_recent_audit_activity(groups),
        check_scm_integration_working(groups, group_orgs),
        check_agent_fix(groups, group_orgs),
        check_os_reachability(groups, group_orgs),
        check_os_broker_group(groups),
    ]

    # ── Org-level checks (run after all group checks) ─────────────────────────────
    console.print("  [dim]Running org-level checks...[/dim]")
    org_checks = [
        check_entitlements(orgs),
        check_scm_integrations(orgs),
        check_pr_checks(orgs),
        check_fix_prs(orgs),
        check_pr_code_test(orgs),
        check_pr_secrets_test(orgs),
        check_pr_fail_policy(orgs),
        check_auto_dep_upgrade(orgs),
        check_sast_enabled(orgs),
        check_secrets_enabled(orgs),
        check_ignore_approval_workflow(orgs),
        check_ignore_reason_required(orgs),
        check_org_service_accounts(orgs),
        check_broker_integration(orgs),
        check_notification_settings(orgs),
        check_projects_exist(orgs),
        check_project_origin_mix(orgs),
        check_scm_scan_freshness(orgs),
        check_cli_scan_freshness(orgs),
    ]

    broker = check_broker()
    if broker:
        platform.append(broker)

    return [
        ("Platform", platform),
        ("Group-Level Checks", group_checks),
        ("Org-Level Checks", org_checks),
    ]

# ── Report ─────────────────────────────────────────────────────────────────────

STATUS_STYLE = {
    "YES":   "[bold green]YES[/bold green]",
    "NO":    "[bold red] NO[/bold red]",
    "ERROR": "[bold yellow]ERR[/bold yellow]",
    "NA":    "[bold dim]N/A[/bold dim]",
}

def _render_section(title: str, results: list[CheckResult]) -> tuple[int, int, int, int]:
    """Render one section as its own table; return (yes, no, err, na) counts."""
    table = Table(
        title=f"[bold]{title}[/bold]", title_justify="left",
        box=box.ROUNDED, show_header=True, header_style="bold cyan",
    )
    table.add_column("Configuration Check", style="bold", min_width=28)
    table.add_column("Configured?", justify="center", min_width=11)
    table.add_column("Detail", min_width=48)

    yes = no = err = na = 0
    for name, status, detail in results:
        table.add_row(name, STATUS_STYLE[status], detail)
        if status == "YES":
            yes += 1
        elif status == "NO":
            no += 1
        elif status == "NA":
            na += 1
        else:
            err += 1

    console.print(table)
    na_part = f" · [dim]{na} n/a[/dim]" if na else ""
    console.print(
        f"    [green]{yes} yes[/green] · [red]{no} no[/red] · [yellow]{err} err[/yellow]{na_part}"
    )
    console.print()
    return yes, no, err, na

def print_report(sections: list[Section], tenant_label: str) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    console.print()
    console.rule(f"[bold cyan]Snyk Configuration Health Check — {now}[/bold cyan]")
    console.print(f"  Tenant : [bold]{tenant_label}[/bold]")
    console.print(f"  API    : [bold]{API_BASE}[/bold]")
    console.print("  [dim]Note: Detail lists up to 3 orgs per line (+N more). The cap is display-only — every org in the group is evaluated.[/dim]")
    console.print()

    g_yes = g_no = g_err = g_na = 0
    for title, results in sections:
        if not results:
            continue
        yes, no, err, na = _render_section(title, results)
        g_yes += yes
        g_no += no
        g_err += err
        g_na += na

    total = g_yes + g_no + g_err   # N/A checks are not scored either way
    console.rule(style="dim")
    na_part = f"  |  [dim]{g_na} not verifiable via API[/dim]" if g_na else ""
    console.print(
        f"  [bold]Overall:[/bold] [green]{g_yes}/{total} configured[/green]  |  "
        f"[red]{g_no} not configured[/red]  |  "
        f"[yellow]{g_err} errors[/yellow]{na_part}"
    )
    console.print()

# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tenant_id, tenant_name = resolve_tenant()
    group_id, group_name = resolve_group(tenant_id)
    sections = run_all_checks({group_id: group_name})
    print_report(sections, f"{tenant_name} ({tenant_id}) / {group_name} ({group_id})")
