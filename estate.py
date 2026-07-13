"""Shared estate plumbing for the documentation drift watchdog.

The job reads the canonical estate manifest, enumerates the repositories it
declares, and fetches repository files through the GitHub API. Keeping this
logic in one module anchors the watchdog to the same source of truth as the
supply-chain audit.

The manifest at atlas-api-public/data/estate.manifest.json is the
enumeration source on purpose: it is the estate's own declaration of
what it owns, so a repo missing from a scan is a manifest gap (worth
fixing there) rather than a hardcoded list going stale here.

Stdlib only, per the estate convention for Python tooling.
"""

import json
import os
import time
import urllib.error
import urllib.request

GITHUB_API = "https://api.github.com"
OWNER = "AtlasReaper311"
MANIFEST_REPO = "atlas-api-public"
MANIFEST_PATH = "data/estate.manifest.json"
USER_AGENT = "atlas-dep-audit (+https://atlas-systems.uk)"


class EstateError(RuntimeError):
    """Operational failure the job cannot proceed past."""


def _token():
    return os.environ.get("GH_DIGEST_PAT", "").strip()


def http_get(url, headers=None, timeout=20, retries=2):
    """GET with small retry on transient failure.

    Returns (status, body_bytes). A 4xx is returned to the caller to
    interpret (404 on a private repo is expected, not fatal); repeated
    network failure or 5xx raises EstateError so the job fails loudly
    instead of producing a silently partial report.
    """
    req_headers = {"User-Agent": USER_AGENT}
    if headers:
        req_headers.update(headers)
    last_err = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=req_headers)
            with urllib.request.urlopen(req, timeout=timeout) as res:
                return res.status, res.read()
        except urllib.error.HTTPError as err:
            if err.code < 500:
                return err.code, err.read()
            last_err = f"http {err.code}"
        except (urllib.error.URLError, TimeoutError, OSError) as err:
            last_err = str(err)
        time.sleep(2 * (attempt + 1))
    raise EstateError(f"GET {url} failed after retries: {last_err}")


def gh_get(path, accept="application/vnd.github+json"):
    """Authenticated GitHub API GET. Returns (status, body_bytes)."""
    headers = {
        "Accept": accept,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = _token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = path if path.startswith("http") else f"{GITHUB_API}{path}"
    return http_get(url, headers=headers)


def fetch_manifest():
    """The canonical estate manifest, straight from the repo."""
    status, body = gh_get(
        f"/repos/{OWNER}/{MANIFEST_REPO}/contents/{MANIFEST_PATH}",
        accept="application/vnd.github.raw+json",
    )
    if status != 200:
        raise EstateError(
            f"could not fetch estate manifest (http {status}); "
            "nothing can be enumerated without it"
        )
    try:
        return json.loads(body)
    except json.JSONDecodeError as err:
        raise EstateError(f"estate manifest is not valid JSON: {err}") from err


def manifest_repositories(manifest):
    """The declared repository list as (name, owner) pairs.

    Names come from the manifest's repositories array; owners parsed
    from each entry's URL so a future repo living elsewhere still
    resolves rather than assuming AtlasReaper311 forever.
    """
    repos = []
    for entry in manifest.get("repositories", []):
        name = entry.get("name")
        url = entry.get("url", "")
        if not name:
            continue
        owner = OWNER
        parts = [p for p in url.replace("https://github.com/", "").split("/") if p]
        if len(parts) >= 2:
            owner = parts[0]
        repos.append((owner, name))
    return repos


def manifest_workers(manifest):
    """Components that are deployed Workers with a declared meta_url."""
    out = []
    for comp in manifest.get("components", []):
        if comp.get("kind") == "worker" and comp.get("meta_url"):
            out.append(comp)
    return out


def default_branch(owner, repo):
    status, body = gh_get(f"/repos/{owner}/{repo}")
    if status == 404:
        return None
    if status != 200:
        raise EstateError(f"repo lookup {owner}/{repo} returned http {status}")
    return json.loads(body).get("default_branch", "main")


def repo_tree(owner, repo, branch):
    """Every path in the repo at HEAD of the given branch.

    One recursive trees call per repo instead of walking directories;
    node_modules is filtered here so no caller ever scans vendored
    dependency trees by accident.
    """
    status, body = gh_get(
        f"/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
    )
    if status != 200:
        raise EstateError(f"tree fetch {owner}/{repo}@{branch} returned http {status}")
    doc = json.loads(body)
    paths = [
        item["path"]
        for item in doc.get("tree", [])
        if item.get("type") == "blob" and "node_modules/" not in item["path"]
    ]
    return paths, bool(doc.get("truncated"))


def fetch_file(owner, repo, path, branch):
    """Raw file contents, or None when the file does not exist."""
    status, body = gh_get(
        f"/repos/{owner}/{repo}/contents/{path}?ref={branch}",
        accept="application/vnd.github.raw+json",
    )
    if status == 200:
        return body
    return None


def fetch_readme(owner, repo):
    """The repo README as text, or None."""
    status, body = gh_get(
        f"/repos/{owner}/{repo}/readme",
        accept="application/vnd.github.raw+json",
    )
    if status == 200:
        return body.decode("utf-8", errors="replace")
    return None


def run_url():
    """The Actions run URL, for the 'full log lives here' field."""
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo = os.environ.get("GITHUB_REPOSITORY", f"{OWNER}/atlas-dep-audit")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if run_id:
        return f"{server}/{repo}/actions/runs/{run_id}"
    return f"{server}/{repo}/actions"
