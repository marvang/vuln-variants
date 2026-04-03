"""
Tier 3: Extract CVE cross-references from GitHub commit messages.

Fetches commit messages for GitHub commit URLs found in CVE references,
regex-matches CVE IDs, and produces new edges where a commit linked to
CVE-A mentions CVE-B in its message.

Usage:
  uv run python parse_commits_t3.py --sample 50     # test on 50 commits
  uv run python parse_commits_t3.py --dry-run        # count commits, no API calls
  uv run python parse_commits_t3.py                  # all commits (needs GITHUB_TOKEN)

Set GITHUB_TOKEN env var for 5,000 req/hour (vs 60 unauthenticated).
"""

import argparse
from http.client import IncompleteRead, RemoteDisconnected
import json
import os
import re
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from github_commit_utils import (
    build_commit_alias_index,
    canonical_commit_key,
    normalize_commit_sha,
)

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, **kwargs):
        print(kwargs.get("desc", "Processing"), "...")
        return iterable

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")
OUTPUT_DIR = Path("output")
CACHE_DIR = Path("data/commit_cache")
REFERENCE_INDEX_PATH = OUTPUT_DIR / "reference_index.json"

GITHUB_API = "https://api.github.com"

def _load_github_token():
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        return token
    env_file = Path(".env")
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("GITHUB_TOKEN=") and not line.startswith("#"):
                return line.split("=", 1)[1].strip().strip("'\"")
    return ""

GITHUB_TOKEN = _load_github_token()
DEFAULT_RETRY_AFTER = 60
PERMANENT_HTTP_ERRORS = {404, 409, 410}
RETRYABLE_CACHE_ERRORS = {422}


def load_commit_refs():
    """Load GitHub commit references from the reference index."""
    with open(REFERENCE_INDEX_PATH) as f:
        data = json.load(f)

    commits = []
    commit_refs = []
    for ref in data["references"]:
        for sid in ref.get("structured_ids", []):
            if sid["type"] == "github_commit":
                sha = normalize_commit_sha(sid["value"])
                commits.append({
                    "cve_id": ref["cve_id"],
                    "repo": sid["repo"],
                    "sha": sha,
                    "url": ref["url"],
                })
                commit_refs.append((sid["repo"], sha))

    alias_to_canonical = build_commit_alias_index(commit_refs)
    for commit in commits:
        commit["canonical_sha"] = canonical_commit_key(
            commit["repo"],
            commit["sha"],
            alias_to_canonical,
        )[1]
    return commits


def load_prior_edges():
    """Load T1+T2 edges (including corroborating) for deduplication."""
    seen = set()
    for filename in ["edges_t1_description.json", "edges_t2_allfields.json"]:
        path = OUTPUT_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for edge in data.get("edges", []) + data.get("corroborating_edges", []):
            seen.add((edge["source"], edge["target"]))
    return seen


def load_published_cves():
    """Load set of all published CVE IDs from parsed corpus."""
    parsed_path = OUTPUT_DIR / "parsed_cves.json"
    if parsed_path.exists():
        with open(parsed_path) as f:
            data = json.load(f)
        return set(data.get("cves", {}).keys())
    return set()


def cache_path(repo, sha):
    """Return cache file path for a commit."""
    safe_repo = repo.replace("/", "_")
    return CACHE_DIR / f"{safe_repo}_{normalize_commit_sha(sha)[:12]}.json"


def write_cache(repo, sha, message, *, resolved_sha=None, error=None):
    """Persist commit fetch results for resumable reruns."""
    cached = cache_path(repo, sha)
    cached.parent.mkdir(parents=True, exist_ok=True)
    requested_sha = normalize_commit_sha(sha)
    payload = {
        "message": message,
        "sha": normalize_commit_sha(resolved_sha or sha),
        "repo": repo,
    }
    if payload["sha"] != requested_sha:
        payload["requested_sha"] = requested_sha
    if error is not None:
        payload["error"] = error
    with open(cached, "w") as f:
        json.dump(payload, f)


def should_cache_http_error(status_code):
    """Return whether an HTTP status is stable enough to cache."""
    return status_code in PERMANENT_HTTP_ERRORS


def load_cached_result(repo, sha):
    """Return a reusable cached result, ignoring transient legacy errors."""
    cached = cache_path(repo, sha)
    if not cached.exists():
        return None

    with open(cached) as f:
        data = json.load(f)

    if data.get("error") in RETRYABLE_CACHE_ERRORS:
        return None
    return data


MAX_RETRIES = 1


def parse_retry_after_seconds(value):
    """Parse Retry-After header, falling back to a safe default."""
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return DEFAULT_RETRY_AFTER


def fetch_commit_message(repo, sha):
    """Fetch commit message from GitHub API, with caching."""
    data = load_cached_result(repo, sha)
    if data is not None:
        return data.get("message")

    url = f"{GITHUB_API}/repos/{repo}/commits/{sha}"
    headers = {"Accept": "application/vnd.github.v3+json"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

    for attempt in range(1 + MAX_RETRIES):
        try:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=15) as resp:
                data = json.load(resp)
                message = data.get("commit", {}).get("message", "")
                resolved_sha = normalize_commit_sha(data.get("sha", sha))

                write_cache(repo, sha, message, resolved_sha=resolved_sha)
                return message
        except HTTPError as e:
            if should_cache_http_error(e.code):
                write_cache(repo, sha, None, error=e.code)
                return None
            if e.code == 403 and attempt < MAX_RETRIES:
                retry_after = parse_retry_after_seconds(e.headers.get("Retry-After"))
                print(f"\nRate limited. Waiting {retry_after}s...")
                time.sleep(retry_after)
                continue
            print(f"\nHTTP {e.code} for {repo}/{sha[:12]}")
            return None
        except (URLError, TimeoutError, RemoteDisconnected, IncompleteRead):
            return None
    return None


def extract_context(message, match):
    """Extract a ~80 char context snippet around a CVE match."""
    start = max(0, match.start() - 40)
    end = min(len(message), match.end() + 40)
    snippet = message[start:end].replace("\n", " ").strip()
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(message) else ""
    return f"{prefix}{snippet}{suffix}"


def main():
    parser = argparse.ArgumentParser(description="T3: GitHub commit message CVE extraction")
    parser.add_argument("--sample", type=int, default=0, help="Process only N commits")
    parser.add_argument("--dry-run", action="store_true", help="Count commits, no API calls")
    parser.add_argument(
        "--cves", default="",
        help="Only process commits for these CVEs (comma-separated)",
    )
    args = parser.parse_args()

    if not REFERENCE_INDEX_PATH.exists():
        print("Error: Run build_reference_index.py first.")
        return

    print("Loading commit references...")
    all_commits = load_commit_refs()

    # Filter by CVEs if specified
    if args.cves:
        target_cves = {c.strip() for c in args.cves.split(",")}
        all_commits = [c for c in all_commits if c["cve_id"] in target_cves]

    # Deduplicate: same (repo, sha) can appear for multiple CVEs
    unique_commits = {}
    commit_to_cves = defaultdict(set)
    for c in all_commits:
        key = (c["repo"], c["canonical_sha"])
        unique_commits[key] = {
            "repo": c["repo"],
            "sha": c["canonical_sha"],
            "url": c["url"],
        }
        commit_to_cves[key].add(c["cve_id"])

    print(f"Found {len(all_commits):,} commit references "
          f"({len(unique_commits):,} unique commits)")

    if args.dry_run:
        auth_rate = "5,000/hour" if GITHUB_TOKEN else "60/hour (set GITHUB_TOKEN for 5,000)"
        hours = len(unique_commits) / (5000 if GITHUB_TOKEN else 60)
        print(f"\nAPI rate: {auth_rate}")
        print(f"Estimated time: {hours:.1f} hours")
        return

    # Apply sample limit
    commit_list = list(unique_commits.values())
    if args.sample:
        commit_list = commit_list[:args.sample]

    print(f"\nProcessing {len(commit_list):,} commits...")
    if not GITHUB_TOKEN:
        print("WARNING: No GITHUB_TOKEN set. Rate limit: 60/hour.")
        print("Set GITHUB_TOKEN env var for 5,000/hour.\n")

    all_published_cves = load_published_cves()
    prior_edges = load_prior_edges()

    new_edges = []
    corroborating_edges = []
    edges_by_field = defaultdict(int)
    seen_edges = set()  # deduplicate within T3 only
    fetched = 0
    cached_count = 0
    failed = 0
    commits_with_cve_refs = 0

    rate_delay = 0.8 if GITHUB_TOKEN else 1.1  # stay under rate limit

    for commit in tqdm(commit_list, desc="Fetching commits"):
        repo, sha = commit["repo"], commit["sha"]
        source_cves = commit_to_cves[(repo, sha)]

        # Check cache first
        if load_cached_result(repo, sha) is not None:
            cached_count += 1
        else:
            fetched += 1
            time.sleep(rate_delay)

        message = fetch_commit_message(repo, sha)
        if message is None:
            failed += 1
            continue
        if not message:
            continue

        # Find CVE references in commit message
        matches = list(CVE_PATTERN.finditer(message))
        if not matches:
            continue

        found_cves = {m.group(0) for m in matches}
        # Filter: must be in published CVE corpus, not a self-reference
        found_cves = {c for c in found_cves if c in all_published_cves} - source_cves

        if not found_cves:
            continue

        commits_with_cve_refs += 1

        for source_cve in source_cves:
            for match in matches:
                target_cve = match.group(0)
                if target_cve not in all_published_cves:
                    continue
                if target_cve == source_cve:
                    continue

                edge_key = (source_cve, target_cve)
                if edge_key in seen_edges:
                    continue
                seen_edges.add(edge_key)

                context = extract_context(message, match)
                edge_entry = {
                    "source": source_cve,
                    "target": target_cve,
                    "found_in": "t3_commit",
                    "context": context,
                }
                if edge_key in prior_edges:
                    corroborating_edges.append(edge_entry)
                else:
                    new_edges.append(edge_entry)
                edges_by_field["t3_commit"] += 1

    # Output
    OUTPUT_DIR.mkdir(exist_ok=True)
    output = {
        "tier": "t3_commits",
        "edge_count": len(new_edges),
        "corroborating_count": len(corroborating_edges),
        "edges_by_field": dict(edges_by_field),
        "commits_processed": len(commit_list),
        "commits_fetched": fetched,
        "commits_cached": cached_count,
        "commits_failed": failed,
        "commits_with_cve_refs": commits_with_cve_refs,
        "generated_at": datetime.now().isoformat(),
        "edges": new_edges,
        "corroborating_edges": corroborating_edges,
    }

    out_path = OUTPUT_DIR / "edges_t3_commits.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    # Summary
    print(f"\n{'='*60}")
    print(f"Commits processed:          {len(commit_list):>8,}")
    print(f"  Fetched from API:         {fetched:>8,}")
    print(f"  From cache:               {cached_count:>8,}")
    print(f"  Failed:                   {failed:>8,}")
    print(f"Commits with CVE refs:      {commits_with_cve_refs:>8,}")
    print(f"New edges (beyond T1+T2):   {len(new_edges):>8,}")
    print(f"Corroborating (also T1/T2): {len(corroborating_edges):>8,}")
    print(f"{'='*60}")
    print(f"\nSaved to {out_path}")


if __name__ == "__main__":
    main()
