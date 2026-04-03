"""
Export cached GitHub commit messages as a researcher-friendly JSONL dataset.

Each line links a CVE to its associated commit message, so researchers
don't need to re-fetch from the GitHub API.

Run after parse_commits_t3.py completes:
  uv run python export_commits.py
"""

import json
import os
from collections import defaultdict
from pathlib import Path

from github_commit_utils import (
    build_commit_alias_index,
    canonical_commit_key,
    normalize_commit_sha,
)

CACHE_DIR = Path("data/commit_cache")
REFERENCE_INDEX_PATH = Path("output/reference_index.json")
OUTPUT_PATH = Path("output/github_commits.jsonl")


def load_commit_to_cves():
    """Map canonical (repo, sha) -> set of CVE IDs from the reference index."""
    with open(REFERENCE_INDEX_PATH) as f:
        data = json.load(f)

    commit_refs = []
    for ref in data["references"]:
        for sid in ref.get("structured_ids", []):
            if sid["type"] == "github_commit":
                commit_refs.append({
                    "cve_id": ref["cve_id"],
                    "repo": sid["repo"],
                    "sha": normalize_commit_sha(sid["value"]),
                })

    alias_to_canonical = build_commit_alias_index(
        (ref["repo"], ref["sha"]) for ref in commit_refs
    )
    mapping = defaultdict(set)
    for ref in commit_refs:
        key = canonical_commit_key(ref["repo"], ref["sha"], alias_to_canonical)
        mapping[key].add(ref["cve_id"])
    return mapping, alias_to_canonical


def select_preferred_cache_entry(current, candidate):
    """Pick the cache entry with the most specific SHA spelling."""
    if current is None:
        return candidate

    current_sha = normalize_commit_sha(current.get("sha", ""))
    candidate_sha = normalize_commit_sha(candidate.get("sha", ""))
    if len(candidate_sha) != len(current_sha):
        return candidate if len(candidate_sha) > len(current_sha) else current
    return candidate if candidate_sha < current_sha else current


def main():
    if not CACHE_DIR.exists():
        print(f"Error: {CACHE_DIR} not found. Run parse_commits_t3.py first.")
        return

    if not REFERENCE_INDEX_PATH.exists():
        print(f"Error: {REFERENCE_INDEX_PATH} not found. Run build_reference_index.py first.")
        return

    commit_to_cves, alias_to_canonical = load_commit_to_cves()

    cached_messages = {}
    skipped = 0

    for fname in sorted(os.listdir(CACHE_DIR)):
        if not fname.endswith(".json"):
            continue

        with open(CACHE_DIR / fname) as f:
            cached = json.load(f)

        message = cached.get("message")
        if message is None:
            skipped += 1
            continue

        repo = cached.get("repo", "")
        sha = normalize_commit_sha(cached.get("sha", ""))
        key = canonical_commit_key(repo, sha, alias_to_canonical)
        if key not in commit_to_cves:
            skipped += 1
            continue

        cached["sha"] = sha
        cached_messages[key] = select_preferred_cache_entry(cached_messages.get(key), cached)

    written = 0
    missing = 0

    with open(OUTPUT_PATH, "w") as out:
        for (repo, canonical_sha), cve_ids in sorted(commit_to_cves.items()):
            cached = cached_messages.get((repo, canonical_sha))
            if cached is None:
                missing += 1
                continue

            export_sha = canonical_sha
            if len(cached["sha"]) > len(export_sha):
                export_sha = cached["sha"]

            for cve_id in sorted(cve_ids):
                record = {
                    "cve_id": cve_id,
                    "repo": repo,
                    "sha": export_sha,
                    "message": cached["message"],
                }
                out.write(json.dumps(record) + "\n")
                written += 1

    print(f"Wrote {written:,} records to {OUTPUT_PATH}")
    print(f"Skipped {skipped:,} cached entries (404s, empty messages, or unmapped)")
    print(f"Missing {missing:,} canonical commits with no cached message")


if __name__ == "__main__":
    main()
