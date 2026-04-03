"""
Export cached GitHub commit messages as a researcher-friendly JSONL dataset.

Each line links a CVE to its associated commit message, so researchers
don't need to re-fetch from the GitHub API.

Run after parse_commits_t3.py completes:
  uv run python export_commits.py
"""

import json
import os
from pathlib import Path

CACHE_DIR = Path("data/commit_cache")
REFERENCE_INDEX_PATH = Path("output/reference_index.json")
OUTPUT_PATH = Path("output/github_commits.jsonl")


def load_commit_to_cves():
    """Map (repo, sha) -> set of CVE IDs from the reference index."""
    with open(REFERENCE_INDEX_PATH) as f:
        data = json.load(f)

    mapping = {}
    for ref in data["references"]:
        for sid in ref.get("structured_ids", []):
            if sid["type"] == "github_commit":
                key = (sid["repo"], sid["value"])
                mapping.setdefault(key, set()).add(ref["cve_id"])
    return mapping


def main():
    if not CACHE_DIR.exists():
        print(f"Error: {CACHE_DIR} not found. Run parse_commits_t3.py first.")
        return

    if not REFERENCE_INDEX_PATH.exists():
        print(f"Error: {REFERENCE_INDEX_PATH} not found. Run build_reference_index.py first.")
        return

    commit_to_cves = load_commit_to_cves()

    written = 0
    skipped = 0

    with open(OUTPUT_PATH, "w") as out:
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
            sha = cached.get("sha", "")
            cve_ids = sorted(commit_to_cves.get((repo, sha), set()))

            if not cve_ids:
                skipped += 1
                continue

            for cve_id in cve_ids:
                record = {
                    "cve_id": cve_id,
                    "repo": repo,
                    "sha": sha,
                    "message": message,
                }
                out.write(json.dumps(record) + "\n")
                written += 1

    print(f"Wrote {written:,} records to {OUTPUT_PATH}")
    print(f"Skipped {skipped:,} cached entries (404s or unmapped)")


if __name__ == "__main__":
    main()
