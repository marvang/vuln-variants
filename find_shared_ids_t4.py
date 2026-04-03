"""
Tier 4: Find CVE pairs that share external bug tracker IDs.

Scans the reference index for CVEs linking to the same Bugzilla bug,
GitHub issue, or GitHub PR. These structural links are weak evidence
that two CVEs may be variants — useful as context for T5 LLM classification.

Usage:
  uv run python find_shared_ids_t4.py
  uv run python find_shared_ids_t4.py --include-jira   # include noisy JIRA matches
"""

import argparse
import json
from collections import defaultdict
from datetime import datetime
from itertools import combinations
from pathlib import Path

OUTPUT_DIR = Path("output")
REFERENCE_INDEX_PATH = OUTPUT_DIR / "reference_index.json"

DEFAULT_ID_TYPES = {"bugzilla", "github_issue", "github_pr"}
MAX_CLUSTER = 20  # skip groups larger than this (too generic)


def load_structured_ids():
    """Load (cve_id, structured_id) pairs from the reference index."""
    with open(REFERENCE_INDEX_PATH) as f:
        data = json.load(f)

    results = []
    for ref in data["references"]:
        for sid in ref.get("structured_ids", []):
            results.append((ref["cve_id"], sid))
    return results


def load_prior_edges():
    """Load T1+T2+T3 edges for corroboration tracking."""
    seen = set()
    for filename in [
        "edges_t1_description.json",
        "edges_t2_allfields.json",
        "edges_t3_commits.json",
    ]:
        path = OUTPUT_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for edge in data.get("edges", []) + data.get("corroborating_edges", []):
            seen.add(tuple(sorted((edge["source"], edge["target"]))))
    return seen


def load_published_dates():
    """Load published dates for chronological edge direction."""
    parsed_path = OUTPUT_DIR / "parsed_cves.json"
    if not parsed_path.exists():
        return {}
    with open(parsed_path) as f:
        data = json.load(f)
    return {
        cve_id: info.get("published", "")
        for cve_id, info in data.get("cves", {}).items()
    }


def group_by_shared_id(structured_refs, enabled_types):
    """Group CVEs by shared external ID. Returns {group_key: set of CVE IDs}."""
    groups = defaultdict(set)

    for cve_id, sid in structured_refs:
        sid_type = sid["type"]
        if sid_type not in enabled_types:
            continue

        if sid_type == "bugzilla":
            key = ("bugzilla", sid.get("domain", ""), sid["value"])
        elif sid_type in ("github_issue", "github_pr"):
            key = (sid_type, sid.get("repo", ""), sid["value"])
        elif sid_type == "jira":
            key = ("jira", sid["value"])
        else:
            continue

        groups[key].add(cve_id)

    # Filter: need at least 2 CVEs, skip overly large clusters
    return {
        key: cves for key, cves in groups.items()
        if 2 <= len(cves) <= MAX_CLUSTER
    }


def format_context(key):
    """Human-readable description of a shared ID group."""
    id_type = key[0]
    if id_type == "bugzilla":
        return f"shared Bugzilla #{key[2]} on {key[1]}"
    elif id_type in ("github_issue", "github_pr"):
        label = "issue" if id_type == "github_issue" else "PR"
        return f"shared GitHub {label} {key[1]}#{key[2]}"
    elif id_type == "jira":
        return f"shared JIRA {key[1]}"
    return f"shared {id_type} {key[-1]}"


def main():
    parser = argparse.ArgumentParser(description="T4: Find CVE pairs sharing bug tracker IDs")
    parser.add_argument(
        "--include-jira", action="store_true",
        help="Include JIRA matches (noisy, off by default)",
    )
    args = parser.parse_args()

    if not REFERENCE_INDEX_PATH.exists():
        print(f"Error: {REFERENCE_INDEX_PATH} not found. Run build_reference_index.py first.")
        return

    enabled_types = set(DEFAULT_ID_TYPES)
    if args.include_jira:
        enabled_types.add("jira")

    print("Loading structured IDs from reference index...")
    structured_refs = load_structured_ids()
    print(f"Found {len(structured_refs):,} structured ID references")

    groups = group_by_shared_id(structured_refs, enabled_types)
    print(f"Found {len(groups):,} shared-ID groups (2-{MAX_CLUSTER} CVEs each)")

    prior_edges = load_prior_edges()
    dates = load_published_dates()

    new_edges = []
    corroborating_edges = []
    edges_by_type = defaultdict(int)

    # Accumulate all contexts per pair, then emit one edge each
    pair_contexts = defaultdict(list)  # (cve_a, cve_b) -> [(id_type, context), ...]

    for key, cves in groups.items():
        context = format_context(key)
        id_type = key[0]

        for cve_a, cve_b in combinations(sorted(cves), 2):
            pair_contexts[(cve_a, cve_b)].append((id_type, context))

    for (cve_a, cve_b), contexts in pair_contexts.items():
        # Direction: newer CVE is the source (variant), older is target (original)
        date_a = dates.get(cve_a, "9999")
        date_b = dates.get(cve_b, "9999")
        if date_a >= date_b:
            source, target = cve_a, cve_b
        else:
            source, target = cve_b, cve_a

        combined_context = "; ".join(ctx for _, ctx in contexts)
        id_types = sorted({t for t, _ in contexts})
        found_in = f"t4_shared_{'_'.join(id_types)}" if len(id_types) == 1 else "t4_shared_ids"

        edge = {
            "source": source,
            "target": target,
            "found_in": found_in,
            "context": combined_context,
        }

        normalized = tuple(sorted((cve_a, cve_b)))
        if normalized in prior_edges:
            corroborating_edges.append(edge)
        else:
            new_edges.append(edge)
        for id_type, _ in contexts:
            edges_by_type[id_type] += 1

    # Output
    OUTPUT_DIR.mkdir(exist_ok=True)
    output = {
        "tier": "t4_shared_ids",
        "edge_count": len(new_edges),
        "corroborating_count": len(corroborating_edges),
        "edges_by_type": dict(edges_by_type),
        "groups_found": len(groups),
        "id_types_enabled": sorted(enabled_types),
        "generated_at": datetime.now().isoformat(),
        "edges": new_edges,
        "corroborating_edges": corroborating_edges,
    }

    out_path = OUTPUT_DIR / "edges_t4_shared_ids.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n{'='*60}")
    print(f"ID types enabled:           {', '.join(sorted(enabled_types))}")
    print(f"Shared-ID groups:           {len(groups):>8,}")
    print(f"Total pairs found:          {len(pair_contexts):>8,}")
    print(f"New edges (beyond T1-T3):   {len(new_edges):>8,}")
    print(f"Corroborating (also T1-T3): {len(corroborating_edges):>8,}")
    print(f"{'='*60}")

    print("\nBy ID type:")
    for id_type, count in sorted(edges_by_type.items(), key=lambda x: -x[1]):
        print(f"  {id_type:25s}  {count:>8,}")

    print(f"\nSaved to {out_path}")


if __name__ == "__main__":
    main()
