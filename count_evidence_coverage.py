"""
Count how many CVEs fall into the direct, candidate-only, and discovery-only lanes.

Direct evidence is defined as any T1 or T2 edge involvement.
Candidate-only evidence is defined as structured IDs or T3 evidence without direct edges.
Discovery-only CVEs have neither direct nor candidate evidence.
"""

import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

OUTPUT_DIR = Path("output")
PARSED_CVES_PATH = OUTPUT_DIR / "parsed_cves.json"
REFERENCE_INDEX_PATH = OUTPUT_DIR / "reference_index.json"
OUT_PATH = OUTPUT_DIR / "evidence_coverage.json"
CLEAN_CANDIDATE_TYPES = {"bugzilla", "github_commit", "github_issue", "github_pr"}


def load_published_cves(path=PARSED_CVES_PATH):
    """Load all published CVE IDs."""
    with open(path) as f:
        return set(json.load(f)["cves"].keys())


def load_edge_involvement():
    """Return per-CVE evidence classes from T1/T2/T3 edge files."""
    involvement = defaultdict(set)
    tier_files = {
        "t1": "edges_t1_description.json",
        "t2": "edges_t2_allfields.json",
        "t3": "edges_t3_commits.json",
    }
    for label, filename in tier_files.items():
        path = OUTPUT_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for edge in data.get("edges", []) + data.get("corroborating_edges", []):
            involvement[edge["source"]].add(label)
            involvement[edge["target"]].add(label)
    return dict(involvement)


def load_structured_id_involvement(path=REFERENCE_INDEX_PATH):
    """Return per-CVE structured-ID classes from the reference index."""
    involvement = defaultdict(set)
    with open(path) as f:
        data = json.load(f)
    valid_types = {"github_commit", "bugzilla", "github_issue", "github_pr", "jira"}
    for ref in data["references"]:
        cve_id = ref["cve_id"]
        for sid in ref.get("structured_ids", []):
            if sid["type"] in valid_types:
                involvement[cve_id].add(sid["type"])
    return dict(involvement)


def build_coverage_summary(published_cves, edge_involvement, structured_involvement):
    """Build the coverage breakdown for direct, candidate-only, and discovery-only CVEs."""
    direct = set()
    candidate = set()
    default_candidate = set()
    class_counts = Counter()

    for cve_id, labels in edge_involvement.items():
        if "t1" in labels or "t2" in labels:
            direct.add(cve_id)
        if "t3" in labels:
            candidate.add(cve_id)
            default_candidate.add(cve_id)
        for label in labels:
            class_counts[label] += 1

    for cve_id, sid_labels in structured_involvement.items():
        candidate.add(cve_id)
        if sid_labels & CLEAN_CANDIDATE_TYPES:
            default_candidate.add(cve_id)
        for label in sid_labels:
            class_counts[label] += 1

    candidate_only = candidate - direct
    default_candidate_only = default_candidate - direct
    discovery_only = published_cves - direct - candidate
    default_discovery_only = published_cves - direct - default_candidate
    jira_only_candidate = candidate_only - default_candidate_only

    return {
        "published_total": len(published_cves),
        "direct_evidence_total": len(direct),
        "candidate_only_total": len(candidate_only),
        "candidate_only_default_total": len(default_candidate_only),
        "jira_only_candidate_total": len(jira_only_candidate),
        "discovery_only_total": len(discovery_only),
        "discovery_only_default_total": len(default_discovery_only),
        "direct_evidence_pct": round(len(direct) / len(published_cves) * 100, 2),
        "candidate_only_pct": round(len(candidate_only) / len(published_cves) * 100, 2),
        "candidate_only_default_pct": round(
            len(default_candidate_only) / len(published_cves) * 100, 2
        ),
        "jira_only_candidate_pct": round(len(jira_only_candidate) / len(published_cves) * 100, 2),
        "discovery_only_pct": round(len(discovery_only) / len(published_cves) * 100, 2),
        "discovery_only_default_pct": round(
            len(default_discovery_only) / len(published_cves) * 100, 2
        ),
        "by_evidence_class": dict(sorted(class_counts.items())),
    }


def main():
    published_cves = load_published_cves()
    edge_involvement = load_edge_involvement()
    structured_involvement = load_structured_id_involvement()
    summary = build_coverage_summary(published_cves, edge_involvement, structured_involvement)

    output = {
        "metadata": {
            "direct_policy": "t1_and_all_t2",
            "candidate_policy": "t3_and_structured_ids_without_direct_evidence",
            "generated_at": datetime.now().isoformat(),
        },
        "summary": summary,
    }

    with open(OUT_PATH, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Published CVEs:                       {summary['published_total']:>8,}")
    print(
        f"Direct evidence (T1/T2):              {summary['direct_evidence_total']:>8,}"
        f"  ({summary['direct_evidence_pct']:.2f}%)"
    )
    print(
        f"Candidate-only evidence:              {summary['candidate_only_total']:>8,}"
        f"  ({summary['candidate_only_pct']:.2f}%)"
    )
    print(
        f"Candidate-only (default T4, JIRA off):"
        f"{summary['candidate_only_default_total']:>8,}"
        f"  ({summary['candidate_only_default_pct']:.2f}%)"
    )
    print(
        f"Discovery-only:                       {summary['discovery_only_total']:>8,}"
        f"  ({summary['discovery_only_pct']:.2f}%)"
    )
    print(f"\nSaved to {OUT_PATH}")


if __name__ == "__main__":
    main()
