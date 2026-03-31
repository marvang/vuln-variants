"""
Step 1: Parse all CVE JSON files from cvelistV5 and extract cross-references.

Walks data/cvelistV5/cves/, regex-matches CVE IDs in descriptions,
and outputs both the full parsed corpus and the graph-only reference subset.
"""

import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, **kwargs):
        print(kwargs.get("desc", "Processing"), "...")
        return iterable

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")
DATA_DIR = Path("data/cvelistV5/cves")
OUTPUT_DIR = Path("output")
PARSED_OUTPUT_PATH = OUTPUT_DIR / "parsed_cves.json"
GRAPH_OUTPUT_PATH = OUTPUT_DIR / "cve_references.json"


def parse_cve_file(filepath):
    """Extract CVE ID, published date, description, and referenced CVEs."""
    try:
        with open(filepath) as f:
            data = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

    meta = data.get("cveMetadata", {})
    cve_id = meta.get("cveId")
    if not cve_id or meta.get("state") != "PUBLISHED":
        return None

    published = meta.get("datePublished", "")

    # Get English description
    descs = data.get("containers", {}).get("cna", {}).get("descriptions", [])
    desc_text = ""
    for d in descs:
        if d.get("lang", "").startswith("en"):
            desc_text = d.get("value", "")
            break
    if not desc_text and descs:
        desc_text = descs[0].get("value", "")

    # Find other CVE IDs mentioned in the description
    refs = sorted(set(CVE_PATTERN.findall(desc_text)) - {cve_id})

    return {
        "cve_id": cve_id,
        "published": published,
        "description": desc_text,
        "references": refs,
    }


def main():
    OUTPUT_DIR.mkdir(exist_ok=True)

    if not DATA_DIR.exists():
        print(f"ERROR: {DATA_DIR} not found.")
        print("Clone the CVE database first:")
        print("  git clone https://github.com/CVEProject/cvelistV5.git data/cvelistV5")
        return

    # Find all CVE JSON files
    print("Scanning for CVE files...")
    json_files = sorted(DATA_DIR.rglob("CVE-*.json"))
    total_files = len(json_files)
    print(f"Found {total_files:,} CVE files\n")

    all_cves = {}
    parse_errors = 0

    for filepath in tqdm(json_files, desc="Parsing CVEs"):
        result = parse_cve_file(filepath)
        if result is None:
            parse_errors += 1
            continue
        all_cves[result["cve_id"]] = {
            "published": result["published"],
            "description": result["description"],
            "references": result["references"],
        }

    total_published = len(all_cves)
    referencing = {cid for cid, d in all_cves.items() if d["references"]}
    referenced = set()
    for d in all_cves.values():
        for ref in d["references"]:
            if ref in all_cves:
                referenced.add(ref)

    involved = referencing | referenced

    # Build filtered output (only CVEs in the reference graph)
    filtered = {cid: all_cves[cid] for cid in involved}

    # --- Statistics ---
    pct_referencing = (len(referencing) / total_published * 100) if total_published else 0
    pct_involved = (len(involved) / total_published * 100) if total_published else 0

    # Count by year
    year_counts = defaultdict(lambda: {"total": 0, "referencing": 0})
    for cid, d in all_cves.items():
        year = cid.split("-")[1]
        year_counts[year]["total"] += 1
        if cid in referencing:
            year_counts[year]["referencing"] += 1

    stats = {
        "total_files_scanned": total_files,
        "total_published_cves": total_published,
        "parse_errors": parse_errors,
        "cves_referencing_others": len(referencing),
        "cves_referenced_by_others": len(referenced),
        "total_in_reference_graph": len(involved),
        "pct_referencing": round(pct_referencing, 2),
        "pct_in_graph": round(pct_involved, 2),
        "by_year": {
            y: {
                "total": c["total"],
                "referencing": c["referencing"],
                "pct": round(c["referencing"] / c["total"] * 100, 2) if c["total"] else 0,
            }
            for y, c in sorted(year_counts.items())
        },
        "generated_at": datetime.now().isoformat(),
    }

    # Print summary
    print(f"\n{'='*50}")
    print(f"Total published CVEs:        {total_published:>8,}")
    print(f"CVEs referencing others:      {len(referencing):>8,}  ({pct_referencing:.2f}%)")
    print(f"CVEs referenced by others:    {len(referenced):>8,}")
    print(f"Total in reference graph:     {len(involved):>8,}  ({pct_involved:.2f}%)")
    print(f"Parse errors/skipped:         {parse_errors:>8,}")
    print(f"{'='*50}")

    print("\nBreakdown by year (top 10 by referencing count):")
    top_years = sorted(year_counts.items(), key=lambda x: x[1]["referencing"], reverse=True)[:10]
    for year, counts in top_years:
        pct = counts["referencing"] / counts["total"] * 100 if counts["total"] else 0
        print(f"  {year}: {counts['referencing']:,} / {counts['total']:,} ({pct:.1f}%)")

    # Save full parsed corpus for downstream metadata and membership checks
    parsed_output = {
        "metadata": stats,
        "cves": all_cves,
    }

    with open(PARSED_OUTPUT_PATH, "w") as f:
        json.dump(parsed_output, f)
    print(f"\nFull parsed corpus saved to {PARSED_OUTPUT_PATH}")

    # Save reference graph (only CVEs participating in at least one edge)
    graph_output = {
        "metadata": stats,
        "cves": filtered,
    }

    with open(GRAPH_OUTPUT_PATH, "w") as f:
        json.dump(graph_output, f)
    print(f"Reference graph saved to {GRAPH_OUTPUT_PATH}")

    # Save tier 1 edges file (standardized format for tiered pipeline)
    t1_edges = []
    for cid, d in all_cves.items():
        for ref in d["references"]:
            if ref in all_cves:
                # Extract a short context snippet around the CVE mention
                desc = d["description"]
                idx = desc.find(ref)
                if idx >= 0:
                    start = max(0, idx - 40)
                    end = min(len(desc), idx + len(ref) + 40)
                    context = desc[start:end]
                    if start > 0:
                        context = "..." + context
                    if end < len(desc):
                        context = context + "..."
                else:
                    context = ""
                t1_edges.append({
                    "source": cid,
                    "target": ref,
                    "found_in": "t1_description",
                    "context": context,
                })

    t1_output = {
        "tier": "t1_description",
        "edge_count": len(t1_edges),
        "generated_at": datetime.now().isoformat(),
        "edges": t1_edges,
    }

    t1_path = OUTPUT_DIR / "edges_t1_description.json"
    with open(t1_path, "w") as f:
        json.dump(t1_output, f)
    print(f"Tier 1 edges saved to {t1_path} ({len(t1_edges):,} edges)")

    # Save stats separately for easy access
    stats_path = OUTPUT_DIR / "stats.json"
    with open(stats_path, "w") as f:
        json.dump(stats, f, indent=2)
    print(f"Statistics saved to {stats_path}")


if __name__ == "__main__":
    main()
