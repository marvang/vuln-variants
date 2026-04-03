"""
Validate the automated CVE variant chains against a manually curated ground truth.

Checks two things:
  1. CVE coverage — are the curated CVEs present in the parsed corpus and generated chains?
  2. Edge coverage — for each curated A→B relationship, did the raw tier outputs detect it?

Usage:
  uv run python validate.py
  uv run python validate.py --ground-truth my_list.json
"""

import argparse
import json
from collections import defaultdict
from pathlib import Path

from build_chains import TIER_FILES

OUTPUT_DIR = Path("output")
PARSED_OUTPUT_PATH = OUTPUT_DIR / "parsed_cves.json"


def load_ground_truth(path):
    with open(path) as f:
        return json.load(f)


def load_generated(path):
    with open(path) as f:
        return json.load(f)


def extract_chain_edges_and_cves(chains_data):
    """Walk the generated tree structure and extract tree edges and CVE IDs."""
    edges = set()
    cves = set()

    def walk(node, parent_id=None):
        cve_id = node["cve_id"]
        cves.add(cve_id)
        if parent_id:
            edges.add((parent_id, cve_id))
        for variant in node.get("variants", []):
            walk(variant, cve_id)

    for chain in chains_data.get("chains", []):
        for tree in chain.get("trees", []):
            walk(tree)

    return edges, cves


def normalize_tier_label(label):
    label = str(label).lower().strip()
    if label.startswith("t"):
        label = label[1:]
    return label


def extract_detected_edges(chains_data, edge_dir=None):
    """Load the full detected edge set from raw tier outputs."""
    tiers_used = chains_data.get("metadata", {}).get("tiers_used") or ["t1"]
    edges = set()
    missing_files = []

    for tier_label in tiers_used:
        tier = normalize_tier_label(tier_label)
        tier_path = TIER_FILES.get(tier)
        if not tier_path:
            continue

        path = edge_dir / tier_path.name if edge_dir else tier_path
        if not path.exists():
            missing_files.append(str(path))
            continue

        data = load_generated(path)
        for edge in data.get("edges", []) + data.get("corroborating_edges", []):
            # Raw files store child -> parent; validation compares parent -> child.
            edges.add((edge["target"], edge["source"]))

    return edges, missing_files


def load_parsed_corpus(parsed_path, references_path):
    parsed_path = Path(parsed_path)
    if parsed_path.exists():
        return load_generated(parsed_path), False
    return load_generated(references_path), True


def main():
    parser = argparse.ArgumentParser(description="Validate against ground truth")
    parser.add_argument(
        "--ground-truth", default="ground_truth.json", help="Path to curated list"
    )
    parser.add_argument(
        "--chains", default=str(OUTPUT_DIR / "variant_chains.json"),
        help="Path to generated chains",
    )
    parser.add_argument(
        "--references", default=str(OUTPUT_DIR / "cve_references.json"),
        help="Path to generated reference graph",
    )
    parser.add_argument(
        "--parsed", default=str(PARSED_OUTPUT_PATH),
        help="Path to full parsed CVE corpus",
    )
    args = parser.parse_args()

    gt = load_ground_truth(args.ground_truth)
    chains_data = load_generated(args.chains)
    _ = load_generated(args.references)  # Validate that the graph artifact exists.
    parsed_data, used_parsed_fallback = load_parsed_corpus(args.parsed, args.references)
    edge_dir = Path(args.chains).resolve().parent

    tree_edges, generated_cves = extract_chain_edges_and_cves(chains_data)
    generated_edges, missing_edge_files = extract_detected_edges(chains_data, edge_dir)
    if not generated_edges:
        generated_edges = tree_edges

    all_parsed_cves = set(parsed_data.get("cves", {}).keys())

    # --- CVE-level coverage ---
    print("=" * 70)
    print("CVE-LEVEL COVERAGE")
    print("=" * 70)

    if used_parsed_fallback:
        print(
            f"\nNOTE: {args.parsed} not found;"
            f" falling back to {args.references} for membership checks."
        )
    if missing_edge_files:
        print("\nNOTE: Missing tier edge file(s); only available raw edges were used:")
        for path in missing_edge_files:
            print(f"  - {path}")
        if generated_edges == tree_edges:
            print("  Falling back to tree edges because no raw edge files were available.")

    all_gt_cves = set()
    for chain in gt["chains"]:
        all_gt_cves.update(chain["cves"])

    found_in_graph = all_gt_cves & generated_cves
    found_in_parsed = all_gt_cves & all_parsed_cves
    missing_from_chains = all_gt_cves - generated_cves
    missing_from_data = all_gt_cves - all_parsed_cves

    print(f"\nGround truth CVEs:           {len(all_gt_cves)}")
    print(f"Found in generated chains:   {len(found_in_graph)}  "
          f"({len(found_in_graph)/len(all_gt_cves)*100:.1f}%)")
    print(f"Found in parsed data:        {len(found_in_parsed)}  "
          f"({len(found_in_parsed)/len(all_gt_cves)*100:.1f}%)")

    if missing_from_data:
        print("\nMissing from parsed data entirely (not in cvelistV5 or unpublished):")
        for cve in sorted(missing_from_data):
            print(f"  - {cve}")

    if missing_from_chains - missing_from_data:
        print("\nParsed but NOT in any chain (description doesn't reference other CVEs):")
        for cve in sorted(missing_from_chains - missing_from_data):
            # Check if it's referenced by anything or references anything
            cve_data = parsed_data.get("cves", {}).get(cve)
            if cve_data:
                refs = cve_data.get("references", [])
                print(f"  - {cve}  (refs in desc: {refs if refs else 'none'})")
            else:
                print(f"  - {cve}  (not in reference graph — no refs found)")

    # --- Edge-level coverage ---
    print(f"\n{'=' * 70}")
    print("EDGE-LEVEL COVERAGE")
    print("=" * 70)

    total_gt_edges = 0
    found_edges = 0
    missed_edges = []

    for chain in gt["chains"]:
        cves = chain["cves"]
        name = chain.get("name", "unnamed")
        print(f"\n--- {name} ---")
        print(f"  Curated chain: {' → '.join(cves)}")

        # Generate all consecutive edges from the curated chain
        chain_found = 0
        chain_total = 0
        for i in range(len(cves) - 1):
            parent, child = cves[i], cves[i + 1]
            chain_total += 1
            total_gt_edges += 1

            # Check if this edge exists in generated data (in either direction)
            if (parent, child) in generated_edges:
                print(f"  [FOUND]   {parent} → {child}")
                found_edges += 1
                chain_found += 1
            elif (child, parent) in generated_edges:
                print(f"  [FOUND*]  {parent} → {child}  (reversed direction in generated)")
                found_edges += 1
                chain_found += 1
            else:
                # Diagnose WHY it's missing
                child_data = parsed_data.get("cves", {}).get(child, {})
                child_refs = child_data.get("references", [])
                parent_data = parsed_data.get("cves", {}).get(parent, {})
                parent_refs = parent_data.get("references", [])

                reason = "unknown"
                if child not in all_parsed_cves:
                    reason = f"{child} not in dataset"
                elif parent not in all_parsed_cves:
                    reason = f"{parent} not in dataset"
                elif parent not in child_refs and child not in parent_refs:
                    reason = "neither description mentions the other CVE"
                else:
                    reason = "edge mentioned in descriptions but not detected in tier outputs"

                print(f"  [MISSED]  {parent} → {child}  — {reason}")
                missed_edges.append({
                    "chain": name,
                    "parent": parent,
                    "child": child,
                    "reason": reason,
                })

        print(f"  Coverage: {chain_found}/{chain_total} edges")

    # --- Summary ---
    print(f"\n{'=' * 70}")
    print("SUMMARY")
    print("=" * 70)
    pct_cves = len(found_in_graph) / len(all_gt_cves) * 100 if all_gt_cves else 0
    pct_edges = found_edges / total_gt_edges * 100 if total_gt_edges else 0

    print(f"CVE recall:   {len(found_in_graph)}/{len(all_gt_cves)} ({pct_cves:.1f}%)")
    print(f"Edge recall:  {found_edges}/{total_gt_edges} ({pct_edges:.1f}%)")

    if missed_edges:
        print(f"\n{len(missed_edges)} missed edge(s) — reasons:")
        reasons = defaultdict(int)
        for e in missed_edges:
            reasons[e["reason"]] += 1
        for reason, count in sorted(reasons.items(), key=lambda x: -x[1]):
            print(f"  {count}x  {reason}")

    # Save results
    results = {
        "cve_recall": {
            "found": len(found_in_graph),
            "total": len(all_gt_cves),
            "pct": round(pct_cves, 2),
            "missing": sorted(missing_from_chains),
        },
        "edge_recall": {
            "found": found_edges,
            "total": total_gt_edges,
            "pct": round(pct_edges, 2),
            "missed": missed_edges,
        },
    }

    OUTPUT_DIR.mkdir(exist_ok=True)
    out_path = OUTPUT_DIR / "validation_results.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
