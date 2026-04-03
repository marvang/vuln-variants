"""
Build variant chains from tiered CVE edge data.

Loads edges from one or more tiers, builds a directed graph,
finds connected components, and outputs tree-structured chains
with provenance tracking (which tier found each edge).

Usage:
  uv run python build_chains.py                  # T1 only (default)
  uv run python build_chains.py --tiers 1,2      # T1 + T2
  uv run python build_chains.py --tiers 1,2,3    # all tiers
"""

import argparse
import json
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

OUTPUT_DIR = Path("output")
DATASETS_DIR = Path("datasets")
PARSED_OUTPUT_PATH = OUTPUT_DIR / "parsed_cves.json"
REFERENCE_GRAPH_PATH = OUTPUT_DIR / "cve_references.json"

TIER_FILES = {
    "1": OUTPUT_DIR / "edges_t1_description.json",
    "2": OUTPUT_DIR / "edges_t2_allfields.json",
    "3": OUTPUT_DIR / "edges_t3_commits.json",
    "4": OUTPUT_DIR / "edges_t4_shared_ids.json",
    "5": DATASETS_DIR / "edges_t5_llm.json",
}


def load_edges(tiers):
    """Load and merge edges from specified tier files.

    Returns edge_provenance as a dict mapping (source, target) to a list of
    evidence dicts, preserving all provenance from every tier that found
    the same edge.
    """
    edge_provenance = defaultdict(list)  # (source, target) -> [evidence, ...]
    edges_by_tier = {}
    missing_tiers = []

    for tier in tiers:
        filename = TIER_FILES.get(tier)
        if not filename:
            print(f"WARNING: Unknown tier '{tier}', skipping")
            continue

        path = filename
        if not path.exists():
            missing_tiers.append(tier)
            continue

        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        tier_edges = data.get("edges", [])
        corroborating = data.get("corroborating_edges", [])
        edges_by_tier[f"t{tier}"] = len(tier_edges)

        for edge in tier_edges + corroborating:
            key = (edge["source"], edge["target"])
            edge_provenance[key].append({
                "found_in": edge.get("found_in", f"t{tier}"),
                "context": edge.get("context", ""),
            })

    if missing_tiers:
        print(f"NOTE: Tier file(s) not found for tier(s) {', '.join(missing_tiers)} — skipping")

    return dict(edge_provenance), edges_by_tier


def load_cve_metadata():
    """Load CVE metadata from the full parsed corpus when available."""
    for path in (PARSED_OUTPUT_PATH, REFERENCE_GRAPH_PATH):
        if not path.exists():
            continue

        with open(path) as f:
            data = json.load(f)

        return data.get("cves", {}), data.get("metadata", {})

    return {}, {}


def build_graph(edge_provenance, cve_data):
    """Build parent->children adjacency lists from edges."""
    children = defaultdict(set)
    parents = defaultdict(set)

    for (source, target) in edge_provenance:
        # source mentions target in some field → target is parent, source is child
        children[target].add(source)
        parents[source].add(target)

    return children, parents


def find_components(edge_provenance, children, parents):
    """Find connected components via BFS."""
    involved = set()
    for source, target in edge_provenance:
        involved.add(source)
        involved.add(target)

    visited = set()
    components = []

    for start in involved:
        if start in visited:
            continue
        component = set()
        queue = deque([start])
        while queue:
            node = queue.popleft()
            if node in visited:
                continue
            visited.add(node)
            component.add(node)
            for neighbor in children.get(node, set()) | parents.get(node, set()):
                if neighbor not in visited:
                    queue.append(neighbor)
        if len(component) >= 2:
            components.append(component)

    return components


def published_sort_key(cve_id, cve_data):
    """Sort missing dates last instead of treating them as earliest."""
    return cve_data.get(cve_id, {}).get("published") or "9999-12-31T23:59:59"


def build_tree(cve_id, cve_data, children, parents, edge_provenance, visited, parent_id=None):
    """Recursively build a tree node with provenance tracking."""
    if cve_id in visited:
        return None
    visited.add(cve_id)

    data = cve_data.get(cve_id, {})

    # Find all evidence for how this node was linked to the tree parent.
    evidence = []
    if parent_id is not None:
        key = (cve_id, parent_id)
        if key in edge_provenance:
            evidence = edge_provenance[key]

    node = {
        "cve_id": cve_id,
        "published": data.get("published", ""),
        "description": data.get("description", ""),
    }
    if evidence:
        node["evidence"] = evidence
    node["variants"] = []

    # Sort children chronologically
    child_ids = sorted(
        children.get(cve_id, set()),
        key=lambda x: published_sort_key(x, cve_data),
    )

    for child_id in child_ids:
        child_node = build_tree(
            child_id,
            cve_data,
            children,
            parents,
            edge_provenance,
            visited,
            parent_id=cve_id,
        )
        if child_node:
            node["variants"].append(child_node)

    return node


def count_tree_depth(node):
    """Get max depth of a tree."""
    if not node.get("variants"):
        return 1
    return 1 + max(count_tree_depth(v) for v in node["variants"])


def main():
    parser = argparse.ArgumentParser(description="Build CVE variant chains")
    parser.add_argument(
        "--min-size", type=int, default=2, help="Minimum chain size (default: 2)"
    )
    parser.add_argument(
        "--tiers", default="1,2,3",
        help="Comma-separated tier numbers (default: 1,2,3). Add 4 for weak T4, 5 for LLM T5"
    )
    args = parser.parse_args()

    tiers = [t.strip() for t in args.tiers.split(",")]
    print(f"Loading edges from tier(s): {', '.join(tiers)}")

    edge_provenance, edges_by_tier = load_edges(tiers)
    cve_data, scan_meta = load_cve_metadata()

    if not edge_provenance:
        print("ERROR: No edges loaded. Run parse_cves.py first.")
        return

    total_edges = len(edge_provenance)
    print(f"Loaded {total_edges:,} unique edges\n")

    # Ensure all CVEs referenced in edges have at least stub data
    for source, target in edge_provenance:
        for cve_id in (source, target):
            if cve_id not in cve_data:
                cve_data[cve_id] = {"published": "", "description": ""}

    children, parents = build_graph(edge_provenance, cve_data)
    components = find_components(edge_provenance, children, parents)

    # Filter and sort
    components = [c for c in components if len(c) >= args.min_size]
    components.sort(key=len, reverse=True)

    print(f"Found {len(components):,} chains (min size {args.min_size})\n")

    chains = []
    size_distribution = defaultdict(int)

    for i, component in enumerate(components):
        roots = [n for n in component if not (parents.get(n, set()) & component)]

        if not roots:
            roots = [
                min(component, key=lambda x: published_sort_key(x, cve_data))
            ]

        roots.sort(key=lambda x: published_sort_key(x, cve_data))

        visited = set()
        trees = []
        for root in roots:
            tree = build_tree(root, cve_data, children, parents, edge_provenance, visited)
            if tree:
                trees.append(tree)

        for n in component:
            if n not in visited:
                tree = build_tree(n, cve_data, children, parents, edge_provenance, visited)
                if tree:
                    trees.append(tree)

        max_depth = max(count_tree_depth(t) for t in trees) if trees else 0

        chain = {
            "chain_id": i + 1,
            "size": len(component),
            "max_depth": max_depth,
            "trees": trees,
        }
        chains.append(chain)
        size_distribution[len(component)] += 1

    # Statistics
    total_cves_in_chains = sum(c["size"] for c in chains)
    total_scanned = scan_meta.get("total_published_cves", 0)
    pct_in_chains = (
        total_cves_in_chains / total_scanned * 100 if total_scanned else 0
    )

    stats = {
        "total_cves_scanned": total_scanned,
        "total_cves_in_chains": total_cves_in_chains,
        "pct_cves_in_chains": round(pct_in_chains, 2),
        "chains_found": len(chains),
        "largest_chain_size": chains[0]["size"] if chains else 0,
        "deepest_chain_depth": max((c["max_depth"] for c in chains), default=0),
        "min_chain_size_filter": args.min_size,
        "tiers_used": [f"t{t}" for t in tiers],
        "edges_by_tier": edges_by_tier,
        "total_unique_edges": total_edges,
        "size_distribution": {
            str(k): v for k, v in sorted(size_distribution.items())
        },
        "generated_at": datetime.now().isoformat(),
    }

    output = {
        "metadata": stats,
        "chains": chains,
    }

    out_path = OUTPUT_DIR / "variant_chains.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    # Raw graph: flat edge list with all evidence, before treeification
    raw_edges = []
    for (source, target), evidence_list in edge_provenance.items():
        raw_edges.append({
            "source": source,
            "target": target,
            "evidence": evidence_list,
        })
    graph_output = {
        "metadata": {
            "total_edges": len(raw_edges),
            "tiers_used": [f"t{t}" for t in tiers],
            "generated_at": datetime.now().isoformat(),
        },
        "edges": raw_edges,
    }
    graph_path = OUTPUT_DIR / "edge_graph.json"
    with open(graph_path, "w") as f:
        json.dump(graph_output, f, indent=2)

    # Print summary
    print(f"{'='*60}")
    print(f"Tiers used:                  {', '.join(f't{t}' for t in tiers)}")
    print(f"Total unique edges:          {total_edges:>10,}")
    for tier_name, count in edges_by_tier.items():
        print(f"  {tier_name}:{'':>{22-len(tier_name)}}{count:>10,}")
    print(f"Total CVEs scanned:          {total_scanned:>10,}")
    print(f"CVEs in variant chains:      {total_cves_in_chains:>10,}  ({pct_in_chains:.2f}%)")
    print(f"Chains found:                {stats['chains_found']:>10,}")
    print(f"Largest chain:               {stats['largest_chain_size']:>10} CVEs")
    print(f"Deepest chain:               {stats['deepest_chain_depth']:>10} levels")
    print(f"{'='*60}")

    print("\nChain size distribution:")
    for size, count in sorted(size_distribution.items()):
        print(f"  {size} CVEs: {count:,} chains")

    print("\nTop 20 chains by size:")
    for chain in chains[:20]:
        root_ids = [t["cve_id"] for t in chain["trees"]]
        print(
            f"  #{chain['chain_id']:>4}  size={chain['size']:<4} "
            f"depth={chain['max_depth']:<3} roots: {', '.join(root_ids[:3])}"
            f"{'...' if len(root_ids) > 3 else ''}"
        )

    print(f"\nSaved to {out_path}")
    print(f"Raw edge graph saved to {graph_path}")


if __name__ == "__main__":
    main()
