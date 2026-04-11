"""Sample edges from each tier and fetch CVE descriptions for manual categorization."""
import json
import random
from pathlib import Path

DATA_DIR = Path("data/cvelistV5/cves")
OUTPUT_DIR = Path("output")

random.seed(42)

def load_cve_description(cve_id):
    """Load description for a CVE from the cvelistV5 data."""
    parts = cve_id.split("-")
    year = parts[1]
    num = int(parts[2])
    bucket = f"{num // 1000}xxx"
    path = DATA_DIR / year / bucket / f"{cve_id}.json"
    if not path.exists():
        return "(file not found)"
    with open(path) as f:
        data = json.load(f)
    descs = data.get("containers", {}).get("cna", {}).get("descriptions", [])
    for d in descs:
        if d.get("lang", "en").startswith("en"):
            return d["value"]
    return descs[0]["value"] if descs else "(no description)"

def sample_tier(filepath, n, tier_name):
    """Load edges from a tier file and sample n of them."""
    with open(filepath) as f:
        data = json.load(f)
    edges = data["edges"]
    print(f"\n{'='*80}")
    print(f"TIER: {tier_name} — {len(edges)} total edges, sampling {min(n, len(edges))}")
    print(f"{'='*80}")

    sampled = random.sample(edges, min(n, len(edges)))
    results = []
    for i, edge in enumerate(sampled, 1):
        source = edge["source"]
        target = edge["target"]
        found_in = edge["found_in"]
        context = edge.get("context", "")

        source_desc = load_cve_description(source)
        target_desc = load_cve_description(target)

        entry = {
            "idx": i,
            "source": source,
            "target": target,
            "found_in": found_in,
            "context": context,
            "source_description": source_desc,
            "target_description": target_desc,
        }
        results.append(entry)

        print(f"\n--- Sample {i}: {source} → {target} [{found_in}] ---")
        print(f"Context: {context[:300]}")
        print(f"\nSource ({source}):")
        print(f"  {source_desc[:500]}")
        print(f"\nTarget ({target}):")
        print(f"  {target_desc[:500]}")

    return results

all_samples = {}

# T1: description edges
t1 = sample_tier(OUTPUT_DIR / "edges_t1_description.json", 100, "T1 Description")
all_samples["t1"] = t1

# T2: all-fields edges (only edges NOT already in T1 — the novel ones)
with open(OUTPUT_DIR / "edges_t1_description.json") as f:
    t1_data = json.load(f)
t1_pairs = {(e["source"], e["target"]) for e in t1_data["edges"]}

with open(OUTPUT_DIR / "edges_t2_allfields.json") as f:
    t2_data = json.load(f)
t2_novel = [e for e in t2_data["edges"] if (e["source"], e["target"]) not in t1_pairs]
print(f"\nT2 has {len(t2_data['edges'])} total edges, {len(t2_novel)} novel (not in T1)")

# Sample from novel T2 edges
sampled_t2 = random.sample(t2_novel, min(20, len(t2_novel)))
t2_results = []
print(f"\n{'='*80}")
print(f"TIER: T2 Novel — {len(t2_novel)} novel edges, sampling {len(sampled_t2)}")
print(f"{'='*80}")
for i, edge in enumerate(sampled_t2, 1):
    source = edge["source"]
    target = edge["target"]
    found_in = edge["found_in"]
    context = edge.get("context", "")
    source_desc = load_cve_description(source)
    target_desc = load_cve_description(target)
    entry = {
        "idx": i, "source": source, "target": target,
        "found_in": found_in, "context": context,
        "source_description": source_desc, "target_description": target_desc,
    }
    t2_results.append(entry)
    print(f"\n--- Sample {i}: {source} → {target} [{found_in}] ---")
    print(f"Context: {context[:300]}")
    print(f"\nSource ({source}):")
    print(f"  {source_desc[:500]}")
    print(f"\nTarget ({target}):")
    print(f"  {target_desc[:500]}")
all_samples["t2_novel"] = t2_results

# T3: commit edges
t3 = sample_tier(OUTPUT_DIR / "edges_t3_commits.json", 20, "T3 Commits")
all_samples["t3"] = t3

# Save all samples
with open(OUTPUT_DIR / "edge_samples.json", "w") as f:
    json.dump(all_samples, f, indent=2)
print(f"\n\nSaved all samples to {OUTPUT_DIR / 'edge_samples.json'}")
