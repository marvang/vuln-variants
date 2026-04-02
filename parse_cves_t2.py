"""
Tier 2: Scan ALL text fields in CVE JSON for cross-references.

Expands beyond T1 (description only) to also check:
  - references[].name (mailing list subjects)
  - references[].url (URLs embedding CVE IDs)
  - title
  - ADP container descriptions
  - ADP container references[].name
  - x_legacyV4Record descriptions

Outputs only NEW edges not already found in T1.
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


def extract_field_texts(data):
    """Extract all text fields from CVE JSON, tagged by source.

    Returns list of (found_in_label, text) tuples.
    """
    fields = []
    cna = data.get("containers", {}).get("cna", {})

    # CNA title
    title = cna.get("title", "")
    if title:
        fields.append(("t2_title", title))

    # CNA reference names and URLs
    for ref in cna.get("references", []):
        name = ref.get("name", "")
        if name:
            fields.append(("t2_ref_name", name))
        url = ref.get("url", "")
        if url:
            fields.append(("t2_ref_url", url))

    # ADP containers
    for adp in data.get("containers", {}).get("adp", []):
        for desc in adp.get("descriptions", []):
            val = desc.get("value", "")
            if val:
                fields.append(("t2_adp_description", val))
        for ref in adp.get("references", []):
            name = ref.get("name", "")
            if name:
                fields.append(("t2_ref_name", name))

    # Legacy V4 record descriptions
    legacy = cna.get("x_legacyV4Record", {})
    if not legacy:
        legacy = data.get("x_legacyV4Record", {})
    legacy_descs = legacy.get("description", {}).get("description_data", [])
    for d in legacy_descs:
        val = d.get("value", "")
        if val:
            fields.append(("t2_legacy", val))

    return fields


def main():
    OUTPUT_DIR.mkdir(exist_ok=True)

    # Load T1 edges to track overlap
    t1_path = OUTPUT_DIR / "edges_t1_description.json"
    if not t1_path.exists():
        print(f"ERROR: {t1_path} not found. Run parse_cves.py first.")
        return

    with open(t1_path) as f:
        t1_data = json.load(f)

    t1_edges = {(e["source"], e["target"]) for e in t1_data["edges"]}
    seen_edges = set()  # deduplicate within T2 only
    print(f"Loaded {len(t1_edges):,} T1 edges for overlap tracking\n")

    if not DATA_DIR.exists():
        print(f"ERROR: {DATA_DIR} not found.")
        return

    print("Scanning for CVE files...")
    json_files = sorted(DATA_DIR.rglob("CVE-*.json"))
    print(f"Found {len(json_files):,} CVE files\n")

    # Load published CVE IDs from parsed corpus (already produced by parse_cves.py)
    parsed_path = OUTPUT_DIR / "parsed_cves.json"
    if not parsed_path.exists():
        print(f"ERROR: {parsed_path} not found. Run parse_cves.py first.")
        return

    with open(parsed_path) as f:
        all_cve_ids = set(json.load(f)["cves"].keys())

    print(f"Loaded {len(all_cve_ids):,} published CVE IDs from parsed corpus")

    # Pass 2: scan all fields, streaming (no full JSON retained in memory)
    new_edges = []
    corroborating_edges = []
    edges_by_field = defaultdict(int)

    for filepath in tqdm(json_files, desc="Scanning fields"):
        try:
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue

        meta = data.get("cveMetadata", {})
        cve_id = meta.get("cveId")
        if not cve_id or meta.get("state") != "PUBLISHED":
            continue

        field_texts = extract_field_texts(data)

        for found_in, text in field_texts:
            refs = set(CVE_PATTERN.findall(text)) - {cve_id}
            for ref in refs:
                if ref not in all_cve_ids:
                    continue
                edge = (cve_id, ref)
                if edge in seen_edges:
                    continue

                idx = text.find(ref)
                if idx >= 0:
                    start = max(0, idx - 40)
                    end = min(len(text), idx + len(ref) + 40)
                    context = text[start:end]
                    if start > 0:
                        context = "..." + context
                    if end < len(text):
                        context = context + "..."
                else:
                    context = text[:80]

                edge_entry = {
                    "source": cve_id,
                    "target": ref,
                    "found_in": found_in,
                    "context": context,
                }
                if edge in t1_edges:
                    corroborating_edges.append(edge_entry)
                else:
                    new_edges.append(edge_entry)
                edges_by_field[found_in] += 1
                seen_edges.add(edge)

    # Output
    t2_output = {
        "tier": "t2_allfields",
        "edge_count": len(new_edges),
        "corroborating_count": len(corroborating_edges),
        "edges_by_field": dict(edges_by_field),
        "generated_at": datetime.now().isoformat(),
        "edges": new_edges,
        "corroborating_edges": corroborating_edges,
    }

    out_path = OUTPUT_DIR / "edges_t2_allfields.json"
    with open(out_path, "w") as f:
        json.dump(t2_output, f)

    # Print summary
    print(f"\n{'='*50}")
    print(f"T1 edges (description only):  {len(t1_data['edges']):>8,}")
    print(f"T2 new edges (all fields):    {len(new_edges):>8,}")
    print(f"T2 corroborating (also in T1):{len(corroborating_edges):>8,}")
    print(f"Combined unique total:        {len(t1_data['edges']) + len(new_edges):>8,}")
    print(f"{'='*50}")

    print("\nT2 edges by field type:")
    for field, count in sorted(edges_by_field.items(), key=lambda x: -x[1]):
        print(f"  {field}: {count:,}")

    print(f"\nSaved to {out_path}")


if __name__ == "__main__":
    main()
