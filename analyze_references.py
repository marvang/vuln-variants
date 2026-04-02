"""
Analyze the distribution of reference URLs across CVE records.

Produces domain frequency counts grouped by reference tag type
(vendor-advisory, third-party-advisory, mailing-list, untagged).
Helps decide which advisory sources to build structured extractors for.

Usage:
  uv run python analyze_references.py
  uv run python analyze_references.py --sample 50000
  uv run python analyze_references.py --all
"""

import argparse
import json
import os
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, **kwargs):
        print(kwargs.get("desc", "Processing"), "...")
        return iterable

DATA_DIR = Path("data/cvelistV5/cves")
OUTPUT_DIR = Path("output")

# Tags we care about for classification
ADVISORY_TAGS = {"vendor-advisory", "third-party-advisory", "mailing-list"}


def classify_reference(ref):
    """Classify a reference entry by its tags. Returns the most specific tag."""
    tags = set(ref.get("tags", []))
    for tag in ["vendor-advisory", "third-party-advisory", "mailing-list"]:
        if tag in tags:
            return tag
    return "untagged"


def extract_domain(url):
    """Extract and normalize the domain from a URL."""
    try:
        netloc = urlparse(url).netloc.lower()
        # Strip www. prefix for cleaner grouping
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return netloc
    except Exception:
        return "unknown"


def collect_cve_files(data_dir, sample_size=0):
    """Collect CVE JSON file paths, optionally limiting to a sample."""
    files = []
    for year in sorted(os.listdir(data_dir)):
        ypath = data_dir / year
        if not ypath.is_dir():
            continue
        for bucket in sorted(os.listdir(ypath)):
            bpath = ypath / bucket
            if not bpath.is_dir():
                continue
            for fname in os.listdir(bpath):
                if fname.endswith(".json"):
                    files.append(bpath / fname)
    if sample_size and sample_size < len(files):
        # Deterministic sample: evenly spaced across the sorted list
        step = len(files) / sample_size
        files = [files[int(i * step)] for i in range(sample_size)]
    return files


def analyze_references(files):
    """Analyze reference URLs across CVE files.

    Returns a dict with:
      - domains_by_tag: {tag: Counter of domains}
      - tag_counts: Counter of tag occurrences
      - total_refs: total reference count
      - total_cves: CVEs processed
      - cves_with_refs: CVEs that have at least one reference URL
      - refs_per_cve: distribution stats
      - url_patterns: common URL path patterns
    """
    domains_by_tag = defaultdict(Counter)
    tag_counts = Counter()
    all_domains = Counter()
    total_refs = 0
    total_cves = 0
    cves_with_refs = 0
    ref_counts = []
    has_tags_count = 0
    no_tags_count = 0

    # Track which domains have structured per-CVE pages
    # (URL contains the CVE ID in the path)
    domains_with_cve_in_url = Counter()

    for fpath in tqdm(files, desc="Analyzing references"):
        try:
            with open(fpath) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        metadata = data.get("cveMetadata", {})
        if metadata.get("state") != "PUBLISHED":
            continue

        cve_id = metadata.get("cveId", "")
        total_cves += 1

        # Collect references from CNA and ADP containers
        refs = []
        cna = data.get("containers", {}).get("cna", {})
        refs.extend(cna.get("references", []))
        for adp in data.get("containers", {}).get("adp", []):
            refs.extend(adp.get("references", []))

        if not refs:
            ref_counts.append(0)
            continue

        cves_with_refs += 1
        ref_counts.append(len(refs))

        seen_urls = set()
        for ref in refs:
            url = ref.get("url", "")
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)

            total_refs += 1
            domain = extract_domain(url)
            tag = classify_reference(ref)

            domains_by_tag[tag][domain] += 1
            all_domains[domain] += 1
            tag_counts[tag] += 1

            if tag != "untagged":
                has_tags_count += 1
            else:
                no_tags_count += 1

            # Check if CVE ID appears in the URL path
            if cve_id and cve_id.lower() in url.lower():
                domains_with_cve_in_url[domain] += 1

    return {
        "domains_by_tag": dict(domains_by_tag),
        "tag_counts": tag_counts,
        "all_domains": all_domains,
        "total_refs": total_refs,
        "total_cves": total_cves,
        "cves_with_refs": cves_with_refs,
        "has_tags_count": has_tags_count,
        "no_tags_count": no_tags_count,
        "domains_with_cve_in_url": domains_with_cve_in_url,
    }


def print_report(stats):
    """Print a human-readable analysis report."""
    print("=" * 70)
    print("CVE REFERENCE URL ANALYSIS")
    print("=" * 70)

    print(f"\nCVEs analyzed:        {stats['total_cves']:,}")
    print(f"CVEs with references: {stats['cves_with_refs']:,} "
          f"({stats['cves_with_refs'] / stats['total_cves'] * 100:.1f}%)")
    print(f"Total reference URLs: {stats['total_refs']:,}")
    print(f"Avg refs per CVE:     {stats['total_refs'] / stats['total_cves']:.1f}")

    print(f"\n{'=' * 70}")
    print("TAG DISTRIBUTION")
    print("=" * 70)
    for tag, count in stats["tag_counts"].most_common():
        pct = count / stats["total_refs"] * 100
        print(f"  {tag:25s}  {count:>8,}  ({pct:5.1f}%)")

    for tag in ["vendor-advisory", "third-party-advisory", "mailing-list", "untagged"]:
        domains = stats["domains_by_tag"].get(tag, Counter())
        if not domains:
            continue
        print(f"\n{'=' * 70}")
        print(f"TOP 20 DOMAINS — {tag.upper()}")
        print("=" * 70)
        for domain, count in domains.most_common(20):
            pct = count / stats["tag_counts"].get(tag, 1) * 100
            print(f"  {count:>6,}  ({pct:5.1f}%)  {domain}")

    print(f"\n{'=' * 70}")
    print("TOP 30 DOMAINS OVERALL")
    print("=" * 70)
    for domain, count in stats["all_domains"].most_common(30):
        pct = count / stats["total_refs"] * 100
        print(f"  {count:>6,}  ({pct:5.1f}%)  {domain}")

    print(f"\n{'=' * 70}")
    print("DOMAINS WITH CVE ID IN URL PATH (structured per-CVE pages)")
    print("=" * 70)
    for domain, count in stats["domains_with_cve_in_url"].most_common(20):
        print(f"  {count:>6,}  {domain}")


def save_report(stats):
    """Save analysis results as JSON."""
    OUTPUT_DIR.mkdir(exist_ok=True)
    out = {
        "generated_at": datetime.now().isoformat(),
        "total_cves": stats["total_cves"],
        "cves_with_refs": stats["cves_with_refs"],
        "total_refs": stats["total_refs"],
        "tag_distribution": {
            tag: count for tag, count in stats["tag_counts"].most_common()
        },
        "top_domains_by_tag": {},
        "top_domains_overall": [
            {"domain": d, "count": c}
            for d, c in stats["all_domains"].most_common(50)
        ],
        "domains_with_cve_in_url": [
            {"domain": d, "count": c}
            for d, c in stats["domains_with_cve_in_url"].most_common(50)
        ],
    }
    for tag in ["vendor-advisory", "third-party-advisory", "mailing-list", "untagged"]:
        domains = stats["domains_by_tag"].get(tag, Counter())
        out["top_domains_by_tag"][tag] = [
            {"domain": d, "count": c}
            for d, c in domains.most_common(50)
        ]

    path = OUTPUT_DIR / "reference_analysis.json"
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nResults saved to {path}")


def main():
    parser = argparse.ArgumentParser(description="Analyze CVE reference URL distribution")
    parser.add_argument(
        "--sample", type=int, default=0,
        help="Sample N CVE files (0 = use default 20000, --all for everything)",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="Analyze all CVE files (slow, ~5 minutes)",
    )
    args = parser.parse_args()

    if not DATA_DIR.exists():
        print(f"Error: {DATA_DIR} not found. Run: git clone --depth 1 "
              "https://github.com/CVEProject/cvelistV5.git data/cvelistV5")
        return

    sample_size = 0 if args.all else (args.sample or 20000)
    files = collect_cve_files(DATA_DIR, sample_size=sample_size)
    label = f"{len(files):,} files" + (" (sampled)" if sample_size else " (all)")
    print(f"Analyzing {label}...\n")

    stats = analyze_references(files)
    print_report(stats)
    save_report(stats)


if __name__ == "__main__":
    main()
