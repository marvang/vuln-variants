"""
Build a structured reference index from all CVE records.

Extracts every reference URL with its metadata (domain, tags, ref name,
source container) and classifies domains into a taxonomy. This index is
the substrate for shared-ID extraction, URL clustering, commit fetching,
and advisory analysis.

Usage:
  uv run python build_reference_index.py
  uv run python build_reference_index.py --sample 10000
"""

import argparse
import json
import os
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from url_utils import normalize_url

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, **kwargs):
        print(kwargs.get("desc", "Processing"), "...")
        return iterable

DATA_DIR = Path("data/cvelistV5/cves")
OUTPUT_DIR = Path("output")

# Domain taxonomy — manually classified from analyze_references.py output.
# Covers the top ~50 domains by reference count.
DOMAIN_TAXONOMY = {
    # Per-CVE structured pages
    "msrc.microsoft.com": "per_cve_page",
    "portal.msrc.microsoft.com": "per_cve_page",
    "access.redhat.com": "per_cve_page",
    "security-tracker.debian.org": "per_cve_page",
    "security.paloaltonetworks.com": "per_cve_page",
    "cisa.gov": "per_cve_page",
    "cert-portal.siemens.com": "per_cve_page",
    "support.apple.com": "per_cve_page",
    "wordfence.com": "per_cve_page",
    # Multi-CVE bulletins (distro advisories)
    "lists.opensuse.org": "multi_cve_bulletin",
    "lists.fedoraproject.org": "multi_cve_bulletin",
    "lists.debian.org": "multi_cve_bulletin",
    "debian.org": "multi_cve_bulletin",
    "usn.ubuntu.com": "multi_cve_bulletin",
    "ubuntu.com": "multi_cve_bulletin",
    "security.gentoo.org": "multi_cve_bulletin",
    "rhn.redhat.com": "multi_cve_bulletin",
    "redhat.com": "multi_cve_bulletin",
    "lists.apple.com": "multi_cve_bulletin",
    "helpx.adobe.com": "multi_cve_bulletin",
    "docs.microsoft.com": "multi_cve_bulletin",
    "novell.com": "multi_cve_bulletin",
    "mandriva.com": "multi_cve_bulletin",
    "sunsolve.sun.com": "multi_cve_bulletin",
    "oracle.com": "multi_cve_bulletin",
    "ibm.com": "multi_cve_bulletin",
    "www-01.ibm.com": "multi_cve_bulletin",
    "tools.cisco.com": "multi_cve_bulletin",
    "sec.cloudapps.cisco.com": "multi_cve_bulletin",
    "patchstack.com": "multi_cve_bulletin",
    "source.android.com": "multi_cve_bulletin",
    # Bug trackers
    "bugzilla.redhat.com": "bug_tracker",
    "bugzilla.mozilla.org": "bug_tracker",
    "bugzilla.suse.com": "bug_tracker",
    "bugs.debian.org": "bug_tracker",
    "bugs.chromium.org": "bug_tracker",
    "bugs.launchpad.net": "bug_tracker",
    "issues.apache.org": "bug_tracker",
    # Code repositories and commits
    "github.com": "code_repo",
    "gitlab.com": "code_repo",
    "git.kernel.org": "code_repo",
    "sourceforge.net": "code_repo",
    "plugins.trac.wordpress.org": "code_repo",
    # Mailing lists
    "openwall.com": "mailing_list",
    "seclists.org": "mailing_list",
    "marc.info": "mailing_list",
    "archives.neohapsis.com": "mailing_list",
    "lists.grok.org.uk": "mailing_list",
    "securityfocus.com": "mailing_list",
    # Third-party advisories
    "secunia.com": "third_party_advisory",
    "vuldb.com": "third_party_advisory",
    "kb.cert.org": "third_party_advisory",
    "us-cert.gov": "third_party_advisory",
    "vulncheck.com": "third_party_advisory",
    "jvn.jp": "third_party_advisory",
    "jvndb.jvn.jp": "third_party_advisory",
    "zerodayinitiative.com": "third_party_advisory",
    # Generic aggregators / databases
    "exchange.xforce.ibmcloud.com": "generic_aggregator",
    "securitytracker.com": "generic_aggregator",
    "osvdb.org": "generic_aggregator",
    "vupen.com": "generic_aggregator",
    "exploit-db.com": "generic_aggregator",
    "packetstormsecurity.com": "generic_aggregator",
    "oval.cisecurity.org": "generic_aggregator",
    "nvd.nist.gov": "generic_aggregator",
    "cve.org": "generic_aggregator",
    "cve.mitre.org": "generic_aggregator",
}

# Regex patterns for extracting structured IDs from URLs and ref names
GITHUB_COMMIT_RE = re.compile(
    r"github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})", re.IGNORECASE
)
GITHUB_ISSUE_RE = re.compile(
    r"github\.com/([^/]+/[^/]+)/(issues|pull)/(\d+)", re.IGNORECASE
)
BUGZILLA_RE = re.compile(r"show_bug\.cgi\?id=(\d+)", re.IGNORECASE)
# Match JIRA-style project keys, excluding known non-JIRA prefixes
JIRA_RE = re.compile(r"(?<!\w)(?!CVE-|RHSA-|RHBA-|RHEA-|DSA-|DLA-|USN-|GLSA-)([A-Z][A-Z0-9]+-\d+)")


def classify_domain(domain):
    """Look up domain in taxonomy, return type or 'unknown'."""
    return DOMAIN_TAXONOMY.get(domain, "unknown")


def extract_domain(url):
    """Extract and normalize domain from URL."""
    try:
        host = urlparse(url).hostname or ""
        host = host.lower()
        if host.startswith("www."):
            host = host[4:]
        return host
    except Exception:
        return ""


def classify_ref_tags(tags):
    """Return the most specific tag from a reference entry."""
    tag_set = set(tags) if tags else set()
    for tag in ["vendor-advisory", "third-party-advisory", "mailing-list"]:
        if tag in tag_set:
            return tag
    return "untagged"


def extract_structured_ids(url, ref_name):
    """Extract bug IDs, commit hashes, etc. from URL and ref name."""
    ids = []

    if url:
        m = GITHUB_COMMIT_RE.search(url)
        if m:
            ids.append({"type": "github_commit", "repo": m.group(1), "value": m.group(2)})

        m = GITHUB_ISSUE_RE.search(url)
        if m:
            kind = "github_pr" if m.group(2) == "pull" else "github_issue"
            ids.append({"type": kind, "repo": m.group(1), "value": m.group(3)})

        m = BUGZILLA_RE.search(url)
        if m:
            domain = extract_domain(url)
            ids.append({"type": "bugzilla", "domain": domain, "value": m.group(1)})

    if ref_name:
        for m in JIRA_RE.finditer(ref_name):
            ids.append({"type": "jira", "value": m.group(1)})

    return ids


def collect_cve_files(data_dir, sample_size=0):
    """Collect CVE JSON file paths."""
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
        step = len(files) / sample_size
        files = [files[int(i * step)] for i in range(sample_size)]
    return files


def build_index(files):
    """Build the reference index from CVE files."""
    references = []
    domain_counts = Counter()
    type_counts = Counter()
    tag_counts = Counter()
    commit_count = 0
    issue_count = 0
    total_cves = 0

    for fpath in tqdm(files, desc="Building reference index"):
        try:
            with open(fpath) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        metadata = data.get("cveMetadata", {})
        if metadata.get("state") != "PUBLISHED":
            continue

        cve_id = metadata.get("cveId", "")
        published = metadata.get("datePublished", "")
        total_cves += 1

        # Collect refs from CNA and ADP containers
        containers = []
        cna = data.get("containers", {}).get("cna", {})
        if cna.get("references"):
            containers.append(("cna", cna["references"]))
        for adp in data.get("containers", {}).get("adp", []):
            if adp.get("references"):
                containers.append(("adp", adp["references"]))

        seen_urls = set()
        for source_container, refs in containers:
            for ref in refs:
                url = ref.get("url", "")
                if not url or url in seen_urls:
                    continue
                seen_urls.add(url)

                domain = extract_domain(url)
                normalized = normalize_url(url)
                domain_type = classify_domain(domain)
                tags = ref.get("tags", [])
                tag_label = classify_ref_tags(tags)
                ref_name = ref.get("name", "")
                structured_ids = extract_structured_ids(url, ref_name)

                entry = {
                    "cve_id": cve_id,
                    "url": url,
                    "normalized_url": normalized,
                    "domain": domain,
                    "domain_type": domain_type,
                    "ref_name": ref_name,
                    "ref_tags": tag_label,
                    "source_container": source_container,
                    "published": published,
                }
                if structured_ids:
                    entry["structured_ids"] = structured_ids

                references.append(entry)
                domain_counts[domain] += 1
                type_counts[domain_type] += 1
                tag_counts[tag_label] += 1

                for sid in structured_ids:
                    if sid["type"] == "github_commit":
                        commit_count += 1
                    elif sid["type"] in ("github_issue", "github_pr", "bugzilla", "jira"):
                        issue_count += 1

    return {
        "references": references,
        "stats": {
            "total_cves": total_cves,
            "total_references": len(references),
            "github_commits": commit_count,
            "bug_tracker_ids": issue_count,
            "by_domain_type": dict(type_counts.most_common()),
            "by_tag": dict(tag_counts.most_common()),
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Build CVE reference index")
    parser.add_argument("--sample", type=int, default=0, help="Sample N files (0 = all)")
    args = parser.parse_args()

    if not DATA_DIR.exists():
        print(f"Error: {DATA_DIR} not found.")
        return

    files = collect_cve_files(DATA_DIR, sample_size=args.sample)
    print(f"Scanning {len(files):,} CVE files...\n")

    result = build_index(files)
    stats = result["stats"]

    OUTPUT_DIR.mkdir(exist_ok=True)
    output = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "domain_taxonomy": DOMAIN_TAXONOMY,
            **stats,
        },
        "references": result["references"],
    }

    out_path = OUTPUT_DIR / "reference_index.json"
    with open(out_path, "w") as f:
        json.dump(output, f)
    print(f"Saved to {out_path} ({os.path.getsize(out_path) / 1e6:.0f} MB)")

    # Summary
    print(f"\n{'='*60}")
    print(f"Total CVEs:              {stats['total_cves']:>10,}")
    print(f"Total references:        {stats['total_references']:>10,}")
    print(f"GitHub commits found:    {stats['github_commits']:>10,}")
    print(f"Bug tracker IDs found:   {stats['bug_tracker_ids']:>10,}")
    print("\nBy domain type:")
    for dtype, count in sorted(stats["by_domain_type"].items(), key=lambda x: -x[1]):
        print(f"  {dtype:25s}  {count:>8,}")
    print("\nBy tag:")
    for tag, count in sorted(stats["by_tag"].items(), key=lambda x: -x[1]):
        print(f"  {tag:25s}  {count:>8,}")


if __name__ == "__main__":
    main()
