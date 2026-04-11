"""
Tier 6: Targeted variant-phrase search across all CVE text fields.

Unlike T1/T2 which find ANY CVE mention, T6 searches for specific phrases
that indicate true variant relationships (incomplete fixes, bypasses,
regressions, exploit chains). Derived from LLM classification of 140
sampled edges (one Haiku agent per edge).

Scans: CNA descriptions, reference names/URLs, ADP descriptions, titles,
legacy descriptions — reusing parse_cves_t2.extract_field_texts().

Output: output/edges_t6_variant_phrases.json
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

from parse_cves_t2 import extract_field_texts

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}")
DATA_DIR = Path("data/cvelistV5/cves")
OUTPUT_DIR = Path("output")
CLAUSE_BOUNDARIES = ".!?;\n"
MAX_FALLBACK_DISTANCE = 60

# Variant signal phrases, grouped by relationship category.
# Each pattern should capture a CVE ID near the signal phrase.
# We search for the phrase, then extract CVE IDs from the surrounding context.
VARIANT_PHRASES = {
    "incomplete_fix": [
        # Direct "incomplete/insufficient fix" language
        r"(?:insufficient|incomplete|inadequate|improper|incorrect|partial|failed)\s+(?:fix|patch|correction|mitigation|remediation|resolution)\s+(?:for|of|to)",
        r"incompletely?\s+(?:addressed|fixed|patched|resolved|remediated|mitigated)",
        # Re-introduced / regression
        r"re-?introduced\s+CVE-",
        r"re-?introduces?\s+(?:the\s+)?(?:same\s+)?(?:vulnerability|bug|flaw|issue)",
        r"regression\s+(?:of|in|for|from)\s+CVE-",
        r"CVE-\d{4}-\d{4,}\s+regression",
        r"(?:introduced|caused)\s+by\s+(?:the\s+)?(?:fix|patch|update|correction)\s+(?:for|of|to)\s+CVE-",
        r"(?:side[- ]?effect|consequence)\s+of\s+(?:the\s+)?(?:fix|patch)\s+(?:for\s+)?CVE-",
        # Bypass
        r"bypass(?:es|ing|ed)?\s+(?:the\s+)?(?:fix|patch|mitigation|protection|remediation|security\s+measure|CVE-)",
        r"bypass\s+of\s+CVE-",
        r"circumvent(?:s|ing|ed)?\s+(?:the\s+)?(?:fix|patch|mitigation|protection)\s+(?:for\s+)?CVE-",
        r"evad(?:e|es|ing|ed)\s+(?:the\s+)?(?:fix|patch|mitigation)\s+(?:for\s+)?CVE-",
        # "exists because of" insufficient fix
        r"(?:exists?|present|remains?)\s+because\s+of\s+(?:a[n]?\s+)?(?:insufficient|incomplete|inadequate|improper|incorrect)",
        r"(?:exists?|present)\s+(?:due\s+to|because\s+of)\s+(?:a[n]?\s+)?(?:initial\s+)?(?:incomplete|insufficient)",
        # "did not fully fix"
        r"did\s+not\s+(?:fully|completely|properly|adequately|sufficiently)\s+(?:fix|address|resolve|mitigate|patch|remediate)",
        r"(?:was|were)\s+not\s+(?:fully|completely|properly|adequately)\s+(?:fixed|addressed|resolved|mitigated|patched)",
        r"not\s+(?:fully|completely|properly|adequately)\s+(?:fixed|addressed|resolved|patched|mitigated)",
        # Still vulnerable after fix
        r"(?:still|remains?)\s+(?:vulnerable|exploitable|affected)\s+(?:after|despite|following|even\s+after)",
        # "original/prior fix for CVE-X"
        r"(?:original|prior|previous|earlier|initial)\s+(?:fix|patch|correction)\s+(?:for|of)\s+CVE-",
        # "partial fix" / "addresses the partial fix"
        r"partial\s+(?:fix|patch|correction|mitigation)\s+(?:for|of)\s+CVE-",
        r"(?:additional|further|extra|more|new)\s+(?:fix|patch|correction|mitigation)\s+(?:for|of|to)\s+CVE-",
        # "fix for CVE-X was insufficient/incomplete"
        r"(?:fix|patch|correction)\s+for\s+CVE-\d{4}-\d{4,}\s+(?:was|is|were|has\s+been)\s+(?:insufficient|incomplete|inadequate|improper|incorrect)",
        # Mitigation workarounds
        r"(?:workaround|mitigation)\s+(?:for|of)\s+CVE-",
        r"(?:previous|prior|earlier)\s+mitigations?\s+(?:for|of)\s+CVE-",
        # Reverts / undoes fix
        r"(?:reverts?|undoes?|rolls?\s+back)\s+(?:the\s+)?(?:fix|patch|correction)\s+(?:for\s+)?CVE-",
        # "it was found that the fix for CVE-X"
        r"(?:it\s+was\s+found\s+that\s+the\s+)?(?:security\s+)?fix\s+for\s+CVE-\d{4}-\d{4,}\s+(?:was|is|in\s+\S+\s+was)\s+(?:not\s+)?(?:incomplete|insufficient|inadequate)",
        r"wasn'?t\s+fully\s+(?:addressed|fixed|patched|resolved)",
        r"patched\s+insufficiently",
        r"insufficiently\s+patched",
        r"undermines?\s+(?:a\s+)?(?:patch|fix|mitigation)\s+for\s+CVE-",
        r"recurring\s+bug(?:s)?\s+(?:of|from)\s+CVE-",
    ],
    "chained": [
        # Exploiting one to reach another
        r"(?:by|via|through)\s+exploiting\s+CVE-",
        r"can\s+be\s+(?:obtained|achieved|reached|triggered)\s+by\s+exploiting",
        r"requires?\s+(?:exploiting\s+)?CVE-",
        r"enables?\s+(?:exploitation\s+of\s+)?CVE-",
        # "combined with" / "in conjunction with"
        r"combined\s+with\s+CVE-",
        r"in\s+conjunction\s+with\s+CVE-",
        r"(?:when\s+)?(?:used|combined|paired|chained)\s+(?:together\s+)?with\s+CVE-",
        r"chain(?:ed|ing)?\s+with\s+CVE-",
        # Leverage
        r"leverag(?:e|es|ing)\s+CVE-",
        # "prerequisite" / "depends on"
        r"prerequisite\s+(?:for|of|is)\s+CVE-",
        r"depends?\s+(?:on|upon)\s+CVE-",
        # "escalate via" / "pivot from"
        r"(?:escalat|pivot)(?:e|es|ed|ing)\s+(?:via|from|through|using)\s+CVE-",
        # "leads to" / "results in"
        r"(?:leads?\s+to|results?\s+in)\s+(?:the\s+)?(?:exploitation\s+of\s+)?CVE-",
        # "obtained via CVE-X" / "leveraged with"
        r"(?:obtained|retrieved|acquired|stolen)\s+(?:via|from|through|using)\s+CVE-",
        r"(?:this\s+)?can\s+be\s+leveraged\s+(?:with|for|to\s+exploit)\s+CVE-",
        r"leverag(?:e|es|ed|ing)\s+(?:with\s+)?(?:other\s+)?vulnerabilit\w+\s+(?:such\s+as\s+)?CVE-",
        r"because\s+of\s+CVE-\d{4}-\d{4,}",
    ],
    "same_or_duplicate": [
        # "same issue as"
        r"(?:the\s+)?same\s+(?:issue|vulnerability|bug|flaw|problem|root\s+cause)\s+(?:as|that)\s+CVE-",
        r"(?:identical|exact)\s+(?:issue|vulnerability|bug|flaw)\s+(?:as|to)\s+CVE-",
        # "already covered by"
        r"already\s+covered\s+by\s+CVE-",
        # "duplicate"
        r"duplicate\s+of\s+CVE-",
        r"duplicates?\s+CVE-",
        # "might be the same"
        r"might\s+be\s+the\s+same\s+(?:issue|vulnerability|bug|flaw)?\s*(?:as\s+)?CVE-",
        r"(?:appears?|seems?)\s+to\s+be\s+(?:the\s+)?same\s+(?:as\s+)?CVE-",
        r"(?:could|may)\s+be\s+(?:the\s+)?same\s+(?:as\s+)?CVE-",
        r"(?:unclear|not\s+clear)\s+(?:whether|if)\s+(?:this\s+is\s+)?the\s+same\s+(?:issue|vulnerability)?\s*(?:as\s+)?CVE-",
        # "subsumed" / "superseded"
        r"subsume[ds]?\s+by\s+CVE-",
        r"supersede[ds]?\s+by\s+CVE-",
        # "equivalent to"
        r"equivalent\s+(?:to|of)\s+CVE-",
        # "overlap"
        r"(?:might\s+)?overlap(?:s|ping)?\s+(?:with\s+)?CVE-",
        # "originally identified as"
        r"(?:originally|previously|formerly)\s+(?:identified|reported|tracked|assigned|addressed)\s+(?:as|by|in)\s+CVE-",
        # REJECTED

        r"REJECTED\s+because\s+\S+\s+\S+\s+\S+\s+duplicate\s+of\s+CVE-",
        # "originally mapped to"
        r"(?:originally|incorrectly)\s+mapped\s+to\s+CVE-",
        # "it is possible that this is CVE-X"
    ],
    "related_issue": [
        # "related issue to"
        r"related\s+(?:issue|vulnerability|bug|flaw|problem)\s+to\s+CVE-",
        r"(?<!not\s)(?<!un)(?:closely\s+)?related\s+to\s+CVE-",
        # "different vector"
        r"(?:a\s+)?different\s+(?:vector|attack\s+vector|attack\s+surface|entry\s+point)\s+(?:than|from|for)\s+CVE-",
        # "similar" variants
        r"similar\s+(?:issue|vulnerability|bug|flaw|problem|attack|weakness)\s+(?:to|as)\s+CVE-",
        r"similar\s+to\s+CVE-",
        # "complements" / "follow-up"
        r"complements?\s+(?:the\s+)?(?:fix|patch|commit|work)\s+(?:for|in|on|of)\s+CVE-",
        r"follow[- ]?up\s+(?:to|for|of)\s+CVE-",
        # SPLIT — creates distinct CVEs from one, a provenance link not a duplicate
        r"(?:was|were|has\s+been)\s+SPLIT\s+from\s+CVE-",
        # "variant of" / "variation of" — related vulnerability class, not necessarily a failed fix
        r"(?:a\s+)?variant\s+(?:of|on)\s+CVE-",
        r"(?:new|another|different|separate|additional)\s+variant\s+(?:of|on)\s+CVE-",
        r"(?:a\s+)?variation\s+(?:of|on)\s+CVE-",
        # "analogous to"
        r"analogous\s+to\s+(?:previously\s+)?(?:disclosed\s+)?CVE-",
        # "similar to but not identical"
        r"similar\s+to,?\s+(?:but\s+)?not\s+identical\s+to,?\s+CVE-",
        r"(?:very\s+)?similar,?\s+(?:yet|but)\s+not\s+identical\s+(?:to\s+)?CVE-",
        r"(?:a\s+)?(?:flaw|vulnerability|bug|issue),?\s+similar\s+to\s+CVE-",
        # Explicit differentiation — "differs from", "not the same as", "not identical to"
        # These indicate a related but distinct vulnerability, not a duplicate
        r"(?:this\s+)?CVE\s+differs?\s+from\s+CVE-",
        r"not\s+(?:the\s+same\s+(?:as|vulnerability\s+as)|identical\s+to)\s+CVE-",
        r"(?:this\s+)?(?:CVE\s+)?(?:is\s+)?different\s+from\s+CVE-\d{4}-\d{4,}\s+(?:but|and|in\s+that)",
    ],
    "batch_disambiguation": [
        # Known NOISE patterns — use as negative signal to filter T1 edges
        r"(?:a\s+)?different\s+vulnerability\s+than\s+CVE-",
        r"(?:this\s+)?CVE\s+ID\s+is\s+unique\s+from\s+CVE-",
        r"(?:this\s+)?(?:vulnerability\s+)?is\s+distinct\s+from\s+CVE-",
        r"(?:this\s+)?vulnerability\s+is\s+different\s+from\s+(?:those\s+described\s+in\s+)?CVE-",
        r"(?:a\s+)?different\s+(?:issue|vulnerability|problem)\s+than\s+CVE-",
        r"different\s+set\s+of\s+(?:vulnerabilities|vectors)\s+than\s+CVE-",
    ],
}

# Compile all patterns
COMPILED_PATTERNS = {}
for category, patterns in VARIANT_PHRASES.items():
    COMPILED_PATTERNS[category] = [
        re.compile(p, re.IGNORECASE) for p in patterns
    ]


def get_description(data):
    """Extract English description from CVE JSON."""
    descs = data.get("containers", {}).get("cna", {}).get("descriptions", [])
    for d in descs:
        if d.get("lang", "").startswith("en"):
            return d.get("value", "")
    if descs:
        return descs[0].get("value", "")
    return ""


def span_overlaps(a_start, a_end, b_start, b_end):
    """Return whether two half-open spans overlap."""
    return a_start < b_end and b_start < a_end


def find_clause_bounds(text, start, end):
    """Return clause bounds around a match, stopping at punctuation/newlines."""
    left = max(text.rfind(char, 0, start) for char in CLAUSE_BOUNDARIES)
    right_candidates = [text.find(char, end) for char in CLAUSE_BOUNDARIES]
    right_candidates = [pos for pos in right_candidates if pos != -1]
    right = min(right_candidates) if right_candidates else len(text)
    return left + 1, right


_LIST_STRIP_PATTERNS = [
    re.compile(r"\([^)]{0,40}\)"),
    re.compile(r"'[^']{0,40}'"),
    re.compile(r'"[^"]{0,40}"'),
]
_AND_OR_PATTERN = re.compile(r"(?:and|or|and/or)", re.IGNORECASE)


def is_list_continuation(gap_text):
    """Return whether text between two CVEs is just list punctuation."""
    if not gap_text.strip():
        return True
    if any(char in gap_text for char in CLAUSE_BOUNDARIES):
        return False

    cleaned = gap_text
    for pattern in _LIST_STRIP_PATTERNS:
        cleaned = pattern.sub("", cleaned)
    cleaned = cleaned.strip(" ,:/-")
    if not cleaned:
        return True

    return bool(_AND_OR_PATTERN.fullmatch(cleaned))


def extend_forward_cve_list(text, cve_matches, start_index):
    """Collect a comma/and/or-separated run of CVEs starting at start_index."""
    refs = [cve_matches[start_index].group(0)]
    prev_end = cve_matches[start_index].end()

    for next_index in range(start_index + 1, len(cve_matches)):
        gap_text = text[prev_end:cve_matches[next_index].start()]
        if not is_list_continuation(gap_text):
            break
        refs.append(cve_matches[next_index].group(0))
        prev_end = cve_matches[next_index].end()

    return refs


def extract_refs_for_match(cve_id, text, match, cve_matches):
    """Extract the CVE IDs governed by one specific phrase match."""
    overlapping_indexes = [
        index
        for index, cve_match in enumerate(cve_matches)
        if span_overlaps(
            cve_match.start(),
            cve_match.end(),
            match.start(),
            match.end(),
        )
    ]

    refs = []
    if overlapping_indexes:
        refs.extend(extend_forward_cve_list(text, cve_matches, overlapping_indexes[0]))
    else:
        clause_start, clause_end = find_clause_bounds(text, match.start(), match.end())
        clause_matches = [
            (index, cve_match)
            for index, cve_match in enumerate(cve_matches)
            if clause_start <= cve_match.start() and cve_match.end() <= clause_end
        ]
        candidates = []

        after_matches = [
            (index, cve_match)
            for index, cve_match in clause_matches
            if cve_match.start() >= match.end()
        ]
        if after_matches:
            after_index, after_match = after_matches[0]
            distance = after_match.start() - match.end()
            if distance <= MAX_FALLBACK_DISTANCE:
                candidates.append((distance, 0, after_index, "after"))

        before_matches = [
            (index, cve_match)
            for index, cve_match in clause_matches
            if cve_match.end() <= match.start()
        ]
        if before_matches:
            before_index, before_match = before_matches[-1]
            distance = match.start() - before_match.end()
            if distance <= MAX_FALLBACK_DISTANCE:
                candidates.append((distance, 1, before_index, "before"))

        if candidates:
            _, _, chosen_index, direction = min(candidates)
            if direction == "after":
                refs.extend(extend_forward_cve_list(text, cve_matches, chosen_index))
            else:
                refs.append(cve_matches[chosen_index].group(0))

    deduped = []
    seen = set()
    for ref in refs:
        if ref == cve_id or ref in seen:
            continue
        seen.add(ref)
        deduped.append(ref)
    return deduped


def find_variant_phrases(cve_id, data):
    """Search all text fields for variant signal phrases.

    Returns list of edge dicts for each match found.
    """
    edges = []

    # Collect all searchable text: description + T2 fields
    texts = [("t6_description", get_description(data))]
    texts.extend(extract_field_texts(data))

    for _, text in texts:
        if not text:
            continue

        cve_matches = list(CVE_PATTERN.finditer(text))
        if not cve_matches:
            continue

        for category, compiled in COMPILED_PATTERNS.items():
            for pattern in compiled:
                for match in pattern.finditer(text):
                    # Extract context window around the match
                    start = max(0, match.start() - 60)
                    end = min(len(text), match.end() + 100)
                    context = text[start:end]
                    if start > 0:
                        context = "..." + context
                    if end < len(text):
                        context = context + "..."

                    refs = extract_refs_for_match(cve_id, text, match, cve_matches)

                    for ref in refs:
                        found_in = f"t6_{category}"
                        edges.append({
                            "source": cve_id,
                            "target": ref,
                            "found_in": found_in,
                            "category": category,
                            "context": context,
                            "pattern": pattern.pattern,
                        })

    return edges


def main():
    OUTPUT_DIR.mkdir(exist_ok=True)

    # Load published CVE IDs
    parsed_path = OUTPUT_DIR / "parsed_cves.json"
    if not parsed_path.exists():
        print(f"ERROR: {parsed_path} not found. Run parse_cves.py first.")
        return

    with open(parsed_path) as f:
        all_cve_ids = set(json.load(f)["cves"].keys())
    print(f"Loaded {len(all_cve_ids):,} published CVE IDs\n")

    if not DATA_DIR.exists():
        print(f"ERROR: {DATA_DIR} not found.")
        return

    json_files = sorted(DATA_DIR.rglob("CVE-*.json"))
    print(f"Found {len(json_files):,} CVE files\n")

    # Print pattern counts
    total_patterns = sum(len(v) for v in COMPILED_PATTERNS.values())
    print(
        "Searching with "
        f"{total_patterns} variant patterns across "
        f"{len(COMPILED_PATTERNS)} categories:"
    )
    for cat, pats in COMPILED_PATTERNS.items():
        print(f"  {cat}: {len(pats)} patterns")
    print()

    # Scan all CVEs
    all_edges = []
    seen = set()  # deduplicate (source, target, category)
    edges_by_category = defaultdict(int)

    for filepath in tqdm(json_files, desc="Scanning for variant phrases"):
        try:
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue

        meta = data.get("cveMetadata", {})
        cve_id = meta.get("cveId")
        if not cve_id or meta.get("state") != "PUBLISHED":
            continue

        edges = find_variant_phrases(cve_id, data)

        for edge in edges:
            # Only keep edges to valid published CVEs
            if edge["target"] not in all_cve_ids:
                continue

            key = (edge["source"], edge["target"], edge["category"])
            if key in seen:
                continue
            seen.add(key)

            all_edges.append(edge)
            edges_by_category[edge["category"]] += 1

    # Summary
    print(f"\nFound {len(all_edges):,} variant-phrase edges:")
    for cat, count in sorted(edges_by_category.items(), key=lambda x: -x[1]):
        print(f"  {cat:25s} {count:,}")

    # Unique source-target pairs (some may have multiple categories)
    unique_pairs = len({(e["source"], e["target"]) for e in all_edges})
    print(f"\nUnique (source, target) pairs: {unique_pairs:,}")

    # Output
    output = {
        "generated": str(Path(__file__).name),
        "timestamp": datetime.now().isoformat(),
        "total_edges": len(all_edges),
        "edges_by_category": dict(edges_by_category),
        "unique_pairs": unique_pairs,
        "edges": all_edges,
    }

    out_path = OUTPUT_DIR / "edges_t6_variant_phrases.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nWritten to {out_path}")


if __name__ == "__main__":
    main()
