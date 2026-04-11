# CVE Variant Chain Analysis Report

**Date:** 2026-04-11
**Dataset:** cvelistV5 (341,154 files, 323,709 published CVEs)

## Method

We identify candidate CVE variant chains by regex-matching CVE IDs (`CVE-\d{4}-\d{4,}`) across CVE record fields and external sources. When a CVE mentions another CVE, we treat it as evidence for a directed edge from the newer CVE to the older one. This often corresponds to a variant/bypass/incomplete-fix relationship, but it is not proof on its own. Edges are assembled into a graph, connected components extracted, and each component arranged into a chronological tree.

The pipeline runs in tiers, each adding new edges from progressively deeper sources:

| Tier | Source | What it scans |
|---|---|---|
| T1 | CNA description | `containers.cna.descriptions[].value` |
| T2 | All JSON fields | Reference names, reference URLs, titles, ADP descriptions, legacy records |
| T3 | Git commits | GitHub commit messages fetched via API (20,672 unique commits) |
| T4 | Shared bug IDs | CVE pairs sharing Bugzilla/GitHub issue/PR references (weak signal) |
| T5 | LLM classification | Discovery (per-CVE) or verification (existing edges) via OpenRouter |
| T6 | Variant phrases | Signal-phrase regex across all fields (88 patterns, 5 categories) |

Every edge carries a provenance label (`t1_description`, `t2_ref_name`, `t3_commit`, etc.) so results can be filtered or audited by source. When multiple tiers find the same edge, all evidence is preserved.

## Results by Tier

**Terminology:** A *cluster* is a connected component — all CVEs transitively linked by edges. A *chain depth* is the longest linear path within a cluster (A→B→C→D = depth 4). A cluster of 237 CVEs means they are all reachable from each other through some sequence of edges, not that there is a single chain of 237.

### Cumulative results

| Metric | T1 | +T2 | +T3 | +T4* | +T5 | +T6 |
|---|---|---|---|---|---|---|
| New edges | 39,294 | +2,644 | +109 | +5,102 | +8 | +0 |
| **Total edges** | **39,294** | **41,938** | **42,047** | **47,149** | **47,157** | **47,157** |
| Clusters | 5,653 | 6,128 | 6,164 | 7,139 | 7,144 | 7,144 |
| CVEs in clusters | 15,125 (4.67%) | 16,947 (5.24%) | 17,067 (5.27%) | 20,085 (6.20%) | 20,097 (6.21%) | 20,097 (6.21%) |
| Largest cluster | 61 | 235 | 235 | 237 | 237 | 237 |
| Deepest chain | 61 | 61 | 61 | 61 | 61 | 61 |

*T4 edges are weak structural signals (shared bug tracker IDs). T5 proof-of-concept: 531 CVEs and 362 pairs classified so far. T6 adds 0 new unique edges — all T6 pairs are already present in T1 or T2.

### T1: CNA descriptions (39,294 edges)

Regex-matches CVE IDs in the primary CNA description field (`containers.cna.descriptions[].value`).

### T2: All JSON fields (+2,644 edges)

Scans reference names, reference URLs, titles, ADP descriptions, and legacy records. Reference names (mailing list subjects like "[oss-security] CVE-2021-XXXX") are the biggest new source. T2 also found 37,853 corroborating edges — same edge as T1 but from a different field, giving 47% of tree nodes multi-source evidence.

| Field | New edges | Corroborating |
|---|---|---|
| `references[].name` | 1,910 | 151 |
| `references[].url` | 710 | 70 |
| `title` | 21 | 52 |
| `x_legacyV4Record` | 3 | 37,579 |
| `adp[].descriptions` | 0 | 1 |

### T3: GitHub commit messages (+109 edges)

Fetched 20,672 unique commit messages via GitHub API. Developers write "fix for CVE-X" in commits but this text doesn't appear in CVE descriptions. 314 commits failed (deleted repos, force-pushed — HTTP 404/409/422). 110 commits contained published CVE cross-references. Dataset exported as `datasets/github_commits.jsonl` (21,765 records).

### T4: Shared bug tracker IDs (+5,102 edges, weak signal)

Finds CVE pairs that reference the same Bugzilla bug, GitHub issue, or GitHub PR but never mention each other in text. These are structural links — same bug doesn't prove a variant relationship.

| ID type | New edges |
|---|---|
| GitHub issues | 2,319 |
| Bugzilla | 1,756 |
| GitHub PRs | 812 |
| Multiple shared ID types | 145 |

### T6: Variant-phrase search (36,387 edges: 3,207 positive + 33,180 negative)

What does it mean that a CVE references another CVE? T6 searches all CVE text fields for specific phrases that indicate a relation, and the nature of it. An analysis of 140 samples inspired the use of this keyword patterns to classify why CVEs reference each other (see `datasets/edge_taxonomy_report.md`). Uses 88 regex patterns across 5 categories.

| Category             | Edges  | Signal   | Description                                                                      |
| -------------------- | ------ | -------- | -------------------------------------------------------------------------------- |
| batch_disambiguation | 33,180 | Negative | "different vulnerability than" / "unique from"                                   |
| related_issue        | 1,564  | Positive | "related issue to" / "similar to" / "variant of" / "differs from" / "SPLIT from" |
| incomplete_fix       | 857    | Positive | "insufficient fix" / "bypass" / "regression" / "re-introduced"                   |
| same_or_duplicate    | 616    | Positive | "same issue as" / "duplicate of" / "equivalent to"                               |
| chained              | 170    | Positive | "by exploiting" / "in conjunction with" / "leveraging"                           |

All unique positive T6 pairs already appear in T1 or T2, and 99%
already appear in T1. T6 heuristically classifies a substantial portion of T1's 39,294 edges
as noise or positive signal. The 857 incomplete_fix edges represent the strongest heuristic variant signals in the dataset outside of T5 LLM classification.

### Edge taxonomy study

A 140-sample study (100 T1, 20 T2, 20 T3 edges) was classified by independent LLM agents to answer: *why do CVEs reference each other?* Key finding: 89% of T1 edges are batch disambiguation ("different vulnerability than"), with only 5% being true variants. This directly inspired T6. Full methodology and results: `datasets/edge_taxonomy_report.md`. Raw classifications: `datasets/edge_classifications.json`.

### Top 5 largest clusters (T1+T2+T3+T4)

| Cluster size | Deepest chain | Root CVE(s) | Notes |
|---|---|---|---|
| 237 | 8 | CVE-2007-0086, CVE-2008-3281, CVE-2003-1564 | Multi-root, XML/HTTP parser vulnerabilities |
| 61 | 61 | CVE-2015-8048 | Adobe Flash Player |
| 50 | 4 | CVE-2010-1632, CVE-2021-30468 | Apache CXF / Axis |
| 49 | 49 | CVE-2016-6940 | Adobe Reader/Acrobat |
| 47 | 47 | CVE-2016-1037 | Adobe Flash Player |

### Cluster size distribution (T1+T2+T3+T4)

| Cluster size | Count |
|---|---|
| 2 | 5,101 |
| 3 | 1,029 |
| 4 | 403 |
| 5 | 201 |
| 6-9 | 272 |
| 10-19 | 111 |
| 20-49 | 19 |
| 50+ | 3 |

## Year-by-Year Trend

| Year | Total CVEs | Referencing others | % |
|---|---|---|---|
| 2007 | 6,458 | 634 | 9.8% |
| 2013 | 6,220 | 570 | 9.2% |
| **2015** | **8,110** | **1,194** | **14.7%** |
| **2016** | **9,318** | **991** | **10.6%** |
| 2020 | 19,339 | 646 | 3.3% |
| 2024 | 38,267 | 218 | 0.6% |
| 2025 | 42,107 | 239 | 0.6% |

Peak in 2015-2016 driven by Adobe CVEs using "similar to CVE-XXXX" phrasing. Post-2020 drops below 1% as description conventions shifted.

## Validation Against Ground Truth

Ground truth: 10 curated variant chains, 23 CVEs, 13 edges.

| Chain | Edges | Found | Missed | Reason |
|---|---|---|---|---|
| Log4Shell | 3 | 1 | 2 | 45105 and 44832 descriptions don't cite prior CVEs |
| Spring4Shell | 1 | 0 | 1 | CVE-2022-22965 description doesn't mention CVE-2010-1622 |
| PrintNightmare | 1 | 1 | 0 | Fully captured |
| Dirty COW → Dirty Pipe | 1 | 1 | 0 | Captured (reversed direction) |
| ImageTragick | 1 | 1 | 0 | Fully captured |
| PHP-CGI | 1 | 1 | 0 | Fully captured |
| Baron Samedit | 2 | 0 | 2 | Neither description mentions the other |
| ProxyLogon → ProxyShell | 1 | 0 | 1 | Neither description mentions the other |
| Struts OGNL | 1 | 0 | 1 | Neither description mentions the other |
| Spectre v1 → v2 | 1 | 0 | 1 | Neither description mentions the other |

| Metric | T1 | +T2 | +T3 | +T4 | +T5 |
|---|---|---|---|---|---|
| CVE cluster recall | 9/23 (39.1%) | 13/23 (56.5%) | 14/23 (60.9%) | 14/23 (60.9%) | 14/23 (60.9%) |
| Edge recall | 3/13 (23.1%) | 5/13 (38.5%) | 5/13 (38.5%) | 5/13 (38.5%) | 5/13 (38.5%) |

T5 has not yet improved ground truth recall (531 CVEs classified, processed newest-first, ground truth CVEs are older). All 8 missed edges are implicit relationships where neither text, commits, nor URLs connect the CVEs. T5 found 10 new edges beyond T1-T3 in other CVEs, demonstrating the approach works.

## Reference URL Analysis

Analysis of 1,114,310 reference URLs across 323,709 CVEs:

| Domain Type | Count | % |
|---|---|---|
| unknown | 281,219 | 25.2% |
| multi_cve_bulletin | 191,840 | 17.2% |
| code_repo | 170,441 | 15.3% |
| generic_aggregator | 143,937 | 12.9% |
| mailing_list | 126,403 | 11.3% |
| third_party_advisory | 120,602 | 10.8% |
| per_cve_page | 63,490 | 5.7% |
| bug_tracker | 16,378 | 1.5% |

Extracted structured IDs: 22,141 GitHub commits, 242,662 bug tracker IDs.

## Advisory Investigation Finding

We investigated whether vendor advisory pages contain CVE cross-references not found in CVE descriptions:

- **Red Hat API** (`/hydra/rest/securitydata/cve/`): `details` field mirrors CNA description. `statement` field is vendor-authored but focused on impact/mitigation, not cross-referencing.
- **Debian tracker** (`security-tracker.debian.org`): mirrors NVD description in a table cell.
- **Cisco advisories**: JS-rendered, requires browser rendering to fetch.
- **Apache security pages**: lists CVEs sequentially with individual descriptions, but descriptions are the same CNA text.

**Conclusion:** Vendor advisory pages largely mirror the same CNA description that T1 already scans. Structured advisory extraction does NOT find new edges. The unique vendor-authored text (impact statements, mitigation advice) does not typically contain CVE cross-references.

## Limitations

1. **Explicit references only.** Many real variant relationships are never stated in CVE text or commit messages.
2. **False positives.** A CVE mentioning another CVE may mean "discovered during same audit" rather than "variant of". In some cases, it means the opposite: "different from", although this is partly solved by T6 negative signals.
3. **CNA bias.** Well-documented products (Adobe, Microsoft, Apache) are over-represented because their CNAs write cross-referencing descriptions.
4. **Post-2020 gap.** Modern CVE descriptions rarely cross-reference prior CVEs (<1%), meaning recent variant chains are systematically missed by regex methods.

## T5: LLM Classification

T5 feeds all available evidence per CVE (descriptions, fetched URL content, commit messages) to an LLM via OpenRouter and lets it identify variant relationships.

Two modes:
- **Discovery** (default): For each CVE, fetches reference URLs (direct + Jina Reader fallback for JS-rendered pages), loads commit messages, and asks the LLM to identify variant relationships. Skips noisy domains, prioritizes bug trackers and code repos, filters out URL content with 0 CVE mentions.
- **Verification** (`--verify`): Takes existing edges from any tier and asks the LLM to confirm or reclassify them. Fetches URLs for both CVEs and includes the original evidence context.

### Proof-of-concept results (531 CVEs, 362 pairs)

| Metric                     | Value               |
| -------------------------- | ------------------- |
| CVEs processed             | 531                 |
| Pairs processed            | 362                 |
| New edges (beyond T1-T3)   | 10                  |
| Corroborating edges        | 7                   |
| Model                      | x-ai/grok-4.1-fast  |
| Cost                       | ~$0.06 per 100 CVEs |

Example new edges found by T5:
- **CVE-2026-33732 → CVE-2026-33131** (bypass): "This is a bypass of CVE-2026-33131"
- **CVE-2026-32284 → CVE-2022-41719** (incomplete_fix): "This code path was not covered by the fix for CVE-2022-41719"
- **CVE-2026-27893 → CVE-2025-66448** (incomplete_fix): "CVE-2025-66448 fixed auth bypass, this is a follow-on"
- **CVE-2025-69986 → CVE-2024-51347** (same_vuln_class): "shares a similar root cause with CVE-2024-51347"
- **CVE-2026-32285 → CVE-2020-10675** (regression): "CVE-2020-10675 was an incomplete fix"

## Outputs

| File                                   | Description                                                         |
| -------------------------------------- | ------------------------------------------------------------------- |
| `output/parsed_cves.json`              | Full parsed corpus (all published CVEs with parsed metadata)        |
| `output/edges_t1_description.json`     | T1 edges with provenance                                            |
| `output/edges_t2_allfields.json`       | T2 edges (new + corroborating, deduplicated against T1)             |
| `output/edges_t3_commits.json`         | T3 edges from GitHub commit messages                                |
| `output/edges_t4_shared_ids.json`      | T4 edges from shared bug tracker IDs (weak signal)                  |
| `output/edges_t6_variant_phrases.json` | T6 edges with signal-phrase categories and matched patterns         |
| `datasets/edges_t5_llm.json`           | Cumulative T5 edges + processed CVE/pair tracking (git-tracked)     |
| `datasets/t5_classifications.jsonl`    | Cumulative T5 classifications with full reasoning (git-tracked)     |
| `datasets/github_commits.jsonl`        | Researcher-friendly dataset: CVE-to-commit-message mapping          |
| `output/t5_classifications.json`       | Per-run T5 audit artifact with full pipeline traces                 |
| `output/cve_references.json`           | Reference-graph subset (only CVEs involved in T1 description edges) |
| `output/variant_chains.json`           | Tree-structured chains with per-edge evidence lists                 |
| `output/edge_graph.json`               | Raw flat edge list with all evidence (for auditing)                 |
| `output/reference_index.json`          | Structured index of all 1.1M reference URLs with domain taxonomy    |
| `output/reference_analysis.json`       | Domain/tag distribution analysis                                    |
| `output/stats.json`                    | Parsing statistics and year-by-year breakdown                       |
| `output/validation_results.json`       | Ground truth validation results                                     |
