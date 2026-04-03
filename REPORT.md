# CVE Variant Chain Analysis Report

**Date:** 2026-04-03
**Dataset:** cvelistV5 (341,154 files, 323,709 published CVEs)

## Method

We identify CVE variant chains by regex-matching CVE IDs (`CVE-\d{4}-\d{4,}`) across CVE record fields and external sources. When a CVE mentions another CVE, we treat it as a directed edge (the newer CVE is a variant/bypass/incomplete-fix of the older). Edges are assembled into a graph, connected components extracted, and each component arranged into a chronological tree.

The pipeline runs in tiers, each adding new edges from progressively deeper sources:

| Tier | Source | What it scans |
|---|---|---|
| T1 | CNA description | `containers.cna.descriptions[].value` |
| T2 | All JSON fields | Reference names, reference URLs, titles, ADP descriptions, legacy records |
| T3 | Git commits | GitHub commit messages fetched via API (20,684 unique commits) |
| T4 | Shared bug IDs | CVE pairs sharing Bugzilla/GitHub issue/PR references (weak signal) |
| T5 | LLM classification | T4 candidates + fetched URL content classified via OpenRouter (planned) |

Every edge carries a provenance label (`t1_description`, `t2_ref_name`, `t3_commit`, etc.) so results can be filtered or audited by source. When multiple tiers find the same edge, all evidence is preserved.

## Results by Tier

**Terminology:** A *cluster* is a connected component — all CVEs transitively linked by edges. A *chain depth* is the longest linear path within a cluster (A→B→C→D = depth 4). A cluster of 237 CVEs means they are all reachable from each other through some sequence of edges, not that there is a single chain of 237.

### Cumulative results

| Metric | T1 | +T2 | +T3 | +T4 |
|---|---|---|---|---|
| New edges | 39,294 | +2,644 | +116 | +5,032 |
| **Total edges** | **39,294** | **41,938** | **42,054** | **47,156** |
| Clusters | 5,653 | 6,128 | 6,165 | 7,140 |
| CVEs in clusters | 15,125 (4.67%) | 16,947 (5.24%) | 17,070 (5.27%) | 20,088 (6.21%) |
| Largest cluster | 61 | 235 | 235 | 237 |
| Deepest chain | 61 | 61 | 61 | 61 |
| Corroborating edges | — | 37,853 | 34 | 216 |

### T1: CNA descriptions (39,294 edges)

Regex-matches CVE IDs in the primary CNA description field. This is the core dataset — when a CVE's description explicitly says "this is related to CVE-XXXX", that's a strong signal.

### T2: All JSON fields (+2,644 edges)

Scans reference names, reference URLs, titles, ADP descriptions, and legacy records. Reference names (mailing list subjects like "[oss-security] CVE-2021-XXXX") are the biggest new source. T2 also found 37,853 corroborating edges — same edge as T1 but from a different field, giving 47% of tree nodes multi-source evidence.

| Field | New edges |
|---|---|
| `references[].name` | 1,910 |
| `references[].url` | 710 |
| `title` | 21 |
| `x_legacyV4Record` | 3 |

### T3: GitHub commit messages (+116 edges)

Fetched 20,684 unique commit messages via GitHub API. Developers write "fix for CVE-X" in commits but this text doesn't appear in CVE descriptions. 314 commits failed (deleted repos, force-pushed — HTTP 404/409/422). 114 commits contained CVE cross-references. Dataset exported as `datasets/github_commits.jsonl` (21,762 records).

### T4: Shared bug tracker IDs (+5,032 edges, weak signal)

Finds CVE pairs that reference the same Bugzilla bug, GitHub issue, or GitHub PR but never mention each other in text. These are structural links — same bug doesn't prove a variant relationship — but provide context for T5 LLM classification.

| ID Type | Edges |
|---|---|
| GitHub issues | 2,452 |
| Bugzilla | 1,913 |
| GitHub PRs | 883 |

### Top 5 largest clusters (T1+T2+T3+T4)

| Cluster size | Deepest chain | Root CVE(s) | Notes |
|---|---|---|---|
| 237 | 8 | CVE-2007-0086, CVE-2008-3281, CVE-2003-1564 | Multi-root, XML/HTTP parser vulnerabilities |
| 61 | 61 | CVE-2015-8428 | Adobe Flash Player |
| 50 | 4 | CVE-2010-1632, CVE-2021-30468 | Apache CXF / Axis |
| 49 | 49 | CVE-2016-6995 | Adobe Reader/Acrobat |
| 47 | 47 | CVE-2016-4101 | Adobe Flash Player |

### Cluster size distribution (T1+T2+T3+T4)

| Cluster size | Count |
|---|---|
| 2 | 5,101 |
| 3 | 1,030 |
| 4 | 403 |
| 5 | 201 |
| 6-9 | 272 |
| 10-19 | 132 |
| 20-49 | 13 |
| 50+ | 5 |

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

| Metric | T1 | +T2 | +T3 | +T4 |
|---|---|---|---|---|
| CVE dataset membership | 23/23 | 23/23 | 23/23 | 23/23 |
| CVE cluster recall | 9/23 (39.1%) | 13/23 (56.5%) | 14/23 (60.9%) | 14/23 (60.9%) |
| Edge recall | 3/13 (23.1%) | 5/13 (38.5%) | 5/13 (38.5%) | 5/13 (38.5%) |

All 8 missed edges are cases where neither text, commit messages, nor shared bug tracker IDs connect the CVEs — implicit relationships that only an LLM reading full context can identify (T5).

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


## Evidence Coverage

Of 323,709 published CVEs:

| Bucket | Count | % |
|---|---|---|
| Direct evidence (T1/T2 edges) | 16,947 | 5.24% |
| Candidate-only, broad (all structured IDs + T3) | 92,296 | 28.51% |
| Candidate-only, default T4 (JIRA off) | 44,228 | 13.66% |
| Discovery-only (no cross-references) | 214,466 | 66.25% |

The broad candidate-only pool (28.51%) is an upper bound on indirect evidence. The practical default T4 queue is 44,228 CVEs (13.66%) once JIRA-only cases are excluded.

## Limitations

1. **Explicit references only.** Many real variant relationships are never stated in CVE text or commit messages.
2. **False positives.** A CVE mentioning another CVE may mean "discovered during same audit" rather than "variant of."
3. **CNA bias.** Well-documented products (Adobe, Microsoft, Apache) are over-represented because their CNAs write cross-referencing descriptions.
4. **Post-2020 gap.** Modern CVE descriptions rarely cross-reference prior CVEs (<1%), meaning recent variant chains are systematically missed by regex methods.

## T5: LLM Classification

T5 feeds all available evidence per CVE (descriptions, fetched URL content, commit messages) to an LLM via OpenRouter and lets it identify variant relationships. This targets the 8 missed ground truth edges where no text or structural signal exists — only an analyst reading full context can find these.

Two modes:
- **Per-CVE** (default): For each CVE, fetches reference URLs (direct + Jina Reader fallback for JS-rendered pages), loads commit messages, and asks the LLM to identify variant relationships. Skips noisy domains, prioritizes vendor pages and bug trackers, filters out URL content with 0 CVE mentions.
- **Candidate pairs** (`--candidates`): For T4 shared-ID pairs, fetches URLs for both CVEs and includes the shared bug tracker context.

Results accumulate in `datasets/edges_t5_llm.json` (git-tracked), which also tracks processed CVE IDs and candidate pairs so subsequent runs (by any researcher) automatically continue from where the last run left off. Full pipeline traces (URLs selected/skipped, prompts, LLM responses, token usage, cost) are saved per-CVE in `data/llm_cache/` and per-run in `output/t5_classifications.json`.

## Future Work

1. **Run T5 at scale** — classify more CVEs and T4 candidates, evaluate precision
2. **Expand ground truth** with additional curated variant chains
3. **Tune T5** — refine URL selection, prompts, and model choice based on results

## Outputs

| File | Description |
|---|---|
| `output/parsed_cves.json` | Full parsed corpus (all published CVEs with parsed metadata) |
| `output/edges_t1_description.json` | T1 edges with provenance |
| `output/edges_t2_allfields.json` | T2 edges (new + corroborating, deduplicated against T1) |
| `output/edges_t3_commits.json` | T3 edges from GitHub commit messages |
| `output/edges_t4_shared_ids.json` | T4 edges from shared bug tracker IDs (weak signal) |
| `datasets/edges_t5_llm.json` | Cumulative T5 edges + processed CVE/pair tracking (git-tracked) |
| `datasets/github_commits.jsonl` | Researcher-friendly dataset: CVE-to-commit-message mapping |
| `output/t5_classifications.json` | Per-run T5 audit artifact with full pipeline traces |
| `output/cve_references.json` | Reference-graph subset (only CVEs involved in T1 description edges) |
| `output/variant_chains.json` | Tree-structured chains with per-edge evidence lists |
| `output/edge_graph.json` | Raw flat edge list with all evidence (for auditing) |
| `output/reference_index.json` | Structured index of all 1.1M reference URLs with domain taxonomy |
| `output/reference_analysis.json` | Domain/tag distribution analysis |
| `output/stats.json` | Parsing statistics and year-by-year breakdown |
| `output/validation_results.json` | Ground truth validation results |
