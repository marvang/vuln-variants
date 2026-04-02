# CVE Variant Chain Analysis Report

**Date:** 2026-04-02
**Dataset:** cvelistV5 (341,154 files, 323,709 published CVEs)

## Method

We identify CVE variant chains by regex-matching CVE IDs (`CVE-\d{4}-\d{4,}`) across CVE record fields and external sources. When a CVE mentions another CVE, we treat it as a directed edge (the newer CVE is a variant/bypass/incomplete-fix of the older). Edges are assembled into a graph, connected components extracted, and each component arranged into a chronological tree.

The pipeline runs in tiers, each adding new edges from progressively deeper sources:

| Tier | Source | What it scans |
|---|---|---|
| T1 | CNA description | `containers.cna.descriptions[].value` |
| T2 | All JSON fields | Reference names, reference URLs, titles, ADP descriptions, legacy records |
| T3 | Git commits | GitHub commit messages fetched via API (22k commits identified) |

Every edge carries a provenance label (`t1_description`, `t2_ref_name`, `t3_commit`, etc.) so results can be filtered or audited by source. When multiple tiers find the same edge, all evidence is preserved.

## Results: T1 vs T1+T2

| Metric | T1 (description only) | T1+T2 (all fields) | Delta |
|---|---|---|---|
| Edges | 39,294 | 41,938 | +2,644 (+6.7%) |
| Chains | 5,653 | 6,128 | +475 |
| CVEs in chains | 15,125 (4.67%) | 16,947 (5.24%) | +1,822 |
| Largest chain | 61 | 235 | merged via new edges |
| Deepest chain | 61 | 61 | unchanged |

### T2 Edge Breakdown

| Field | New edges found |
|---|---|
| `references[].name` | 1,910 |
| `references[].url` | 710 |
| `title` | 21 |
| `x_legacyV4Record` | 3 |
| **Total T2** | **2,644** |

Reference names (mailing list subjects like "[oss-security] CVE-2021-XXXX") are the biggest new source.

### T2 Corroborating Evidence

T2 also found 37,853 edges that were already in T1 (same CVE cross-reference in a different field). These are stored as `corroborating_edges` and merged into the evidence model, so 47% of tree nodes now carry multi-source evidence.

## Chain Size Distribution (T1+T2)

| Chain Size | Count |
|---|---|
| 2 | 4,478 |
| 3 | 860 |
| 4 | 325 |
| 5 | 167 |
| 6-9 | 187 |
| 10-19 | 106 |
| 20-49 | 14 |
| 50+ | 4 |

## Top 5 Largest Chains (T1+T2)

| Size | Root CVE(s) | Notes |
|---|---|---|
| 235 | CVE-2021-31618, CVE-2007-0086, CVE-2008-3281 | Multi-root, merged by T2 edges |
| 61 | CVE-2015-8450 | Adobe Flash Player |
| 49 | CVE-2021-30468, CVE-2010-1632 | Apache CXF / Axis |
| 49 | CVE-2016-7009 | Adobe Reader/Acrobat |
| 47 | CVE-2016-4105 | Adobe Flash Player |

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

| Metric | Result |
|---|---|
| CVE dataset membership | 23/23 (100%) — all ground truth CVEs found in parsed corpus |
| CVE chain recall | 13/23 (56.5%) — 13 appear in a generated chain |
| Edge recall | 5/13 (38.5%) — measured against raw tier edge files |

All 8 missed edges are due to descriptions that don't cross-reference the prior CVE — not missing data.

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

## T3: GitHub Commit Messages (in progress)

GitHub commit messages are the most promising untapped source. When developers fix an incomplete patch, they often write "fix for CVE-X" in the commit message — text that doesn't make it into the CVE description.

- 22,141 GitHub commit references identified in the dataset
- T3 script fetches commit messages via GitHub API, applies same CVE regex
- Pilot test (50 commits): 1 commit with CVE refs, 1 corroborating edge
- Full run requires `GITHUB_TOKEN` (~4.5 hours at 5,000 req/hr)

## Limitations

1. **Explicit references only.** Many real variant relationships are never stated in CVE text or commit messages.
2. **False positives.** A CVE mentioning another CVE may mean "discovered during same audit" rather than "variant of."
3. **CNA bias.** Well-documented products (Adobe, Microsoft, Apache) are over-represented because their CNAs write cross-referencing descriptions.
4. **Post-2020 gap.** Modern CVE descriptions rarely cross-reference prior CVEs (<1%), meaning recent variant chains are systematically missed by regex methods.

## Future Work

1. **Run T3 at scale** on all 22k GitHub commits with authenticated API access.
2. **Shared-ID extraction** — CVEs referencing the same bug tracker issue or advisory ID as candidate signals (not chain edges).
3. **LLM classification** — feed candidate CVE pairs from T3 snippets or shared IDs to an LLM to classify variant relationships. Narrower and cheaper than full-page extraction.
4. **Expand ground truth** with additional curated variant chains for more robust evaluation.

## Outputs

| File | Description |
|---|---|
| `output/parsed_cves.json` | Full parsed corpus (all published CVEs with parsed metadata) |
| `output/edges_t1_description.json` | T1 edges with provenance |
| `output/edges_t2_allfields.json` | T2 edges (new + corroborating, deduplicated against T1) |
| `output/edges_t3_commits.json` | T3 edges from GitHub commit messages |
| `output/cve_references.json` | Reference-graph subset (only CVEs involved in T1 description edges) |
| `output/variant_chains.json` | Tree-structured chains with per-edge evidence lists |
| `output/edge_graph.json` | Raw flat edge list with all evidence (for auditing) |
| `output/reference_index.json` | Structured index of all 1.1M reference URLs with domain taxonomy |
| `output/reference_analysis.json` | Domain/tag distribution analysis |
| `output/stats.json` | Parsing statistics and year-by-year breakdown |
| `output/validation_results.json` | Ground truth validation results |
