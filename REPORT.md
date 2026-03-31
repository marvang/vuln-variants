# CVE Variant Chain Analysis Report

**Date:** 2026-03-31
**Dataset:** cvelistV5 (341,154 files, 323,709 published CVEs)

## Method

We identify CVE variant chains by regex-matching CVE IDs (`CVE-\d{4}-\d{4,}`) across CVE record fields. When a CVE mentions another CVE, we treat it as a directed edge (the newer CVE is a variant/bypass/incomplete-fix of the older). Edges are assembled into a graph, connected components extracted, and each component arranged into a chronological tree.

The pipeline runs in tiers, each adding new edges from progressively deeper sources:

| Tier | Source | What it scans |
|---|---|---|
| T1 | CNA description | `containers.cna.descriptions[].value` |
| T2 | All JSON fields | Reference names, reference URLs, titles, ADP descriptions, legacy records |
| T3 | Advisory pages | External URLs via Cloudflare /crawl (not yet run) |

Every edge carries a provenance label (`t1_description`, `t2_ref_name`, `t2_ref_url`, etc.) so results can be filtered or audited by source.

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

| Chain | Edges | Found | Missed | Reason |
|---|---|---|---|---|
| Log4Shell | 3 | 1 | 2 | 45105 and 44832 descriptions don't cite prior CVEs |
| Spring4Shell | 1 | 0 | 1 | CVE-2022-22965 description doesn't mention CVE-2010-1622 |
| PrintNightmare | 1 | 1 | 0 | Fully captured |

| Metric | Result |
|---|---|
| CVE dataset membership | 8/8 (100%) — all ground truth CVEs found in parsed corpus |
| CVE chain recall | 5/8 (62.5%) — 5 appear in a generated chain |
| Edge recall | 2/5 (40.0%) — measured against raw tier edge files |

All 3 missed edges are due to descriptions that don't cross-reference the prior CVE — not missing data. T3 (advisory scraping) is expected to improve this by fetching the linked advisory pages where these relationships are often documented.

## Limitations

1. **Explicit references only.** Many real variant relationships are never stated in CVE text.
2. **False positives.** A CVE mentioning another CVE may mean "discovered during same audit" rather than "variant of."
3. **CNA bias.** Well-documented products (Adobe, Microsoft, Apache) are over-represented because their CNAs write cross-referencing descriptions.

## Outputs

| File | Description |
|---|---|
| `output/parsed_cves.json` | Full parsed corpus (all published CVEs with parsed metadata) |
| `output/edges_t1_description.json` | T1 edges with provenance |
| `output/edges_t2_allfields.json` | T2 edges (new only, deduplicated against T1) |
| `output/cve_references.json` | Reference-graph subset (only CVEs involved in T1 description edges) |
| `output/variant_chains.json` | Tree-structured chains with per-edge provenance |
| `output/stats.json` | Parsing statistics and year-by-year breakdown |
| `output/validation_results.json` | Ground truth validation results |
