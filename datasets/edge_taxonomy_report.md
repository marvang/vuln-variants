# Why Do CVEs Reference Each Other? A Taxonomy of Cross-References

**Sample size:** 100 T1 edges (description), 20 T2 novel edges (reference metadata), 20 T3 edges (commit messages)
**Method:** 140 independent Haiku agents (1 per edge), each reading both CVE records and classifying the relationship. Random sample (seed=42).
**Prior version:** v1 used 6 batched agents (25 edges each) — see comparison at bottom.

---

## T1: Description Edges (n=100)

Edges created when CVE-B's description text mentions CVE-A.

| Category | Count | % | Description |
|---|---|---|---|
| **batch_disambiguation** | 89 | 89% | "different vulnerability than" / "unique from" — same product, same advisory, different bugs |
| **incomplete_fix** | 4 | 4% | Bypass, regression, insufficient fix — **TRUE VARIANT** |
| **related_issue** | 3 | 3% | "related issue to" / "different vector than" — similar bug, different attack path |
| **same_or_duplicate** | 2 | 2% | "might be same issue" / "already covered by" |
| **chained** | 1 | 1% | One vuln enables/requires exploiting the other |
| **co_disclosed** | 1 | 1% | Joint advisory describing multiple CVEs together |

### True variants found in T1 (5/100):

| Source | Target | Category | Signal Phrase |
|---|---|---|---|
| CVE-2024-0248 | CVE-2023-6029 | incomplete_fix | "re-introduced CVE-2023-6029" |
| CVE-2008-3173 | CVE-2004-0866 | incomplete_fix | "insufficient fix for CVE-2004-0866" |
| CVE-2016-7431 | CVE-2015-8138 | incomplete_fix | "CVE-2015-8138 regression" |
| CVE-2023-44467 | CVE-2023-36258 | incomplete_fix | "bypass the CVE-2023-36258 fix" |
| CVE-2017-14705 | CVE-2017-14706 | chained | "can be obtained by exploiting CVE-2017-14706" |

### Noise sources

The **batch disambiguation** pattern (89%) is driven by a CNA convention from the 2000s-2010s where vendors publish near-identical descriptions for bugs in the same advisory, differentiating them with "a different vulnerability than CVE-X, CVE-Y, CVE-Z." This creates O(n^2) edges per advisory batch, none of which are variant relationships.

Top offenders: Adobe Flash Player, Adobe Reader/Acrobat, Microsoft IE/Edge, Microsoft Windows, Oracle CPU.

---

## T2: Novel Reference-Metadata Edges (n=20)

Edges found only in reference names/URLs (not in descriptions).

| Category | Count | % | Description |
|---|---|---|---|
| **batch_disambiguation** | 7 | 35% | Same product, co-listed in shared advisory with explicit "different" language |
| **co_disclosed** | 6 | 30% | Joint advisory or security announcement listing multiple CVEs |
| **changelog** | 2 | 10% | Documentation/changelog commits listing multiple CVEs |
| **same_codebase_context** | 1 | 5% | Same project, referenced for context only |
| **co_fixed** | 1 | 5% | Multiple CVEs addressed in same dependency update |
| **same_product_batch** | 1 | 5% | Co-listed in shared advisory URL |
| **related_issue** | 1 | 5% | Similar vulnerability class, different specific bug |
| **chained** | 1 | 5% | One vuln enables exploitation of the other |

### True variant found in T2 (1/20):

| Source | Target | Category | Signal |
|---|---|---|---|
| CVE-2024-8349 | CVE-2024-8350 | chained | "leverage CVE-2024-8349 and gain admin access" |

### Key observations

T2 is more diverse than T1 — no single noise pattern dominates. The references capture structural co-location: CVEs sharing advisory URLs, mailing list posts, or project documentation pages. Most edges are "same product, same timeframe" indicators rather than variant evidence.

---

## T3: Commit Message Edges (n=20)

Edges from GitHub commits associated with one CVE that mention another CVE.

| Category | Count | % | Description |
|---|---|---|---|
| **co_fixed** | 8 | 40% | Multiple CVEs fixed in the same commit or release |
| **co_disclosed** | 4 | 20% | CVEs listed together in commit metadata (Security-References, etc.) |
| **same_or_duplicate** | 2 | 10% | Same underlying vulnerability in different contexts |
| **related_issue** | 2 | 10% | Same bug class, different product or component |
| **incomplete_fix** | 1 | 5% | Patch complements prior CVE's fix — **TRUE VARIANT** |
| **batch_disambiguation** | 1 | 5% | Multiple bugs fixed in single commit, distinct issues |
| **same_codebase_context** | 1 | 5% | Referenced for context in commit message |
| **chained** | 1 | 5% | Exploitation of one requires the other |

### True variants found in T3 (2/20):

| Source | Target | Category | Signal |
|---|---|---|---|
| CVE-2012-2674 | CVE-2009-0607 | incomplete_fix | "complements commit 6f04a0f4 (CVE-2009-0607)" |
| CVE-2021-23222 | CVE-2021-23214 | chained | "possible with a server vulnerable to CVE-2021-23214" |

### Key observations

T3's dominant pattern is **co_fixed** (40%) — multiple CVEs addressed in the same commit. These are structural links, not variant evidence. Developers bundle fixes for related (or unrelated) bugs into single commits or releases.

The **co_disclosed** category (20%) captures commit metadata that lists multiple CVEs (e.g., TYPO3's "Security-References:" tags).

---

## Overall Signal Quality by Tier

| Tier | True Variant Rate | Primary Pattern | Signal Quality |
|---|---|---|---|
| **T1 (description)** | 5% (5/100) | batch_disambiguation (89%) | Low — dominated by advisory disambiguation |
| **T2 (ref metadata)** | 5% (1/20) | batch_disambiguation + co_disclosed (65%) | Low — structural co-location |
| **T3 (commits)** | 10% (2/20) | co_fixed (40%) | Moderate — highest signal but still mostly structural |

### Defining "true variant"

For this analysis, **true variant** = `incomplete_fix` (bypass, regression, insufficient fix) + `chained` (exploitation dependency). These are the categories that represent genuine failed-patch or attack-chain relationships.

Categories like `co_fixed`, `co_disclosed`, `related_issue`, and `same_or_duplicate` are **structurally interesting** but do not indicate that one CVE is a variant (failed fix, bypass) of another.

---

## From Taxonomy to Tier 6

The taxonomy above answered the original research question — *why do CVEs reference each other?* — and revealed that the answer is almost always embedded in specific signal phrases. Batch disambiguation uses "different vulnerability than" / "unique from". True variants use "insufficient fix for" / "bypass" / "regression". These phrases are unambiguous and machine-readable.

This insight led directly to **Tier 6** (`find_variant_phrases_t6.py`): instead of matching any CVE mention (T1/T2), search specifically for phrases that indicate the *nature* of the relationship. T6 uses 88 regex patterns across 5 categories, derived from the taxonomy and expanded with known variant-language conventions from CVE descriptions.

### T6 results (full corpus: 323,709 CVEs)

| Category | Edges | Description |
|---|---|---|
| **batch_disambiguation** | 33,180 | "different vulnerability than" / "unique from" — **negative signal** |
| **related_issue** | 1,564 | "related issue to" / "similar to" / "variant of" / "SPLIT from" / "differs from" |
| **incomplete_fix** | 857 | Bypass, regression, insufficient fix — **strongest positive signal** |
| **same_or_duplicate** | 616 | "same issue as" / "duplicate of" / "equivalent to" |
| **chained** | 170 | "by exploiting" / "in conjunction with" / "leveraging" |
| **Total** | **36,387** | **3,207 positive + 33,180 negative** |

### How T6 relates to other tiers

T6 edges are a semantic subset of T1/T2 — since T1/T2 already find all CVE mentions, T6 finds the same (source, target) pairs but only when a signal phrase is present. **All 3,203 unique positive T6 pairs also appear in T1 or T2.** T6 adds no new pairs; it adds *meaning* to existing pairs.

| T6 Category | Edges | Also in T1 |
|---|---|---|
| incomplete_fix | 857 | 839 (98%) |
| chained | 170 | 167 (98%) |
| related_issue | 1,564 | 1,561 (100%) |
| same_or_duplicate | 616 | 614 (100%) |
| **Unique positive pairs** | **3,203** | **3,177 (99%)** |

Note: the per-category rows sum to 3,207 edges, but only 3,203 unique pairs exist because some pairs match multiple categories.

### What T6 tells us about T1

T6 classifies T1 edges into three buckets. Note that 17 edges appear in *both* positive and noise categories (e.g., a description says "different vulnerability than CVE-X" but also "related issue to CVE-X"), so the buckets overlap slightly.

| T1 Classification | Edges | % of T1's 39,294 |
|---|---|---|
| Flagged as **batch_disambiguation** (noise) | 33,179 | 84.4% |
| Flagged with **positive signal** | 3,177 | 8.1% |
| In both positive and noise | 17 | <0.1% |
| Unclassified by T6 | 2,955 | 7.5% |

T6 classifies **92.5% of T1 edges**. The remaining 7.5% use language that doesn't match any of the 88 patterns (e.g., bare CVE-ID lists, or unusual phrasing) — these would need T5 (LLM) or manual review.

### T6 as a tier in the evidence model

T6 is a standalone edge discovery tier, not a filter. Its edges carry provenance (`t6_incomplete_fix`, `t6_chained`, etc.) just like any other tier. This means:

- **Corroboration strengthens signal.** An edge found by T1 + T3 + T6 is stronger than T1 alone. T6's category label adds semantic information that raw CVE-ID matching cannot provide.
- **Negative signal is unique to T6.** No other tier produces negative evidence. The 33,180 batch_disambiguation edges (33,179 of which overlap with T1) explicitly mark relationships as noise — information that T1 alone cannot provide.
- **Researchers build their own rankings.** The dataset preserves all tier provenance. A researcher studying incomplete fixes can filter to `t6_incomplete_fix` edges; one studying exploit chains can filter to `t6_chained`. We provide the evidence; they decide what counts.

---

## Implications for the Pipeline

1. **T6 classifies 92.5% of T1 edges.** Of T1's 39,294 edges, T6 flags 33,179 as noise and 3,177 as positive signal (with 17 edges in both). The remaining 2,955 (7.5%) are unclassified — they mention CVE IDs without using recognizable signal or disambiguation phrases.

2. **T3 true variant rate (10%) is lower than previously estimated (40%).** The prior batched analysis over-counted by treating `co_fixed` as "true_variant." Many commit-level edges are co-fix structural links, not bypass/regression relationships.

3. **857 incomplete_fix edges are the highest-confidence dataset.** These are edges where the CVE text explicitly says "insufficient fix", "bypass", "regression", or "re-introduced" — the strongest evidence for variant relationships short of LLM classification.

4. **Multi-tier corroboration is available.** Researchers can use tier overlap as a confidence ranking — an edge found by T1 + T3 + T6 carries more weight than T1 alone.

---

## Comparison with v1 (Batched Approach)

| Aspect | v1 (6 agents, 25 edges each) | v2 (140 agents, 1 edge each) |
|---|---|---|
| **T1 results** | Nearly identical | 89% batch_disambig, 5% true variant |
| **T2 results** | 85% same_product_batch | 35% batch_disambig + 30% co_disclosed — more granular |
| **T3 true variant** | **40%** | **10%** — significant correction |
| **Method cost** | ~6 agent calls | ~140 agent calls |
| **Accuracy** | T1 good, T2/T3 over-simplified | More granular, especially T2/T3 |

### Key difference: T3 true variant rate dropped from 40% to 10%

The v1 batched analysis used "true_variant" as a broad catch-all category. When each edge is classified independently with more specific categories (`co_fixed`, `co_disclosed`, `related_issue`), many edges previously labeled "true_variant" are revealed to be structural co-fix links rather than genuine bypass/regression relationships.

### Conclusion

The per-agent approach produces **more accurate and granular results**, particularly for T2 and T3 where the batched approach over-simplified. T1 results are robust across both methods — the "different vulnerability than" pattern is so unambiguous that even batched analysis catches it correctly.

---

## Limitations

- **Small sample sizes.** The taxonomy used 100 T1, 20 T2, and 20 T3 edges. The 5% T1 true-variant rate has a 95% Clopper-Pearson CI of [1.6%, 11.3%]. The 10% T3 rate (n=20) has CI [1.2%, 31.7%]. T2 and T3 confidence intervals are too wide for precise comparison.
- **No stratification.** Sampling was uniform random (seed=42) with no stratification by year, vendor, or description length. Adobe/Microsoft dominate the 2015-2016 era and the batch_disambiguation pattern; the true-variant rate may differ substantially by vendor.
- **Non-anchored T6 patterns.** Some `incomplete_fix` patterns (e.g., "not fully fixed", "exists because of an incomplete") lack a CVE ID in the regex and rely on proximity extraction. These can produce false edges when the nearest CVE ID is there for an unrelated reason.
- **Edge direction is textual, not temporal.** The convention source=mentioner, target=mentioned assumes the mentioner is the newer CVE. This is usually but not always true, particularly for `related_issue` and `same_or_duplicate` edges where directionality is inherently ambiguous.
- **T4 has no quality assessment.** The taxonomy sampled T1/T2/T3 but not T4, which produces 12% of all edges. T4's "weak signal" label is an assertion, not a finding.
- **T6 unclassified gap.** T6 leaves a portion of T1 edges unclassified — edges where the CVE mention uses no recognizable signal or disambiguation phrase. These may contain unusual variant language the 88 patterns miss.
- **Temporal coverage bias.** CVE cross-referencing drops from ~10% (2007-2016) to <1% (post-2020). The dataset is weighted toward historical variants; post-2020 variants are largely invisible to regex-based tiers.
- **batch_disambiguation edges are in the chain graph.** T6 noise edges flow into `build_chains.py` as evidence entries (`t6_batch_disambiguation`). These edges already exist from T1 — T6 adds a semantic label, not a new edge. Researchers should interpret `t6_batch_disambiguation` as negative evidence, but nothing in the schema enforces this.

---

*Generated: 2026-04-08 | 140 Haiku agents, 1 per edge | Sample seed=42 | Classifications: datasets/edge_classifications.json*
