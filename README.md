# vuln-variants

Systematically discovers CVE vulnerability variant chains (failed patches, bypasses, incomplete fixes) by regex-matching CVE IDs across CVE record fields and external sources. When one CVE's text references another CVE, it signals a variant, bypass, or incomplete fix.

**Results:** 42,057 strong edges across 17,085 CVEs (5.28% of all published CVEs) organized into 6,172 variant chains using T1-T3 regex + T5 LLM classification. T4 adds 5,032 weak structural edges (shared bug tracker IDs). See [REPORT.md](REPORT.md) for full analysis, statistics, and methodology.

## Setup

```bash
# Clone this repo, then:
uv sync

# Download the CVE database (~4-5 GB, takes a few minutes)
git clone --depth 1 https://github.com/CVEProject/cvelistV5.git data/cvelistV5
```

## Usage

### Tier 1: Description regex (fast, ~30 seconds)
```bash
uv run python parse_cves.py
uv run python build_chains.py
```

### Tier 2: All-fields regex (adds ~2,600 edges, ~1 minute)
```bash
uv run python parse_cves_t2.py
uv run python build_chains.py --tiers 1,2
```

### Tier 3: GitHub commit messages (needs GITHUB_TOKEN)
```bash
uv run python build_reference_index.py           # Build reference index first
uv run python parse_commits_t3.py --sample 50    # Test on 50 commits
GITHUB_TOKEN=ghp_... uv run python parse_commits_t3.py  # All ~22k commits
uv run python build_chains.py --tiers 1,2,3
```

### Tier 4: Shared bug tracker IDs (fast, local)
```bash
uv run python find_shared_ids_t4.py              # finds CVE pairs sharing Bugzilla/GitHub IDs
uv run python build_chains.py --tiers 1,2,3,4    # include T4 weak edges
```

T4 edges are weak signals — two CVEs linking to the same bug doesn't prove a variant relationship. Default `build_chains.py` (no flags) uses only strong T1-T3 edges. Add `4` to include T4.

### Tier 5: LLM classification (needs OPENROUTER_API_KEY)
```bash
uv run python classify_variants_t5.py                          # per-CVE mode, default 100 CVEs
uv run python classify_variants_t5.py --limit 500              # first 500 CVEs
uv run python classify_variants_t5.py --cve CVE-2021-45046     # specific CVE(s), comma-separated
uv run python classify_variants_t5.py --candidates             # candidate pair mode (T4 pairs)
uv run python classify_variants_t5.py --dry-run                # count items, no API/fetch calls
uv run python build_chains.py --tiers 1,2,3,5                  # include T5 strong edges
```

T5 has two modes. **Per-CVE** (default) fetches reference URLs for each CVE and asks the LLM to identify variant relationships from the content. **Candidate** mode classifies T4 shared-ID pairs with both CVEs' evidence. Both are resumable — cached results are skipped on re-run. Use `--cve` to test specific CVEs. Tracks token usage and cost per run.

Set `OPENROUTER_API_KEY` and optionally `OPENROUTER_MODEL` in `.env` (see `.env.example`).

### Validate against ground truth
```bash
uv run python validate.py
```

Edit `ground_truth.json` to add your own curated chains (10 chains, 23 CVEs currently).
Validation uses `parsed_cves.json` for dataset membership and the raw tier edge files for edge recall.

### Analysis tools
```bash
uv run python analyze_references.py --all    # Reference URL domain/tag analysis
uv run python build_reference_index.py       # Structured reference index with domain taxonomy
uv run python count_evidence_coverage.py     # Corpus coverage: direct / candidate / discovery
uv run python export_commits.py             # Export commit cache as researcher-friendly JSONL
```

### Filter by chain size
```bash
uv run python build_chains.py --tiers 1,2 --min-size 3
```

## Output

Generated pipeline artifacts go to `output/`. Exported datasets go to `datasets/`:

- `variant_chains.json` -- tree-structured chains with per-edge evidence lists
- `edge_graph.json` -- raw flat edge list with all evidence (for auditing)
- `parsed_cves.json` -- full parsed corpus for all published CVEs
- `edges_t1_description.json` -- T1 edges
- `edges_t2_allfields.json` -- T2 edges (new only)
- `edges_t3_commits.json` -- T3 edges from GitHub commit messages
- `edges_t4_shared_ids.json` -- T4 edges from shared bug tracker IDs (weak signal)
- `t5_classifications.json` -- per-run T5 audit artifact (all classifications with traces)
- `datasets/edges_t5_llm.json` -- cumulative T5 edges + processed CVE/pair tracking (git-tracked)
- `datasets/t5_classifications.jsonl` -- cumulative T5 classifications with full reasoning (git-tracked)
- `datasets/github_commits.jsonl` -- researcher-friendly dataset linking CVEs to commit messages
- `cve_references.json` -- graph-only subset used for reference-graph inspection
- `reference_index.json` -- structured index of all 1.1M reference URLs
- `reference_analysis.json` -- domain/tag distribution analysis
- `evidence_coverage.json` -- corpus coverage split (direct / candidate / discovery)
- `stats.json` -- parsing statistics
- `validation_results.json` -- ground truth comparison

## Tests and linting

```bash
uv run pytest -v
uv run ruff check .
uv run mypy parse_cves.py parse_cves_t2.py build_chains.py validate.py
```

## How it works

Each tier scans progressively deeper fields in the CVE JSON records:

| Tier | Source | Fields |
|---|---|---|
| T1 | Description | `containers.cna.descriptions` |
| T2 | All fields | Reference names/URLs, titles, ADP descriptions, legacy records |
| T3 | Git commits | GitHub commit messages fetched via API |
| T4 | Shared bug IDs | CVE pairs sharing Bugzilla/GitHub issue/PR (weak signal) |
| T5 | LLM classification | Per-CVE URL fetching + LLM, or T4 candidate pairs via OpenRouter |

Every edge is tagged with its source (`t1_description`, `t2_ref_name`, `t3_commit`, etc.) and multiple tiers finding the same edge produces multiple evidence entries.

`build_chains.py` outputs both tree-structured chains (`variant_chains.json`) and a raw flat edge graph (`edge_graph.json`) for auditing.

### Key finding

Vendor advisory pages (Red Hat, Debian, Cisco) largely mirror the same CNA description that T1 already scans — structured advisory extraction does not find new edges. GitHub commit messages are the most promising untapped source: developers write "fix for CVE-X" in commits but this text doesn't make it into CVE descriptions.

See [REPORT.md](REPORT.md) for full results and statistics.

## Evidence coverage

Of 323,709 published CVEs:
- **5.24%** (16,947) have direct regex evidence (T1/T2 edges)
- **28.51%** (92,296) have candidate-only signals in the broad sense (all structured IDs, including noisy JIRA matches)
- **13.66%** (44,228) are in the default T4 candidate pool with JIRA disabled
- **66.25%** (214,466) have no cross-references (discovery-only)

## T5 cost and yield projections

Based on 531 CVEs classified so far (x-ai/grok-4.1-fast via OpenRouter):

| Metric | Observed | Projected (full corpus) |
|---|---|---|
| CVEs processed | 531 | 323,709 |
| New edges found | 10 | ~6,100 |
| Corroborating edges | 7 | ~4,300 |
| Edge yield rate | 1.88% of CVEs | — |
| Tokens per CVE | median ~5k, mean ~8.8k | ~2.9B total |
| Cost per CVE (grok-4.1-fast) | median $0.0015, mean $0.0022 | **~$470-700** |

T4 candidate pairs (5,032 pairs) would cost an additional ~$10 and yield ~130 edges.

**Notes:**
- Results are cumulative and resumable — runs pick up where the last one left off.

