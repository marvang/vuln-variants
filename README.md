# vuln-variants

Discovers CVE variant chains (failed patches, bypasses, incomplete fixes) by mining cross-references across CVE records, commit messages, shared bug tracker IDs, and LLM classification via OpenRouter.

**Results:** 42,057 edges across 17,085 CVEs organized into 6,172 variant chains. See [REPORT.md](REPORT.md) for full analysis and methodology.

**Use the results:** Published release snapshot: [`datasets/releases/2026-04-04/`](datasets/releases/2026-04-04/) with frozen copies of `variant_chains.json`, `edge_graph.json`, and `manifest.json`. Live rerunnable artifacts: `output/variant_chains.json` and `output/edge_graph.json`.

**Quick start:** Want to use the published snapshot as-is? Start at [`datasets/releases/2026-04-04/`](datasets/releases/2026-04-04/). Want to reproduce T1-T4 from scratch? Start at [Setup](#setup). Want to continue T5 LLM classification? Jump to [Tier 5](#tier-5-llm-classification-needs-openrouter_api_key).

## Table of contents

- [Setup](#setup)
- [Usage](#usage) — T1 through T5 pipeline, validation, analysis tools
- [Output](#output) — generated artifacts and datasets
- [Tests and linting](#tests-and-linting)
- [How it works](#how-it-works) — tier architecture and key findings
- [Evidence coverage](#evidence-coverage)
- [T5 cost and yield projections](#t5-cost-and-yield-projections)
- [Future work](#future-work)

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

### Build reference index (required for T3, T4, T5)
```bash
uv run python build_reference_index.py           # ~1 minute, indexes all 1.1M reference URLs
```

### Tier 3: GitHub commit messages (needs GITHUB_TOKEN)
```bash
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

T5 has two modes. **Per-CVE** (default) fetches reference URLs for each CVE and asks the LLM to identify variant relationships from the content. **Candidate** mode classifies T4 shared-ID pairs with both CVEs' evidence. Runs in parallel (`--workers N`, default 20). Resumable — results accumulate in `datasets/` and re-runs skip already-classified CVEs. Falls back to `json_object` mode for models that don't support strict `json_schema`.

Set `OPENROUTER_API_KEY` and optionally `OPENROUTER_MODEL` in `.env` (see `.env.example`).

### Validate against ground truth
```bash
uv run python validate.py
```

Edit `ground_truth.json` to add your own curated chains (10 chains, 23 CVEs currently).
Validation uses `parsed_cves.json` for dataset membership and the raw tier edge files for edge recall.

### Analysis tools

Optional exploration scripts used during development to understand the dataset and inform pipeline design. Not required for the main pipeline.

```bash
uv run python analyze_references.py --all    # Reference URL domain/tag analysis
uv run python count_evidence_coverage.py     # Corpus coverage: direct / candidate / discovery
uv run python export_commits.py             # Export commit cache as researcher-friendly JSONL
```

### Filter by chain size
```bash
uv run python build_chains.py --tiers 1,2 --min-size 3
```

## Output

Generated pipeline artifacts go to `output/`. Frozen release snapshots go to `datasets/releases/`. Other exported datasets stay in `datasets/`:

- `datasets/releases/2026-04-04/variant_chains.json` -- frozen published snapshot of the tree-structured chains
- `datasets/releases/2026-04-04/edge_graph.json` -- frozen published snapshot of the flat edge graph
- `datasets/releases/2026-04-04/manifest.json` -- release metadata, provenance, file hashes, and summary counts
- `output/variant_chains.json` -- live tree-structured chains with per-edge evidence lists
- `output/edge_graph.json` -- live raw flat edge list with all evidence (for auditing)
- `output/parsed_cves.json` -- full parsed corpus for all published CVEs
- `output/edges_t1_description.json` -- T1 edges
- `output/edges_t2_allfields.json` -- T2 edges (new + corroborating, deduplicated against T1)
- `output/edges_t3_commits.json` -- T3 edges from GitHub commit messages
- `output/edges_t4_shared_ids.json` -- T4 edges from shared bug tracker IDs (weak signal)
- `output/t5_classifications.json` -- per-run T5 audit artifact (all classifications with traces)
- `datasets/edges_t5_llm.json` -- cumulative T5 edges + processed CVE/pair tracking (git-tracked)
- `datasets/t5_classifications.jsonl` -- cumulative T5 classifications with full reasoning (git-tracked)
- `datasets/github_commits.jsonl` -- researcher-friendly dataset linking CVEs to commit messages
- `output/cve_references.json` -- graph-only subset used for reference-graph inspection
- `output/reference_index.json` -- structured index of all 1.1M reference URLs
- `output/reference_analysis.json` -- domain/tag distribution analysis
- `output/evidence_coverage.json` -- corpus coverage split (direct / candidate / discovery)
- `output/stats.json` -- parsing statistics
- `output/validation_results.json` -- ground truth comparison

## Tests and linting

```bash
uv run pytest -v
uv run ruff check .
uv run mypy *.py
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

Of 323,709 published CVEs, 5.24% have direct regex evidence (T1/T2), 13.66% are in the default T4 candidate pool, and 66.25% have no cross-references. See [REPORT.md](REPORT.md) for full coverage breakdown and T5 cost projections.

## Future work

1. **Scale T5** — classify more CVEs (531/323k done), target ground truth gaps
2. **Precision evaluation** — sample and manually verify edges from each tier to estimate per-tier accuracy
3. **Expand ground truth** with additional curated variant chains
4. **Visualizations** — interactive chain explorer, timeline views, and tier contribution diagrams
