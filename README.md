# vuln-variants

Discovers CVE variant chains (failed patches, bypasses, incomplete fixes) by
mining cross-references across CVE records, commit messages, shared bug tracker
IDs, LLM classification via OpenRouter, and targeted heuristic signal-phrase extraction.

**Results:** 42,057 edges across 17,085 CVEs organized into 6,172 variant chains. See [REPORT.md](REPORT.md) for full analysis and methodology.

**Use the results:** Published release snapshot: [`datasets/releases/2026-04-11/`](datasets/releases/2026-04-11/) with frozen copies of `variant_chains.json`, `edge_graph.json`, and `manifest.json`. Live rerunnable artifacts: `output/variant_chains.json` and `output/edge_graph.json`.

**Quick start:** Want to use the published snapshot as-is? Start at [`datasets/releases/2026-04-11/`](datasets/releases/2026-04-11/). Want to reproduce T1-T4 from scratch? Start at [Setup](#setup). Want to continue T5 LLM classification? Jump to [Tier 5](#tier-5-llm-classification-needs-openrouter_api_key).

## Table of contents

- [Setup](#setup)
- [Usage](#usage) — T1 through T6 pipeline, validation, analysis tools
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

# Download the CVE database (~4-5 GB)
git clone --depth 1 https://github.com/CVEProject/cvelistV5.git data/cvelistV5
```

## Usage

### Tier 1: Description regex (~1-2 minutes)
```bash
uv run python parse_cves.py
uv run python build_chains.py
```

### Tier 2: All-fields regex (adds ~2,600 edges, ~1-2 minutes)
```bash
uv run python parse_cves_t2.py
uv run python build_chains.py
```

### Build reference index (OBS: required for T3, T4, T5)
```bash
uv run python build_reference_index.py           # ~1-2 minutes, indexes all 1.1M reference URLs
```

### Tier 3: GitHub commit messages (needs GITHUB_TOKEN)
```bash
uv run python parse_commits_t3.py --sample 50    # Test on 50 commits
GITHUB_TOKEN=ghp_... uv run python parse_commits_t3.py  # All ~22k commits (slow, hours)
uv run python build_chains.py
```

### Tier 4: Shared bug tracker IDs (fast, local)
```bash
uv run python find_shared_ids_t4.py              # finds CVE pairs sharing Bugzilla/GitHub IDs
uv run python build_chains.py
```

OBS: T4 edges are weak signals — two CVEs sharing a bug tracker ID doesn't prove a variant relationship.

### Tier 5: LLM classification (needs OPENROUTER_API_KEY)
```bash
uv run python classify_variants_t5.py                          # discovery mode, default 100 CVEs
uv run python classify_variants_t5.py --limit 500              # first 500 CVEs
uv run python classify_variants_t5.py --cve CVE-2021-45046     # specific CVE(s), comma-separated
uv run python classify_variants_t5.py --verify                 # verify edges from other tiers
uv run python classify_variants_t5.py --verify --tiers 1,6     # verify only T1+T6 edges
uv run python classify_variants_t5.py --dry-run                # count items, no API/fetch calls
uv run python build_chains.py
```

T5 has two modes. **Discovery** (default) fetches reference URLs for each CVE and asks the LLM to find variant relationships from the content. **Verification** (`--verify`) takes existing edges from other tiers and asks the LLM to confirm or reclassify them. Runs in parallel (`--workers N`, default 20). Resumable — results accumulate in `datasets/` and re-runs skip already-classified items.

Set `OPENROUTER_API_KEY` and optionally `OPENROUTER_MODEL` in `.env` (see `.env.example`).

### Tier 6: Variant-phrase search (local, ~5-10 minutes)
```bash
uv run python find_variant_phrases_t6.py              # search all CVEs for variant signal phrases
uv run python build_chains.py
```

T6 searches for specific phrases that indicate the *nature* of a CVE cross-reference (e.g., "insufficient fix for", "bypass", "regression", "in conjunction with"). Derived from a 140-sample edge taxonomy study — see [`datasets/edge_taxonomy_report.md`](datasets/edge_taxonomy_report.md).

**Note:** `build_chains.py` auto-detects all available tier files and includes them. Re-run it after completing any new tier to rebuild the graph. Use `--tiers 1,2,3` to explicitly select a subset.

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

- `datasets/releases/2026-04-11/variant_chains.json` -- frozen published snapshot of the tree-structured chains (T1+T2+T3+T5+T6)
- `datasets/releases/2026-04-11/edge_graph.json` -- frozen published snapshot of the flat edge graph
- `datasets/releases/2026-04-11/manifest.json` -- release metadata, provenance, file hashes, and summary counts
- `output/variant_chains.json` -- live tree-structured chains with per-edge evidence lists
- `output/edge_graph.json` -- live raw flat edge list with all evidence (for auditing)
- `output/parsed_cves.json` -- full parsed corpus for all published CVEs
- `output/edges_t1_description.json` -- T1 edges
- `output/edges_t2_allfields.json` -- T2 edges (new + corroborating, deduplicated against T1)
- `output/edges_t3_commits.json` -- T3 edges from GitHub commit messages
- `output/edges_t4_shared_ids.json` -- T4 edges from shared bug tracker IDs (weak signal)
- `output/edges_t6_variant_phrases.json` -- T6 edges with signal-phrase categories and matched patterns
- `output/t5_classifications.json` -- per-run T5 audit artifact (all classifications with traces)
- `datasets/edges_t5_llm.json` -- cumulative T5 edges + processed CVE/pair tracking (git-tracked)
- `datasets/t5_classifications.jsonl` -- cumulative T5 classifications with full reasoning (git-tracked)
- `datasets/github_commits.jsonl` -- researcher-friendly dataset linking CVEs to commit messages
- `datasets/edge_taxonomy_report.md` -- 140-sample edge taxonomy: why CVEs reference each other
- `datasets/edge_classifications.json` -- all 140 per-edge classifications with reasoning
- `datasets/edge_samples.json` -- the 140 sampled edges used in the taxonomy study
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
| T6 | Variant phrases | Signal-phrase regex: "insufficient fix", "bypass", "regression", "in conjunction with", etc. |

Every edge is tagged with its source (`t1_description`, `t2_ref_name`, `t3_commit`, etc.) and multiple tiers finding the same edge produces multiple evidence entries.

`build_chains.py` outputs both tree-structured chains (`variant_chains.json`) and a raw flat edge graph (`edge_graph.json`) for auditing.

### Key finding

Vendor advisory pages (Red Hat, Debian, Cisco) largely mirror the same CNA description that T1 already scans — structured advisory extraction does not find new edges. GitHub commit messages are the most promising untapped source: developers write "fix for CVE-X" in commits but this text doesn't make it into CVE descriptions.

See [REPORT.md](REPORT.md) for full results and statistics.

## Evidence coverage

Of 323,709 published CVEs, 5.24% have direct regex evidence (T1/T2), 13.66% are in the default T4 candidate pool, and 66.25% have no cross-references. See [REPORT.md](REPORT.md) for full coverage breakdown and T5 cost projections.

## Future work

1. **Scale T5** — classify more CVEs (531/323k done), target ground truth gaps
2. **Expand precision evaluation** — 140-sample taxonomy done (see `datasets/edge_taxonomy_report.md`), scale to 1,000+ samples
3. **Expand ground truth** with additional curated variant chains
4. **Visualizations** — interactive chain explorer, timeline views, and tier contribution diagrams
