# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Setup
uv sync
git clone --depth 1 https://github.com/CVEProject/cvelistV5.git data/cvelistV5

# Run pipeline
uv run python parse_cves.py                      # Writes parsed_cves.json + T1 graph/edges (~30s)
uv run python parse_cves_t2.py                   # Tier 2: all-fields regex (~1min)
uv run python build_chains.py --tiers 1,2        # Build chains from tiers
uv run python validate.py                        # Validate against ground_truth.json

# T3: GitHub commit messages (needs GITHUB_TOKEN for 5k req/hr)
uv run python build_reference_index.py           # Build reference index (~1min)
uv run python parse_commits_t3.py --sample 50    # Test on 50 commits
uv run python parse_commits_t3.py                # All 22k commits (~4.5hr with token)
uv run python build_chains.py --tiers 1,2,3      # Include T3 edges

# Analysis
uv run python analyze_references.py --all        # Reference URL domain analysis

# Tests and linting
uv run pytest -v                                 # All tests
uv run pytest test_pipeline.py::TestParseCveFile  # Single test class
uv run ruff check .                              # Lint
uv run mypy parse_cves.py parse_cves_t2.py build_chains.py validate.py  # Type check
```

## Architecture

This project detects CVE variant chains (failed patches, bypasses, incomplete fixes) by regex-matching CVE IDs across CVE record fields in the cvelistV5 database (341k+ CVE JSON files stored locally in `data/`).

Important artifact split:
- `output/parsed_cves.json` is the full parsed corpus of all published CVEs.
- `output/cve_references.json` is the graph-only subset from T1 description matches.
- `output/reference_index.json` is the structured index of all 1.1M reference URLs with domain taxonomy and extracted structured IDs (GitHub commits, bug tracker IDs).
- `build_chains.py` and `validate.py` should treat `parsed_cves.json` as the source of truth for metadata and dataset membership.

### Tiered pipeline

Each tier scans deeper sources, producing an edges file. The chain builder merges edges from whichever tiers have been run.

```
parse_cves.py           → output/edges_t1_description.json     (CNA descriptions)
parse_cves_t2.py        → output/edges_t2_allfields.json       (ref names, URLs, titles, ADP, legacy)
parse_commits_t3.py     → output/edges_t3_commits.json         (GitHub commit messages via API)
                               ↓
build_chains.py --tiers 1,2,3 → output/variant_chains.json     (trees with provenance)
                              → output/edge_graph.json          (raw flat edge list)
validate.py                   → output/validation_results.json
```

### Edge direction convention

If CVE-B's text mentions CVE-A, the edge is `source=B, target=A`. In the tree output, A is the parent (original) and B is the child (variant). Trees are sorted chronologically by published date.

### Evidence model

Each edge carries a list of evidence from every tier that found it:
```json
{
  "evidence": [
    {"found_in": "t1_description", "context": "fix to address CVE-2021-44228..."},
    {"found_in": "t3_commit", "context": "...patch for CVE-2021-44228..."}
  ]
}
```

Labels: `t1_description`, `t2_ref_name`, `t2_ref_url`, `t2_title`, `t2_adp_description`, `t2_legacy`, `t3_commit`.

The raw graph (`edge_graph.json`) preserves all edges with all evidence before treeification. Use it for auditing — the tree view drops alternative parents.

### Key functions

- `parse_cves.parse_cve_file(filepath)` — parses a single CVE JSON, returns `{cve_id, published, description, references}` or None
- `parse_cves_t2.extract_field_texts(data)` — returns `[(found_in_label, text)]` for all scannable fields
- `build_chains.load_edges(tiers)` — loads and merges edges, preserving all evidence per (source, target)
- `build_chains.build_graph(edge_provenance, cve_data)` — builds adjacency lists from edge dict
- `build_chains.build_tree(cve_id, ...)` — recursive tree builder with evidence attachment
- `url_utils.normalize_url(url)` — URL normalization for consistent caching/dedup

### CVE JSON structure (cvelistV5)

Files are at `data/cvelistV5/cves/{year}/{id_bucket}/CVE-{year}-{id}.json` where `id_bucket` = `str(int(id) // 1000) + "xxx"`. Key paths:
- `cveMetadata.{cveId, state, datePublished}` — only `state == "PUBLISHED"` is processed
- `containers.cna.descriptions[].value` — primary description (T1)
- `containers.cna.references[].{name, url, tags}` — advisory references (T2, T3)
- `containers.adp[].descriptions[].value` — ADP container descriptions (T2)

### Test fixtures

`test_fixtures/` contains 6 real CVE JSONs. Only one edge exists in the fixtures: CVE-2021-45046 → CVE-2021-44228. Tests import functions directly from the pipeline scripts.

### Key finding from advisory investigation

Vendor advisory pages (Red Hat API, Debian tracker, Cisco) mirror the same CNA description text that T1 already scans. Structured advisory extraction does NOT find new edges. GitHub commit messages are the best untapped source — developers write "fix for CVE-X" in commits but that text doesn't make it into CVE descriptions.

### Next tiers (planned)

- **T3 full run**: `GITHUB_TOKEN=... uv run python parse_commits_t3.py` on all 22k commits
- **T4 LLM classification**: `classify_variants.py` via OpenRouter API — feed candidate CVE pairs from T3 snippets and shared bug/advisory IDs to classify variant relationships
- **Shared-ID extraction**: `find_shared_ids.py` — candidate signal (not chain edges) from CVEs referencing the same Bugzilla/JIRA/GitHub issue
