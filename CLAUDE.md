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
- `build_chains.py` and `validate.py` should treat `parsed_cves.json` as the source of truth for metadata and dataset membership.

### Tiered pipeline

Each tier scans deeper fields, producing an edges file. The chain builder merges edges from whichever tiers have been run.

```
parse_cves.py    → output/parsed_cves.json             (full parsed corpus)
                → output/cve_references.json           (graph-only T1 subset)
                → output/edges_t1_description.json     (CNA descriptions)
parse_cves_t2.py → output/edges_t2_allfields.json      (ref names, URLs, titles, ADP, legacy)
(T3 planned)     → output/edges_t3_advisories.json      (scraped advisory pages)
                        ↓
build_chains.py --tiers 1,2,3 → output/variant_chains.json
validate.py                   → output/validation_results.json
```

### Edge direction convention

If CVE-B's text mentions CVE-A, the edge is `source=B, target=A`. In the tree output, A is the parent (original) and B is the child (variant). Trees are sorted chronologically by published date, and provenance is attached from the actual parent edge chosen in the tree.

### Provenance tracking

Every edge carries a `found_in` label (`t1_description`, `t2_ref_name`, `t2_ref_url`, `t2_title`, `t2_adp_description`, `t2_legacy`, `t3_advisory`) that propagates to the final tree nodes. The chain builder's metadata includes per-tier edge counts. Validation measures edge recall from the raw tier edge files, not the treeified chain view.

### Key functions

- `parse_cves.parse_cve_file(filepath)` — parses a single CVE JSON, returns `{cve_id, published, description, references}` or None
- `parse_cves_t2.extract_field_texts(data)` — returns `[(found_in_label, text)]` for all scannable fields
- `build_chains.build_graph(edge_provenance, cve_data)` — builds adjacency lists from edge dict
- `build_chains.build_tree(cve_id, cve_data, children, parents, edge_provenance, visited)` — recursive tree builder

### CVE JSON structure (cvelistV5)

Files are at `data/cvelistV5/cves/{year}/{id_bucket}/CVE-{year}-{id}.json` where `id_bucket` = `str(int(id) // 1000) + "xxx"`. Key paths:
- `cveMetadata.{cveId, state, datePublished}` — only `state == "PUBLISHED"` is processed
- `containers.cna.descriptions[].value` — primary description (T1)
- `containers.cna.references[].{name, url}` — advisory references (T2)
- `containers.adp[].descriptions[].value` — ADP container descriptions (T2)

### Test fixtures

`test_fixtures/` contains 6 real CVE JSONs. Only one edge exists in the fixtures: CVE-2021-45046 → CVE-2021-44228. Tests import functions directly from the pipeline scripts.
