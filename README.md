# vuln-variants

Systematically discovers CVE vulnerability variant chains by regex-matching CVE IDs across CVE record fields. When one CVE's description (or other metadata) references another CVE, it signals a variant, bypass, or incomplete fix.

`parse_cves.py` now produces two different artifacts:
- `output/parsed_cves.json` contains the full parsed corpus of published CVEs.
- `output/cve_references.json` contains only the graph-participating subset from T1 description matches.

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

### Validate against ground truth
```bash
uv run python validate.py
```

Edit `ground_truth.json` to add your own curated chains.
Validation uses `parsed_cves.json` for dataset membership and the raw tier edge files for edge recall.

### Filter by chain size
```bash
uv run python build_chains.py --tiers 1,2 --min-size 3
```

## Output

Results go to `output/`:

- `variant_chains.json` -- tree-structured chains with provenance labels
- `parsed_cves.json` -- full parsed corpus for all published CVEs
- `edges_t1_description.json` -- T1 edges
- `edges_t2_allfields.json` -- T2 edges (new only)
- `cve_references.json` -- graph-only subset used for reference-graph inspection
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
| T3 | Advisory pages | External URLs scraped via Cloudflare /crawl (planned) |

Every edge is tagged with its source (`t1_description`, `t2_ref_name`, etc.) so results can be filtered by provenance.
`build_chains.py` uses `parsed_cves.json` for metadata so T2/T3-only CVEs keep their published dates and descriptions in the final trees.

See [REPORT.md](REPORT.md) for full results and statistics.
