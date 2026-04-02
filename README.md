# vuln-variants

Systematically discovers CVE vulnerability variant chains (failed patches, bypasses, incomplete fixes) by regex-matching CVE IDs across CVE record fields and external sources. When one CVE's text references another CVE, it signals a variant, bypass, or incomplete fix.

**Results:** 41,938 edges across 16,947 CVEs (5.24% of all published CVEs) organized into 6,128 variant chains. See [REPORT.md](REPORT.md) for full analysis, statistics, and methodology.

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
```

### Filter by chain size
```bash
uv run python build_chains.py --tiers 1,2 --min-size 3
```

## Output

Results go to `output/`:

- `variant_chains.json` -- tree-structured chains with per-edge evidence lists
- `edge_graph.json` -- raw flat edge list with all evidence (for auditing)
- `parsed_cves.json` -- full parsed corpus for all published CVEs
- `edges_t1_description.json` -- T1 edges
- `edges_t2_allfields.json` -- T2 edges (new only)
- `edges_t3_commits.json` -- T3 edges from GitHub commit messages
- `cve_references.json` -- graph-only subset used for reference-graph inspection
- `reference_index.json` -- structured index of all 1.1M reference URLs
- `reference_analysis.json` -- domain/tag distribution analysis
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

Every edge is tagged with its source (`t1_description`, `t2_ref_name`, `t3_commit`, etc.) and multiple tiers finding the same edge produces multiple evidence entries.

`build_chains.py` outputs both tree-structured chains (`variant_chains.json`) and a raw flat edge graph (`edge_graph.json`) for auditing.

### Key finding

Vendor advisory pages (Red Hat, Debian, Cisco) largely mirror the same CNA description that T1 already scans — structured advisory extraction does not find new edges. GitHub commit messages are the most promising untapped source: developers write "fix for CVE-X" in commits but this text doesn't make it into CVE descriptions.

See [REPORT.md](REPORT.md) for full results and statistics.

## Future work

1. **Run T3 at scale** — all 22k GitHub commits with `GITHUB_TOKEN` (~4.5 hours)
2. **T4: LLM classification** — feed candidate CVE pairs (from T3 snippets, shared bug IDs) to an LLM to classify variant relationships via OpenRouter API
3. **Shared-ID extraction** — CVEs referencing the same bug tracker issue or advisory ID as candidate signals for LLM classification
4. **Expand ground truth** with additional curated variant chains
