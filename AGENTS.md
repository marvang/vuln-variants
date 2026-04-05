# AGENTS.md

Guidance for coding agents working in this repository.

## Project overview

This project discovers candidate CVE variant chains by extracting CVE-to-CVE references from cvelistV5 and related evidence sources.

- T1 scans CNA descriptions.
- T2 scans additional JSON fields such as reference names, URLs, titles, ADP descriptions, and legacy fields.
- T3 scans GitHub commit messages linked from CVE references.
- T4 finds weak structural links from shared Bugzilla/GitHub issue/PR IDs.
- T5 uses an LLM to classify variant relationships from fetched evidence.

Important interpretation rule:
- A CVE mentioning another CVE is evidence for a possible variant-like relationship, not proof on its own.

## Setup and common commands

```bash
# Setup
uv sync
git clone --depth 1 https://github.com/CVEProject/cvelistV5.git data/cvelistV5

# Core pipeline
uv run python parse_cves.py
uv run python parse_cves_t2.py
uv run python build_reference_index.py
uv run python parse_commits_t3.py --sample 50
uv run python find_shared_ids_t4.py
uv run python classify_variants_t5.py --dry-run
uv run python build_chains.py --tiers 1,2,3
uv run python validate.py

# Tests and linting
uv run pytest -v
uv run ruff check .
uv run mypy parse_cves.py parse_cves_t2.py build_chains.py validate.py
```

## Repository map

- `parse_cves.py` writes `output/parsed_cves.json`, `output/cve_references.json`, and `output/edges_t1_description.json`
- `parse_cves_t2.py` writes `output/edges_t2_allfields.json`
- `build_reference_index.py` writes `output/reference_index.json`
- `parse_commits_t3.py` writes `output/edges_t3_commits.json`
- `export_commits.py` writes `datasets/github_commits.jsonl`
- `find_shared_ids_t4.py` writes `output/edges_t4_shared_ids.json`
- `classify_variants_t5.py` updates `datasets/edges_t5_llm.json`, `datasets/t5_classifications.jsonl`, and `output/t5_classifications.json`
- `build_chains.py` writes `output/variant_chains.json` and `output/edge_graph.json`
- `validate.py` writes `output/validation_results.json`

Published snapshot:
- `datasets/releases/2026-04-04/` contains a frozen release of `variant_chains.json`, `edge_graph.json`, and `manifest.json`

## Data and artifact conventions

- `output/` contains live rerunnable artifacts from the pipeline.
- `datasets/releases/` contains frozen publishable snapshots.
- `datasets/` contains reusable exported datasets, including T5 cumulative outputs.
- `output/parsed_cves.json` is the source of truth for dataset membership and CVE metadata.
- `output/cve_references.json` is only the graph subset from T1 description matches.

Do not casually edit generated artifacts by hand. If a task requires changed outputs, regenerate them intentionally or update the published snapshot intentionally.

## Edge model

Edge direction is `source = newer/reference CVE`, `target = older/referenced CVE`.

Example:
- If CVE-B mentions CVE-A, the stored edge is `source=B, target=A`.
- In `variant_chains.json`, CVE-A becomes the parent and CVE-B becomes the child.

Each edge can carry multiple evidence entries such as:
- `t1_description`
- `t2_ref_name`
- `t2_ref_url`
- `t2_title`
- `t2_adp_description`
- `t2_legacy`
- `t3_commit`
- `t4_shared_bugzilla`
- `t4_shared_github_issue`
- `t4_shared_github_pr`
- `t5_llm`

Use `output/edge_graph.json` when auditing full evidence. The tree view in `output/variant_chains.json` is easier to consume but can hide alternative parents.

## Cost and runtime notes

- cvelistV5 is large: hundreds of thousands of CVE JSON files and more than 1.1M reference URLs.
- T3 is network-bound and slow for full runs; it benefits from `GITHUB_TOKEN`.
- T4 is local and fast, but weak-signal only.
- T5 is resumable but can cost real money and should not be run broadly without intent.
- `build_chains.py` defaults to tiers `1,2,3`; add `4` for weak T4 edges and `5` for T5 edges.

## Validation and testing

- `ground_truth.json` holds curated reference chains for validation.
- `validate.py` checks both CVE recall and edge recall.
- `test_fixtures/` contains a small set of real CVE JSONs for tests.

## Practical guidance for agents

- Prefer reading current artifacts before changing claims in docs.
- Keep README and report numbers aligned with checked-in outputs.
- Be explicit about whether a file is a live artifact, cumulative dataset, or frozen snapshot.
- When documenting results, distinguish strong T1-T3/T5 edges from weak T4 structural links.
- Avoid treating shared bug IDs or cross-references as definitive proof of causality.
