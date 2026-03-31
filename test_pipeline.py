"""
Tests for the CVE variant chain pipeline using real CVE JSON fixtures.

Fixtures (from cvelistV5):
  - CVE-2021-44228  (Log4Shell original — no CVE refs in description)
  - CVE-2021-45046  (Log4Shell incomplete fix — references CVE-2021-44228)
  - CVE-2021-45105  (Log4Shell recursion DoS — no CVE refs in description)
  - CVE-2010-1622   (Spring Framework original — no CVE refs in description)
  - CVE-2022-22965  (Spring4Shell — no CVE refs in description)
  - CVE-2023-44487  (HTTP/2 Rapid Reset — standalone, no CVE refs)

Only one real edge exists in these fixtures:
  CVE-2021-45046 → CVE-2021-44228  ("fix to address CVE-2021-44228")
"""

import json
from pathlib import Path

import pytest

import build_chains
import validate
from build_chains import build_graph, build_tree, find_components
from parse_cves import parse_cve_file

FIXTURES = Path(__file__).parent / "test_fixtures"


# ---------------------------------------------------------------------------
# 1. Parsing individual CVE files
# ---------------------------------------------------------------------------

class TestParseCveFile:

    def test_extracts_cve_id(self):
        result = parse_cve_file(FIXTURES / "CVE-2021-44228.json")
        assert result["cve_id"] == "CVE-2021-44228"

    def test_extracts_published_date(self):
        result = parse_cve_file(FIXTURES / "CVE-2021-44228.json")
        assert result["published"].startswith("2021-12-10")

    def test_extracts_english_description(self):
        result = parse_cve_file(FIXTURES / "CVE-2021-45046.json")
        assert "Log4j" in result["description"]

    def test_detects_cve_reference_in_description(self):
        """CVE-2021-45046 says 'fix to address CVE-2021-44228'."""
        result = parse_cve_file(FIXTURES / "CVE-2021-45046.json")
        assert "CVE-2021-44228" in result["references"]

    def test_no_self_reference(self):
        """A CVE should never list itself as a reference."""
        result = parse_cve_file(FIXTURES / "CVE-2021-45046.json")
        assert "CVE-2021-45046" not in result["references"]

    def test_standalone_cve_has_no_references(self):
        """CVE-2023-44487 doesn't mention any other CVE in its description."""
        result = parse_cve_file(FIXTURES / "CVE-2023-44487.json")
        assert result["references"] == []

    def test_original_cve_has_no_references(self):
        """CVE-2021-44228 is the original — its description doesn't cite earlier CVEs."""
        result = parse_cve_file(FIXTURES / "CVE-2021-44228.json")
        assert result["references"] == []

    def test_invalid_file_returns_none(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{invalid json")
        assert parse_cve_file(bad) is None

    def test_rejected_state_returns_none(self, tmp_path):
        """A CVE with state != PUBLISHED should be skipped."""
        f = tmp_path / "CVE-9999-0001.json"
        f.write_text('{"cveMetadata": {"cveId": "CVE-9999-0001", "state": "REJECTED"}}')
        assert parse_cve_file(f) is None


# ---------------------------------------------------------------------------
# 2. Graph construction
# ---------------------------------------------------------------------------

@pytest.fixture
def all_parsed_cves():
    """Parse all 6 fixtures into the dict format expected by build_chains."""
    cves = {}
    for f in sorted(FIXTURES.glob("CVE-*.json")):
        result = parse_cve_file(f)
        if result:
            cves[result["cve_id"]] = {
                "published": result["published"],
                "description": result["description"],
                "references": result["references"],
            }
    return cves


def make_edge_provenance(cves):
    """Convert parsed CVEs dict into edge_provenance dict for build_graph."""
    provenance = {}
    for cve_id, data in cves.items():
        for ref in data.get("references", []):
            if ref in cves:
                provenance[(cve_id, ref)] = {
                    "found_in": "t1_description",
                    "context": "",
                }
    return provenance


class TestBuildGraph:

    def test_parent_child_edge(self, all_parsed_cves):
        """CVE-2021-45046 references 44228 → 44228 is parent, 45046 is child."""
        ep = make_edge_provenance(all_parsed_cves)
        children, parents = build_graph(ep, all_parsed_cves)
        assert "CVE-2021-45046" in children["CVE-2021-44228"]
        assert "CVE-2021-44228" in parents["CVE-2021-45046"]

    def test_standalone_has_no_edges(self, all_parsed_cves):
        """CVE-2023-44487 should be completely disconnected."""
        ep = make_edge_provenance(all_parsed_cves)
        children, parents = build_graph(ep, all_parsed_cves)
        assert "CVE-2023-44487" not in children
        assert "CVE-2023-44487" not in parents

    def test_unreferenced_variant_has_no_edges(self, all_parsed_cves):
        """CVE-2021-45105 doesn't reference anyone in its description."""
        ep = make_edge_provenance(all_parsed_cves)
        children, parents = build_graph(ep, all_parsed_cves)
        assert "CVE-2021-45105" not in parents


# ---------------------------------------------------------------------------
# 3. Connected components
# ---------------------------------------------------------------------------

class TestFindComponents:

    def test_finds_log4shell_component(self, all_parsed_cves):
        ep = make_edge_provenance(all_parsed_cves)
        children, parents = build_graph(ep, all_parsed_cves)
        components = find_components(ep, children, parents)
        log4shell = None
        for c in components:
            if "CVE-2021-44228" in c:
                log4shell = c
        assert log4shell is not None
        assert "CVE-2021-45046" in log4shell

    def test_standalone_not_in_any_component(self, all_parsed_cves):
        ep = make_edge_provenance(all_parsed_cves)
        children, parents = build_graph(ep, all_parsed_cves)
        components = find_components(ep, children, parents)
        all_in_components = set().union(*components) if components else set()
        assert "CVE-2023-44487" not in all_in_components

    def test_min_component_size_is_2(self, all_parsed_cves):
        ep = make_edge_provenance(all_parsed_cves)
        children, parents = build_graph(ep, all_parsed_cves)
        components = find_components(ep, children, parents)
        for c in components:
            assert len(c) >= 2


# ---------------------------------------------------------------------------
# 4. Tree construction
# ---------------------------------------------------------------------------

class TestBuildTree:

    def test_root_is_original_cve(self, all_parsed_cves):
        ep = make_edge_provenance(all_parsed_cves)
        children, parents = build_graph(ep, all_parsed_cves)
        visited = set()
        tree = build_tree("CVE-2021-44228", all_parsed_cves, children, parents, ep, visited)
        assert tree["cve_id"] == "CVE-2021-44228"

    def test_variant_appears_as_child(self, all_parsed_cves):
        ep = make_edge_provenance(all_parsed_cves)
        children, parents = build_graph(ep, all_parsed_cves)
        visited = set()
        tree = build_tree("CVE-2021-44228", all_parsed_cves, children, parents, ep, visited)
        variant_ids = [v["cve_id"] for v in tree["variants"]]
        assert "CVE-2021-45046" in variant_ids

    def test_tree_node_has_expected_fields(self, all_parsed_cves):
        ep = make_edge_provenance(all_parsed_cves)
        children, parents = build_graph(ep, all_parsed_cves)
        visited = set()
        tree = build_tree("CVE-2021-44228", all_parsed_cves, children, parents, ep, visited)
        assert "cve_id" in tree
        assert "published" in tree
        assert "description" in tree
        assert "variants" in tree

    def test_no_duplicate_nodes(self, all_parsed_cves):
        """Each CVE should appear at most once in the tree."""
        ep = make_edge_provenance(all_parsed_cves)
        children, parents = build_graph(ep, all_parsed_cves)
        visited = set()
        tree = build_tree("CVE-2021-44228", all_parsed_cves, children, parents, ep, visited)

        seen = []
        def collect(node):
            seen.append(node["cve_id"])
            for v in node["variants"]:
                collect(v)
        collect(tree)

        assert len(seen) == len(set(seen))

    def test_visited_prevents_revisit(self, all_parsed_cves):
        """Calling build_tree on an already-visited node returns None."""
        ep = make_edge_provenance(all_parsed_cves)
        children, parents = build_graph(ep, all_parsed_cves)
        visited = {"CVE-2021-44228"}
        result = build_tree("CVE-2021-44228", all_parsed_cves, children, parents, ep, visited)
        assert result is None

    def test_provenance_comes_from_parent_used_in_tree(self):
        cve_data = {
            "CVE-2000-0001": {
                "published": "2000-01-01T00:00:00.000Z",
                "description": "root one",
            },
            "CVE-2000-0002": {
                "published": "2000-01-02T00:00:00.000Z",
                "description": "root two",
            },
            "CVE-2000-0003": {
                "published": "2000-01-03T00:00:00.000Z",
                "description": "child",
            },
        }
        edge_provenance = {
            ("CVE-2000-0003", "CVE-2000-0001"): {
                "found_in": "t1_description",
                "context": "linked from root one",
            },
            ("CVE-2000-0003", "CVE-2000-0002"): {
                "found_in": "t2_ref_name",
                "context": "linked from root two",
            },
        }

        children, parents = build_graph(edge_provenance, cve_data)
        visited = set()
        tree = build_tree("CVE-2000-0002", cve_data, children, parents, edge_provenance, visited)

        child = tree["variants"][0]
        assert child["cve_id"] == "CVE-2000-0003"
        assert child["found_in"] == "t2_ref_name"
        assert child["match_context"] == "linked from root two"


class TestMetadataAndValidationHelpers:

    def test_load_cve_metadata_prefers_full_parsed_corpus(self, tmp_path, monkeypatch):
        parsed_path = tmp_path / "parsed_cves.json"
        graph_path = tmp_path / "cve_references.json"

        parsed_path.write_text(json.dumps({
            "metadata": {"total_published_cves": 2},
            "cves": {
                "CVE-2022-0001": {
                    "published": "2022-01-01T00:00:00.000Z",
                    "description": "from full corpus",
                    "references": [],
                }
            },
        }))
        graph_path.write_text(json.dumps({
            "metadata": {"total_published_cves": 1},
            "cves": {
                "CVE-2021-0001": {
                    "published": "2021-01-01T00:00:00.000Z",
                    "description": "from graph only",
                    "references": [],
                }
            },
        }))

        monkeypatch.setattr(build_chains, "PARSED_OUTPUT_PATH", parsed_path)
        monkeypatch.setattr(build_chains, "REFERENCE_GRAPH_PATH", graph_path)

        cves, metadata = build_chains.load_cve_metadata()

        assert "CVE-2022-0001" in cves
        assert "CVE-2021-0001" not in cves
        assert metadata["total_published_cves"] == 2

    def test_extract_detected_edges_uses_raw_tier_outputs(self, tmp_path):
        edge_path = tmp_path / "edges_t1_description.json"
        edge_path.write_text(json.dumps({
            "edges": [
                {
                    "source": "CVE-2021-45046",
                    "target": "CVE-2021-44228",
                    "found_in": "t1_description",
                    "context": "fix to address CVE-2021-44228",
                }
            ]
        }))

        chains_data = {
            "metadata": {"tiers_used": ["t1"]},
            "chains": [],
        }

        edges, missing_files = validate.extract_detected_edges(chains_data, tmp_path)

        assert edges == {("CVE-2021-44228", "CVE-2021-45046")}
        assert missing_files == []

    def test_load_parsed_corpus_falls_back_to_references(self, tmp_path):
        references_path = tmp_path / "cve_references.json"
        references_path.write_text(json.dumps({
            "cves": {
                "CVE-2021-45105": {
                    "published": "2021-12-18T00:00:00.000Z",
                    "description": "",
                    "references": [],
                }
            }
        }))

        data, used_fallback = validate.load_parsed_corpus(
            tmp_path / "parsed_cves.json",
            references_path,
        )

        assert used_fallback is True
        assert "CVE-2021-45105" in data["cves"]
