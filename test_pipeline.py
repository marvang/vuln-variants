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

import io
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
                provenance[(cve_id, ref)] = [{
                    "found_in": "t1_description",
                    "context": "",
                }]
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
            ("CVE-2000-0003", "CVE-2000-0001"): [{
                "found_in": "t1_description",
                "context": "linked from root one",
            }],
            ("CVE-2000-0003", "CVE-2000-0002"): [{
                "found_in": "t2_ref_name",
                "context": "linked from root two",
            }],
        }

        children, parents = build_graph(edge_provenance, cve_data)
        visited = set()
        tree = build_tree("CVE-2000-0002", cve_data, children, parents, edge_provenance, visited)

        child = tree["variants"][0]
        assert child["cve_id"] == "CVE-2000-0003"
        assert child["evidence"] == [{"found_in": "t2_ref_name", "context": "linked from root two"}]

    def test_multi_tier_evidence_preserved(self):
        """Same edge found by two tiers should keep both evidence entries."""
        cve_data = {
            "CVE-2000-0001": {
                "published": "2000-01-01T00:00:00.000Z",
                "description": "parent",
            },
            "CVE-2000-0002": {
                "published": "2000-01-02T00:00:00.000Z",
                "description": "child",
            },
        }
        edge_provenance = {
            ("CVE-2000-0002", "CVE-2000-0001"): [
                {"found_in": "t1_description", "context": "from description"},
                {"found_in": "t4_advisory_redhat", "context": "from Red Hat advisory"},
            ],
        }

        children, parents = build_graph(edge_provenance, cve_data)
        visited = set()
        tree = build_tree("CVE-2000-0001", cve_data, children, parents, edge_provenance, visited)

        child = tree["variants"][0]
        assert child["cve_id"] == "CVE-2000-0002"
        assert len(child["evidence"]) == 2
        assert child["evidence"][0]["found_in"] == "t1_description"
        assert child["evidence"][1]["found_in"] == "t4_advisory_redhat"


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

    def test_extract_detected_edges_includes_corroborating(self, tmp_path):
        """Corroborating edges should count as detected for validation."""
        edge_path = tmp_path / "edges_t2_allfields.json"
        edge_path.write_text(json.dumps({
            "edges": [],
            "corroborating_edges": [
                {
                    "source": "CVE-2021-45046",
                    "target": "CVE-2021-44228",
                    "found_in": "t2_ref_name",
                    "context": "corroborating",
                }
            ],
        }))

        chains_data = {
            "metadata": {"tiers_used": ["t2"]},
            "chains": [],
        }

        edges, _ = validate.extract_detected_edges(chains_data, tmp_path)
        assert ("CVE-2021-44228", "CVE-2021-45046") in edges


class TestT3RetryBound:

    def test_fetch_stops_after_max_retries(self, tmp_path, monkeypatch):
        """403 retries must be bounded — no infinite recursion."""
        import parse_commits_t3 as t3

        monkeypatch.setattr(t3, "CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr(t3, "GITHUB_TOKEN", "fake")

        call_count = 0

        def fake_urlopen(req, timeout=None):
            nonlocal call_count
            call_count += 1
            err = t3.HTTPError(req.full_url, 403, "rate limited", {}, None)
            raise err

        monkeypatch.setattr(t3, "urlopen", fake_urlopen)
        monkeypatch.setattr(t3.time, "sleep", lambda _: None)

        result = t3.fetch_commit_message("owner/repo", "abc1234567")

        assert result is None
        assert call_count == 1 + t3.MAX_RETRIES

    def test_fetch_uses_default_for_bad_retry_after(self, tmp_path, monkeypatch):
        """Malformed Retry-After headers should not crash the whole run."""
        import parse_commits_t3 as t3

        monkeypatch.setattr(t3, "CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr(t3, "GITHUB_TOKEN", "fake")

        call_count = 0
        sleep_calls = []

        def fake_urlopen(req, timeout=None):
            nonlocal call_count
            call_count += 1
            err = t3.HTTPError(
                req.full_url,
                403,
                "rate limited",
                {"Retry-After": "not-a-number"},
                None,
            )
            raise err

        monkeypatch.setattr(t3, "urlopen", fake_urlopen)
        monkeypatch.setattr(t3.time, "sleep", sleep_calls.append)

        result = t3.fetch_commit_message("owner/repo", "abc1234567")

        assert result is None
        assert sleep_calls == [t3.DEFAULT_RETRY_AFTER]
        assert call_count == 1 + t3.MAX_RETRIES

    def test_fetch_handles_remote_disconnect(self, tmp_path, monkeypatch):
        """Transient socket disconnects should fail locally, not abort T3."""
        from http.client import RemoteDisconnected

        import parse_commits_t3 as t3

        monkeypatch.setattr(t3, "CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr(t3, "GITHUB_TOKEN", "fake")
        monkeypatch.setattr(
            t3,
            "urlopen",
            lambda req, timeout=None: (_ for _ in ()).throw(
                RemoteDisconnected("Remote end closed connection without response")
            ),
        )

        result = t3.fetch_commit_message("owner/repo", "abc1234567")

        assert result is None
        assert not t3.cache_path("owner/repo", "abc1234567").exists()

    @pytest.mark.parametrize("status_code", [404, 409, 410])
    def test_fetch_caches_permanent_http_errors(self, tmp_path, monkeypatch, status_code):
        """Stable bad commit refs should be cached so reruns skip them."""
        import parse_commits_t3 as t3

        monkeypatch.setattr(t3, "CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr(t3, "GITHUB_TOKEN", "fake")

        call_count = 0

        def fake_urlopen(req, timeout=None):
            nonlocal call_count
            call_count += 1
            raise t3.HTTPError(req.full_url, status_code, "bad commit", {}, None)

        monkeypatch.setattr(t3, "urlopen", fake_urlopen)

        first = t3.fetch_commit_message("owner/repo", "abc1234567")
        second = t3.fetch_commit_message("owner/repo", "abc1234567")

        assert first is None
        assert second is None
        assert call_count == 1

        with open(t3.cache_path("owner/repo", "abc1234567")) as f:
            cached = json.load(f)
        assert cached["error"] == status_code
        assert cached["message"] is None

    def test_fetch_does_not_cache_422(self, tmp_path, monkeypatch):
        """HTTP 422 can be transient abuse throttling and must be retried later."""
        import parse_commits_t3 as t3

        monkeypatch.setattr(t3, "CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr(t3, "GITHUB_TOKEN", "fake")

        call_count = 0

        def fake_urlopen(req, timeout=None):
            nonlocal call_count
            call_count += 1
            raise t3.HTTPError(req.full_url, 422, "endpoint has been spammed", {}, None)

        monkeypatch.setattr(t3, "urlopen", fake_urlopen)

        first = t3.fetch_commit_message("owner/repo", "abc1234567")
        second = t3.fetch_commit_message("owner/repo", "abc1234567")

        assert first is None
        assert second is None
        assert call_count == 2
        assert not t3.cache_path("owner/repo", "abc1234567").exists()

    def test_fetch_ignores_legacy_422_cache(self, tmp_path, monkeypatch):
        """Old poisoned 422 cache entries should not block later successful reruns."""
        import parse_commits_t3 as t3

        monkeypatch.setattr(t3, "CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr(t3, "GITHUB_TOKEN", "fake")

        requested_sha = "abc1234567"
        resolved_sha = "abc1234567890def1234567890def1234567890"
        t3.write_cache("owner/repo", requested_sha, None, error=422)

        call_count = 0

        class FakeResponse(io.StringIO):
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                self.close()
                return False

        def fake_urlopen(req, timeout=None):
            nonlocal call_count
            call_count += 1
            body = json.dumps({
                "sha": resolved_sha,
                "commit": {"message": "fixed on rerun"},
            })
            return FakeResponse(body)

        monkeypatch.setattr(t3, "urlopen", fake_urlopen)

        message = t3.fetch_commit_message("owner/repo", requested_sha)

        assert message == "fixed on rerun"
        assert call_count == 1

        with open(t3.cache_path("owner/repo", requested_sha)) as f:
            cached = json.load(f)
        assert cached["sha"] == resolved_sha
        assert cached["requested_sha"] == requested_sha
        assert "error" not in cached


class TestGitHubCommitNormalization:

    def test_load_commit_refs_canonicalizes_equivalent_shas(self, tmp_path, monkeypatch):
        import parse_commits_t3 as t3

        shorter = "7caac62ed598a196d6ddf8d9c121e12e082cac3"
        full = "7caac62ed598a196d6ddf8d9c121e12e082cac3a"
        ref_path = tmp_path / "reference_index.json"
        ref_path.write_text(json.dumps({
            "references": [
                {
                    "cve_id": "CVE-2019-14814",
                    "url": f"https://github.com/torvalds/linux/commit/{full}",
                    "structured_ids": [
                        {"type": "github_commit", "repo": "torvalds/linux", "value": full}
                    ],
                },
                {
                    "cve_id": "CVE-2019-14815",
                    "url": f"https://github.com/torvalds/linux/commit/{full}",
                    "structured_ids": [
                        {"type": "github_commit", "repo": "torvalds/linux", "value": full}
                    ],
                },
                {
                    "cve_id": "CVE-2019-14816",
                    "url": f"https://github.com/torvalds/linux/commit/{shorter}",
                    "structured_ids": [
                        {"type": "github_commit", "repo": "torvalds/linux", "value": shorter}
                    ],
                },
            ]
        }))

        monkeypatch.setattr(t3, "REFERENCE_INDEX_PATH", ref_path)

        commits = t3.load_commit_refs()

        assert {commit["canonical_sha"] for commit in commits} == {full}

    def test_export_commits_merges_equivalent_sha_variants(self, tmp_path, monkeypatch):
        import export_commits as export

        shorter = "7caac62ed598a196d6ddf8d9c121e12e082cac3"
        full = "7caac62ed598a196d6ddf8d9c121e12e082cac3a"
        cache_dir = tmp_path / "commit_cache"
        cache_dir.mkdir()
        ref_path = tmp_path / "reference_index.json"
        out_path = tmp_path / "github_commits.jsonl"

        ref_path.write_text(json.dumps({
            "references": [
                {
                    "cve_id": "CVE-2019-14814",
                    "url": f"https://github.com/torvalds/linux/commit/{full}",
                    "structured_ids": [
                        {"type": "github_commit", "repo": "torvalds/linux", "value": full}
                    ],
                },
                {
                    "cve_id": "CVE-2019-14815",
                    "url": f"https://github.com/torvalds/linux/commit/{full}",
                    "structured_ids": [
                        {"type": "github_commit", "repo": "torvalds/linux", "value": full}
                    ],
                },
                {
                    "cve_id": "CVE-2019-14816",
                    "url": f"https://github.com/torvalds/linux/commit/{shorter}",
                    "structured_ids": [
                        {"type": "github_commit", "repo": "torvalds/linux", "value": shorter}
                    ],
                },
            ]
        }))
        (cache_dir / f"torvalds_linux_{shorter[:12]}.json").write_text(json.dumps({
            "message": "This fix addresses CVE-2019-14814,CVE-2019-14815,CVE-2019-14816.",
            "sha": shorter,
            "repo": "torvalds/linux",
        }))

        monkeypatch.setattr(export, "CACHE_DIR", cache_dir)
        monkeypatch.setattr(export, "REFERENCE_INDEX_PATH", ref_path)
        monkeypatch.setattr(export, "OUTPUT_PATH", out_path)

        export.main()

        rows = [json.loads(line) for line in out_path.read_text().splitlines()]
        assert len(rows) == 3
        assert {row["cve_id"] for row in rows} == {
            "CVE-2019-14814",
            "CVE-2019-14815",
            "CVE-2019-14816",
        }
        assert {row["sha"] for row in rows} == {full}


class TestJiraRegex:

    def test_cve_id_not_matched_as_jira(self):
        """CVE IDs should not produce JIRA structured IDs."""
        from build_reference_index import extract_structured_ids

        ids = extract_structured_ids("", "CVE-2021-44228")
        jira_ids = [s for s in ids if s["type"] == "jira"]
        assert jira_ids == []

    def test_advisory_prefixes_not_matched_as_jira(self):
        """RHSA, DSA, etc. should not produce JIRA structured IDs."""
        from build_reference_index import extract_structured_ids

        for prefix in ["RHSA-2024", "DSA-5000", "USN-6543", "GLSA-202301"]:
            ids = extract_structured_ids("", prefix)
            jira_ids = [s for s in ids if s["type"] == "jira"]
            assert jira_ids == [], f"{prefix} incorrectly matched as JIRA"

    def test_real_jira_key_still_matches(self):
        """Legitimate JIRA keys should still be extracted."""
        from build_reference_index import extract_structured_ids

        ids = extract_structured_ids("", "HADOOP-12345")
        jira_ids = [s for s in ids if s["type"] == "jira"]
        assert len(jira_ids) == 1
        assert jira_ids[0]["value"] == "HADOOP-12345"


# ---------------------------------------------------------------------------
# T4: Shared bug tracker IDs (find_shared_ids_t4.py)
# ---------------------------------------------------------------------------

class TestFindSharedIdsT4:

    def test_group_by_shared_bugzilla(self):
        from find_shared_ids_t4 import group_by_shared_id

        refs = [
            ("CVE-2021-0001", {"type": "bugzilla", "domain": "bz.example.com", "value": "99"}),
            ("CVE-2021-0002", {"type": "bugzilla", "domain": "bz.example.com", "value": "99"}),
            ("CVE-2021-0003", {"type": "bugzilla", "domain": "bz.example.com", "value": "100"}),
        ]

        groups = group_by_shared_id(refs, {"bugzilla"})
        assert len(groups) == 1
        key = list(groups.keys())[0]
        assert groups[key] == {"CVE-2021-0001", "CVE-2021-0002"}

    def test_group_by_shared_github_issue(self):
        from find_shared_ids_t4 import group_by_shared_id

        refs = [
            ("CVE-A", {"type": "github_issue", "repo": "org/repo", "value": "42"}),
            ("CVE-B", {"type": "github_issue", "repo": "org/repo", "value": "42"}),
        ]

        groups = group_by_shared_id(refs, {"github_issue"})
        assert len(groups) == 1
        assert list(groups.values())[0] == {"CVE-A", "CVE-B"}

    def test_jira_excluded_by_default_id_types(self):
        from find_shared_ids_t4 import DEFAULT_ID_TYPES, group_by_shared_id

        refs = [
            ("CVE-A", {"type": "jira", "value": "PROJ-123"}),
            ("CVE-B", {"type": "jira", "value": "PROJ-123"}),
        ]

        groups = group_by_shared_id(refs, DEFAULT_ID_TYPES)
        assert len(groups) == 0

    def test_jira_included_when_enabled(self):
        from find_shared_ids_t4 import group_by_shared_id

        refs = [
            ("CVE-A", {"type": "jira", "value": "PROJ-123"}),
            ("CVE-B", {"type": "jira", "value": "PROJ-123"}),
        ]

        groups = group_by_shared_id(refs, {"jira"})
        assert len(groups) == 1

    def test_max_cluster_filters_large_groups(self):
        from find_shared_ids_t4 import group_by_shared_id

        refs = [
            (f"CVE-{i}", {"type": "bugzilla", "domain": "bz.example.com", "value": "1"})
            for i in range(25)
        ]

        groups = group_by_shared_id(refs, {"bugzilla"})
        assert len(groups) == 0

    def test_format_context_human_readable(self):
        from find_shared_ids_t4 import format_context

        assert format_context(("bugzilla", "bz.example.com", "99")) == \
            "shared Bugzilla #99 on bz.example.com"
        assert format_context(("github_issue", "org/repo", "42")) == \
            "shared GitHub issue org/repo#42"


# ---------------------------------------------------------------------------
# T5: LLM classification (classify_variants_t5.py)
# ---------------------------------------------------------------------------

class TestClassifyVariantsT5:

    def test_load_t4_candidates_dedups_new_edges_only(self, tmp_path, monkeypatch):
        import classify_variants_t5 as t5

        path = tmp_path / "edges_t4_shared_ids.json"
        path.write_text(json.dumps({
            "edges": [
                {"source": "CVE-B", "target": "CVE-A",
                 "found_in": "t4_shared_bugzilla", "context": "shared Bugzilla #7"},
                {"source": "CVE-A", "target": "CVE-B",
                 "found_in": "t4_shared_bugzilla", "context": "shared Bugzilla #7"},
            ],
            "corroborating_edges": [
                {"source": "CVE-C", "target": "CVE-D",
                 "found_in": "t4_shared_bugzilla", "context": "old"},
            ],
        }))
        monkeypatch.setattr(t5, "T4_EDGES_PATH", path)

        candidates = t5.load_t4_candidates()

        assert candidates == [{
            "cve_a": "CVE-A",
            "cve_b": "CVE-B",
            "found_in": "t4_shared_bugzilla",
            "context": "shared Bugzilla #7",
        }]

    def test_build_candidate_prompt_includes_descriptions_and_context(self):
        from classify_variants_t5 import build_candidate_prompt

        candidate = {
            "cve_a": "CVE-2021-44228",
            "cve_b": "CVE-2021-45046",
            "found_in": "t4_shared_bugzilla",
            "context": "shared Bugzilla #123 on bz.redhat.com",
        }
        cve_data = {
            "CVE-2021-44228": {"published": "2021-12-10", "description": "Log4Shell original"},
            "CVE-2021-45046": {
                "published": "2021-12-14",
                "description": "Log4Shell incomplete fix",
            },
        }

        messages = build_candidate_prompt(candidate, cve_data, [], [], [], [])
        assert len(messages) == 2
        assert messages[0]["role"] == "system"
        assert "Log4Shell original" in messages[1]["content"]
        assert "Log4Shell incomplete fix" in messages[1]["content"]
        assert "shared Bugzilla #123" in messages[1]["content"]

    def test_parse_candidate_result_valid(self):
        from classify_variants_t5 import parse_candidate_result

        result = parse_candidate_result({
            "relationship_type": "incomplete_fix",
            "confidence": 0.9,
            "direction": "b_is_variant_of_a",
            "reasoning": "CVE-B fixes what CVE-A missed.",
            "evidence_used": ["description_a", "description_b"],
            "additional_related_cves": [],
        })

        assert result["relationship_type"] == "incomplete_fix"
        assert result["confidence"] == 0.9
        assert result["direction"] == "b_is_variant_of_a"

    def test_parse_candidate_result_clamps_confidence(self):
        from classify_variants_t5 import parse_candidate_result

        result = parse_candidate_result({
            "relationship_type": "bypass",
            "confidence": 1.5,
            "direction": "a_is_variant_of_b",
            "reasoning": "test",
            "evidence_used": [],
            "additional_related_cves": [],
        })

        assert result["confidence"] == 1.0

    def test_parse_candidate_result_invalid_defaults(self):
        from classify_variants_t5 import parse_candidate_result

        result = parse_candidate_result({
            "relationship_type": "made_up_label",
            "confidence": 0.5,
            "direction": "invalid",
            "reasoning": "test",
            "evidence_used": [],
            "additional_related_cves": ["not-a-cve", "CVE-2024-1234"],
        })

        assert result["relationship_type"] == "insufficient_evidence"
        assert result["direction"] == "unknown"
        assert result["additional_related_cves"] == ["CVE-2024-1234"]

    def test_candidate_edge_direction_a_is_variant(self):
        from classify_variants_t5 import candidate_to_edge

        edge = candidate_to_edge({
            "relationship_type": "incomplete_fix",
            "confidence": 0.9,
            "direction": "a_is_variant_of_b",
            "reasoning": "A is the variant",
            "evidence_used": [],
            "additional_related_cves": [],
        }, "CVE-A", "CVE-B")

        assert edge["source"] == "CVE-A"
        assert edge["target"] == "CVE-B"
        assert edge["found_in"] == "t5_llm"

    def test_candidate_edge_direction_b_is_variant(self):
        from classify_variants_t5 import candidate_to_edge

        edge = candidate_to_edge({
            "relationship_type": "bypass",
            "confidence": 0.85,
            "direction": "b_is_variant_of_a",
            "reasoning": "B bypasses A",
            "evidence_used": [],
            "additional_related_cves": [],
        }, "CVE-A", "CVE-B")

        assert edge["source"] == "CVE-B"
        assert edge["target"] == "CVE-A"

    def test_candidate_edge_not_emitted_for_non_positive_or_unknown(self):
        from classify_variants_t5 import candidate_to_edge

        assert candidate_to_edge({
            "relationship_type": "unrelated",
            "confidence": 0.95,
            "direction": "a_is_variant_of_b",
            "reasoning": "no",
            "evidence_used": [],
            "additional_related_cves": [],
        }, "CVE-A", "CVE-B") is None

        assert candidate_to_edge({
            "relationship_type": "same_vuln_class",
            "confidence": 0.8,
            "direction": "unknown",
            "reasoning": "unclear",
            "evidence_used": [],
            "additional_related_cves": [],
        }, "CVE-A", "CVE-B") is None

    def test_per_cve_to_edges(self):
        from classify_variants_t5 import per_cve_to_edges

        variants = [
            {
                "related_cve": "CVE-2021-44228",
                "relationship_type": "incomplete_fix",
                "direction": "this_is_variant_of",
                "confidence": 0.9,
                "reasoning": "Incomplete fix for Log4Shell",
            },
            {
                "related_cve": "CVE-2021-99999",
                "relationship_type": "unrelated",
                "direction": "this_is_variant_of",
                "confidence": 0.8,
                "reasoning": "Not related",
            },
        ]
        edges = per_cve_to_edges("CVE-2021-45046", variants)
        assert len(edges) == 1
        assert edges[0]["source"] == "CVE-2021-45046"
        assert edges[0]["target"] == "CVE-2021-44228"

    def test_parse_per_cve_result(self):
        from classify_variants_t5 import parse_per_cve_result

        result = parse_per_cve_result({
            "variants": [
                {
                    "related_cve": "CVE-2021-44228",
                    "relationship_type": "incomplete_fix",
                    "direction": "this_is_variant_of",
                    "confidence": 0.9,
                    "reasoning": "Fix was incomplete",
                },
                {
                    "related_cve": "not-a-cve",
                    "relationship_type": "bypass",
                    "direction": "this_is_variant_of",
                    "confidence": 0.8,
                    "reasoning": "Bad CVE ID",
                },
            ]
        })
        assert len(result) == 1
        assert result[0]["related_cve"] == "CVE-2021-44228"

    def test_load_openrouter_model_from_env(self, monkeypatch):
        from classify_variants_t5 import _load_openrouter_model

        monkeypatch.setenv("OPEN_ROUTER_MODEL", "openai/gpt-4.1-mini")
        assert _load_openrouter_model() == "openai/gpt-4.1-mini"


# ---------------------------------------------------------------------------
# Coverage counting
# ---------------------------------------------------------------------------

class TestEvidenceCoverage:

    def test_build_coverage_summary_buckets_counts(self):
        from count_evidence_coverage import build_coverage_summary

        published = {"CVE-A", "CVE-B", "CVE-C", "CVE-D"}
        edge_involvement = {
            "CVE-A": {"t1"},
            "CVE-B": {"t2"},
            "CVE-C": {"t3"},
        }
        structured_involvement = {
            "CVE-C": {"bugzilla"},
        }

        summary = build_coverage_summary(published, edge_involvement, structured_involvement)
        assert summary["direct_evidence_total"] == 2
        assert summary["candidate_only_total"] == 1
        assert summary["candidate_only_default_total"] == 1
        assert summary["jira_only_candidate_total"] == 0
        assert summary["discovery_only_total"] == 1

    def test_build_coverage_summary_separates_jira_only_lane(self):
        from count_evidence_coverage import build_coverage_summary

        published = {"CVE-A", "CVE-B", "CVE-C"}
        edge_involvement = {}
        structured_involvement = {
            "CVE-A": {"jira"},
            "CVE-B": {"github_issue"},
        }

        summary = build_coverage_summary(published, edge_involvement, structured_involvement)
        assert summary["candidate_only_total"] == 2
        assert summary["candidate_only_default_total"] == 1
        assert summary["jira_only_candidate_total"] == 1
        assert summary["discovery_only_default_total"] == 2
