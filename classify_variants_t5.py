"""
Tier 5: LLM classification of CVE variants via OpenRouter.

Two modes:
  Per-CVE (default): For each CVE, fetch reference URLs, load commit messages,
  and ask the LLM whether this CVE is a variant of any other CVE.

  Candidate (--candidates): For T4 shared-ID pairs, load both CVEs' evidence
  and ask the LLM to classify the pair.

Usage:
  uv run python classify_variants_t5.py              # per-CVE mode, all CVEs
  uv run python classify_variants_t5.py --limit 100  # first 100 CVEs
  uv run python classify_variants_t5.py --candidates  # candidate pair mode
  uv run python classify_variants_t5.py --dry-run    # count, no API/fetch calls
"""

import argparse
import hashlib
import json
import os
import re
import resource
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

import requests  # type: ignore[import-untyped]
from bs4 import BeautifulSoup

from url_utils import normalize_url

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, **kwargs):
        print(kwargs.get("desc", "Processing"), "...")
        return iterable

OUTPUT_DIR = Path("output")
DATASETS_DIR = Path("datasets")
T4_EDGES_PATH = OUTPUT_DIR / "edges_t4_shared_ids.json"
PARSED_CVES_PATH = OUTPUT_DIR / "parsed_cves.json"
REFERENCE_INDEX_PATH = OUTPUT_DIR / "reference_index.json"
COMMIT_CACHE_DIR = Path("data/commit_cache")
URL_CACHE_DIR = Path("data/url_cache")
LLM_CACHE_DIR = Path("data/llm_cache")
T5_EDGES_DATASET = DATASETS_DIR / "edges_t5_llm.json"
T5_CLASSIFICATIONS_DATASET = DATASETS_DIR / "t5_classifications.jsonl"
PROMPT_VERSION = "t5_v2"

POSITIVE_LABELS = {
    "incomplete_fix",
    "bypass",
    "regression",
    "same_vuln_class",
    "different_attack_path",
    "variant_technique",
}
ALL_LABELS = POSITIVE_LABELS | {"unrelated", "insufficient_evidence"}

CONFIDENCE_THRESHOLD = 0.7
DEFAULT_WORKERS = 20
MAX_URLS_PER_CVE = 15
ABORT_AFTER_N_FAILURES = 3
MIN_CONTENT_LENGTH = 200
JINA_DELAY = 0.5
FETCH_TIMEOUT = 15
MAX_CONTENT_PER_URL = 60000
MAX_TOTAL_CONTENT = 200000  # ~50k tokens

# Domains to skip — noisy, list hundreds of unrelated CVEs
SKIP_DOMAINS = {
    # Quarterly mega-patches
    "oracle.com",
    # Distro mailing lists / bulletins
    "lists.fedoraproject.org",
    "lists.debian.org",
    "lists.opensuse.org",
    "usn.ubuntu.com",
    "security.gentoo.org",
    "lists.apple.com",
    "rhn.redhat.com",
    # Generic aggregators — just mirror NVD/CVE data
    "exchange.xforce.ibmcloud.com",
    "securitytracker.com",
    "osvdb.org",
    "vupen.com",
    "exploit-db.com",
    "packetstormsecurity.com",
    "oval.cisecurity.org",
    "nvd.nist.gov",
    "cve.org",
    "cve.mitre.org",
    # Third-party advisories that rarely cross-reference
    "secunia.com",
    "vuldb.com",
    "securityfocus.com",
}

# Priority order for URL selection (lower = fetched first)
# "unknown" = vendor-specific pages (apache.org, sudo.ws, etc.) — often most valuable
DOMAIN_TYPE_PRIORITY = {
    "bug_tracker": 0,
    "unknown": 1,
    "code_repo": 2,
    "mailing_list": 3,
    "per_cve_page": 4,
    "third_party_advisory": 5,
    "multi_cve_bulletin": 6,
    "generic_aggregator": 99,  # should be skipped, but just in case
}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")

# File extensions to skip (binaries, media, archives)
SKIP_EXTENSIONS = {
    ".exe", ".msi", ".dmg", ".pkg", ".deb", ".rpm",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".mp3", ".mp4", ".avi", ".mov", ".wmv",
    ".bin", ".iso", ".img", ".apk", ".ipa",
    ".patch", ".diff",
    ".sig", ".asc", ".gpg",
}

# --- LLM schemas ---

PER_CVE_SCHEMA = {
    "type": "object",
    "properties": {
        "variants": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "related_cve": {"type": "string"},
                    "relationship_type": {
                        "type": "string",
                        "enum": sorted(POSITIVE_LABELS | {"unrelated", "insufficient_evidence"}),
                    },
                    "direction": {
                        "type": "string",
                        "enum": ["this_is_variant_of", "other_is_variant_of_this"],
                    },
                    "confidence": {"type": "number"},
                    "reasoning": {"type": "string"},
                },
                "required": ["related_cve", "relationship_type", "direction",
                             "confidence", "reasoning"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["variants"],
    "additionalProperties": False,
}

CANDIDATE_SCHEMA = {
    "type": "object",
    "properties": {
        "relationship_type": {
            "type": "string",
            "enum": sorted(ALL_LABELS),
        },
        "confidence": {"type": "number"},
        "direction": {
            "type": "string",
            "enum": ["a_is_variant_of_b", "b_is_variant_of_a", "unknown"],
        },
        "reasoning": {"type": "string"},
        "evidence_used": {
            "type": "array",
            "items": {"type": "string"},
        },
        "additional_related_cves": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "required": ["relationship_type", "confidence", "direction", "reasoning",
                 "evidence_used", "additional_related_cves"],
    "additionalProperties": False,
}

PER_CVE_SYSTEM_PROMPT = """\
You are a cybersecurity vulnerability analyst specializing in CVE variant chain detection.

You will be given all available evidence for a single CVE: its description, reference URL \
contents, and any associated commit messages. Based ONLY on this evidence, determine whether \
this CVE is a variant of any other CVE, or whether any other CVEs are variants of this one.

A variant relationship means one CVE is a failed fix, bypass, regression, or closely related \
follow-on vulnerability to the other.

Important rules:
- Answer ONLY from the supplied evidence. Do not use outside knowledge.
- Only report relationships where the evidence explicitly mentions another CVE ID and \
describes a variant-like relationship (fix for, bypass of, regression of, etc.).
- Same product or same time period alone is NOT enough.
- If no variant relationships are found, return an empty variants array.
- Be conservative — if the evidence is thin or ambiguous, do not report a relationship.
"""

CANDIDATE_SYSTEM_PROMPT = """\
You are a cybersecurity vulnerability analyst specializing in CVE variant chain detection.

Given two CVEs that share a bug tracker reference, plus all available evidence for both, \
decide whether they have a variant-like relationship. A variant-like relationship means \
one CVE is a failed fix, bypass, regression, or closely related follow-on vulnerability \
to the other.

Allowed relationship labels:
- incomplete_fix, bypass, regression, same_vuln_class, different_attack_path, variant_technique
- unrelated, insufficient_evidence

Important rules:
- Same bulletin, same tracker, same package, or same time period alone is NOT enough.
- Answer only from the supplied evidence. Do not use outside knowledge.
- If direction is unclear, set direction to "unknown".
- If the evidence is thin, prefer "insufficient_evidence".
- You may list additional_related_cves only if they are explicitly mentioned in the \
  provided evidence. Do not invent or infer unseen CVE IDs.
"""


# --- Environment ---

def _load_env_var(*var_names, default=""):
    for name in var_names:
        value = os.environ.get(name, "")
        if value:
            return value
    env_file = Path(".env")
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key.strip() in var_names:
                return value.strip().strip("'\"")
    return default


def _load_openrouter_key():
    return _load_env_var("OPENROUTER_API_KEY")


def _load_openrouter_model(default="google/gemini-2.5-flash"):
    return _load_env_var("OPENROUTER_MODEL", "OPEN_ROUTER_MODEL", default=default)


# --- Data loading ---

def load_cve_metadata():
    if not PARSED_CVES_PATH.exists():
        return {}
    with open(PARSED_CVES_PATH) as f:
        return json.load(f).get("cves", {})


def load_reference_index():
    """Load reference index and group URLs by CVE ID."""
    if not REFERENCE_INDEX_PATH.exists():
        print(f"Warning: {REFERENCE_INDEX_PATH} not found. No URLs to fetch.")
        return {}
    with open(REFERENCE_INDEX_PATH) as f:
        data = json.load(f)
    by_cve = defaultdict(list)
    for ref in data.get("references", []):
        by_cve[ref["cve_id"]].append(ref)
    return dict(by_cve)


def load_commit_messages(refs_by_cve=None):
    """Load commit messages from cache, grouped by CVE ID.

    Uses refs_by_cve (from load_reference_index) to map commits to CVEs,
    avoiding a second parse of reference_index.json.
    """
    if not COMMIT_CACHE_DIR.exists():
        return {}

    if refs_by_cve is None:
        if not REFERENCE_INDEX_PATH.exists():
            return {}
        with open(REFERENCE_INDEX_PATH) as f:
            data = json.load(f)
        all_refs = data.get("references", [])
    else:
        all_refs = [ref for refs in refs_by_cve.values() for ref in refs]

    commit_to_cves = defaultdict(set)
    for ref in all_refs:
        for sid in ref.get("structured_ids", []):
            if sid["type"] == "github_commit":
                key = f"{sid['repo']}_{sid['value'][:12]}"
                commit_to_cves[key].add(ref["cve_id"])

    # Load cached messages
    cve_commits = defaultdict(list)
    for fname in os.listdir(COMMIT_CACHE_DIR):
        if not fname.endswith(".json"):
            continue
        try:
            with open(COMMIT_CACHE_DIR / fname) as f:
                cached = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        message = cached.get("message")
        if not message:
            continue
        repo = cached.get("repo", "")
        sha = cached.get("sha", "")[:12]
        key = f"{repo}_{sha}"
        for cve_id in commit_to_cves.get(key, set()):
            cve_commits[cve_id].append({
                "repo": repo,
                "sha": cached.get("sha", ""),
                "message": message,
            })

    return dict(cve_commits)


def load_t4_candidates():
    """Load T4 shared-ID edges as candidate pairs (skip corroborating)."""
    if not T4_EDGES_PATH.exists():
        print(f"Error: {T4_EDGES_PATH} not found. Run find_shared_ids_t4.py first.")
        sys.exit(1)
    with open(T4_EDGES_PATH) as f:
        data = json.load(f)
    seen = set()
    candidates = []
    for edge in data.get("edges", []):
        pair = tuple(sorted((edge["source"], edge["target"])))
        if pair in seen:
            continue
        seen.add(pair)
        candidates.append({
            "cve_a": pair[0],
            "cve_b": pair[1],
            "found_in": edge.get("found_in", "t4_shared_ids"),
            "context": edge.get("context", ""),
        })
    return candidates


def load_prior_edges():
    """Load T1-T3 edges for corroboration marking."""
    seen = set()
    for filename in [
        "edges_t1_description.json",
        "edges_t2_allfields.json",
        "edges_t3_commits.json",
    ]:
        path = OUTPUT_DIR / filename
        if not path.exists():
            continue
        with open(path) as f:
            data = json.load(f)
        for edge in data.get("edges", []) + data.get("corroborating_edges", []):
            seen.add(tuple(sorted((edge["source"], edge["target"]))))
    return seen


# --- Dataset (cumulative, git-tracked, single source of truth) ---

def load_dataset():
    """Load the cumulative T5 dataset from datasets/.

    Returns (edges, corroborating, processed_cves, processed_pairs).
    """
    if not T5_EDGES_DATASET.exists():
        return [], [], set(), set()
    with open(T5_EDGES_DATASET) as f:
        data = json.load(f)
    edges = data.get("edges", [])
    corr = data.get("corroborating_edges", [])
    processed_cves = set(data.get("processed_cves", []))
    processed_pairs = {
        tuple(sorted(p)) for p in data.get("processed_pairs", [])
    }
    return edges, corr, processed_cves, processed_pairs


def save_dataset(edges, corroborating, processed_cves, processed_pairs, model):
    """Save cumulative T5 dataset to datasets/.

    Same JSON format as other tier edge files so build_chains.py reads it.
    """
    DATASETS_DIR.mkdir(exist_ok=True)
    output = {
        "tier": "t5_llm",
        "model": model,
        "confidence_threshold": CONFIDENCE_THRESHOLD,
        "edge_count": len(edges),
        "corroborating_count": len(corroborating),
        "processed_cve_count": len(processed_cves),
        "processed_pair_count": len(processed_pairs),
        "edges_by_field": {
            "t5_llm": len(edges) + len(corroborating),
        },
        "generated_at": datetime.now().isoformat(),
        "edges": edges,
        "corroborating_edges": corroborating,
        "processed_cves": sorted(processed_cves),
        "processed_pairs": sorted([list(p) for p in processed_pairs]),
    }
    with open(T5_EDGES_DATASET, "w") as f:
        json.dump(output, f, indent=2)


def merge_into_dataset(ds_edges, ds_corr, new_edges, new_corroborating):
    """Merge new edges into cumulative dataset lists, deduplicating by (source, target)."""
    existing = {(e["source"], e["target"]) for e in ds_edges + ds_corr}
    for e in new_edges:
        if (e["source"], e["target"]) not in existing:
            ds_edges.append(e)
            existing.add((e["source"], e["target"]))
    for e in new_corroborating:
        if (e["source"], e["target"]) not in existing:
            ds_corr.append(e)
            existing.add((e["source"], e["target"]))


def load_classification_keys():
    """Load set of already-exported classification keys from JSONL dataset."""
    if not T5_CLASSIFICATIONS_DATASET.exists():
        return set()
    keys = set()
    with open(T5_CLASSIFICATIONS_DATASET) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if "cve_id" in obj:
                    keys.add(obj["cve_id"])
                elif "cve_a" in obj:
                    keys.add(tuple(sorted((obj["cve_a"], obj["cve_b"]))))
            except (json.JSONDecodeError, KeyError):
                continue
    return keys


def append_classifications(classifications, mode):
    """Append new classifications to the cumulative JSONL dataset."""
    DATASETS_DIR.mkdir(exist_ok=True)
    existing = load_classification_keys()
    with open(T5_CLASSIFICATIONS_DATASET, "a") as f:
        for cls in classifications:
            if mode == "per_cve":
                key = cls["cve_id"]
            else:
                key = tuple(sorted((cls["cve_a"], cls["cve_b"])))
            if key in existing:
                continue
            f.write(json.dumps(cls) + "\n")


# --- URL fetching ---

def _url_cache_key(url):
    normalized = normalize_url(url)
    return hashlib.sha256(normalized.encode()).hexdigest()


def _url_cache_path(key):
    return URL_CACHE_DIR / key[:2] / f"{key}.json"


def load_url_cached(url):
    key = _url_cache_key(url)
    path = _url_cache_path(key)
    if path.exists():
        try:
            with open(path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return None


def save_url_cached(url, content, source="direct"):
    key = _url_cache_key(url)
    path = _url_cache_path(key)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump({
            "url": url,
            "content": content,
            "source": source,
            "fetched_at": datetime.now().isoformat(),
        }, f)


ALLOWED_CONTENT_TYPES = {
    "text/html",
    "text/plain",
    "application/xhtml+xml",
    "application/xml",
    "text/xml",
    "application/json",
    "text/markdown",
}


def _content_type_allowed(content_type):
    """Check if content-type is text-based and worth parsing."""
    if not content_type:
        return False
    # Strip charset and params: "text/html; charset=utf-8" -> "text/html"
    mime = content_type.split(";")[0].strip().lower()
    return mime in ALLOWED_CONTENT_TYPES


def fetch_url_direct(url):
    """Fetch URL content directly with BeautifulSoup text extraction."""
    try:
        resp = requests.get(url, timeout=FETCH_TIMEOUT, headers={
            "User-Agent": "Mozilla/5.0 (CVE-variant-research)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        resp.raise_for_status()
        if not _content_type_allowed(resp.headers.get("Content-Type", "")):
            return ""
        content = resp.text
        soup = BeautifulSoup(content, "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "header"]):
            tag.decompose()
        return soup.get_text(separator="\n", strip=True)
    except Exception:
        return ""


def fetch_url_jina(url):
    """Fetch URL via Jina Reader for JS-rendered pages."""
    jina_url = f"https://r.jina.ai/{url}"
    try:
        resp = requests.get(jina_url, timeout=30, headers={
            "Accept": "text/plain",
        })
        resp.raise_for_status()
        return resp.text
    except Exception:
        return ""


def fetch_url(url):
    """Fetch URL content: try direct first, Jina fallback if needed.

    Returns (content, source) where source is 'direct', 'jina', or 'cached'.
    """
    cached = load_url_cached(url)
    if cached and cached.get("content"):
        return cached["content"], "cached"

    content = fetch_url_direct(url)
    cve_mentions = len(CVE_RE.findall(content)) if content else 0

    if len(content) < MIN_CONTENT_LENGTH or cve_mentions == 0:
        time.sleep(JINA_DELAY)
        jina_content = fetch_url_jina(url)
        if len(jina_content) > len(content):
            save_url_cached(url, jina_content, source="jina")
            return jina_content, "jina"

    if content:
        save_url_cached(url, content, source="direct")
        return content, "direct"

    save_url_cached(url, "", source="empty")
    return "", "empty"


def select_urls(refs):
    """Select and prioritize URLs to fetch for a CVE.

    Returns (selected, skipped) where:
      selected = [(url, domain_type, priority), ...] capped at MAX_URLS_PER_CVE
      skipped = [(url, domain, reason), ...] for all skipped URLs
    """
    candidates = []
    skipped = []
    seen_normalized = set()

    for ref in refs:
        url = ref.get("url", "")
        if not url:
            continue
        normalized = normalize_url(url)
        if normalized in seen_normalized:
            continue
        seen_normalized.add(normalized)

        # Skip binary/media URLs by extension
        path_lower = url.rsplit("?", 1)[0].lower()
        ext = "." + path_lower.rsplit(".", 1)[-1] if "." in path_lower.rsplit("/", 1)[-1] else ""
        if ext in SKIP_EXTENSIONS:
            skipped.append((url, ref.get("domain", ""), f"skip_extension:{ext}"))
            continue

        domain = ref.get("domain", "")
        if domain in SKIP_DOMAINS:
            skipped.append((url, domain, f"skip_domain:{domain}"))
            continue
        parts = domain.split(".")
        if len(parts) > 2:
            parent = ".".join(parts[-2:])
            if parent in SKIP_DOMAINS:
                skipped.append((url, domain, f"skip_parent_domain:{parent}"))
                continue

        domain_type = ref.get("domain_type", "unknown")
        priority = DOMAIN_TYPE_PRIORITY.get(domain_type, 6)
        candidates.append((priority, url, domain_type))

    candidates.sort(key=lambda x: x[0])
    selected = [(url, dtype, prio) for prio, url, dtype in candidates[:MAX_URLS_PER_CVE]]

    # URLs that passed filtering but exceeded the cap
    for _prio, url, dtype in candidates[MAX_URLS_PER_CVE:]:
        skipped.append((url, dtype, "over_cap"))

    return selected, skipped


def fetch_urls_for_cve(refs):
    """Fetch URLs for a CVE, respecting the cap and skip logic.

    Returns (fetched, url_trace) where:
      fetched = [(url, content, source), ...] for URLs with content
      url_trace = full trace of all URL decisions
    """
    selected, skipped = select_urls(refs)

    url_trace = {
        "total_refs": len(refs),
        "selected": [],
        "skipped": [{"url": u, "domain": d, "reason": r} for u, d, r in skipped],
    }

    fetched = []
    for url, domain_type, _priority in selected:
        content, source = fetch_url(url)
        trace_entry = {
            "url": url,
            "domain_type": domain_type,
            "fetch_source": source,
            "content_length": len(content),
            "cve_mentions": len(CVE_RE.findall(content)) if content else 0,
        }
        url_trace["selected"].append(trace_entry)
        if content:
            fetched.append((url, content, source))

    url_trace["fetched_count"] = len(fetched)
    return fetched, url_trace


# --- LLM caching ---

def _llm_cache_key(cve_id, model, mode="per_cve"):
    canonical = f"{cve_id}|{model}|{mode}|{PROMPT_VERSION}"
    return hashlib.sha256(canonical.encode()).hexdigest()


def _llm_cache_key_pair(cve_a, cve_b, model):
    canonical = f"{min(cve_a, cve_b)}|{max(cve_a, cve_b)}|{model}|candidate|{PROMPT_VERSION}"
    return hashlib.sha256(canonical.encode()).hexdigest()


def _llm_cache_path(key):
    return LLM_CACHE_DIR / key[:2] / f"{key}.json"


def load_llm_cached(key):
    path = _llm_cache_path(key)
    if path.exists():
        try:
            with open(path) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return None


def save_llm_cached(key, data):
    path = _llm_cache_path(key)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


# --- Prompting helpers ---

def _append_url_contents(parts, url_contents, budget, prefix=""):
    """Append truncated URL contents to parts list, returning chars consumed."""
    total = 0
    for url, content, _source in url_contents:
        if not CVE_RE.search(content):
            continue
        truncated = content[:MAX_CONTENT_PER_URL]
        if total + len(truncated) > budget:
            truncated = truncated[:max(0, budget - total)]
            if not truncated:
                break
        parts.append(f"{prefix}[{url}]")
        parts.append(f"{prefix}{truncated}")
        total += len(truncated)
    return total


# --- Prompting: per-CVE mode ---

def build_per_cve_prompt(cve_id, cve_data, url_contents, commit_messages):
    """Build prompt for per-CVE classification."""
    data = cve_data.get(cve_id, {})
    parts = [f"== {cve_id} =="]
    parts.append(f"Published: {data.get('published', 'unknown')}")
    parts.append(f"Description: {data.get('description', 'No description available.')}")

    if commit_messages:
        parts.append("\n== Associated commit messages ==")
        for cm in commit_messages[:5]:
            parts.append(f"[{cm['repo']} {cm['sha'][:12]}]")
            parts.append(cm["message"][:500])

    if url_contents:
        parts.append("\n== Reference URL contents ==")
        _append_url_contents(parts, url_contents, MAX_TOTAL_CONTENT)

    user_content = "\n".join(parts)
    user_content += (
        "\n\nBased ONLY on the evidence above, is this CVE a variant of any other CVE, "
        "or are other CVEs variants of this one? Return a JSON object with a 'variants' "
        "array. Each variant should have: related_cve, relationship_type, direction "
        "(this_is_variant_of or other_is_variant_of_this), confidence (0-1), reasoning."
    )

    return [
        {"role": "system", "content": PER_CVE_SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]


# --- Prompting: candidate mode ---

def build_candidate_prompt(candidate, cve_data, url_contents_a, url_contents_b,
                           commits_a, commits_b):
    """Build prompt for candidate pair classification."""
    cve_a, cve_b = candidate["cve_a"], candidate["cve_b"]
    a_data = cve_data.get(cve_a, {})
    b_data = cve_data.get(cve_b, {})

    parts = [f"== CVE A: {cve_a} =="]
    parts.append(f"Published: {a_data.get('published', 'unknown')}")
    parts.append(f"Description: {a_data.get('description', 'No description available.')}")

    if commits_a:
        parts.append("\nCommit messages for CVE A:")
        for cm in commits_a[:3]:
            parts.append(f"  [{cm['repo']} {cm['sha'][:12]}] {cm['message'][:300]}")

    half_budget = MAX_TOTAL_CONTENT // 2

    if url_contents_a:
        parts.append("\nReference URL contents for CVE A:")
        used_a = _append_url_contents(parts, url_contents_a, half_budget, prefix="  ")
    else:
        used_a = 0

    parts.append(f"\n== CVE B: {cve_b} ==")
    parts.append(f"Published: {b_data.get('published', 'unknown')}")
    parts.append(f"Description: {b_data.get('description', 'No description available.')}")

    if commits_b:
        parts.append("\nCommit messages for CVE B:")
        for cm in commits_b[:3]:
            parts.append(f"  [{cm['repo']} {cm['sha'][:12]}] {cm['message'][:300]}")

    if url_contents_b:
        parts.append("\nReference URL contents for CVE B:")
        _append_url_contents(parts, url_contents_b, MAX_TOTAL_CONTENT - used_a, prefix="  ")

    parts.append("\n== Why this pair was selected ==")
    parts.append(candidate.get("context", "Shared external reference"))

    user_content = "\n".join(parts)
    return [
        {"role": "system", "content": CANDIDATE_SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]


# --- Classification parsing ---

def parse_per_cve_result(raw_json):
    """Parse LLM response for per-CVE mode."""
    if not raw_json:
        return []
    if isinstance(raw_json, str):
        raw_json = json.loads(raw_json)
    variants = raw_json.get("variants", [])
    parsed = []
    for v in variants:
        related = str(v.get("related_cve", ""))
        if not CVE_RE.fullmatch(related):
            continue
        rel_type = v.get("relationship_type", "insufficient_evidence")
        if rel_type not in ALL_LABELS:
            rel_type = "insufficient_evidence"
        direction = v.get("direction", "")
        if direction not in {"this_is_variant_of", "other_is_variant_of_this"}:
            continue
        try:
            confidence = max(0.0, min(1.0, float(v.get("confidence", 0.0))))
        except (TypeError, ValueError):
            confidence = 0.0
        reasoning = str(v.get("reasoning", ""))[:1000]
        parsed.append({
            "related_cve": related,
            "relationship_type": rel_type,
            "direction": direction,
            "confidence": confidence,
            "reasoning": reasoning,
        })
    return parsed


def parse_candidate_result(raw_json):
    """Parse LLM response for candidate mode."""
    if not raw_json:
        return {
            "relationship_type": "insufficient_evidence",
            "confidence": 0.0,
            "direction": "unknown",
            "reasoning": "Empty model response",
            "evidence_used": [],
            "additional_related_cves": [],
        }
    if isinstance(raw_json, str):
        raw_json = json.loads(raw_json)
    result = {}
    result["relationship_type"] = raw_json.get("relationship_type", "insufficient_evidence")
    if result["relationship_type"] not in ALL_LABELS:
        result["relationship_type"] = "insufficient_evidence"
    try:
        result["confidence"] = max(0.0, min(1.0, float(raw_json.get("confidence", 0.0))))
    except (TypeError, ValueError):
        result["confidence"] = 0.0
    result["direction"] = raw_json.get("direction", "unknown")
    if result["direction"] not in {"a_is_variant_of_b", "b_is_variant_of_a", "unknown"}:
        result["direction"] = "unknown"
    result["reasoning"] = str(raw_json.get("reasoning", ""))[:1000]
    evidence_used = raw_json.get("evidence_used", [])
    result["evidence_used"] = evidence_used if isinstance(evidence_used, list) else []
    extras = raw_json.get("additional_related_cves", [])
    if not isinstance(extras, list):
        extras = []
    result["additional_related_cves"] = [
        cve_id for cve_id in dict.fromkeys(str(item) for item in extras)
        if CVE_RE.fullmatch(cve_id)
    ]
    return result


def per_cve_to_edges(cve_id, variants):
    """Convert per-CVE variants to standard edges."""
    edges = []
    for v in variants:
        if v["relationship_type"] not in POSITIVE_LABELS:
            continue
        if v["confidence"] < CONFIDENCE_THRESHOLD:
            continue
        if v["direction"] == "this_is_variant_of":
            source, target = cve_id, v["related_cve"]
        else:
            source, target = v["related_cve"], cve_id
        edges.append({
            "source": source,
            "target": target,
            "found_in": "t5_llm",
            "context": v["reasoning"][:200],
        })
    return edges


def candidate_to_edge(classification, cve_a, cve_b):
    """Convert candidate classification to a standard edge."""
    if classification["relationship_type"] not in POSITIVE_LABELS:
        return None
    if classification["direction"] == "unknown":
        return None
    if classification["direction"] == "a_is_variant_of_b":
        source, target = cve_a, cve_b
    else:
        source, target = cve_b, cve_a
    return {
        "source": source,
        "target": target,
        "found_in": "t5_llm",
        "context": classification["reasoning"][:200],
    }


# --- LLM call helper ---

def _llm_call_json_object(client, model, messages, schema):
    """Call LLM with json_object mode, schema described in prompt."""
    fallback_messages = list(messages)
    schema_hint = json.dumps(schema, indent=2)
    fallback_messages[-1] = {
        "role": fallback_messages[-1]["role"],
        "content": fallback_messages[-1]["content"]
        + f"\n\nRespond with valid JSON matching this schema:\n{schema_hint}",
    }
    return client.chat.completions.create(
        model=model,
        messages=fallback_messages,
        response_format={"type": "json_object"},
        temperature=0,
    )


def _llm_call(client, model, messages, schema):
    """Call LLM with json_schema mode, fallback to json_object if unsupported or empty."""
    try:
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "variant_classification",
                    "strict": True,
                    "schema": schema,
                },
            },
            temperature=0,
        )
        content = response.choices[0].message.content
        if not content:
            return _llm_call_json_object(client, model, messages, schema)
        return response
    except Exception as first_err:
        err_str = str(first_err).lower()
        if "json_schema" not in err_str and "response_format" not in err_str:
            raise
        return _llm_call_json_object(client, model, messages, schema)


# --- Usage tracking ---

def _extract_usage(response):
    """Extract token usage and cost from OpenRouter response."""
    usage = getattr(response, "usage", None)
    if not usage:
        return {}
    result = {
        "prompt_tokens": getattr(usage, "prompt_tokens", 0) or 0,
        "completion_tokens": getattr(usage, "completion_tokens", 0) or 0,
        "total_tokens": getattr(usage, "total_tokens", 0) or 0,
    }
    cost = getattr(usage, "cost", None)
    if cost is not None:
        result["cost"] = cost
    return result


# --- Per-CVE classification ---

def classify_per_cve(cve_id, cve_data, refs_by_cve, commits_by_cve, model, client):
    """Classify a single CVE: fetch URLs, build prompt, call LLM.

    Returns (cve_id, variants, was_cached, trace) where trace is the full
    pipeline decision log for this CVE.
    """
    cache_key = _llm_cache_key(cve_id, model)
    cached = load_llm_cached(cache_key)
    if cached:
        return (cve_id, cached.get("variants", []), True,
                cached.get("trace", {}), cached.get("usage", {}))

    refs = refs_by_cve.get(cve_id, [])
    url_contents, url_trace = fetch_urls_for_cve(refs)
    commits = commits_by_cve.get(cve_id, [])
    messages = build_per_cve_prompt(cve_id, cve_data, url_contents, commits)

    usage = {}
    error = False
    try:
        response = _llm_call(client, model, messages, PER_CVE_SCHEMA)
        raw_response = response.choices[0].message.content
        variants = parse_per_cve_result(raw_response)
        usage = _extract_usage(response)
    except Exception as exc:
        variants = []
        raw_response = f"ERROR: {type(exc).__name__}: {exc}"
        error = True
        print(f"  Error classifying {cve_id}: {type(exc).__name__}: {exc}")

    # Build full trace
    cve_meta = cve_data.get(cve_id, {})
    trace = {
        "cve_input": {
            "cve_id": cve_id,
            "published": cve_meta.get("published", ""),
            "description": cve_meta.get("description", ""),
        },
        "commits": [
            {"repo": cm["repo"], "sha": cm["sha"][:12], "message": cm["message"][:500]}
            for cm in commits[:5]
        ],
        "url_trace": url_trace,
        "model": model,
        "prompt": messages[1]["content"],
        "llm_raw_response": raw_response,
        "usage": usage,
    }

    # Only cache successful results — transient errors should be retried
    if not error:
        save_llm_cached(cache_key, {
            "cve_id": cve_id,
            "model": model,
            "variants": variants,
            "trace": trace,
            "usage": usage,
            "cached_at": datetime.now().isoformat(),
        })

    return cve_id, variants, False, trace, usage


# --- Candidate classification ---

def classify_candidate(candidate, cve_data, refs_by_cve, commits_by_cve, model, client):
    """Classify a candidate pair: fetch URLs for both, build prompt, call LLM.

    Returns (candidate, classification, was_cached, trace).
    """
    cve_a, cve_b = candidate["cve_a"], candidate["cve_b"]
    cache_key = _llm_cache_key_pair(cve_a, cve_b, model)
    cached = load_llm_cached(cache_key)
    if cached:
        return (candidate, cached.get("classification", {}), True,
                cached.get("trace", {}), cached.get("usage", {}))

    # Fetch URLs for both CVEs
    url_contents_a, url_trace_a = fetch_urls_for_cve(refs_by_cve.get(cve_a, []))
    url_contents_b, url_trace_b = fetch_urls_for_cve(refs_by_cve.get(cve_b, []))

    commits_a = commits_by_cve.get(cve_a, [])
    commits_b = commits_by_cve.get(cve_b, [])

    messages = build_candidate_prompt(
        candidate, cve_data, url_contents_a, url_contents_b, commits_a, commits_b
    )

    usage = {}
    error = False
    try:
        response = _llm_call(client, model, messages, CANDIDATE_SCHEMA)
        raw_response = response.choices[0].message.content
        classification = parse_candidate_result(raw_response)
        usage = _extract_usage(response)
    except Exception as exc:
        raw_response = f"ERROR: {type(exc).__name__}: {exc}"
        error = True
        classification = {
            "relationship_type": "insufficient_evidence",
            "confidence": 0.0,
            "direction": "unknown",
            "reasoning": f"API error: {type(exc).__name__}: {exc}",
            "evidence_used": [],
            "additional_related_cves": [],
        }

    a_meta = cve_data.get(cve_a, {})
    b_meta = cve_data.get(cve_b, {})
    trace = {
        "cve_a_input": {
            "cve_id": cve_a,
            "published": a_meta.get("published", ""),
            "description": a_meta.get("description", ""),
        },
        "cve_b_input": {
            "cve_id": cve_b,
            "published": b_meta.get("published", ""),
            "description": b_meta.get("description", ""),
        },
        "commits_a": [
            {"repo": cm["repo"], "sha": cm["sha"][:12], "message": cm["message"][:300]}
            for cm in commits_a[:3]
        ],
        "commits_b": [
            {"repo": cm["repo"], "sha": cm["sha"][:12], "message": cm["message"][:300]}
            for cm in commits_b[:3]
        ],
        "url_trace_a": url_trace_a,
        "url_trace_b": url_trace_b,
        "shared_context": candidate.get("context", ""),
        "model": model,
        "prompt": messages[1]["content"],
        "llm_raw_response": raw_response,
        "usage": usage,
    }

    if not error:
        save_llm_cached(cache_key, {
            "cve_a": cve_a,
            "cve_b": cve_b,
            "model": model,
            "classification": classification,
            "trace": trace,
            "usage": usage,
            "cached_at": datetime.now().isoformat(),
        })

    return candidate, classification, False, trace, usage


# --- Main: per-CVE mode ---

def run_per_cve(args, cve_data, refs_by_cve, commits_by_cve, model, client):
    """Run per-CVE classification."""
    ds_edges, ds_corr, ds_cves, ds_pairs = load_dataset()

    if args.cve:
        # Specific CVE list — always process (even if already done)
        all_cves = [c.strip() for c in args.cve.split(",") if c.strip()]
        missing = [c for c in all_cves if c not in cve_data]
        if missing:
            print(f"Warning: CVEs not in dataset: {', '.join(missing)}")
            all_cves = [c for c in all_cves if c in cve_data]
    else:
        # Default: reverse-chronological, skip already-processed
        all_cves = sorted(
            cve_data.keys(),
            key=lambda x: cve_data[x].get("published", "") or "",
            reverse=True,
        )
        before = len(all_cves)
        all_cves = [c for c in all_cves if c not in ds_cves]
        if before != len(all_cves):
            print(f"Skipping {before - len(all_cves):,} already-processed CVEs")
        if args.limit:
            all_cves = all_cves[:args.limit]

    print(f"Processing {len(all_cves):,} CVEs in per-CVE mode")

    if args.dry_run:
        cached = sum(
            1 for cve_id in all_cves
            if load_llm_cached(_llm_cache_key(cve_id, model))
        )
        print(f"Already cached:   {cached:,}")
        print(f"API calls needed: {len(all_cves) - cached:,}")
        return

    prior_edges = load_prior_edges()
    all_new_edges = []
    all_corroborating = []
    all_classifications = []
    cached_count = 0
    api_count = 0
    total_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "cost": 0.0}

    error_count = 0
    completed_count = 0
    workers = min(args.workers, len(all_cves)) or 1
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(classify_per_cve, cve_id, cve_data, refs_by_cve,
                        commits_by_cve, model, client): cve_id
            for cve_id in all_cves
        }
        with tqdm(total=len(all_cves), desc="Classifying CVEs") as pbar:
            for future in as_completed(futures):
                try:
                    cve_id, variants, was_cached, trace, usage = future.result()
                except Exception as exc:
                    print(f"\nUnexpected error for {futures[future]}: {exc}")
                    pbar.update(1)
                    error_count += 1
                    completed_count += 1
                    if error_count >= ABORT_AFTER_N_FAILURES and error_count == completed_count:
                        print(f"\nAborting: first {error_count} results all failed")
                        pool.shutdown(wait=False, cancel_futures=True)
                        break
                    continue

                completed_count += 1
                raw_resp = trace.get("llm_raw_response", "")
                if isinstance(raw_resp, str) and raw_resp.startswith("ERROR:"):
                    error_count += 1
                    if error_count >= ABORT_AFTER_N_FAILURES and error_count == completed_count:
                        print(f"\nAborting: first {error_count} results all failed")
                        pool.shutdown(wait=False, cancel_futures=True)
                        break

                if was_cached:
                    cached_count += 1
                else:
                    api_count += 1
                    for k in total_usage:
                        total_usage[k] += usage.get(k, 0) or 0

                all_classifications.append({
                    "cve_id": cve_id,
                    "variants": variants,
                    "trace": trace,
                })

                edges = per_cve_to_edges(cve_id, variants)
                for edge in edges:
                    pair = tuple(sorted((edge["source"], edge["target"])))
                    if pair in prior_edges:
                        all_corroborating.append(edge)
                    else:
                        all_new_edges.append(edge)

                pbar.update(1)

    _write_outputs(all_new_edges, all_corroborating, all_classifications,
                   cached_count, api_count, model, "per_cve", total_usage)

    merge_into_dataset(ds_edges, ds_corr, all_new_edges, all_corroborating)
    ds_cves.update(all_cves)
    save_dataset(ds_edges, ds_corr, ds_cves, ds_pairs, model)

    if not args.no_export_classifications:
        append_classifications(all_classifications, "per_cve")


# --- Main: candidate mode ---

def run_candidates(args, cve_data, refs_by_cve, commits_by_cve, model, client):
    """Run candidate pair classification on T4 pairs, newest first."""
    ds_edges, ds_corr, ds_cves, ds_pairs = load_dataset()
    candidates = load_t4_candidates()
    candidates.sort(
        key=lambda c: max(
            cve_data.get(c["cve_a"], {}).get("published", "") or "",
            cve_data.get(c["cve_b"], {}).get("published", "") or "",
        ),
        reverse=True,
    )

    # Skip already-processed pairs
    before = len(candidates)
    candidates = [
        c for c in candidates
        if tuple(sorted((c["cve_a"], c["cve_b"]))) not in ds_pairs
    ]
    if before != len(candidates):
        print(f"Skipping {before - len(candidates):,} already-processed pairs")
    print(f"Loaded {len(candidates):,} candidate pairs from T4")

    if args.limit:
        candidates = candidates[:args.limit]
        print(f"Limited to {len(candidates):,} pairs")

    if args.dry_run:
        cached = sum(
            1 for c in candidates
            if load_llm_cached(_llm_cache_key_pair(c["cve_a"], c["cve_b"], model))
        )
        print(f"Already cached:   {cached:,}")
        print(f"API calls needed: {len(candidates) - cached:,}")
        return

    prior_edges = load_prior_edges()
    all_new_edges = []
    all_corroborating = []
    all_classifications = []
    cached_count = 0
    api_count = 0
    total_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "cost": 0.0}

    error_count = 0
    completed_count = 0
    workers = min(args.workers, len(candidates)) or 1
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(classify_candidate, candidate, cve_data, refs_by_cve,
                        commits_by_cve, model, client): candidate
            for candidate in candidates
        }
        with tqdm(total=len(candidates), desc="Classifying pairs") as pbar:
            for future in as_completed(futures):
                try:
                    candidate, classification, was_cached, trace, usage = future.result()
                except Exception as exc:
                    print(f"\nUnexpected error for pair: {exc}")
                    pbar.update(1)
                    error_count += 1
                    completed_count += 1
                    if error_count >= ABORT_AFTER_N_FAILURES and error_count == completed_count:
                        print(f"\nAborting: first {error_count} results all failed")
                        pool.shutdown(wait=False, cancel_futures=True)
                        break
                    continue

                completed_count += 1
                raw_resp = trace.get("llm_raw_response", "")
                if isinstance(raw_resp, str) and raw_resp.startswith("ERROR:"):
                    error_count += 1
                    if error_count >= ABORT_AFTER_N_FAILURES and error_count == completed_count:
                        print(f"\nAborting: first {error_count} results all failed")
                        pool.shutdown(wait=False, cancel_futures=True)
                        break

                if was_cached:
                    cached_count += 1
                else:
                    api_count += 1
                    for k in total_usage:
                        total_usage[k] += usage.get(k, 0) or 0

                all_classifications.append({
                    "cve_a": candidate["cve_a"],
                    "cve_b": candidate["cve_b"],
                    "context": candidate.get("context", ""),
                    "classification": classification,
                    "trace": trace,
                })

                edge = candidate_to_edge(classification, candidate["cve_a"], candidate["cve_b"])
                if edge and classification["confidence"] >= CONFIDENCE_THRESHOLD:
                    pair = tuple(sorted((edge["source"], edge["target"])))
                    if pair in prior_edges:
                        all_corroborating.append(edge)
                    else:
                        all_new_edges.append(edge)

                pbar.update(1)

    _write_outputs(all_new_edges, all_corroborating, all_classifications,
                   cached_count, api_count, model, "candidate", total_usage)

    merge_into_dataset(ds_edges, ds_corr, all_new_edges, all_corroborating)
    ds_pairs.update(
        tuple(sorted((c["cve_a"], c["cve_b"]))) for c in candidates
    )
    save_dataset(ds_edges, ds_corr, ds_cves, ds_pairs, model)

    if not args.no_export_classifications:
        append_classifications(all_classifications, "candidate")


# --- Output ---

def _write_outputs(new_edges, corroborating, classifications, cached_count,
                   api_count, model, mode, total_usage):
    """Write edge file and audit artifact."""
    OUTPUT_DIR.mkdir(exist_ok=True)

    def _dedup(edges):
        seen = set()
        out = []
        for edge in edges:
            pair = (edge["source"], edge["target"])
            if pair not in seen:
                seen.add(pair)
                out.append(edge)
        return out

    deduped_new = _dedup(new_edges)
    deduped_corr = _dedup(corroborating)

    # Edge file
    edge_output = {
        "tier": "t5_llm",
        "model": model,
        "mode": mode,
        "confidence_threshold": CONFIDENCE_THRESHOLD,
        "edge_count": len(deduped_new),
        "corroborating_count": len(deduped_corr),
        "classified_total": len(classifications),
        "edges_by_field": {"t5_llm": len(deduped_new) + len(deduped_corr)},
        "usage": total_usage,
        "generated_at": datetime.now().isoformat(),
        "edges": deduped_new,
        "corroborating_edges": deduped_corr,
    }
    edge_path = OUTPUT_DIR / "edges_t5_llm.json"
    with open(edge_path, "w") as f:
        json.dump(edge_output, f, indent=2)

    # Audit artifact
    audit_output = {
        "metadata": {
            "model": model,
            "mode": mode,
            "confidence_threshold": CONFIDENCE_THRESHOLD,
            "classified_total": len(classifications),
            "cached_total": cached_count,
            "api_total": api_count,
            "new_edges": len(deduped_new),
            "corroborating_edges": len(deduped_corr),
            "usage": total_usage,
            "generated_at": datetime.now().isoformat(),
        },
        "classifications": classifications,
    }
    audit_path = OUTPUT_DIR / "t5_classifications.json"
    with open(audit_path, "w") as f:
        json.dump(audit_output, f, indent=2)

    # Summary
    print(f"\n{'='*60}")
    print(f"T5 CLASSIFICATION REPORT ({mode} mode)")
    print(f"{'='*60}")
    print(f"Classified:                 {len(classifications):>8,}")
    print(f"  From cache:               {cached_count:>8,}")
    print(f"  API calls:                {api_count:>8,}")
    print(f"New edges (beyond T1-T3):   {len(deduped_new):>8,}")
    print(f"Corroborating (also T1-T3): {len(deduped_corr):>8,}")
    if total_usage.get("total_tokens"):
        print(f"\nTokens:  {total_usage['prompt_tokens']:,} in + "
              f"{total_usage['completion_tokens']:,} out = "
              f"{total_usage['total_tokens']:,} total")
    if total_usage.get("cost"):
        print(f"Cost:    ${total_usage['cost']:.4f}")
    print(f"Model:   {model}")
    print(f"\nEdges: {edge_path}")
    print(f"Audit: {audit_path}")
    print(f"{'='*60}")


# --- Entry point ---

def main():
    # Raise open file limit for parallel URL fetching + cache I/O
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < 10240:
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(10240, hard), hard))

    default_model = _load_openrouter_model()
    parser = argparse.ArgumentParser(
        description="T5: LLM classification of CVE variants"
    )
    parser.add_argument("--limit", type=int, default=100,
                        help="Process first N CVEs/pairs (default: 100, 0 = all)")
    parser.add_argument("--cve", type=str, default="",
                        help="Comma-separated CVE IDs to classify")
    parser.add_argument("--candidates", action="store_true",
                        help="Candidate pair mode (T4 pairs) instead of per-CVE")
    parser.add_argument("--dry-run", action="store_true", help="Count items, no API/fetch calls")
    parser.add_argument("--no-export-classifications", action="store_true",
                        help="Skip exporting full classifications to datasets/ (saves space)")
    parser.add_argument("--model", default=default_model, help="OpenRouter model override")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS,
                        help=f"Parallel worker threads (default: {DEFAULT_WORKERS})")
    args = parser.parse_args()

    api_key = _load_openrouter_key()
    if not api_key and not args.dry_run:
        print("Error: OPENROUTER_API_KEY not set in environment or .env file.")
        sys.exit(1)

    print("Loading data...")
    cve_data = load_cve_metadata()
    refs_by_cve = load_reference_index()
    commits_by_cve = load_commit_messages(refs_by_cve)
    print(f"  CVEs: {len(cve_data):,}")
    print(f"  CVEs with URLs: {len(refs_by_cve):,}")
    print(f"  CVEs with commits: {len(commits_by_cve):,}")

    client = None
    if not args.dry_run:
        from openai import OpenAI
        client = OpenAI(base_url="https://openrouter.ai/api/v1", api_key=api_key)

    if args.candidates:
        run_candidates(args, cve_data, refs_by_cve, commits_by_cve, args.model, client)
    else:
        run_per_cve(args, cve_data, refs_by_cve, commits_by_cve, args.model, client)


if __name__ == "__main__":
    main()
