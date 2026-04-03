"""Helpers for normalizing GitHub commit references across pipeline stages."""

from collections import defaultdict

MIN_GITHUB_SHA_LEN = 7


def normalize_commit_sha(sha):
    """Normalize a commit SHA or prefix for matching."""
    return (sha or "").strip().lower()


def _resolve_canonical_sha(repo_shas, sha):
    """Choose a unique longest known SHA that extends the given prefix."""
    candidates = [candidate for candidate in repo_shas if candidate.startswith(sha)]
    if not candidates:
        return sha

    max_len = max(len(candidate) for candidate in candidates)
    longest = sorted(candidate for candidate in candidates if len(candidate) == max_len)
    if len(longest) == 1:
        return longest[0]
    return sha


def build_commit_alias_index(commit_refs):
    """Map each observed (repo, sha) variant to a canonical commit key."""
    repo_to_shas = defaultdict(set)
    for repo, sha in commit_refs:
        normalized_sha = normalize_commit_sha(sha)
        if repo and normalized_sha:
            repo_to_shas[repo].add(normalized_sha)

    alias_to_canonical = {}
    for repo, shas in repo_to_shas.items():
        for sha in shas:
            alias_to_canonical[(repo, sha)] = (repo, _resolve_canonical_sha(shas, sha))
    return alias_to_canonical


def canonical_commit_key(repo, sha, alias_to_canonical):
    """Resolve a repo/SHA pair to the canonical commit key when possible."""
    normalized_sha = normalize_commit_sha(sha)
    key = (repo, normalized_sha)
    if key in alias_to_canonical:
        return alias_to_canonical[key]

    prefix_matches = {
        alias_to_canonical[(repo, normalized_sha[:i])]
        for i in range(MIN_GITHUB_SHA_LEN, len(normalized_sha))
        if (repo, normalized_sha[:i]) in alias_to_canonical
    }
    if len(prefix_matches) == 1:
        return next(iter(prefix_matches))
    return key
