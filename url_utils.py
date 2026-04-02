"""URL normalization utilities shared across T4 scraping and shared-URL analysis."""

import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

# Tracking params to strip from URLs
TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "ref", "source", "srsltid", "fbclid", "gclid", "msclkid",
}


def normalize_url(url):
    """Normalize a URL for consistent caching and deduplication.

    - Lowercases scheme and host
    - Strips www. prefix
    - Strips fragments (#...)
    - Strips tracking query params (utm_*, ref, etc.)
    - Collapses double slashes in path
    - Strips trailing slash from path
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return url

    # Lowercase scheme and host
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    if host.startswith("www."):
        host = host[4:]

    # Preserve port if non-default
    port = parsed.port
    netloc = host
    if port and port not in (80, 443):
        netloc = f"{host}:{port}"

    # Clean path: collapse double slashes, strip trailing slash
    path = re.sub(r"/+", "/", parsed.path)
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")

    # Strip tracking params from query
    if parsed.query:
        params = parse_qs(parsed.query, keep_blank_values=True)
        filtered = {
            k: v for k, v in params.items()
            if k.lower() not in TRACKING_PARAMS
        }
        query = urlencode(filtered, doseq=True) if filtered else ""
    else:
        query = ""

    # Drop fragment entirely
    return urlunparse((scheme, netloc, path, "", query, ""))
