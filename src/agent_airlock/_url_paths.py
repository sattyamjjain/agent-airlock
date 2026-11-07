"""Shared URL-path normalization: resolve ``.`` / ``..`` dot segments.

The npm publish-window guard and the endpoint path-scope allowlist need to resolve
a URL path the way a server would before comparing it, so a ``..`` (or its
percent-encoded or path-parameter spellings) cannot step outside a prefix the
caller believes it checked, and ``oauth.issuer_from_discovery_url`` refuses a path
it would change. The logic lives here so the callers cannot drift apart.
"""

from __future__ import annotations

#: Path segments a URL parser reads as ``.`` (percent-encoded dot included).
_SINGLE_DOT_SEGMENTS = frozenset({".", "%2e"})

#: Path segments a URL parser reads as ``..`` (percent-encoded dots included).
_DOUBLE_DOT_SEGMENTS = frozenset({"..", ".%2e", "%2e.", "%2e%2e"})


def normalize_url_path(path: str, *, strip_path_params: bool = False) -> str:
    """Resolve a URL path's dot segments and drop its empty segments.

    ``.`` and ``..`` (and their percent-encoded spellings ``%2e`` / ``%2e%2e``)
    are resolved as a URL parser resolves them before the origin server sees the
    path, so ``/a/b/../c`` becomes ``/a/c``. Empty segments are dropped, which
    can only refuse more.

    Args:
        path: The raw URL path (``parsed.path``).
        strip_path_params: When True, each segment loses everything from its
            first ``;`` before the dot check, so a servlet-style path parameter
            cannot hide a ``..``: ``..;``, ``..;jsessionid=x`` and ``%2e%2e;x``
            all count as ``..`` (a Tomcat/Jetty container reads the ``;`` suffix
            as a parameter, not part of the segment name). Off by default, so
            the npm guard's behaviour is unchanged.

    Returns:
        The normalized path, always absolute (a leading ``/``).
    """
    segments: list[str] = []
    for raw_segment in path.split("/"):
        segment = raw_segment
        if strip_path_params:
            # The segment name is everything before the first path parameter (';').
            segment = segment.split(";", 1)[0]
        folded = segment.lower()
        if not segment or folded in _SINGLE_DOT_SEGMENTS:
            continue
        if folded in _DOUBLE_DOT_SEGMENTS:
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    return "/" + "/".join(segments)


__all__ = ["normalize_url_path"]
