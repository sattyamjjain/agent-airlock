"""Remove the parts of an HTML page a person cannot see (V0.10.29).

A page can carry instructions for a model in elements no reader sees: styled out of view,
or in a comment. A tool that fetches pages and returns their HTML hands those instructions
to the model as if they were content (langchain-ai/langchain#40431). With
``AirlockConfig(strip_hidden_html=True)`` (or ``sanitize_output(strip_hidden_html=True)``)
such parts are removed from a string result before it is masked.

Removed, with everything inside them:

* an element whose inline ``style`` hides it: ``display:none``, ``visibility:hidden``,
  ``opacity:0``, ``font-size:0``, or a ``text-indent`` far off screen (a negative indent
  of 100 or more units);
* an element with the ``hidden`` attribute;
* comments.

Kept: an element with the ``sr-only``, ``visually-hidden`` or ``visuallyhidden`` class,
text a screen reader reads aloud. Only inline styles are read: a stylesheet rule that hides
an element is not resolved. Standard library only (``html.parser``).
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

__all__ = ["strip_hidden_html"]

#: Elements with no end tag: hiding one removes the tag alone.
_VOID = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "source",
        "track",
        "wbr",
    }
)

#: Inline declarations that take an element out of view.
_HIDING = re.compile(
    r"(?:^|;)\s*(?:"
    r"display\s*:\s*none"
    r"|visibility\s*:\s*hidden"
    r"|opacity\s*:\s*0*(?:\.0*)?\s*(?:!important\s*)?(?:;|$)"
    r"|font-size\s*:\s*0*(?:\.0*)?\s*(?:px|pt|em|rem|%|vw|vh)?\s*(?:!important\s*)?(?:;|$)"
    r"|text-indent\s*:\s*-\s*\d{3,}"
    r")",
    re.IGNORECASE,
)

#: Classes whose text is for screen readers: kept, though styled out of view.
_READ_ALOUD = frozenset({"sr-only", "visually-hidden", "visuallyhidden"})


def _hidden(attrs: list[tuple[str, str | None]]) -> bool:
    """Whether an element with these attributes is out of a reader's view."""
    named = {name.lower(): value or "" for name, value in attrs}
    if _READ_ALOUD & set(named.get("class", "").lower().split()):
        return False
    return "hidden" in named or bool(_HIDING.search(named.get("style", "")))


class _Stripper(HTMLParser):
    """Rebuilds the document without its hidden elements and comments."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.out: list[str] = []
        self._hidden_tag: str | None = None
        self._depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self._hidden_tag is not None:
            self._depth += tag == self._hidden_tag
            return
        if _hidden(attrs):
            if tag not in _VOID:
                self._hidden_tag, self._depth = tag, 1
            return
        self.out.append(self.get_starttag_text() or "")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """``<br/>``: kept unless it, or an element around it, is hidden."""
        if self._hidden_tag is None and not _hidden(attrs) and tag:
            self.out.append(self.get_starttag_text() or "")

    def handle_endtag(self, tag: str) -> None:
        if self._hidden_tag is not None:
            if tag == self._hidden_tag:
                self._depth -= 1
                if self._depth == 0:
                    self._hidden_tag = None
            return
        self.out.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        if self._hidden_tag is None:
            self.out.append(data)

    def handle_entityref(self, name: str) -> None:
        self.handle_data(f"&{name};")

    def handle_charref(self, name: str) -> None:
        self.handle_data(f"&#{name};")

    def handle_decl(self, decl: str) -> None:
        self.handle_data(f"<!{decl}>")

    def handle_comment(self, data: str) -> None:
        """A comment is out of view by definition: dropped."""


def strip_hidden_html(text: str) -> str:
    """``text`` without the elements a person cannot see, and without comments.

    An element left open runs to the end of the document, so the rest of the text is
    dropped with it rather than shown.

    Args:
        text: An HTML document or fragment; text with no markup comes back unchanged.

    Returns:
        The document with hidden elements and comments removed.
    """
    stripper = _Stripper()
    stripper.feed(text)
    stripper.close()
    return "".join(stripper.out)
