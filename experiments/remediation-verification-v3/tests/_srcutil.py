"""Source text with docstrings, string literals, and comments removed."""
from __future__ import annotations

import io
import tokenize


def code_only(src: str) -> str:
    out = []
    for token in tokenize.generate_tokens(io.StringIO(src).readline):
        if token.type in (tokenize.STRING, tokenize.COMMENT):
            continue
        out.append(token.string)
    return " ".join(out)
