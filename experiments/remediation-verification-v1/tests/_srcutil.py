"""Shared helper: source text with docstrings, string literals, and comments removed.

Prose in a docstring may legitimately discuss `urllib` or the scorer; executable
code may not.  Both the leakage guard and the safety guard scan code only, so a
comment cannot trip them and a string cannot hide a real call.
"""
from __future__ import annotations

import io
import tokenize


def code_only(src: str) -> str:
    out = []
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type in (tokenize.STRING, tokenize.COMMENT):
            continue
        out.append(tok.string)
    return " ".join(out)
