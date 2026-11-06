"""The formatted-evidence token counter for retrieval (T13).

It counts with the **same** pinned cl100k encoding, regex pattern and tokenizer identity as the embedding
foundation (`providers.tokenizer.load()`), using ordinary encoding (special-token text is plain text). It does not use
`Tokenizer.count`, whose 32,768-code-point and 65,536-byte limits are embedding-*input* ceilings: a legitimate
evidence assembly can be far longer (for example four 13,000-code-point chunks, 52,250 code points, about 1,700
tokens) and must not be refused for an unrelated limit. The foundation tokenizer and its limits are unchanged.

Own bounds, all checked before encoding, linear in the text:

- the whole assembly is at most `MAX_EVIDENCE_CODE_POINTS` code points and `MAX_EVIDENCE_BYTES` UTF-8 bytes. These
  derive from the delivery limits: 16 blocks plus one candidate block, each at most 20,000 code points of text
  (database CHECK), 500 of heading, 2,000 of source URI and a short header;
- strict UTF-8 (no lone surrogate) and no NUL;
- every actual regex piece at most `MAX_PIECE_BYTES` (the foundation's per-piece CPU bound).

A refusal is `EvidenceCountRefused` with a fixed code. The deadline is checked between the bounded operations; an
asyncio timeout cannot interrupt the synchronous encoding, so these bounds are what limits the work.
"""

from __future__ import annotations

from collections.abc import Callable
import time

import regex

from policyops.providers.tokenizer import MAX_PIECE_BYTES, PATTERN, Tokenizer
from policyops.retrieval.rank import CountRefused


MAX_EVIDENCE_CODE_POINTS = 17 * (20_000 + 500 + 2_000 + 100)  # 384,200
MAX_EVIDENCE_BYTES = 4 * MAX_EVIDENCE_CODE_POINTS
_PIECES = regex.compile(PATTERN)


class EvidenceCountRefused(CountRefused):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class EvidenceDeadline(RuntimeError):
    """The step deadline passed between bounded counting operations."""


class EvidenceCounter:
    """`count(text) -> int` over the pinned encoding with the evidence bounds above."""

    def __init__(self, tokenizer: Tokenizer, *, deadline: float, clock: Callable[[], float] = time.monotonic) -> None:
        self.encoding = tokenizer.encoding
        self.identity_sha256 = tokenizer.identity_sha256
        self.deadline, self.clock = deadline, clock

    def _check_deadline(self) -> None:
        if self.clock() >= self.deadline:
            raise EvidenceDeadline("the step deadline passed while counting evidence")

    def count(self, text: str) -> int:
        self._check_deadline()
        if not isinstance(text, str) or not text:
            raise EvidenceCountRefused("evidence_empty")
        if len(text) > MAX_EVIDENCE_CODE_POINTS:
            raise EvidenceCountRefused("evidence_too_long")
        try:
            size = len(text.encode("utf-8"))
        except UnicodeEncodeError:
            raise EvidenceCountRefused("evidence_not_utf8") from None
        if size > MAX_EVIDENCE_BYTES:
            raise EvidenceCountRefused("evidence_too_large")
        if "\x00" in text:
            raise EvidenceCountRefused("evidence_nul")
        for piece in _PIECES.finditer(text):
            if len(piece.group().encode("utf-8")) > MAX_PIECE_BYTES:
                raise EvidenceCountRefused("evidence_piece_too_long")
        self._check_deadline()
        tokens = len(self.encoding.encode_ordinary(text))
        self._check_deadline()
        return tokens
