"""One complete archive passage per chunk; never interpret Markdown or truncate text."""

from __future__ import annotations

from collections.abc import Callable
import time

from policyops.providers.tokenizer import InputRefused
from policyops.retrieval.parse import (
    MAX_CHUNK_CODE_POINTS,
    MAX_HEADING_CODE_POINTS,
    Chunk,
    ParseRefused,
    TokenCounter,
    embed_input,
)
from policyops.retrieval.sources import SourceDocument


PARSER_VERSION = "policyops.md2d-title-runs/v1"
CHUNK_CONFIG = "chunk.structural-complete-8192/v1"
MAX_TOKENS = 8192


def chunk_passage(source: SourceDocument, counter: TokenCounter, *, deadline: float,
                  clock: Callable[[], float] = time.monotonic) -> tuple[Chunk, ...]:
    origin = source.origin
    if origin is None:
        raise ParseRefused("structural_origin_missing")
    if len(source.body) > MAX_CHUNK_CODE_POINTS:
        raise ParseRefused("structural_chunk_too_large")
    if len(origin.heading) > MAX_HEADING_CODE_POINTS:
        raise ParseRefused("structural_heading_too_large")
    if clock() >= deadline:
        raise ParseRefused("parse_deadline")
    try:
        tokens = counter.count(embed_input(origin.heading, source.body))
    except InputRefused:
        raise ParseRefused("structural_input_uncountable") from None
    if tokens > MAX_TOKENS or tokens <= 0:
        raise ParseRefused("structural_token_bound")
    if clock() >= deadline:
        raise ParseRefused("parse_deadline")
    return (Chunk(0, len(source.body), source.body, origin.heading, 0, 0, len(source.body), tokens),)
