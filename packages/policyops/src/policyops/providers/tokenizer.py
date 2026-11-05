"""Local, offline cl100k_base token counts for embedding inputs (T12). Never a provider count request.

`text-embedding-3-small` uses the cl100k_base encoding. Its vocabulary is **pre-provisioned**, never downloaded
here:
- The file is read from an explicit path; by default `$POLICYOPS_TEMP_DIR/tokenizers/cl100k_base.tiktoken`, which
  `scripts/fetch_tokenizer_vocab.py` fills in CI. That root must be absolute and outside the checkout this code
  runs from.
- The read is bounded, and the bytes must hash to `VOCABULARY_SHA256`, the value the pinned
  `tiktoken_ext/openai_public.py` (tiktoken 0.14.0) expects. A missing, oversized or different file is refused.
- tiktoken's own factories (`get_encoding`, `encoding_for_model`, `load_tiktoken_bpe`) are never called, because
  they may fetch over the network. The ranks are parsed here and passed to `tiktoken.Encoding` with the pinned
  pattern and special tokens.
- The installed tiktoken must be exactly `TIKTOKEN_VERSION`. The pattern and special tokens are copied from its
  `tiktoken_ext/openai_public.py`, identified by the SHA-256 of that file's text with line endings normalized to LF
  (`OPENAI_PUBLIC_SOURCE_SHA256`): the wheels install it with platform-specific line endings, so the raw file hash
  differs between platforms while the text is identical.

**Bounded CPU.** Encoding is synchronous. Before it runs:
- each input is checked against its code-point and byte bounds;
- the pinned cl100k pattern splits the input into its actual pieces (whitespace pieces included), and every piece
  must be at most `MAX_PIECE_BYTES` UTF-8 bytes.

That bounds the byte-pair merge work per piece. An asyncio timeout cannot interrupt this work. Callers run it
before any reservation and check their deadline between inputs.

Counts are exact for this vocabulary and pattern. Whether they equal what the provider bills is a separate claim,
unverified until a live comparison.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
from types import MappingProxyType

import regex
import tiktoken


ENCODING_NAME = "cl100k_base"
VOCABULARY_SHA256 = "223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7"
VOCABULARY_FILE = "cl100k_base.tiktoken"
MAX_VOCABULARY_BYTES = 2 << 20
VOCABULARY_RANKS = 100_256
# Copied from tiktoken 0.14.0 `tiktoken_ext/openai_public.py` (`cl100k_base`), whose LF-normalized text hashes to
# OPENAI_PUBLIC_SOURCE_SHA256. A test compares these constants with the installed module.
PATTERN = (r"""'(?i:[sdmt]|ll|ve|re)|[^\r\n\p{L}\p{N}]?+\p{L}++|\p{N}{1,3}+| ?[^\s\p{L}\p{N}]++[\r\n]*+|\s++$|"""
           r"""\s*[\r\n]|\s+(?!\S)|\s""")
SPECIAL_TOKENS: Mapping[str, int] = MappingProxyType({
    "<|endoftext|>": 100257, "<|fim_prefix|>": 100258, "<|fim_middle|>": 100259, "<|fim_suffix|>": 100260,
    "<|endofprompt|>": 100276})
OPENAI_PUBLIC_SOURCE_SHA256 = "954392738e60d0fb6dca1dad80872efc47c8e2733babecbbf0a23970ed66c2cb"
TIKTOKEN_VERSION = "0.14.0"

MAX_INPUT_CHARS = 32_768
MAX_INPUT_BYTES = 65_536
MAX_PIECE_BYTES = 1024
COUNT_SOURCE = "local.tiktoken-cl100k"

_PIECES = regex.compile(PATTERN)


class TokenizerUnavailable(RuntimeError):
    """The pinned vocabulary is missing, oversized or not the expected bytes. Nothing is downloaded instead."""


class InputRefused(ValueError):
    """An input outside the local bounds; `code` is a fixed reason."""

    def __init__(self, code: str, index: int) -> None:
        super().__init__(f"{code} (input {index})")
        self.code = code
        self.index = index


def default_vocabulary_path(environ: Mapping[str, str] | None = None) -> Path:
    """`$POLICYOPS_TEMP_DIR/tokenizers/cl100k_base.tiktoken`: contained, and never inside the checkout."""
    env = os.environ if environ is None else environ
    raw = env.get("POLICYOPS_TEMP_DIR", "").strip()
    if not raw or not Path(raw).is_absolute():
        raise TokenizerUnavailable("POLICYOPS_TEMP_DIR must name the absolute directory holding the vocabulary")
    root = Path(raw).resolve()
    checkout = _checkout()
    if checkout is not None and (root == checkout or checkout in root.parents):
        raise TokenizerUnavailable("POLICYOPS_TEMP_DIR must be outside the checkout")
    return root / "tokenizers" / VOCABULARY_FILE


def _checkout() -> Path | None:
    """The source checkout this module runs from (an editable install), if any: the directory holding `uv.lock`
    above `packages/policyops/src/policyops/providers`."""
    candidate = Path(__file__).resolve().parents[5]
    return candidate if (candidate / "uv.lock").is_file() else None


def _read_bounded(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_VOCABULARY_BYTES + 1)
    except OSError as error:
        raise TokenizerUnavailable(f"the {ENCODING_NAME} vocabulary is not readable") from error
    if len(data) > MAX_VOCABULARY_BYTES:
        raise TokenizerUnavailable(f"the {ENCODING_NAME} vocabulary is larger than expected")
    return data


def parse_ranks(data: bytes) -> dict[bytes, int]:
    """The `<base64 token> <rank>` lines, strictly: unique tokens and ranks 0..n-1 in order."""
    ranks: dict[bytes, int] = {}
    for number, line in enumerate(data.splitlines()):
        parts = line.split(b" ")
        if len(parts) != 2 or not parts[1].isdigit():
            raise TokenizerUnavailable(f"vocabulary line {number + 1} is malformed")
        try:
            token = base64.b64decode(parts[0], validate=True)
        except binascii.Error as error:
            raise TokenizerUnavailable(f"vocabulary line {number + 1} is not base64") from error
        rank = int(parts[1])
        if rank != number or token in ranks:
            raise TokenizerUnavailable(f"vocabulary line {number + 1} has an unexpected rank or a duplicate token")
        ranks[token] = rank
    return ranks


@dataclass(frozen=True)
class Tokenizer:
    encoding: tiktoken.Encoding
    identity_sha256: str  # the vocabulary, pattern, special tokens and library version together

    def check(self, text: str, index: int = 0) -> None:
        """The linear pre-checks: bounds, strict UTF-8 (no lone surrogates), no NUL, and every actual regex piece
        at most MAX_PIECE_BYTES bytes."""
        if not isinstance(text, str) or not text:
            raise InputRefused("input_empty", index)
        if len(text) > MAX_INPUT_CHARS:
            raise InputRefused("input_too_long", index)
        try:
            size = len(text.encode("utf-8"))
        except UnicodeEncodeError:
            raise InputRefused("input_not_utf8", index) from None
        if size > MAX_INPUT_BYTES:
            raise InputRefused("input_too_large", index)
        if "\x00" in text:
            raise InputRefused("input_nul", index)
        for piece in _PIECES.finditer(text):
            if len(piece.group().encode("utf-8")) > MAX_PIECE_BYTES:
                raise InputRefused("input_piece_too_long", index)

    def count(self, text: str, index: int = 0) -> int:
        self.check(text, index)
        # Ordinary encoding: special-token text is counted as ordinary text, never as a control token.
        return len(self.encoding.encode_ordinary(text))

    def counts(self, texts: Sequence[str]) -> tuple[int, ...]:
        return tuple(self.count(text, index) for index, text in enumerate(texts))


def identity_sha256(vocabulary_sha256: str) -> str:
    body = {"v": "policyops.tokenizer/v1", "encoding": ENCODING_NAME, "vocabulary_sha256": vocabulary_sha256,
            "pattern": PATTERN, "special_tokens": dict(SPECIAL_TOKENS), "tiktoken": TIKTOKEN_VERSION,
            "openai_public_source_sha256": OPENAI_PUBLIC_SOURCE_SHA256, "max_piece_bytes": MAX_PIECE_BYTES}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def load(path: Path | None = None) -> Tokenizer:
    """The cl100k_base tokenizer from the pinned local file. Fails closed; never fetches."""
    try:
        installed = metadata.version("tiktoken")
    except metadata.PackageNotFoundError:
        installed = None
    if installed != TIKTOKEN_VERSION:
        raise TokenizerUnavailable(f"tiktoken {TIKTOKEN_VERSION} is required, not {installed}")
    data = _read_bounded(path or default_vocabulary_path())
    digest = hashlib.sha256(data).hexdigest()
    if digest != VOCABULARY_SHA256:
        raise TokenizerUnavailable(f"the {ENCODING_NAME} vocabulary does not have the pinned digest")
    ranks = parse_ranks(data)
    if len(ranks) != VOCABULARY_RANKS:
        raise TokenizerUnavailable(f"the {ENCODING_NAME} vocabulary has {len(ranks)} ranks")
    encoding = tiktoken.Encoding(ENCODING_NAME, pat_str=PATTERN, mergeable_ranks=ranks,
                                 special_tokens=dict(SPECIAL_TOKENS))
    return Tokenizer(encoding, identity_sha256(digest))
