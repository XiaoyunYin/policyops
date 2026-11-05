"""T12 local cl100k_base counting: the pinned vocabulary and identity, fail-closed loading (never a download), and the
linear input and regex-piece bounds. Offline; the session network guard is active throughout."""

from __future__ import annotations

import base64
import hashlib
from importlib import metadata
import inspect
from pathlib import Path
import time

import pytest
import tiktoken_ext.openai_public as openai_public

from policyops.providers import tokenizer as tk


@pytest.fixture(scope="module")
def tok() -> tk.Tokenizer:
    return tk.load()


def test_the_pinned_identity_matches_the_installed_tiktoken_source() -> None:
    assert metadata.version("tiktoken") == tk.TIKTOKEN_VERSION
    source = Path(openai_public.__file__).read_bytes()
    # The wheels install this file with platform line endings; the identity is the LF-normalized text.
    assert hashlib.sha256(source.replace(b"\r\n", b"\n")).hexdigest() == tk.OPENAI_PUBLIC_SOURCE_SHA256
    definition = inspect.getsource(openai_public.cl100k_base)
    assert f'r"""{tk.PATTERN}"""' in definition
    assert f'expected_hash="{tk.VOCABULARY_SHA256}"' in definition
    constants = {value: key for key, value in vars(openai_public).items()
                 if isinstance(value, str) and value.startswith("<|")}
    for name, rank in tk.SPECIAL_TOKENS.items():
        assert f"{constants[name]}: {rank}," in definition


def test_counts_match_the_published_cookbook_token_ids(tok: tk.Tokenizer) -> None:
    # OpenAI cookbook "How to count tokens with tiktoken": cl100k_base encodes this text as these six IDs.
    assert tok.encoding.encode_ordinary("tiktoken is great!") == [83, 1609, 5963, 374, 2294, 0]
    assert tok.count("tiktoken is great!") == 6
    assert tok.count("<|endoftext|>") == len(tok.encoding.encode_ordinary("<|endoftext|>")) > 1  # never special
    assert tok.counts(["naïve café", "日本語のテキスト"]) == tuple(len(tok.encoding.encode_ordinary(t))
                                                           for t in ("naïve café", "日本語のテキスト"))


@pytest.mark.parametrize(("text", "code"), [
    ("a" * 1024, None), ("a" * 1025, "input_piece_too_long"),
    (" " * 1023 + "x", None), (" " * 2000, "input_piece_too_long"), ("\n" * 1025, "input_piece_too_long"),
    ("é" * 512, None), ("é" * 513, "input_piece_too_long"),  # 2 UTF-8 bytes each
    ("w " * 16_384, None), ("w " * 16_384 + "x", "input_too_long"),
    ("\U0001d538" * 256, None), ("\U0001d538" * 257, "input_piece_too_long"),  # 4-byte letters
    ("\x00", "input_nul"), ("", "input_empty"), ("\ud800", "input_not_utf8"),
])
def test_input_and_piece_bounds(tok: tk.Tokenizer, text: str, code: str | None) -> None:
    if code is None:
        assert tok.count(text) >= 1
    else:
        with pytest.raises(tk.InputRefused) as refused:
            tok.count(text)
        assert refused.value.code == code


def test_the_byte_bound_applies_after_the_code_point_bound(tok: tk.Tokenizer) -> None:
    text = ("\U0001d538 " * 16_384)[:32_768]  # 32768 code points, 4-byte letters: above 65536 bytes
    with pytest.raises(tk.InputRefused) as refused:
        tok.count(text)
    assert refused.value.code == "input_too_large"


def test_worst_admitted_inputs_are_measured_not_interrupted(tok: tk.Tokenizer) -> None:
    """A CI-hardware measurement of the worst admitted pieces (recorded, not a guarantee or a timeout)."""
    # A space joins the following letter run in one cl100k piece, so 1023 letters per run is the admitted worst.
    worst = {"letters": ("a" * 1023 + " ") * 32, "spaces": (" " * 1023 + "x") * 32,
             "mixed": ("aé日1!" * 200 + " ") * 31, "digits": ("1" * 1024 + " ") * 31}
    for name, text in worst.items():
        started = time.perf_counter()
        tok.count(text)
        elapsed = time.perf_counter() - started
        print(f"tokenize worst-case {name}: {len(text)} code points in {elapsed:.4f}s")
        assert elapsed < 10.0


def write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def test_a_missing_oversized_or_different_vocabulary_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(tk.TokenizerUnavailable, match="not readable"):
        tk.load(tmp_path / "absent.tiktoken")
    with pytest.raises(tk.TokenizerUnavailable, match="larger"):
        tk.load(write(tmp_path / "big", b"a" * (tk.MAX_VOCABULARY_BYTES + 1)))
    with pytest.raises(tk.TokenizerUnavailable, match="pinned digest"):
        tk.load(write(tmp_path / "other", base64.b64encode(b"x") + b" 0\n"))
    with pytest.raises(tk.TokenizerUnavailable, match="pinned digest"):
        tk.load(write(tmp_path / "empty", b""))


def test_a_different_tiktoken_version_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("policyops.providers.tokenizer.metadata.version", lambda name: "0.15.0")
    with pytest.raises(tk.TokenizerUnavailable, match=r"0\.14\.0 is required"):
        tk.load()


@pytest.mark.parametrize(("data", "message"), [
    (b"YQ== 0\nYg== 1\n", None),
    (b"YQ== 0\nYQ== 1\n", "duplicate"), (b"YQ== 1\n", "unexpected rank"), (b"YQ==0\n", "malformed"),
    (b"!!!! 0\n", "not base64"), (b"YQ== -1\n", "malformed"),
])
def test_rank_parsing_is_strict(data: bytes, message: str | None) -> None:
    if message is None:
        assert tk.parse_ranks(data) == {b"a": 0, b"b": 1}
    else:
        with pytest.raises(tk.TokenizerUnavailable, match=message):
            tk.parse_ranks(data)


def test_the_default_path_must_be_absolute_and_outside_the_checkout() -> None:
    checkout = Path(tk.__file__).resolve().parents[5]
    with pytest.raises(tk.TokenizerUnavailable):
        tk.default_vocabulary_path({})
    with pytest.raises(tk.TokenizerUnavailable):
        tk.default_vocabulary_path({"POLICYOPS_TEMP_DIR": "relative/dir"})
    with pytest.raises(tk.TokenizerUnavailable, match="outside the checkout"):
        tk.default_vocabulary_path({"POLICYOPS_TEMP_DIR": str(checkout / "tmp")})
    outside = checkout.parent / "policyops-temp-root-for-test"
    assert tk.default_vocabulary_path({"POLICYOPS_TEMP_DIR": str(outside)}) == \
        outside.resolve() / "tokenizers" / tk.VOCABULARY_FILE


def test_loading_never_uses_tiktokens_downloading_factories(monkeypatch: pytest.MonkeyPatch) -> None:
    import tiktoken
    import tiktoken.load

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("a downloading tiktoken factory was called")

    for module, name in ((tiktoken, "get_encoding"), (tiktoken, "encoding_for_model"),
                         (tiktoken.load, "load_tiktoken_bpe"), (tiktoken.load, "read_file_cached")):
        monkeypatch.setattr(module, name, forbidden)
    assert tk.load().count("still offline") >= 1
