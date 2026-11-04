"""Deterministic text extraction and tokenizer-specific counts.

Banking documents render exactly as upstream `format_full_knowledge_base` renders
each one (`## <title>\\n\\n<content>`), joined with `\\n\\n---\\n\\n`. Upstream
iterates an unsorted directory glob, so its order is filesystem-dependent; this
module fixes the order to sorted file stem and says so.

A count is only ever labelled with the tokenizer that produced it. No local
tokenizer is a provider-reported count for gpt-6-luna or claude-haiku-5-5:
installed tiktoken 0.14.0 maps neither model, and Claude token counts come from
the Anthropic `POST /v1/messages/count_tokens` endpoint (credentials required).
This command never calls either endpoint and never substitutes a local count for them.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
import os
from pathlib import Path
import secrets
import statistics
from typing import Any, Protocol

from policyops_evals import upstream
from policyops_evals.banking import load_documents
from policyops_evals.canonical import id_list_digest, sha256_bytes
from policyops_evals.gitobjects import check_component
from policyops_evals.sources import SourceTree


REPORT_SCHEMA = "policyops.corpus-tokens/v1"
DOCUMENT_SEPARATOR = "\n\n---\n\n"
ENCODINGS = ("cl100k_base", "o200k_base")
# Models whose counts the plan needs, and how each count is obtained.
MODEL_COUNTING = {
    "text-embedding-3-small": "local tokenizer: tiktoken model mapping (exact tokenizer for embedding input)",
    "gpt-6-luna": "provider endpoint POST /v1/responses/input_tokens (openai SDK responses.input_tokens.count); "
                  "requires an OpenAI API key; not run by this command and not substituted by o200k_base",
    "claude-haiku-5-5": "provider endpoint POST /v1/messages/count_tokens (request-level estimate; requires "
                        "Anthropic credentials); not run by this offline command",
}


class TokenCounter(Protocol):
    name: str

    def count(self, text: str) -> int: ...


def render_document(document: Mapping[str, str]) -> str:
    return f"## {document['title']}\n\n{document['content']}"


def render_corpus(documents: Mapping[str, Mapping[str, str]]) -> str:
    return DOCUMENT_SEPARATOR.join(render_document(documents[key]) for key in sorted(documents))


def _summary(values: Sequence[int]) -> dict[str, Any]:
    return {"total": sum(values), "min": min(values), "median": statistics.median(values), "max": max(values),
            "mean": round(statistics.mean(values), 2)}


class OutputPathError(ValueError):
    """An output path is a link, aliases another location or leaves its output root."""


def _is_link(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def write_contained(root: Path, relative: str, data: bytes) -> Path:
    """Write data to root/relative without following links and without writing through hardlinks.

    root and every existing directory below it must be real directories (no
    symlinks or Windows junctions) that resolve inside root; an existing target
    must be a regular, non-link file. Bytes go to a new exclusive temporary file
    that then replaces the target entry, so another hardlink to an old output
    keeps its content. This guards ordinary aliasing, not a concurrent race.
    """
    if _is_link(root):
        raise OutputPathError(f"{root} is a link")
    root.mkdir(parents=True, exist_ok=True)
    base = root.resolve()
    directory = root
    *parents, name = relative.split("/")
    for part in parents:
        check_component(part)
        directory = directory / part
        if _is_link(directory):
            raise OutputPathError(f"{directory} is a link")
        directory.mkdir(exist_ok=True)
        if directory.resolve().parent != directory.parent.resolve() or base not in directory.resolve().parents:
            raise OutputPathError(f"{directory} resolves outside {root}")
    check_component(name)
    target = directory / name
    if _is_link(target) or (target.exists() and not target.is_file()):
        raise OutputPathError(f"{target} is not a regular file")
    if target.resolve().parent != directory.resolve():
        raise OutputPathError(f"{target} resolves outside {directory}")
    temporary = directory / f".{name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    try:
        with temporary.open("xb") as handle:
            handle.write(data)
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)
    return target


def write_extracted(tree: SourceTree, out: Path) -> dict[str, str]:
    """Write extracted texts and their digest list below out; return the SHA-256 values."""
    documents = load_documents(tree)
    digests = {}
    for key, document in sorted(documents.items()):
        data = render_document(document).encode("utf-8")
        write_contained(out, f"banking/{key}.md", data)
        digests[f"banking/{key}.md"] = sha256_bytes(data)
    corpus = render_corpus(documents).encode("utf-8")
    policy = tree.read(upstream.RETAIL_POLICY)
    write_contained(out, "banking-corpus.md", corpus)
    write_contained(out, "retail-policy.md", policy)
    digests["banking-corpus.md"] = sha256_bytes(corpus)
    digests["retail-policy.md"] = sha256_bytes(policy)
    write_contained(out, "extracted-sha256.json",
                    (json.dumps(digests, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return digests


def build_token_report(tree: SourceTree, counters: Sequence[TokenCounter],
                       tokenizer_info: Mapping[str, Any]) -> dict[str, Any]:
    documents = load_documents(tree)
    rendered = {key: render_document(documents[key]) for key in sorted(documents)}
    corpus = render_corpus(documents)
    policy = tree.read(upstream.RETAIL_POLICY).decode("utf-8")
    raw_bytes = sum(len(tree.read(path)) for path in tree.listing(upstream.BANKING_DOCUMENTS_DIR))
    counts: dict[str, Any] = {}
    for counter in counters:
        per_document = [counter.count(text) for text in rendered.values()]
        counts[counter.name] = {
            "retail_policy": counter.count(policy),
            "banking_documents": _summary(per_document),
            "banking_corpus_joined": counter.count(corpus),
        }
    return {
        "schema": REPORT_SCHEMA,
        "source_commit": upstream.COMMIT,
        "extraction": {
            "banking_document_format": "## <title>\\n\\n<content> (upstream format_full_knowledge_base)",
            "banking_corpus_format": "documents in sorted file-stem order joined by \\n\\n---\\n\\n; upstream "
                                     "uses unsorted directory order",
            "retail_policy": upstream.RETAIL_POLICY + " bytes, decoded as UTF-8, unmodified",
            "banking_documents": len(rendered),
            "rendered_document_sha256_list_digest": id_list_digest(
                sha256_bytes(text.encode("utf-8")) for text in rendered.values()),
            "banking_corpus_sha256": sha256_bytes(corpus.encode("utf-8")),
            "retail_policy_sha256": sha256_bytes(policy.encode("utf-8")),
        },
        "sizes": {
            "banking_document_files_bytes": raw_bytes,
            "banking_corpus_utf8_bytes": len(corpus.encode("utf-8")),
            "banking_corpus_characters": len(corpus),
            "banking_documents_with_non_ascii": sum(not text.isascii() for text in rendered.values()),
            "retail_policy_bytes": len(policy.encode("utf-8")),
            "retail_policy_characters": len(policy),
        },
        "tokenizer": dict(tokenizer_info),
        "counts_by_encoding": counts,
        "model_counting": MODEL_COUNTING,
        "interpretation": (
            "cl100k_base is the tokenizer installed tiktoken maps to text-embedding-3-small, so those counts are "
            "exact embedding-input counts for this extracted text. o200k_base counts are tokenizer-specific "
            "measurements only; they are not gpt-6-luna or claude-haiku-5-5 counts, and prompt framing, tool "
            "schemas and message overhead are excluded."
        ),
    }


class TiktokenCounter:
    """Count with an installed tiktoken encoding; ordinary encoding treats special-token text as text."""

    def __init__(self, encoding_name: str) -> None:
        import tiktoken

        self.name = encoding_name
        self._encoding = tiktoken.get_encoding(encoding_name)

    def count(self, text: str) -> int:
        return len(self._encoding.encode_ordinary(text))


def tiktoken_counters(cache_dir: Path) -> tuple[list[TokenCounter], dict[str, Any]]:
    """Load the pinned encodings, caching vocabulary files under cache_dir (outside the repository).

    tiktoken downloads each vocabulary file once and verifies it against the
    SHA-256 hard-coded in the installed tiktoken_ext.openai_public.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    os.environ["TIKTOKEN_CACHE_DIR"] = str(cache_dir)
    from importlib import metadata

    import tiktoken
    import tiktoken.model

    counters: list[TokenCounter] = [TiktokenCounter(name) for name in ENCODINGS]
    files = {}
    for name in ENCODINGS:
        url = f"https://openaipublic.blob.core.windows.net/encodings/{name}.tiktoken"
        cached = cache_dir / hashlib.sha1(url.encode(), usedforsecurity=False).hexdigest()
        files[name] = {"url": url, "sha256": sha256_bytes(cached.read_bytes()) if cached.is_file() else None}
    mapping: dict[str, str | None] = {}
    for model in MODEL_COUNTING:
        try:
            mapping[model] = tiktoken.model.encoding_name_for_model(model)
        except KeyError:
            mapping[model] = None
    return counters, {
        "library": "tiktoken", "version": metadata.version("tiktoken"), "vocabulary_files": files,
        "installed_model_mapping": mapping,
    }
