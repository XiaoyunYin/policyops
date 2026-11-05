"""Synthetic ingestion corpora for tests: files written under a test-owned acquisition root plus the matching
`policyops.ingest-manifest/v1` bytes (sizes, SHA-256, git blobs and rendered-list digest computed from the bytes).

Fictional text only; never upstream data.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Any

import httpx2
from pydantic import SecretStr

from policyops.providers import tokenizer as tk
from policyops.providers.calls import Providers
from policyops.retrieval.sources import git_blob_sha1, render, rendered_list_sha256, sha256_hex


REVISION = {"repository": "https://example.invalid/synthetic.git", "commit": "a" * 40, "tree": "b" * 40,
            "source_manifest_sha256": "c" * 64}
SCOPE = "Synthetic fixture text written for tests; no upstream content."


@dataclass
class FixtureCorpus:
    corpus_key: str
    domain: str
    render: str
    documents: Mapping[str, bytes]  # document key -> raw bytes
    directory: str = "docs"
    extra: dict[str, Any] = field(default_factory=dict)

    def path(self, key: str) -> str:
        suffix = ".json" if self.render == "tau2-banking/v1" else ".md"
        return f"{self.directory}/{key}{suffix}"


def banking(key: str, title: str, content: str) -> bytes:
    return json.dumps({"id": key, "title": title, "content": content}, ensure_ascii=False).encode("utf-8")


def write(root: Path, corpora: Sequence[FixtureCorpus], *, revision: Mapping[str, str] = REVISION
          ) -> tuple[bytes, str]:
    """Write every document under `root` and return (manifest bytes, their SHA-256)."""
    entries = []
    for corpus in sorted(corpora, key=lambda c: c.corpus_key):
        documents = []
        rendered = {}
        for key in sorted(corpus.documents):
            raw = corpus.documents[key]
            target = root / corpus.path(key)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            documents.append({"document_key": key, "path": corpus.path(key), "git_blob": git_blob_sha1(raw),
                              "sha256": sha256_hex(raw), "size": len(raw)})
            try:
                rendered[key] = sha256_hex(render(corpus.render, key, raw).encode("utf-8"))
            except ValueError:  # a deliberately invalid file: the digest is irrelevant to that refusal
                rendered[key] = "0" * 64
        entries.append({"corpus_key": corpus.corpus_key, "domain": corpus.domain, "publisher": "Synthetic",
                        "license": "CC0 (synthetic)", "license_scope": SCOPE, "render": corpus.render,
                        "rendered_list_sha256": rendered_list_sha256(rendered), "documents": documents}
                       | corpus.extra)
    raw_manifest = json.dumps({"schema": "policyops.ingest-manifest/v1", "source": dict(revision),
                               "corpora": entries}, indent=2, sort_keys=True).encode("utf-8")
    return raw_manifest, hashlib.sha256(raw_manifest).hexdigest()


class ScriptedEmbeddings(httpx2.AsyncBaseTransport):
    """The scripted OpenAI embeddings endpoint: valid deterministic vectors and exact local-count usage, or a read
    error after the request was sent (an unknown outcome). Counts physical requests and their inputs."""

    def __init__(self, *, fail_after: int | None = None) -> None:
        self.requests: list[list[str]] = []
        self.fail_after = fail_after
        self._tokenizer = tk.load()

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        inputs = json.loads(await request.aread())["input"]
        self.requests.append(inputs)
        if self.fail_after is not None and len(self.requests) > self.fail_after:
            raise httpx2.ReadError("scripted read error after the request was sent", request=request)
        tokens = sum(self._tokenizer.counts(inputs))
        body = {"object": "list", "model": "text-embedding-3-small",
                "usage": {"prompt_tokens": tokens, "total_tokens": tokens},
                "data": [{"object": "embedding", "index": i, "embedding": vector(text)}
                         for i, text in enumerate(inputs)]}
        return httpx2.Response(200, headers={"content-type": "application/json"}, content=json.dumps(body).encode(),
                               request=request)

    @property
    def inputs(self) -> list[str]:
        return [text for batch in self.requests for text in batch]


def vector(text: str) -> list[float]:
    seed = int(hashlib.sha256(text.encode()).hexdigest()[:8], 16)
    return [((i * 7 + seed) % 13 - 6 + 0.5) / 100.0 for i in range(1536)]


class CredentialReads:
    """A providers factory that counts how often the credential was read (the paid path's first irreversible step)."""

    def __init__(self, provider: ScriptedEmbeddings) -> None:
        self.provider, self.reads = provider, 0

    def __call__(self) -> Providers:
        self.reads += 1
        return Providers(credentials={"openai": SecretStr("synthetic-test-credential-0000")},
                         transport=lambda name: self.provider)
