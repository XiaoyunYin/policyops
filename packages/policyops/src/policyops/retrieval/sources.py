"""The ingestion source manifest and verified, contained reading of the files it lists (T12).

The manifest (`policyops.ingest-manifest/v1`) is committed metadata only: per corpus a finite, sorted list of
documents with their stable key, repository path, git blob, SHA-256 and size, and the corpus's pinned render
algorithm and rendered-list digest. It never contains document text. The caller binds the exact manifest bytes with
their SHA-256; nothing is discovered by listing a directory, and nothing is fetched.

Reading (all before any database write or provider call; any refusal refuses the whole corpus):

- every path is a safe relative POSIX path (no `..`, no absolute or drive path, no backslash), joined to an
  acquisition root that is itself free of links; each component is checked for a symlink or junction, and the
  joined path must equal its strict resolution and lie strictly inside the root;
- the file is read bounded by its declared size, and its size, SHA-256 and git blob SHA-1 must all match;
- the raw bytes must be strict UTF-8 without a leading BOM; the rendered body must be non-empty, at most the
  database's 4 MiB, contain no NUL and encode as strict UTF-8 (a JSON `\\udXXX` escape can produce a lone surrogate);
- per corpus: at most `MAX_DOCUMENTS` documents and `MAX_CORPUS_RAW_BYTES` raw bytes.

Renderers are pinned by name: `identity` is the decoded file; `tau2-banking/v1` is `## {title}\\n\\n{content}` over a
JSON object with exactly the string keys `id`, `title`, `content` whose `id` is the document key (T03's
`render_document`). The sorted rendered-body digest list must equal the manifest's `rendered_list_sha256`, which is
revision-specific manifest metadata, not a universal constant.

The check-then-open sequence guards ordinary aliasing, not a concurrent attacker replacing files during the read.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, model_validator


MANIFEST_SCHEMA = "policyops.ingest-manifest/v1"
MAX_MANIFEST_BYTES = 1_048_576
MAX_DOCUMENTS = 2000
MAX_FILE_BYTES = 4_194_304
MAX_BODY_BYTES = 4_194_304  # document_versions_body_size
MAX_CORPUS_RAW_BYTES = 16 * 1_048_576
RENDERS = ("identity", "tau2-banking/v1")

Hex40 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
Hex64 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Slug = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")]
DocumentKey = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_()+.-]{0,199}$")]
Text200 = Annotated[str, StringConstraints(min_length=1, max_length=200)]
Text2000 = Annotated[str, StringConstraints(min_length=1, max_length=2000)]
_PATH = re.compile(r"^[A-Za-z0-9_()+.,-]+(?:/[A-Za-z0-9_()+.,-]+)*$")


class SourceRefused(ValueError):
    """A manifest or source file failed verification; `detail` names the document key or field, never text."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail = code, detail


class _Strict(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class SourceRevision(_Strict):
    repository: Text200
    commit: Hex40
    tree: Hex40
    source_manifest_sha256: Hex64


class ManifestDocument(_Strict):
    document_key: DocumentKey
    path: Annotated[str, StringConstraints(min_length=1, max_length=1000)]
    git_blob: Hex40
    sha256: Hex64
    size: Annotated[int, Field(ge=1, le=MAX_FILE_BYTES)]


class ManifestCorpus(_Strict):
    corpus_key: Slug
    domain: Slug
    publisher: Text200
    license: Text200
    license_scope: Text2000
    render: Literal["identity", "tau2-banking/v1"]
    rendered_list_sha256: Hex64
    documents: Annotated[tuple[ManifestDocument, ...], Field(min_length=1, max_length=MAX_DOCUMENTS)]

    @model_validator(mode="after")
    def _sorted_unique(self) -> ManifestCorpus:
        keys = [d.document_key for d in self.documents]
        if keys != sorted(keys) or len(set(keys)) != len(keys):
            raise ValueError("documents must be sorted by document_key and unique")
        paths = [d.path for d in self.documents]
        if len(set(paths)) != len(paths):
            raise ValueError("document paths must be unique")
        if sum(d.size for d in self.documents) > MAX_CORPUS_RAW_BYTES:
            raise ValueError("the corpus is larger than the raw byte bound")
        return self


class Manifest(_Strict):
    schema_: Literal["policyops.ingest-manifest/v1"] = Field(alias="schema")
    source: SourceRevision
    corpora: Annotated[tuple[ManifestCorpus, ...], Field(min_length=1, max_length=16)]

    @model_validator(mode="after")
    def _unique_corpora(self) -> Manifest:
        keys = [c.corpus_key for c in self.corpora]
        if keys != sorted(keys) or len(set(keys)) != len(keys):
            raise ValueError("corpora must be sorted by corpus_key and unique")
        uris = [source_uri(c.domain, d.document_key) for c in self.corpora for d in c.documents]
        if len(set(uris)) != len(uris):
            raise ValueError("a source identity belongs to more than one corpus")
        return self

    def corpus(self, corpus_key: str) -> ManifestCorpus:
        for corpus in self.corpora:
            if corpus.corpus_key == corpus_key:
                return corpus
        raise SourceRefused("corpus_not_in_manifest", corpus_key)


@dataclass(frozen=True)
class SourceDocument:
    document_key: str
    source_uri: str
    path: str
    git_blob: str
    raw_sha256: str
    raw_bytes: int
    body: str
    version_sha256: str  # SHA-256 of the rendered body's UTF-8 bytes


@dataclass(frozen=True)
class SourceCorpus:
    manifest_sha256: str  # the exact manifest file bytes
    corpus_manifest_sha256: str  # this corpus's entry (canonical JSON), the generation's source digest
    revision: SourceRevision
    corpus: ManifestCorpus
    documents: tuple[SourceDocument, ...]


def source_uri(domain: str, document_key: str) -> str:
    """The stable source identity: no commit and no path, so a new upstream revision keeps the same document."""
    return f"tau2:{domain}/{document_key}"


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\x00" % len(data) + data, usedforsecurity=False).hexdigest()


def rendered_list_sha256(digests_by_key: Mapping[str, str]) -> str:
    """T03's convention: SHA-256 of the rendered-body digests in sorted document-key order, joined by LF."""
    return sha256_hex("\n".join(digests_by_key[key] for key in sorted(digests_by_key)).encode("utf-8"))


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise SourceRefused("json_duplicate_key")
    return dict(pairs)


def _strict_json(data: str, code: str) -> Any:
    def constant(name: str) -> Any:
        raise SourceRefused(code, f"non-finite constant {name}")

    try:
        return json.loads(data, object_pairs_hook=_no_duplicates, parse_constant=constant)
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, SourceRefused):
            raise SourceRefused(code, exc.code) from None
        raise SourceRefused(code) from None


def load_manifest(raw: bytes, expected_sha256: str) -> Manifest:
    if not isinstance(raw, bytes) or len(raw) > MAX_MANIFEST_BYTES:
        raise SourceRefused("manifest_too_large")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256 or ""):
        raise SourceRefused("manifest_sha256_malformed")
    if sha256_hex(raw) != expected_sha256:
        raise SourceRefused("manifest_sha256_mismatch")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise SourceRefused("manifest_not_utf8") from None
    _strict_json(text, "manifest_malformed")  # duplicate keys and non-finite constants, before validation
    try:
        return Manifest.model_validate_json(text)  # strict JSON mode: arrays are valid for tuple fields
    except ValidationError as exc:
        fields = sorted({".".join(str(p) for p in error["loc"]) for error in exc.errors()})[:5]
        raise SourceRefused("manifest_invalid", ", ".join(fields)) from None


def _safe_relative(path: str) -> PurePosixPath:
    """The raw components are checked before any normalization: `PurePosixPath` would collapse `.` aliases."""
    raw = path.split("/")
    if (not _PATH.fullmatch(path) or any(part in ("", ".", "..") for part in raw) or "\\" in path
            or ":" in path):
        raise SourceRefused("path_unsafe", path)
    pure = PurePosixPath(path)
    if pure.is_absolute() or list(pure.parts) != raw:
        raise SourceRefused("path_unsafe", path)
    return pure


def _is_link(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def checked_root(root: Path) -> Path:
    absolute = Path(os.path.abspath(root))  # noqa: PTH100 - lexical on purpose: resolve() would follow links
    try:
        resolved = root.resolve(strict=True)
    except OSError:
        raise SourceRefused("acquisition_root_missing") from None
    if absolute != resolved or not resolved.is_dir():
        raise SourceRefused("acquisition_root_not_canonical")
    current = Path(resolved.anchor)
    for part in resolved.parts[1:]:
        current = current / part
        if _is_link(current):
            raise SourceRefused("acquisition_root_link")
    return resolved


def contained_file(root: Path, relative: str) -> Path:
    """`root` (already checked) joined with a safe relative path: no link on any component, lexically equal to its
    strict resolution, strictly inside the root, a regular file."""
    pure = _safe_relative(relative)
    current = root
    for part in pure.parts:
        current = current / part
        if _is_link(current):
            raise SourceRefused("path_link", relative)
    try:
        resolved = current.resolve(strict=True)
    except OSError:
        raise SourceRefused("source_missing", relative) from None
    if resolved != current or root not in resolved.parents or not resolved.is_file():
        raise SourceRefused("path_not_contained", relative)
    return resolved


def _read_exact(path: Path, size: int, key: str) -> bytes:
    with path.open("rb") as handle:
        data = handle.read(size + 1)
    if len(data) != size:
        raise SourceRefused("source_size_mismatch", key)
    return data


def render(kind: str, document_key: str, raw: bytes) -> str:
    if raw.startswith(b"\xef\xbb\xbf"):
        raise SourceRefused("source_bom", document_key)
    try:
        decoded = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise SourceRefused("source_not_utf8", document_key) from None
    if kind == "identity":
        body = decoded
    elif kind == "tau2-banking/v1":
        try:
            data = _strict_json(decoded, "source_json_malformed")
        except SourceRefused:
            raise SourceRefused("source_json_malformed", document_key) from None
        if (not isinstance(data, dict) or set(data) != {"id", "title", "content"}
                or not all(isinstance(data[k], str) for k in ("id", "title", "content"))):
            raise SourceRefused("source_json_shape", document_key)
        if data["id"] != document_key:
            raise SourceRefused("source_json_id_mismatch", document_key)
        body = f"## {data['title']}\n\n{data['content']}"
    else:
        raise SourceRefused("render_unknown", kind)
    check_body(body, document_key)
    return body


def check_body(body: str, document_key: str) -> None:
    if not body:
        raise SourceRefused("body_empty", document_key)
    if body.startswith("\ufeff"):
        raise SourceRefused("source_bom", document_key)
    if "\x00" in body:
        raise SourceRefused("body_nul", document_key)
    try:
        size = len(body.encode("utf-8", errors="strict"))
    except UnicodeEncodeError:
        raise SourceRefused("body_lone_surrogate", document_key) from None
    if size > MAX_BODY_BYTES:
        raise SourceRefused("body_too_large", document_key)


def read_corpus(manifest_raw: bytes, manifest_sha256: str, corpus_key: str, acquisition_root: Path
                ) -> SourceCorpus:
    """Verify the manifest and every listed file of one corpus; the whole corpus or a `SourceRefused`."""
    manifest = load_manifest(manifest_raw, manifest_sha256)
    corpus = manifest.corpus(corpus_key)
    root = checked_root(acquisition_root)
    documents: list[SourceDocument] = []
    for entry in corpus.documents:
        path = contained_file(root, entry.path)
        raw = _read_exact(path, entry.size, entry.document_key)
        if sha256_hex(raw) != entry.sha256:
            raise SourceRefused("source_sha256_mismatch", entry.document_key)
        if git_blob_sha1(raw) != entry.git_blob:
            raise SourceRefused("source_git_blob_mismatch", entry.document_key)
        body = render(corpus.render, entry.document_key, raw)
        documents.append(SourceDocument(entry.document_key, source_uri(corpus.domain, entry.document_key), entry.path,
                                        entry.git_blob, entry.sha256, entry.size, body,
                                        sha256_hex(body.encode("utf-8"))))
    rendered = rendered_list_sha256({d.document_key: d.version_sha256 for d in documents})
    if rendered != corpus.rendered_list_sha256:
        raise SourceRefused("rendered_list_mismatch", corpus_key)
    entry_digest = sha256_hex(canonical_json(corpus.model_dump(mode="json")))
    return SourceCorpus(sha256_hex(manifest_raw), entry_digest, manifest.source, corpus, tuple(documents))


def corpus_documents(corpus: SourceCorpus) -> Sequence[SourceDocument]:
    return corpus.documents
