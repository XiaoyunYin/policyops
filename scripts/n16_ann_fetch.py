"""Fetch and verify the pinned N16 corpus into a new private directory."""
from __future__ import annotations

import argparse
from collections.abc import Sequence
from hashlib import file_digest, sha256
import json
from pathlib import Path
import re
import sys
from urllib.request import urlopen

from scripts.bm25_latency_probe import output_path


REPOSITORY = "https://huggingface.co/datasets/Supabase/wikipedia-en-embeddings"
REVISION = "a46c85b41829b8c94ec939e1402c3f45133cd717"
ARCHIVE = "wiki_openai.ndjson.gz"
SHA256 = "d97ca1f7d6a58ab52dc081e02012cc2b4494331e5a2043e0aa97acbac544fd6f"
BYTES = 1_928_514_131
ROWS = 224_482
MIT_NOTICE = "the embeddings are published under MIT license"


def verify_sha(path: Path, expected: str) -> None:
    with path.open("rb") as handle:
        actual = file_digest(handle, "sha256").hexdigest()
    if actual != expected:
        raise ValueError("corpus_sha256_mismatch")


def verify_archive(path: Path) -> None:
    if path.stat().st_size != BYTES:
        raise ValueError("corpus_size_mismatch")
    verify_sha(path, SHA256)


def metadata(name: str) -> bytes:
    with urlopen(f"{REPOSITORY}/resolve/{REVISION}/{name}", timeout=60) as response:  # noqa: S310
        data = bytes(response.read(65_537))
    if not data or len(data) > 65_536:
        raise ValueError("corpus_metadata_size_mismatch")
    return data


def verify_licence(card: str, licence: str) -> None:
    if (
        not re.search(r"(?im)^license:\s*mit\s*$", card)
        or "224,482" not in card
        or MIT_NOTICE not in licence
        or "en.wikipedia.org/wiki/Wikipedia:Copyrights" not in licence
        or "Copyright (c) 2023 Stephan Sturges" not in licence
    ):
        raise ValueError("corpus_licence_unverified")


def fetch(directory: Path) -> None:
    directory = output_path(directory)
    directory.mkdir(exist_ok=False)
    card, licence = metadata("README.md"), metadata("Original_License")
    verify_licence(card.decode("utf-8"), licence.decode("utf-8"))
    (directory / "README.md").write_bytes(card)
    (directory / "Original_License").write_bytes(licence)
    partial = directory / (ARCHIVE + ".part")
    url = f"{REPOSITORY}/resolve/{REVISION}/{ARCHIVE}"
    try:
        with urlopen(url, timeout=60) as response, partial.open("xb") as handle:  # noqa: S310
            remaining = BYTES
            while block := response.read(min(1024 * 1024, remaining + 1)):
                remaining -= len(block)
                if remaining < 0:
                    raise ValueError("corpus_size_mismatch")
                handle.write(block)
        verify_archive(partial)
        partial.rename(directory / ARCHIVE)
    finally:
        partial.unlink(missing_ok=True)
    manifest = {
        "dataset": "Supabase/wikipedia-en-embeddings",
        "revision": REVISION,
        "published_checksum": f"{REPOSITORY}/commit/{REVISION}",
        "archive": ARCHIVE,
        "sha256": SHA256,
        "bytes": BYTES,
        "rows": ROWS,
        "embedding_dimension": 1536,
        "embedding_model": "text-embedding-ada-002",
        "embedding_licence": "MIT",
        "article_text_licence": "Wikipedia CC BY-SA",
        "source": url,
        "card_sha256": sha256(card).hexdigest(),
        "licence_sha256": sha256(licence).hexdigest(),
    }
    (directory / "source.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        fetch(args.out)
    except (OSError, ValueError) as error:
        reason = str(error) if type(error) is ValueError else type(error).__name__
        print(f"N16 fetch failed ({reason}).", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
