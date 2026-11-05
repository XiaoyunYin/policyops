"""Provision the pinned cl100k_base vocabulary for the application's local embedding-input counter (T12).

    python -B scripts/fetch_tokenizer_vocab.py                    download the one pinned official file
    python -B scripts/fetch_tokenizer_vocab.py --from-file PATH   verify and copy an already downloaded copy

The destination is always `$POLICYOPS_TEMP_DIR/tokenizers/cl100k_base.tiktoken`. POLICYOPS_TEMP_DIR must be an
existing absolute directory outside this checkout. Before anything is created or written:
- `tokenizers/` must not be a symlink or junction, before or after it is created, and must resolve to itself below
  the resolved temporary root, never into the checkout;
- an existing destination must be a regular file, not a link.

The source is one fixed HTTPS URL (the same file and SHA-256 that tiktoken 0.14.0's `openai_public.py` names); there
is no URL argument. At most 2 MiB is read, and the bytes must hash to the pinned digest before anything is written.
Each run writes its own exclusively created, uniquely named partial file in that directory, fsyncs it and atomically
replaces the destination; a failed run removes only its own partial, never another writer's file. An existing file
with the pinned digest is left as it is. If the replace is refused because another writer holds the destination open
(Windows), the run accepts the destination only after verifying it is a contained regular file holding the pinned
bytes; otherwise the error stands. There is no open-ended retry.

This runs as an explicit setup step (CI does it before the offline checks). The application and its tests never
download: they read the provisioned file and fail closed without it. The vocabulary is fetched for local use only and
is not redistributed with this repository; it is not covered by this repository's license.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import time
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
URL = "https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken"
SHA256 = "223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7"
MAX_BYTES = 2 << 20
DIRECTORY = "tokenizers"
FILE_NAME = "cl100k_base.tiktoken"


class VocabularyError(Exception):
    pass


def _inside(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def _is_link(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def temp_root(environ: Mapping[str, str]) -> Path:
    raw = environ.get("POLICYOPS_TEMP_DIR", "").strip()
    if not raw or not Path(raw).is_absolute():
        raise VocabularyError("POLICYOPS_TEMP_DIR must be an absolute directory")
    root = Path(raw).resolve()
    if not root.is_dir():
        raise VocabularyError("POLICYOPS_TEMP_DIR must be an existing directory")
    if _inside(root, ROOT.resolve()):
        raise VocabularyError("POLICYOPS_TEMP_DIR must be outside the checkout")
    return root


def destination(environ: Mapping[str, str]) -> Path:
    """The destination path (nothing is created here)."""
    return temp_root(environ) / DIRECTORY / FILE_NAME


def _check_directory(directory: Path, root: Path) -> None:
    if _is_link(directory) or not directory.is_dir():
        raise VocabularyError(f"{directory} must be a real directory, not a link")
    resolved = directory.resolve(strict=True)
    if resolved != directory or resolved.parent != root or _inside(resolved, ROOT.resolve()):
        raise VocabularyError(f"{directory} must resolve to itself below the temporary root, outside the checkout")


def contained_directory(root: Path) -> Path:
    """`root/tokenizers`, created if absent, refusing links and anything that resolves elsewhere."""
    directory = root / DIRECTORY
    if _is_link(directory):
        raise VocabularyError(f"{directory} must be a real directory, not a link")
    directory.mkdir(exist_ok=True)
    _check_directory(directory, root)
    return directory


def _check_target(target: Path) -> None:
    if _is_link(target) or (target.exists() and not target.is_file()):
        raise VocabularyError(f"{target} must be a regular file, not a link")


def _bounded(read: Callable[[int], bytes]) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = read(65_536)
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > MAX_BYTES:
            raise VocabularyError("the vocabulary is larger than the 2 MiB bound")
        chunks.append(chunk)


def download() -> bytes:
    # The one fixed https URL; integrity comes from the pinned digest, checked before anything is written.
    with urllib.request.urlopen(URL, timeout=60) as response:
        return _bounded(response.read)


def read_local(path: Path) -> bytes:
    with path.open("rb") as handle:
        return _bounded(handle.read)


def install(data: bytes, root: Path) -> Path:
    """Write the verified bytes to `root/tokenizers/cl100k_base.tiktoken` through this run's own partial file."""
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise VocabularyError("the vocabulary does not have the pinned SHA-256")
    directory = contained_directory(root)
    target = directory / FILE_NAME
    _check_target(target)
    descriptor, name = tempfile.mkstemp(dir=directory, prefix=f".{FILE_NAME}.", suffix=".partial")
    partial = Path(name)
    try:
        if partial.parent != directory:
            raise VocabularyError("the partial file is not in the vocabulary directory")
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _check_directory(directory, root)
        _check_target(target)
        try:
            partial.replace(target)  # replaces the directory entry; the target was checked not to be a link
        except PermissionError:
            # On Windows another writer (or its verification read) may hold the destination open. If it already
            # holds the pinned vocabulary, the outcome is the same file: accept it; anything else is a failure.
            if not _pinned(directory, root):
                raise
    except BaseException:
        partial.unlink(missing_ok=True)  # only this run's own exclusively created partial
        raise
    partial.unlink(missing_ok=True)  # still present only if the destination was accepted as already pinned
    if not _pinned(directory, root):
        raise VocabularyError(f"{target} does not hold the pinned vocabulary after the replace")
    return target


def _pinned(directory: Path, root: Path) -> bool:
    """Whether the contained, regular, non-link destination holds the pinned bytes. A read blocked by a concurrent
    replace on Windows is retried a bounded number of times (3)."""
    _check_directory(directory, root)
    target = directory / FILE_NAME
    _check_target(target)
    for attempt in range(3):
        try:
            return target.is_file() and hashlib.sha256(read_local(target)).hexdigest() == SHA256
        except PermissionError:
            if attempt == 2:
                raise
            time.sleep(0.05)
    return False


def provisioned(root: Path) -> bool:
    target = root / DIRECTORY / FILE_NAME
    if not (root / DIRECTORY).exists() and not _is_link(root / DIRECTORY):
        return False
    _check_directory(root / DIRECTORY, root)
    _check_target(target)
    return target.is_file() and hashlib.sha256(read_local(target)).hexdigest() == SHA256


def main(argv: Sequence[str] | None = None, environ: Mapping[str, str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--from-file", type=Path, help="verify and copy an already downloaded vocabulary file")
    args = parser.parse_args(argv)
    try:
        root = temp_root(os.environ if environ is None else environ)
        if provisioned(root):
            print(f"{root / DIRECTORY / FILE_NAME} already has the pinned vocabulary")
            return 0
        data = read_local(args.from_file) if args.from_file is not None else download()
        target = install(data, root)
    except (VocabularyError, OSError) as error:
        print(f"fetch_tokenizer_vocab: {error}", file=sys.stderr)
        return 1
    print(f"installed the pinned vocabulary at {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
