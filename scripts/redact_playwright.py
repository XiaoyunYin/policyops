"""Retain post-login Playwright action/network metadata, without bodies, cookies, headers or URL queries.

Snapshots/screenshots/sources must be disabled by the caller. Resource files are deliberately omitted.
The raw archive is deleted even on failure. Only external, task-owned .zip files may be processed.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
DROP = frozenset({"headers", "cookies", "postData", "content", "storageState", "localStorage", "sessionStorage"})


def external_zip(path: Path, root: Path) -> None:
    resolved = path.resolve()
    if (
        not path.is_absolute()
        or root.resolve() not in resolved.parents
        or ROOT in resolved.parents
        or path.suffix != ".zip"
        or any(p.is_symlink() or p.is_junction() for p in (path, *path.parents))
    ):
        raise ValueError("trace path must be an unlinked zip under the external temporary root")


def scrub(value: Any, secrets: tuple[str, ...]) -> Any:
    if isinstance(value, dict):
        return {key: "[REDACTED]" if key in DROP else scrub(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [scrub(item, secrets) for item in value]
    if isinstance(value, str):
        for secret in secrets:
            value = value.replace(secret, "[REDACTED]")
        if value.startswith(("http://", "https://")):
            url = urlsplit(value)
            value = urlunsplit((url.scheme, url.netloc.rsplit("@", 1)[-1], url.path, "", ""))
        return re.sub(r"(?i)Bearer\s+[^\s\"']+", "Bearer [REDACTED]", value)
    return value


def sanitize(raw: Path, safe: Path, root: Path, secrets: tuple[str, ...] = ()) -> None:
    external_zip(raw, root)
    external_zip(safe, root)
    if raw.resolve() == safe.resolve() or safe.exists():
        raise ValueError("trace output must be fresh and distinct")
    try:
        with ZipFile(raw) as source, ZipFile(safe, "x", compression=ZIP_DEFLATED) as target:
            if sum(info.file_size for info in source.infolist()) > 64 * 1024 * 1024:
                raise ValueError("trace exceeds bounded sanitizer input")
            for info in source.infolist():
                if "/" in info.filename or not info.filename.endswith((".trace", ".network")):
                    continue
                records = [scrub(json.loads(line), secrets) for line in source.read(info).splitlines() if line]
                target.writestr(info.filename, "\n".join(json.dumps(record) for record in records) + "\n")
    except BaseException:
        if safe.exists():
            safe.unlink()
        raise
    finally:
        raw.unlink()


def main() -> int:
    root = Path(os.environ["POLICYOPS_TEMP_DIR"])
    directory = Path(os.environ["POLICYOPS_SECRETS_DIR"])
    secrets = tuple(
        path.read_text(encoding="utf-8").strip()
        for path in directory.iterdir()
        if path.is_file() and path.name != "owner.json" and path.stat().st_size < 65536
    )
    sanitize(Path(sys.argv[1]), Path(sys.argv[2]), root, secrets)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
