"""Offline metadata inventory, not legal advice or an advisory/vulnerability scan.

Run in each installed Python environment. By default also reconcile apps/web's
lockfile against installed node_modules; --python-only inventories just Python.
Review every copyleft/unknown expression, missing package or metadata mismatch.
Exit 0: policy clear; 1: review required; 2: incomplete/invalid inventory.
No downloads, resolution, imports of inventoried packages, or license-text output.
"""

from __future__ import annotations

import argparse
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
# Conservative allowlist. An OR branch with copyleft still requires review.
PERMISSIVE = {
    "0BSD", "MIT", "MIT-0", "ISC", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "BSD-3-Clause-Clear",
    "BlueOak-1.0.0", "CC0-1.0", "Unlicense", "Python-2.0", "PSF-2.0", "CNRI-Python",
}
CLASSIFIERS = {
    "MIT License": "MIT", "Apache Software License": "Apache-2.0",
    "ISC License (ISCL)": "ISC", "Python Software Foundation License": "PSF-2.0",
}


def license_policy(expression: str) -> str:
    """Parse the deliberately small SPDX AND/OR/parentheses subset; fail closed."""
    tokens = re.findall(r"[A-Za-z0-9.+-]+|[()]|\S", expression)
    position = 0
    identifiers: list[str] = []

    def term() -> bool:
        nonlocal position
        if position >= len(tokens):
            return False
        item = tokens[position]
        position += 1
        if item == "(":
            if not expr() or position >= len(tokens) or tokens[position] != ")":
                return False
            position += 1
            return True
        if item in {"AND", "OR", "WITH", ")"} or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+-]*", item):
            return False
        identifiers.append(item)
        return True

    def expr() -> bool:
        nonlocal position
        if not term():
            return False
        while position < len(tokens) and tokens[position] in {"AND", "OR"}:
            position += 1
            if not term():
                return False
        return True

    if len(tokens) > 100 or not expr() or position != len(tokens):
        return "unknown"
    if any(re.search(r"(?:^|[-.])(?:A?GPL|LGPL|MPL|EPL|EUPL|CDDL|OSL)(?:[-.]|$)", i, re.I)
           for i in identifiers):
        return "copyleft-review"
    return "permissive" if identifiers and all(i in PERMISSIVE for i in identifiers) else "unknown"


def python_inventory() -> list[dict[str, Any]]:
    rows = []
    for dist in metadata.distributions():
        info = dist.metadata
        expression = info.get("License-Expression", "").strip()
        source = "License-Expression"
        if not expression:
            expression = info.get("License", "").strip()
            source = "License"
        if not expression or expression == "UNKNOWN":
            classifiers = [value.rsplit(" :: ", 1)[-1] for value in info.get_all("Classifier", [])
                           if value.startswith("License ::")]
            mapped = [CLASSIFIERS[c] for c in classifiers if c in CLASSIFIERS]
            expression = " AND ".join(mapped) if mapped and len(mapped) == len(classifiers) else ""
            source = "Classifier" if expression else "missing"
        # Legacy fields can be full license text. Keep its hash; never echo it.
        policy = license_policy(expression) if len(expression) <= 512 else "unknown"
        files = [str(p) for p in dist.files or [] if ".dist-info/licenses/" in str(p).replace("\\", "/")]
        rows.append({"ecosystem": "python", "name": info["Name"], "version": dist.version,
                     "license": expression if len(expression) <= 512 and "\n" not in expression else "legacy-text",
                     "license_sha256": hashlib.sha256(expression.encode()).hexdigest(),
                     "source": source, "license_files": sorted(files), "policy": policy,
                     "metadata_sha256": hashlib.sha256((dist.read_text("METADATA") or "").encode()).hexdigest()})
    if not rows:
        raise ValueError("no installed Python distribution metadata")
    return sorted(rows, key=lambda row: (row["name"].lower(), row["version"]))


def npm_license(info: dict[str, Any]) -> str:
    value = info.get("license", "")
    if isinstance(value, dict):
        value = value.get("type", "")
    return value if isinstance(value, str) else ""


def web_inventory(web: Path) -> list[dict[str, Any]]:
    web = web.resolve(strict=True)
    lock = json.loads((web / "package-lock.json").read_text(encoding="utf-8"))
    if (not isinstance(lock, dict) or lock.get("lockfileVersion") != 3
            or not isinstance(lock.get("packages"), dict) or not lock["packages"]):
        raise ValueError("expected npm v3 packages lock")
    modules = web / "node_modules"
    if not modules.is_dir():
        raise ValueError("node_modules missing; installed metadata cannot be inventoried offline")
    rows = []
    locked: set[str] = set()
    for relative, entry in sorted(lock["packages"].items()):
        if not isinstance(entry, dict):
            raise ValueError("invalid lock package metadata")
        if relative == "":  # private workspace root is not a third-party dependency
            continue
        path = PurePosixPath(relative)
        if path.is_absolute() or ".." in path.parts or not relative.startswith("node_modules/"):
            raise ValueError("unsupported linked/outside-lock package")
        locked.add(relative)
        target = web / relative / "package.json"
        if not target.resolve().is_relative_to(modules.resolve()):
            raise ValueError("package metadata escapes node_modules")
        installed = json.loads(target.read_text(encoding="utf-8")) if target.is_file() else None
        if installed is not None and not isinstance(installed, dict):
            raise ValueError("invalid installed package metadata")
        expression = npm_license(entry)
        installed_expression = npm_license(installed) if installed else None
        reasons = []
        if installed is None and not entry.get("optional", False):
            reasons.append("missing-installed-package")
        if installed and installed.get("version") != entry.get("version"):
            reasons.append("version-mismatch")
        if installed and installed_expression != expression:
            reasons.append("license-mismatch")
        policy = license_policy(expression)
        if installed and license_policy(installed_expression or "") != "permissive":
            reasons.append("installed-license-review")
        rows.append({"ecosystem": "npm", "path": relative,
                     "name": entry.get("name", relative.rsplit("node_modules/", 1)[-1]),
                     "version": entry.get("version"), "license": expression,
                     "installed_license": installed_expression, "installed": installed is not None,
                     "optional": bool(entry.get("optional")), "dev": bool(entry.get("dev")),
                     "policy": policy if not reasons else "metadata-review", "reasons": reasons,
                     "package_sha256": hashlib.sha256(target.read_bytes()).hexdigest() if installed else None})
    # Find extra installed packages too, without mistaking bundled fixture package.json
    # files for installed packages. npm module roots sit directly under node_modules/scopes.
    for current, _dirs, _files in os.walk(modules, followlinks=False):
        parent = Path(current)
        if parent.name != "node_modules":
            continue
        for child in parent.iterdir():
            candidates = list(child.iterdir()) if child.name.startswith("@") and child.is_dir() else [child]
            for candidate in candidates:
                if (candidate / "package.json").is_file():
                    relative = candidate.relative_to(web).as_posix()
                    if relative not in locked:
                        rows.append({"ecosystem": "npm", "path": relative, "policy": "extraneous-review"})
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--web", type=Path, default=ROOT / "apps/web")
    parser.add_argument("--python-only", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        temp = Path(os.environ["POLICYOPS_TEMP_DIR"])
        if not temp.is_absolute() or temp.resolve().is_relative_to(ROOT):
            raise ValueError("temporary root must be absolute and external")
        output = args.output.resolve()
        if not output.is_relative_to(temp.resolve()) or output.is_relative_to(ROOT):
            raise ValueError("inventory output must be inside the external temporary root")
        rows = python_inventory()
        if not args.python_only:
            rows += web_inventory(args.web)
        review = sum(row["policy"] != "permissive" for row in rows)
        report = {"schema_version": 1, "python_version": sys.version.split()[0], "packages": rows,
                  "review_count": review, "policy": "Conservative metadata allowlist; copyleft/unknown need review",
                  "web_lock_sha256": None if args.python_only else
                      hashlib.sha256((args.web / "package-lock.json").read_bytes()).hexdigest()}
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes((json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
        print(f"Offline license inventory: {len(rows)} packages; {review} require review; {output}")
        return 1 if review else 0
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        print(f"License inventory could not complete ({type(exc).__name__}).", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
