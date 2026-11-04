"""`policyops-evals` command line: public-data acquisition and manifest checks.

    policyops-evals data fetch --dest DIR             live: git fetch of the pinned commit (network)
    policyops-evals data verify --acquired DIR        offline: re-hash a fetched tree, rebuild and compare
    policyops-evals data build --acquired DIR [--check]
    policyops-evals data upstream-check --acquired DIR [--check]
    policyops-evals data tokens --acquired DIR --cache DIR --extract DIR [--check]
    policyops-evals data check-manifests              offline: committed manifests only, no data

Every directory argument for data, caches or extracted text must lie outside the
repository. No command calls a model, simulator, judge or embedding API.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import json
from pathlib import Path
import sys

from policyops_evals import upstream
from policyops_evals.acquire import AcquisitionError, acquire
from policyops_evals.build import (
    BANKING_SPLIT,
    CORE,
    RETAIL_SPLIT,
    SOURCE,
    TOKENS,
    UPSTREAM,
    build_core,
    default_manifest_dir,
    emit,
    load_committed,
    tree_for,
    validate_manifests,
)
from policyops_evals.canonical import ManifestError


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


def outside_repository(value: str) -> Path:
    """Reject paths that resolve into the checkout; return the unresolved absolute path.

    Returning the unresolved path keeps a symlink or junction visible to the
    output writers, which refuse to write through one.
    """
    path = Path(value).absolute()
    resolved = path.resolve()
    if resolved == REPOSITORY_ROOT or REPOSITORY_ROOT in resolved.parents:
        raise argparse.ArgumentTypeError(f"{value} is inside the repository; use the temporary root")
    return path


def report(result: object) -> None:
    print(json.dumps(result, indent=2, sort_keys=True))


def finish(differing: list[str], check: bool) -> int:
    if check and differing:
        print(f"manifests differ from a fresh rebuild: {', '.join(differing)}", file=sys.stderr)
        return 1
    report({"check" if check else "written": "ok", "differing": differing})
    return 0


def command_fetch(args: argparse.Namespace) -> int:
    inventory = acquire(args.dest, repository=args.repository, commit=upstream.COMMIT, expected_tree=upstream.TREE)
    committed = args.manifests / SOURCE
    summary = {"dest": str(args.dest), "commit": inventory["commit"], "tree": inventory["tree"],
               "files": len(inventory["files"]), "inventory_sha256": inventory["inventory_sha256"]}
    if committed.is_file():
        tree_for(args.dest, args.manifests)
        summary["matches_committed_source_manifest"] = True
    report(summary)
    return 0


def command_verify(args: argparse.Namespace) -> int:
    tree_for(args.acquired, args.manifests)
    differing = emit(build_core(args.acquired), args.manifests, check=True)
    summary = validate_manifests(load_committed(args.manifests))
    report({"acquired": str(args.acquired), "rebuild_differs": differing, "summary": summary})
    return 1 if differing else 0


def command_build(args: argparse.Namespace) -> int:
    return finish(emit(build_core(args.acquired), args.manifests, check=args.check), args.check)


def command_upstream(args: argparse.Namespace) -> int:
    from policyops_evals.upstream_runtime import build_upstream_verification

    tree = tree_for(args.acquired, args.manifests)
    committed = load_committed(args.manifests, CORE)
    inventory = json.loads((args.acquired / "inventory.json").read_bytes())
    tree_files = {item["path"]: item["sha256"] for item in inventory["files"]}
    manifest = build_upstream_verification(tree, tree_files, committed[RETAIL_SPLIT], committed[BANKING_SPLIT])
    return finish(emit({UPSTREAM: manifest}, args.manifests, check=args.check), args.check)


def command_tokens(args: argparse.Namespace) -> int:
    from policyops_evals.corpus import build_token_report, tiktoken_counters, write_extracted

    tree = tree_for(args.acquired, args.manifests)
    counters, info = tiktoken_counters(args.cache)
    manifest = build_token_report(tree, counters, info)
    digests = write_extracted(tree, args.extract)
    extraction = manifest["extraction"]
    if digests["banking-corpus.md"] != extraction["banking_corpus_sha256"] or \
            digests["retail-policy.md"] != extraction["retail_policy_sha256"]:
        raise ManifestError("written extracted text differs from the counted text")
    return finish(emit({TOKENS: manifest}, args.manifests, check=args.check), args.check)


def command_check_manifests(args: argparse.Namespace) -> int:
    report(validate_manifests(load_committed(args.manifests)))
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="policyops-evals", description=__doc__,
                                   formatter_class=argparse.RawDescriptionHelpFormatter)
    data = root.add_subparsers(dest="group", required=True).add_parser("data", help="public benchmark data")
    commands = data.add_subparsers(dest="command", required=True)

    def add(name: str, handler: object, help_text: str, *, acquired: bool = True) -> argparse.ArgumentParser:
        sub = commands.add_parser(name, help=help_text)
        sub.set_defaults(handler=handler)
        sub.add_argument("--manifests", type=Path, default=default_manifest_dir(), help="manifest directory")
        if acquired:
            sub.add_argument("--acquired", type=outside_repository, required=True, help="directory made by fetch")
        return sub

    fetch = add("fetch", command_fetch, "fetch the pinned commit into a new directory", acquired=False)
    fetch.add_argument("--dest", type=outside_repository, required=True)
    fetch.add_argument("--repository", default=upstream.REPOSITORY_URL)
    add("verify", command_verify, "re-hash an acquisition and compare a rebuild with committed manifests")
    for name, handler, text in (("build", command_build, "rebuild source/split/rights/audit manifests"),
                                ("upstream-check", command_upstream, "run pinned upstream verifiers")):
        add(name, handler, text).add_argument("--check", action="store_true", help="compare instead of writing")
    tokens = add("tokens", command_tokens, "extract text and count tokens with installed tokenizers")
    tokens.add_argument("--cache", type=outside_repository, required=True, help="tokenizer vocabulary cache")
    tokens.add_argument("--extract", type=outside_repository, required=True, help="extracted text output")
    tokens.add_argument("--check", action="store_true")
    add("check-manifests", command_check_manifests, "validate committed manifests offline", acquired=False)
    return root


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        code: int = args.handler(args)
        return code
    except (AcquisitionError, ManifestError, OSError, ValueError) as exc:
        print(f"policyops-evals: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
