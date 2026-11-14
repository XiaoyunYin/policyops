"""`policyops-evals` command line: public-data acquisition and manifest checks.

    policyops-evals data fetch --dest DIR             live: git fetch of the pinned commit (network)
    policyops-evals data verify --acquired DIR        offline: re-hash a fetched tree, rebuild and compare
    policyops-evals data build --acquired DIR [--check]
    policyops-evals data upstream-check --acquired DIR [--check]
    policyops-evals data tokens --acquired DIR --cache DIR --extract DIR [--check]
    policyops-evals data check-manifests              offline: committed manifests only, no data
    policyops-evals data calibration [--check]        offline: rebuild the retail dev allowlist and demo seeds
    policyops-evals data policy-trace --acquired DIR  offline: verify policy rule anchors against pinned bytes
    policyops-evals data seed-bindings --acquired DIR --out DIR
                                                      offline: server-only seed customer bindings (private file)

Every directory argument for data, caches or extracted text must lie outside the
repository. Judge calibration calls providers only with explicit paid opt-in and caps.
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
from policyops_evals.calibration import CALIBRATION, build_calibration, validate_calibration
from policyops_evals.canonical import ManifestError, canonical_bytes, load_manifest


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
    committed = load_committed(args.manifests)
    summary = validate_manifests(committed)
    calibration = load_manifest(args.manifests / CALIBRATION)
    validate_calibration(calibration, committed)
    summary["retail_calibration"] = {"allowlisted": calibration["allowlist"]["count"],
                                     "excluded": len(calibration["excluded"]), "seeds": len(calibration["seeds"])}
    report(summary)
    return 0


def command_calibration(args: argparse.Namespace) -> int:
    manifest = build_calibration(load_committed(args.manifests))
    return finish(emit({CALIBRATION: manifest}, args.manifests, check=args.check), args.check)


def command_policy_trace(args: argparse.Namespace) -> int:
    from policyops_evals.policy_trace import trace_policy

    tree = tree_for(args.acquired, args.manifests)
    report(trace_policy(tree.read(upstream.RETAIL_POLICY)))
    return 0


def command_seed_bindings(args: argparse.Namespace) -> int:
    from policyops_evals.corpus import write_contained
    from policyops_evals.projection import SplitGuard
    from policyops_evals.seed_bindings import derive_bindings

    tree = tree_for(args.acquired, args.manifests)
    committed = load_committed(args.manifests)
    calibration = load_manifest(args.manifests / CALIBRATION)
    validate_calibration(calibration, committed)
    guard = SplitGuard({"retail": committed[RETAIL_SPLIT], "banking_knowledge": committed[BANKING_SPLIT]})
    result = derive_bindings(tree, calibration, guard)
    target = write_contained(args.out, "seed-bindings.json", canonical_bytes(result))
    report({"written": str(target), "bindings": len(result["bindings"]), "unavailable": result["unavailable"]})
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="policyops-evals", description=__doc__,
                                   formatter_class=argparse.RawDescriptionHelpFormatter)
    groups = root.add_subparsers(dest="group", required=True)
    judge = groups.add_parser("judge-calibration", help="G6 evaluation-only claim-support calibration")
    judge_commands = judge.add_subparsers(dest="judge_command", required=True)
    for judge_name in ("sample", "preflight", "run", "report", "select"):
        sub = judge_commands.add_parser(judge_name)
        sub.set_defaults(handler=command_judge_calibration)
        sub.add_argument("--manifest", type=Path)
        if judge_name in ("sample", "run"):
            sub.add_argument("--data", type=outside_repository, required=True)
        if judge_name == "sample":
            sub.add_argument("--check", action="store_true")
        if judge_name in ("preflight", "run"):
            from decimal import Decimal

            sub.add_argument("--split", choices=("dev", "test"), required=True)
            sub.add_argument("--selection", type=outside_repository)
            sub.add_argument("--config", type=Path)
            sub.add_argument("--max-usd", type=Decimal, required=True)
            sub.add_argument("--max-calls", type=int, required=True)
            sub.add_argument("--max-counts", type=int, required=True)
            sub.add_argument("--max-seconds", type=int, required=True)
            if judge_name == "preflight":
                sub.add_argument("--register", action="store_true")
            else:
                sub.add_argument("--execute-paid", action="store_true")
                sub.add_argument("--out", type=outside_repository, required=True)
        if judge_name in ("report", "select"):
            sub.add_argument("--run", type=outside_repository, required=True)
            sub.add_argument("--out", type=outside_repository, required=True)
            if judge_name == "select":
                sub.add_argument("--config-out", type=Path, required=True)
    qa = groups.add_parser("qa-study", help="validate, digest or preflight a frozen QA contract")
    qa_commands = qa.add_subparsers(dest="qa_command", required=True)
    for qa_name in ("validate", "digest", "preflight"):
        qa_command = qa_commands.add_parser(qa_name)
        qa_command.add_argument("--study", type=Path, required=True)
        qa_command.set_defaults(handler=command_qa_study)
        if qa_name == "preflight":
            qa_command.add_argument("--register", action="store_true")
    for name in ("preflight", "run"):
        study = groups.add_parser(name, help="plan or execute a durable dev study")
        study.add_argument("--study", type=Path, required=True)
        study.set_defaults(handler=command_study)
        if name == "run":
            study.add_argument("--allow-paid", action="store_true")
            study.add_argument("--resume", action="store_true")
            study.add_argument("--close-unclaimed", action="store_true")
        else:
            study.add_argument("--register", action="store_true")
    frozen_report = groups.add_parser("report", help="render a sealed study snapshot without DB/provider/git")
    frozen_report.add_argument("--study", type=Path, required=True)
    frozen_report.add_argument("--snapshot")
    frozen_report.add_argument("--out", type=outside_repository)
    frozen_report.set_defaults(handler=command_report)
    taxonomy = groups.add_parser("taxonomy", help="count failure codes from sealed and hash-linked private artifacts")
    taxonomy.add_argument("--study", type=Path, required=True)
    taxonomy.add_argument("--snapshot", required=True)
    taxonomy.add_argument("--out", type=outside_repository, required=True)
    taxonomy.set_defaults(handler=command_taxonomy)
    data = groups.add_parser("data", help="public benchmark data")
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
    add("calibration", command_calibration, "rebuild the retail dev allowlist and demo seeds",
        acquired=False).add_argument("--check", action="store_true", help="compare instead of writing")
    add("policy-trace", command_policy_trace, "verify policy rule anchors against the pinned policy")
    add("seed-bindings", command_seed_bindings, "derive server-only seed customer bindings").add_argument(
        "--out", type=outside_repository, required=True, help="private output directory outside the repository")
    return root


def command_judge_calibration(args: argparse.Namespace) -> int:
    from policyops_evals.qa_studies import calibration as g6

    try:
        manifest_path = args.manifest or g6.PUBLIC_MANIFEST
        if args.judge_command == "sample":
            sample = g6.build_sample(args.data)
            payload = canonical_bytes(sample)
            if len(payload) >= 1_000_000:
                raise ValueError("G6 public manifest exceeds size bound")
            if args.check:
                if payload != manifest_path.read_bytes():
                    raise ValueError("G6 sample rebuild differs")
            else:
                # The only public write allowed by this command is the assigned manifest.
                if manifest_path.resolve() != g6.PUBLIC_MANIFEST:
                    raise ValueError("G6 public manifest path is fixed")
                manifest_path.parent.mkdir(parents=True, exist_ok=True)
                manifest_path.write_bytes(payload)
            result = {"manifest_sha256": sample["manifest_sha256"], "counts": sample["counts"],
                      "exclusions": sample["exclusions"], "bytes": len(payload)}
        else:
            sample = g6.load_sample(manifest_path)
            if args.judge_command in ("preflight", "run"):
                receipt = g6.selection(args.selection, sample) if args.selection else None
                result = g6.planning(sample, args.split, max_usd=args.max_usd, max_calls=args.max_calls,
                    max_counts=args.max_counts, max_seconds=args.max_seconds, receipt=receipt)
                if args.judge_command == "run" or args.register:
                    result = g6.command_run(sample, result, receipt,
                        directory=getattr(args, "data", Path()), output=getattr(args, "out", Path()),
                        execute_paid=getattr(args, "execute_paid", False), config_path=args.config,
                        register_requested=getattr(args, "register", False))
            else:
                result = g6.report_run(sample, args.run)
                if args.judge_command == "select":
                    result = g6.select_arm(result, sample)
                    if args.config_out.resolve().parent != g6.PUBLIC_MANIFEST.parent:
                        raise ValueError("G6 test config must be in the assigned manifest directory")
                    g6.write_private(args.out, result, exclusive=True)
                    with args.config_out.open("xb") as handle:
                        handle.write(canonical_bytes(g6.test_configuration(sample, result)))
                    result = {"selection_receipt_sha256": g6.digest(result), "binding": result["binding"]}
                else:
                    g6.write_private(args.out, result, exclusive=True)
    except Exception as error:
        # No untrusted data, Pydantic inputs, provider messages or DB credentials.
        print(f"policyops-evals: judge calibration refused: {type(error).__name__}", file=sys.stderr)
        return 1
    report(result)
    return 0


def command_qa_study(args: argparse.Namespace) -> int:
    from policyops_evals.qa_studies.config import load_study
    from policyops_evals.qa_studies.registration import command, registration_digest, source_provenance

    try:
        study = load_study(args.study)
        if args.qa_command == "validate":
            study.validate_data()
            result = {"valid": True, "study_id": str(study.study_id), "example": study.example,
                      "registered": False}
        elif args.qa_command == "digest":
            result = {"registration_payload_sha256": registration_digest(study, source_provenance()),
                      "registered": False}
        else:
            result = command(study, register_requested=args.register)
    except Exception as error:
        # Never print DB exceptions, credentials, or a Pydantic input payload.
        print(f"policyops-evals: QA study refused: {type(error).__name__}", file=sys.stderr)
        return 1
    report(result)
    return 0 if result.get("within_caps", True) else 1


def command_study(args: argparse.Namespace) -> int:
    from policyops_evals.studies.runner import command

    try:
        result = command(args.study, run=args.group == "run", allow_paid=getattr(args, "allow_paid", False),
                         resume=getattr(args, "resume", False), register=getattr(args, "register", False),
                         close_unclaimed=getattr(args, "close_unclaimed", False))
    except Exception as error:
        # DB/provider exceptions can contain credentials or hidden task text.
        # Emit only the type; fixed StudyRefused codes are safe to display.
        from policyops_evals.studies.runner import StudyRefused

        code = str(error) if isinstance(error, StudyRefused) else type(error).__name__
        print(f"policyops-evals: study refused: {code}", file=sys.stderr)
        return 1
    report(result)
    return 0 if result.get("within_caps", True) and result.get("execution_complete", True) else 1


def command_report(args: argparse.Namespace) -> int:
    from policyops_evals.studies.reports import render

    try:
        out = args.out or args.study.parent / ("report-" + (args.snapshot or "selected"))
        result = render(args.study, snapshot=args.snapshot, out=out)
    except Exception:
        # No bundle payload, untrusted path or validation detail in diagnostics.
        print("policyops-evals: frozen report integrity refusal", file=sys.stderr)
        return 1
    report({"schema_version": result["schema_version"], "snapshot_sha256": result["snapshot_sha256"],
            "integrity_status": result["integrity_status"]})
    return 0 if result["integrity_status"] == "valid" else 1


def command_taxonomy(args: argparse.Namespace) -> int:
    from policyops_evals.studies.taxonomy import render

    try:
        result = render(args.study, snapshot=args.snapshot, out=args.out)
    except Exception:
        print("policyops-evals: taxonomy integrity refusal", file=sys.stderr)
        return 1
    report({key: result[key] for key in ("schema_version", "snapshot_sha256", "scheduled_trials")})
    return 0


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
