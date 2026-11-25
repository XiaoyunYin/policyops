"""Extract the pinned LGTM Prometheus config and test the canary rules with its promtool."""

from argparse import ArgumentParser
import json
import os
from pathlib import Path
import re
import subprocess
from typing import cast


REPO = Path(__file__).resolve().parents[1]
CONFIG = "/otel-lgtm/prometheus.yaml"
RULE = "/otel-lgtm/policyops-canary.yaml"


def pinned_image() -> str:
    pin = json.loads((REPO / "infra/images.json").read_text(encoding="utf-8"))["images"]["observability"]
    return f"{pin['image']}@{pin['digest']}"


def with_rule(config: str) -> str:
    if not config.strip() or not re.search(r"^[\w_]+:", config, flags=re.MULTILINE):
        raise ValueError("expected a Prometheus configuration from the pinned image")
    key = re.search(r"^rule_files:[ \t]*(?:\[\][ \t]*)?(?:#[^\n]*)?$", config, flags=re.MULTILINE)
    if key is not None:
        return config[:key.start()] + f"rule_files:\n  - {RULE}" + config[key.end():]
    if re.search(r"^rule_files:", config, flags=re.MULTILINE):
        raise ValueError("update the canary overlay for the pinned image's rule_files format")
    return config.rstrip() + f"\n\nrule_files:\n  - {RULE}\n"


def main() -> int:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", type=Path, help="New config path under POLICYOPS_TEMP_DIR")
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()
    if not (args.prepare or args.test):
        parser.error("choose --prepare or --test")
    command = ["docker", "run", "--rm", "--network", "none"]
    image = pinned_image()
    if args.test:
        rules = REPO / "infra/observability/rules"
        subprocess.run([*command, "--mount", f"type=bind,source={rules},target=/rules,readonly",
                        "--workdir", "/rules", "--entrypoint", "/bin/sh", image, "-ec",
                        'tool=$(command -v promtool || find /otel-lgtm -name promtool -print -quit); '
                        'test -n "$tool" || { echo "Pinned LGTM image lacks promtool" >&2; exit 1; }; '
                        '"$tool" --version; exec "$tool" test rules canary.test.yaml'], check=True, timeout=120)
    if args.prepare:
        root = Path(os.environ["POLICYOPS_TEMP_DIR"]).resolve(strict=True)
        target = cast(Path, args.prepare).resolve()
        if root.is_relative_to(REPO) or not target.is_relative_to(root):
            raise ValueError("output must be in the external temporary root")
        # Confirm the mount path against the actual pinned image before producing the override.
        config = subprocess.check_output([*command, "--entrypoint", "/bin/sh", image, "-ec",
                                          f"test -s {CONFIG}; cat {CONFIG}"], timeout=120).decode("utf-8")
        with target.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(with_rule(config))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
