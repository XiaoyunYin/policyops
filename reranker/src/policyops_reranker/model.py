"""Offline BERT cross-encoders. Artifact identity is the SHA-256 of its manifest bytes.

The base card is Apache-2.0; its MS MARCO lineage has non-commercial research terms.
No executable model configuration, pickle weights or Hugging Face network access is used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any


# Enforce before importing transformers/huggingface_hub, even if ambient values disagree.
os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["TRANSFORMERS_OFFLINE"] = "1"
os.environ["TOKENIZERS_PARALLELISM"] = "false"

import torch
from transformers import BertConfig, BertForSequenceClassification, BertTokenizerFast


BASE_MANIFEST_SHA256 = "e7d8edecf92c7263757bedaa89ffd84c4f002a2b67d31c2df4fdd4cd78b7a4a5"
MODEL_FILES = frozenset({"config.json", "model.safetensors", "tokenizer.json", "tokenizer_config.json",
                         "special_tokens_map.json", "vocab.txt"})
OPTIONAL_FILES = frozenset({"README.md", "training-manifest.json", "truncation.jsonl"})


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def private_output(path: Path) -> Path:
    root = os.environ.get("POLICYOPS_TEMP_DIR")
    if (not root or not Path(root).is_absolute() or Path(root).resolve() not in path.resolve().parents
            or any(p.is_symlink() or p.is_junction() for p in (path, *path.parents))):
        raise ValueError("private_output_containment")
    return path


def manifest_path(directory: Path) -> Path:
    paths = [directory / name for name in ("artifact-manifest.json", "download-manifest.json")
             if (directory / name).is_file()]
    if len(paths) != 1:
        raise ValueError("one_artifact_manifest_required")
    return paths[0]


def verify(directory: Path, expected_sha256: str | None = None) -> str:
    """Verify every file and refuse extra files, aliases and all alternative weight formats."""
    if any(p.is_symlink() or p.is_junction() for p in (directory, *directory.parents)):
        raise ValueError("artifact_alias")
    path = manifest_path(directory)
    if path.stat().st_size > 1_000_000:
        raise ValueError("manifest_bound")
    identity = sha256(path)
    if expected_sha256 is not None and identity != expected_sha256:
        raise ValueError("artifact_identity")
    if path.name == "download-manifest.json" and identity != BASE_MANIFEST_SHA256:
        raise ValueError("base_pin")
    value = json.loads(path.read_bytes())
    files = value["files"]
    if not isinstance(files, dict) or not MODEL_FILES <= files.keys() <= MODEL_FILES | OPTIONAL_FILES:
        raise ValueError("artifact_file_allowlist")
    if {p.name for p in directory.iterdir()} != set(files) | {path.name}:
        raise ValueError("unexpected_artifact_file_or_pickle")
    for name, pin in files.items():
        target = directory / name
        if (target.is_symlink() or target.is_junction() or not target.is_file()
                or target.stat().st_size != pin["bytes"] or sha256(target) != pin["sha256"]):
            raise ValueError("artifact_file_hash")
    return identity


def seal(directory: Path) -> str:
    """Freeze locally generated files; the returned digest is the external trust anchor."""
    files = {p.name: {"bytes": p.stat().st_size, "sha256": sha256(p)} for p in sorted(directory.iterdir())}
    if not MODEL_FILES <= files.keys() <= MODEL_FILES | OPTIONAL_FILES:
        raise ValueError("artifact_file_allowlist")
    with (directory / "artifact-manifest.json").open("xb") as handle:
        handle.write(canonical({"schema": "policyops.g8-artifact/v1", "files": files}))
    return verify(directory)


def configure_cpu(threads: int) -> None:
    if type(threads) is not int or not 1 <= threads <= 32:
        raise ValueError("cpu_threads_bound")
    torch.set_num_threads(threads)
    if torch.get_num_interop_threads() != 1:
        torch.set_num_interop_threads(1)
    torch.use_deterministic_algorithms(True)


def load(directory: Path, *, threads: int = 4, expected_sha256: str | None = None) -> tuple[Any, Any, str]:
    identity = verify(directory, expected_sha256)
    configure_cpu(threads)
    # Concrete classes deliberately bypass Auto* and configuration-driven code/activation imports.
    config = BertConfig.from_pretrained(str(directory), local_files_only=True)
    if (config.model_type != "bert" or config.num_labels != 1 or config.max_position_embeddings < 384
            or config.num_hidden_layers > 12 or config.hidden_size > 768 or config.vocab_size > 100_000):
        raise ValueError("bert_architecture_bounds")
    tokenizer = BertTokenizerFast.from_pretrained(str(directory), local_files_only=True)
    model = BertForSequenceClassification.from_pretrained(
        str(directory), config=config, local_files_only=True, use_safetensors=True,
        attn_implementation="eager").to(device="cpu", dtype=torch.float32)
    model.eval()
    return model, tokenizer, identity


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify a local G8 artifact without loading weights")
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--expected-sha256")
    args = parser.parse_args()
    print(json.dumps({"artifact_sha256": verify(args.artifact, args.expected_sha256)}))


if __name__ == "__main__":
    main()
