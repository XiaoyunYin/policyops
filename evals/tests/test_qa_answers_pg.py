"""Tiny real-ledger answer study, scripted HTTP providers and an owned fake CE worker."""
from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
import json
from pathlib import Path
import sys
from typing import Any

import pytest

from policyops.persistence.budget import EvalLedgerStore
from policyops.persistence.evaluation import EvaluationRepository
from policyops.persistence.roles import EVAL_RUNTIME
from policyops.retrieval.ingest import PaidCaps, Request, ingest
from policyops_evals.qa_studies import answers as a
from policyops_evals.qa_studies import runner as r
from policyops_evals.qa_studies.config import CrossEncoder, QAStudy, Rerank
from policyops_evals.qa_studies.cross_encoder import CrossEncoderClient
from policyops_evals.qa_studies.registration import run_id
from policyops_testing.app_database import AppDatabase
from policyops_testing.retrieval_fixtures import (
    TOKENIZER,
    Scripted,
    World,
    axis,
    count_reply,
    luna_reply,
    ranking_reply,
)
from policyops_testing.structural_fixtures import KEY, passage, write

from .test_g8_cross_encoder import WORKER
from .test_qa_answers import answer_study
from .test_qa_runner_pg import qa_runner_db
from .test_qa_study_config import parse
from .test_qa_study_registration import materialize_manifests


__all__ = ["qa_runner_db"]
pytestmark = pytest.mark.postgres


def test_tiny_answers_judges_luna_rerank_ce_resume(qa_runner_db: AppDatabase, tmp_path: Path,
                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(qa_runner_db, tmp_path)
    p, other = passage(), passage(1, body="Keep receipts.", heading="Other")
    provider = Scripted({"Refunds\n\nRefunds return to the original card.": axis(0),
        "Other\n\nKeep receipts.": axis(1), "retrieval private": axis(0)})
    raw, digest = write(tmp_path / "corpus", [p, other])
    assert ingest(Request(world.ws, KEY, raw, digest, tmp_path / "corpus", "execute",
        PaidCaps("text-embedding-3-small", 1536, Decimal("1"), 90, 600000, 3600), "structural"),
        engine=world.engine, tokenizer=TOKENIZER, providers=provider.providers(), env="test").outcome == "activated"
    study, inputs, receipt, source = answer_study(tmp_path)
    inputs = replace(inputs, gold=dict.fromkeys(inputs.queries, r.Gold((p["passage_id"],), "responding")),
        passages={}, passage_text={row["passage_id"]: a.Passage(row["passage_id"], row["heading"], row["body"])
                                  for row in (p, other)})
    value = study.model_dump(mode="json")
    materialize_manifests(value, tmp_path)
    study = parse(value)
    validate = QAStudy.validate_data
    monkeypatch.setattr(QAStudy, "validate_data", lambda self: validate(self, tmp_path))
    repository = EvaluationRepository(qa_runner_db.engine(EVAL_RUNTIME, pool_size=5))
    store = EvalLedgerStore(repository.engine, env="evaluation")
    retriever = r.RetrieverExecutor(world.engine, world.ws, KEY, providers=provider.providers(),
                                  tokenizer=TOKENIZER, env="test")
    for item in r.schedule(study, inputs):
        arm = next(arm for arm in study.arms if arm.name == item.arm)
        if arm.kind == "rerank" and arm.reranker.kind == "luna":
            provider.counts.append(count_reply(1000))
            provider.creates.append(ranking_reply("D01", "D02"))
        closed = arm.kind == "closed_book"
        provider.counts.append(count_reply(1000))
        provider.creates.append(luna_reply(json.dumps({"answer": "Refunds return to the original card.",
            "citations": [] if closed else [p["passage_id"]], "abstain": False})))
        if not closed:
            provider.counts.append(count_reply(1000))
            provider.creates.append(luna_reply('{"supported":true,"reason":"Evidence supports the statement."}'))
    artifact = tmp_path / "fake-artifact"
    artifact.mkdir()
    manifest = b'{"files":{}}'
    from policyops_evals.canonical import sha256_bytes
    identity = sha256_bytes(manifest)
    (artifact / "artifact-manifest.json").write_bytes(manifest)
    script = tmp_path / "fake-ce.py"
    script.write_bytes(WORKER.encode())
    ce_arm = next(arm for arm in study.arms if isinstance(arm, Rerank) and isinstance(arm.reranker, CrossEncoder))
    assert isinstance(ce_arm, Rerank)
    # The fake worker is still byte-bound by the specification, not an unbound response stub.
    new_ce = ce_arm.reranker.model_copy(update={"artifact_sha256": identity})
    study = study.model_copy(update={"arms": tuple(arm.model_copy(update={"reranker": new_ce})
                                                  if arm.name == ce_arm.name else arm for arm in study.arms)})
    with CrossEncoderClient(artifact, identity, command=[sys.executable, "-B", str(script), "ok", identity]) as worker:
        def ce(binding: CrossEncoder, deadline: float) -> CrossEncoderClient:
            assert binding.artifact_sha256 == identity
            return worker
        kwargs: dict[str, Any] = dict(allow_paid=True, source=source, providers=provider.providers(),
            tokenizer=TOKENIZER, selection_receipt=receipt, cross_encoder=ce)
        result = r.run(study, inputs, repository, store, retriever, resume=False, **kwargs)
        assert result["execution_complete"] and result["recorded"] == 10
        assert provider.kinds("create") == 20  # 10 answers + 8 judges + 2 Luna reranks
        previous = len(provider.seen)
        assert r.run(study, inputs, repository, store, retriever, resume=True, **kwargs)["execution_complete"]
        assert len(provider.seen) == previous
    scope = store.study_by_key(str(study.study_id))
    assert scope is not None and scope.calls_consumed == 21 and scope.held_usd == 0  # plus one query embedding
    public = r.export(study, r.schedule(study, inputs), repository,
                      {arm.name: run_id(study, scope.id, arm.name) for arm in study.arms})
    assert all(row["outcome"] == "success" for row in public["slots"])
    assert all(row["metrics"]["quality_q"] == (None if row["arm"] == "closed-book-luna" else "1")
               for row in public["slots"])
    assert "GOLD TARGET" not in json.dumps(provider.bodies)
    assert "Refunds return" not in json.dumps(public)
    # Sanity: every scripted provider was used through the actual HTTP count/create adapter.
    assert not provider.counts and not provider.creates
    assert all(isinstance(body["body"], dict) for body in provider.bodies)
