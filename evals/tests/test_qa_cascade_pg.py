"""Real PostgreSQL cascade checkpoints, physical calls, accounting and text isolation."""
from __future__ import annotations

from dataclasses import replace
from decimal import Decimal
import json
from pathlib import Path
import sys
from typing import Any

import httpx2
from pydantic import SecretStr
import pytest
from sqlalchemy import text

from policyops.persistence.budget import EvalLedgerStore
from policyops.persistence.database import transaction
from policyops.persistence.evaluation import EvaluationRepository
from policyops.persistence.roles import EVAL_RUNTIME
from policyops.providers.calls import Providers
from policyops.retrieval.ingest import PaidCaps, Request, ingest
from policyops_evals.canonical import canonical_bytes, sha256_bytes
from policyops_evals.qa_studies import answers as a
from policyops_evals.qa_studies import runner as r
from policyops_evals.qa_studies.config import CrossEncoder, PolicyArm, QAStudy, Rerank, load_study
from policyops_evals.qa_studies.cross_encoder import CrossEncoderClient
from policyops_evals.qa_studies.registration import run_id
from policyops_testing.app_database import AppDatabase
from policyops_testing.retrieval_fixtures import TOKENIZER, Scripted, World, axis, count_reply, luna_reply, openai_json
from policyops_testing.structural_fixtures import KEY, passage, write

from .test_g8_cross_encoder import WORKER
from .test_qa_cascade import cascade_study
from .test_qa_runner_pg import qa_runner_db
from .test_qa_study_config import parse
from .test_qa_study_registration import materialize_manifests


__all__ = ["qa_runner_db"]
pytestmark = pytest.mark.postgres


class BothProviders(Scripted):
    def providers(self) -> Any:
        return lambda: Providers(credentials={name: SecretStr("synthetic-qa-cascade-credential")
            for name in ("openai", "anthropic")}, transport=lambda _: self)

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        if request.url.path.endswith("count_tokens"):
            self.seen.append("count")
            return httpx2.Response(200, json={"input_tokens": 1000}, request=request)
        return await super().handle_async_request(request)


def haiku_reply(payload: str) -> Any:
    return openai_json({"id": "msg_synthetic", "type": "message", "role": "assistant",
        "model": "claude-haiku-5-5", "content": [{"type": "text", "text": payload}],
        "stop_reason": "end_turn", "stop_sequence": None,
        "usage": {"input_tokens": 900, "output_tokens": 40, "cache_read_input_tokens": 0,
                  "cache_creation_input_tokens": 0, "service_tier": "standard"}})


def test_pg_mixed_cascade_resume_cost_and_export(qa_runner_db: AppDatabase, tmp_path: Path,
                                                monkeypatch: pytest.MonkeyPatch) -> None:
    world = World(qa_runner_db, tmp_path)
    p, other = passage(), passage(1, body="Keep receipts.", heading="Other")
    provider = BothProviders({"Refunds\n\nRefunds return to the original card.": axis(0),
        "Other\n\nKeep receipts.": axis(1), "retrieval private": axis(0)})
    raw, digest = write(tmp_path / "corpus", [p, other])
    assert ingest(Request(world.ws, KEY, raw, digest, tmp_path / "corpus", "execute",
        PaidCaps("text-embedding-3-small", 1536, Decimal("1"), 90, 600000, 3600), "structural"),
        engine=world.engine, tokenizer=TOKENIZER, providers=provider.providers(), env="test").outcome == "activated"
    study, inputs, receipt, source = cascade_study(tmp_path)
    inputs = replace(inputs, gold=dict.fromkeys(inputs.queries, r.Gold((p["passage_id"],), "responding")),
        passages={}, passage_text={row["passage_id"]: a.Passage(row["passage_id"], row["heading"], row["body"])
                                  for row in (p, other)})
    value = study.model_dump(mode="json")
    # The optional base CE runs on the same candidate pool, with a byte-bound fake worker.
    original = load_study(Path(__file__).parents[1] / "qa_studies/g1-dev-answers-v1.json")
    ce_arm = next(arm for arm in original.arms if isinstance(arm, Rerank) and isinstance(arm.reranker, CrossEncoder))
    assert isinstance(ce_arm, Rerank)
    binding = ce_arm.reranker.model_dump(mode="json")
    artifact = tmp_path / "fake-artifact"
    artifact.mkdir()
    manifest = b'{"files":{}}'
    identity = sha256_bytes(manifest)
    (artifact / "artifact-manifest.json").write_bytes(manifest)
    binding.update(artifact_sha256=identity,
        candidate_pool_sha256=sha256_bytes(canonical_bytes(value["arms"][1]["retrieval"])))
    value["arms"][1]["policy"]["reranker"] = binding
    materialize_manifests(value, tmp_path)
    study = parse(value)
    validate = QAStudy.validate_data
    monkeypatch.setattr(QAStudy, "validate_data", lambda self: validate(self, tmp_path))
    directory = tmp_path / "qa-studies" / str(study.study_id)
    monkeypatch.setattr(r, "directory_for", lambda _: directory)
    repository = EvaluationRepository(qa_runner_db.engine(EVAL_RUNTIME, pool_size=5))
    store = EvalLedgerStore(repository.engine, env="evaluation")
    retriever = r.RetrieverExecutor(world.engine, world.ws, KEY, providers=provider.providers(),
                                  tokenizer=TOKENIZER, env="test")
    final = json.dumps({"answer": "Refunds return to the original card.", "citations": [p["passage_id"]],
                        "abstain": False})
    for item in r.schedule(study, inputs):
        if item.arm == "cascade":
            confidence = 0.8 if item.question.endswith("/0") else 0.7
            provider.counts.append(count_reply(1000))
            provider.creates.append(luna_reply(json.dumps({"answer": "LUNA PRIVATE FIRST ANSWER.",
                "citations": [p["passage_id"]], "abstain": False, "confidence": confidence, "escalate": False})))
            if confidence < 0.8:
                provider.creates.append(haiku_reply(final))
        else:
            provider.counts.append(count_reply(1000))
            provider.creates.append(luna_reply(final))
        provider.counts.append(count_reply(1000))
        provider.creates.append(luna_reply('{"supported":true,"reason":"Supported."}'))
    script = tmp_path / "fake-ce.py"
    script.write_bytes(WORKER.encode())
    with CrossEncoderClient(artifact, identity, command=[sys.executable, "-B", str(script), "ok", identity]) as worker:
        def ce(binding: CrossEncoder, deadline: float) -> CrossEncoderClient:
            return worker
        kwargs: dict[str, Any] = dict(allow_paid=True, source=source, providers=provider.providers(),
            tokenizer=TOKENIZER, selection_receipt=receipt, cross_encoder=ce)
        def crash(at: str) -> None:
            if at == "cascade_first_checkpoint":
                raise SystemExit("loss between settled first stage and fallback")
        with pytest.raises(SystemExit):
            r.run(study, inputs, repository, store, retriever, resume=False, boundary=crash, **kwargs)
        before = provider.kinds("create")
        remaining = len(provider.creates)
        assert r.run(study, inputs, repository, store, retriever, resume=True, **kwargs)["execution_complete"]
        # Remaining scheduled work consumes the queue exactly, without a repeated first call.
        assert provider.kinds("create") == before + remaining == 9
        assert not provider.creates and not provider.counts
        previous = len(provider.seen)
        assert r.run(study, inputs, repository, store, retriever, resume=True, **kwargs)["execution_complete"]
        assert len(provider.seen) == previous
    scope = store.study_by_key(str(study.study_id))
    assert scope is not None and scope.held_usd == 0
    public = r.export(study, r.schedule(study, inputs), repository,
        {arm.name: run_id(study, scope.id, arm.name) for arm in study.arms}, inputs)
    rows = [s for s in public["slots"] if s["arm"] == "cascade"]
    assert {s["route"] for s in rows} == {"first", "fallback"}
    assert {s["escalation_reason"] for s in rows} == {None, "low_confidence"}
    assert all(s["outcome"] == "success" and s["metrics"]["gold_citation"] == "1" for s in rows)
    fallback = next(s for s in rows if s["route"] == "fallback")
    assert fallback["stages"]["answer.first"]["cost_usd"] == "0.00011000"
    assert fallback["stages"]["answer.fallback"]["cost_usd"] == "0.00011000"
    with transaction(repository.engine) as conn:
        attempts = conn.execute(text("SELECT operation_id, actual_usd, state FROM evaluation.usage_attempts "
            "WHERE study_scope_id = :scope"), {"scope": scope.id}).mappings().all()
    assert sum("cascade.answer.first/" in x["operation_id"] for x in attempts) == 2
    assert sum("cascade.answer.fallback/" in x["operation_id"] for x in attempts) == 1
    assert all(x["state"] == "settled" for x in attempts if "cascade.answer.fallback/" in x["operation_id"])
    assert all(x["actual_usd"] is not None for x in attempts)
    fallback_requests = [x["body"] for x in provider.bodies if x["kind"] == "create"
                         and x["body"].get("model") == "claude-haiku-5-5"]
    assert len(fallback_requests) == 1
    assert "LUNA PRIVATE FIRST ANSWER" not in json.dumps(fallback_requests)
    assert "chronological first" in json.dumps(fallback_requests)
    raw_public = json.dumps(public)
    assert "LUNA PRIVATE" not in raw_public and "chronological first" not in raw_public
    from .test_qa_runner_pg import EXPORT_FIELDS
    assert all(set(s) <= EXPORT_FIELDS for s in public["slots"])
    report = r.report(study, inputs, public, repository, scope.id, source)
    aggregate = next(x for x in report["aggregates"] if x["arm"] == "cascade")
    assert aggregate["escalation_rate"] == "1/2"
    assert aggregate["route_cost"]["fallback"]["known_policy_usd"] == "0.00022000"
    assert isinstance(study.arms[1], PolicyArm)
