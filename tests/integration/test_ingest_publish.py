"""T12 ingestion composed on real PostgreSQL as the actual app runtime LOGIN role, with the real embedding foundation
(frozen job, ledger, evidence, cache) over a scripted embeddings transport that counts physical requests: first
import, read-only plan, paid gating and caps, repeat with zero rows and calls, changed-only embedding, cross-document
reuse, crash recovery (complete job after its deadline versus an expired incomplete job), cumulative token budget,
stale and racing activations, exact-set verification, version digest integrity, source ownership and tenancy."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
import threading
import time
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Connection, text

from policyops.persistence import repositories as repo
from policyops.persistence.budget import build_app_ledger
from policyops.persistence.corpora import CorpusStore, StaleActivation, VerificationMismatch
from policyops.persistence.database import transaction, workspace_transaction
from policyops.persistence.embeddings import EmbeddingStore
from policyops.persistence.records import Workspace
from policyops.persistence.roles import APP_RUNTIME, AUTH_RUNTIME
from policyops.providers import tokenizer as tk
from policyops.providers.embedding_calls import EmbedLimits, pack, prepare_job, run_job
from policyops.retrieval.corpus import Expected, build_expected
from policyops.retrieval.ingest import PURPOSE, Outcome, PaidCaps, Request, ingest
from policyops.retrieval.sources import read_corpus
from policyops.runtime.clock import FixedLeaseClock
from policyops_contracts.clock import FixedClock
from policyops_contracts.embedding import EmbeddingJob
from policyops_testing.app_database import AppDatabase
from policyops_testing.corpus_fixtures import CredentialReads, FixtureCorpus, ScriptedEmbeddings, banking, write


pytestmark = pytest.mark.postgres
TOKENIZER = tk.load()
KEY = "test-banking"
TABLES = ("app.corpora", "app.documents", "app.document_versions", "app.index_generations",
          "app.generation_documents", "app.chunks", "app.embedding_jobs", "app.embedding_job_inputs",
          "app.embedding_batches", "app.embedding_attempt_evidence", "app.embedding_cache", "app.budget_scopes",
          "app.usage_attempts")


def paid(**overrides: Any) -> PaidCaps:
    values: dict[str, Any] = {"model": "text-embedding-3-small", "dimensions": 1536, "max_usd": Decimal("0.01"),
                              "max_calls": 20, "max_input_tokens": 100_000, "max_seconds": 900}
    return PaidCaps(**(values | overrides))


def docs(count: int = 3, *, edit: dict[int, str] | None = None) -> dict[str, bytes]:
    edit = edit or {}
    return {f"d{i:03d}": banking(f"d{i:03d}", f"Title {i}", edit.get(i, f"Rule {i}: refunds follow policy {i}."))
            for i in range(count)}


@dataclass
class Env:
    db: AppDatabase
    root: Path
    ws: UUID = field(default_factory=uuid4)
    provider: ScriptedEmbeddings = field(default_factory=ScriptedEmbeddings)
    clock: FixedLeaseClock | None = None

    def __post_init__(self) -> None:
        with transaction(self.db.engine(AUTH_RUNTIME)) as conn:
            repo.create_workspace(conn, Workspace(id=self.ws, slug=f"ws-{self.ws.hex[:12]}", name="Ingest test",
                                                  created_at=datetime.now(UTC)))
        self.engine = self.db.engine(APP_RUNTIME, pool_size=8)
        self.credentials = CredentialReads(self.provider)
        self._n = 0

    def corpus(self, documents: dict[str, bytes], *, key: str = KEY, domain: str = "banking_knowledge"
               ) -> tuple[bytes, str, Path]:
        self._n += 1
        root = self.root / f"acq-{self._n}"
        raw, digest = write(root, [FixtureCorpus(key, domain, "tau2-banking/v1", documents)])
        return raw, digest, root

    def run(self, documents: dict[str, bytes], *, mode: str = "execute", caps: PaidCaps | None = None,
            key: str = KEY, domain: str = "banking_knowledge", **kwargs: Any) -> Outcome:
        raw, digest, root = self.corpus(documents, key=key, domain=domain)
        request = Request(self.ws, key, raw, digest, root, mode, caps)  # type: ignore[arg-type]
        return ingest(request, engine=self.engine, tokenizer=TOKENIZER, providers=self.credentials,
                      env="test", clock=self.clock, **kwargs)

    def expected(self, documents: dict[str, bytes], *, key: str = KEY) -> Expected:
        raw, digest, root = self.corpus(documents, key=key)
        source = read_corpus(raw, digest, key, root)
        return build_expected(source, TOKENIZER, tokenizer_sha256=TOKENIZER.identity_sha256,
                              model="text-embedding-3-small", dimensions=1536, deadline=time.monotonic() + 60)

    def counts(self) -> dict[str, int]:
        with self.db.superuser() as conn:
            # Table names are the fixed constants above.
            return {t: conn.execute(f"SELECT count(*) FROM {t} WHERE workspace_id = %s",  # noqa: S608
                                    (self.ws,)).fetchone()[0] for t in TABLES}

    def visible_chunks(self) -> list[str]:
        with workspace_transaction(self.engine, self.ws) as conn:
            return list(conn.execute(text("SELECT text FROM app.chunks ORDER BY text")).scalars())

    def pointer(self, key: str = KEY) -> tuple[UUID | None, int]:
        with workspace_transaction(self.engine, self.ws) as conn:
            row = conn.execute(text("SELECT active_generation_id, version FROM app.corpora WHERE corpus_key = :k"),
                               {"k": key}).one()
        return row[0], row[1]

    def statuses(self) -> list[str]:
        with workspace_transaction(self.engine, self.ws) as conn:
            return sorted(conn.execute(text("SELECT status FROM app.index_generations")).scalars())


@pytest.fixture
def env(shared_db: AppDatabase, tmp_path: Path) -> Env:
    return Env(shared_db, tmp_path)


def test_first_import_activates_exactly_and_accounts_every_request(env: Env) -> None:
    outcome = env.run(docs(), caps=paid())
    assert outcome.outcome == "activated" and outcome.exit_code == 0, outcome.to_json()
    details = outcome.details
    assert details["documents"] == 3 and details["chunks"] == 3 and details["missing_inputs"] == 3
    assert details["physical_requests"] == len(env.provider.requests) == 1 == details["estimate"]["batches"]
    assert env.credentials.reads == 1
    assert env.statuses() == ["ready"] and env.pointer()[0] == UUID(details["generation_id"])
    assert len(env.visible_chunks()) == 3
    assert set(details["seconds"]) == {"locked_after", "verified", "total", "lock_held"}
    with workspace_transaction(env.engine, env.ws) as conn:
        settled = conn.execute(text("SELECT count(*) FROM app.usage_attempts WHERE state = 'settled'")).scalar_one()
        same = conn.execute(text("SELECT count(*) FROM app.chunks k JOIN app.embedding_cache e ON e.input_sha256 = "
                                 "k.embed_input_sha256 WHERE k.embedding::text = e.vector::text")).scalar_one()
    assert settled == 1 and same == 3


def test_the_default_plan_is_read_only(env: Env) -> None:
    before = env.counts()
    outcome = env.run(docs(), mode="plan")
    assert outcome.outcome == "planned" and outcome.details["estimate"]["batches"] == 1
    assert env.counts() == before and env.provider.requests == [] and env.credentials.reads == 0


def test_execute_with_misses_needs_explicit_paid_caps(env: Env) -> None:
    before = env.counts()
    outcome = env.run(docs())
    assert (outcome.outcome, outcome.reason, outcome.exit_code) == ("refused", "paid_execution_not_authorized", 2)
    assert env.counts() == before and env.credentials.reads == 0


@pytest.mark.parametrize(("caps", "reason"), [
    (paid(max_usd=Decimal("0.000000001")), "plan_exceeds_usd_cap"),
    (paid(max_calls=1), "plan_exceeds_call_cap"),
    (paid(max_input_tokens=10), "plan_exceeds_token_cap"),
    (paid(max_seconds=45), "plan_exceeds_job_window"),
    (paid(model="text-embedding-3-large"), "paid_model_or_dimensions_mismatch"),
    (paid(dimensions=512), "paid_model_or_dimensions_mismatch"),
])
def test_cap_breaches_refuse_before_any_write_or_credential_read(env: Env, caps: PaidCaps, reason: str) -> None:
    before = env.counts()
    outcome = env.run(docs(70), caps=caps)  # 70 distinct inputs: two batches (64 + 6)
    assert (outcome.outcome, outcome.reason) == ("refused", reason), outcome.to_json()
    assert env.counts() == before and env.credentials.reads == 0 and env.provider.requests == []


def test_a_repeat_import_writes_nothing_and_calls_nothing(env: Env) -> None:
    assert env.run(docs(), caps=paid()).outcome == "activated"
    before, requests, reads = env.counts(), len(env.provider.requests), env.credentials.reads
    for mode in ("plan", "execute"):
        outcome = env.run(docs(), mode=mode, caps=paid() if mode == "execute" else None)
        assert outcome.outcome == "unchanged" and outcome.exit_code == 0
    assert env.counts() == before and len(env.provider.requests) == requests and env.credentials.reads == reads


def test_an_edit_embeds_only_changed_exact_inputs_and_retires_the_old_generation(env: Env) -> None:
    first = env.run(docs(), caps=paid())
    old = UUID(first.details["generation_id"])
    sent = len(env.provider.inputs)
    edited = env.run(docs(edit={1: "Rule 1: refunds now go to store credit."}), caps=paid())
    assert edited.outcome == "activated", edited.to_json()
    assert env.provider.inputs[sent:] == ["Title 1\n\nRule 1: refunds now go to store credit."]  # measured
    assert edited.details["missing_inputs"] == 1 and edited.details["cached_inputs"] == 2
    assert edited.details["versions_new"] == 1 and edited.details["versions_reused"] == 2
    assert edited.details["retired_generation_id"] == str(old)
    assert env.statuses() == ["ready", "retired"]
    assert "Rule 1: refunds follow policy 1." not in env.visible_chunks()  # retired chunks are not retrievable
    back = env.run(docs(), caps=paid())  # the original content again: a new generation, every vector cached
    assert back.outcome == "activated" and back.details["missing_inputs"] == 0 and back.details["versions_new"] == 0


def test_identical_inputs_in_different_documents_are_embedded_once(env: Env) -> None:
    same = {"a": banking("a", "Same", "Identical body."), "b": banking("b", "Same", "Identical body.")}
    outcome = env.run(same, caps=paid())
    assert outcome.outcome == "activated" and outcome.details["chunks"] == 2
    assert env.provider.inputs == ["Same\n\nIdentical body."]


def test_all_cached_new_set_publishes_locally_without_paid_mode(env: Env) -> None:
    assert env.run(docs(), caps=paid(), key="other-corpus", domain="other_domain").outcome == "activated"
    reads = env.credentials.reads
    outcome = env.run(docs())  # execute, no paid caps, every exact input already cached in this workspace
    assert outcome.outcome == "activated" and outcome.details["missing_inputs"] == 0
    assert env.credentials.reads == reads and outcome.details["job_id"] is None


def test_a_complete_job_publishes_after_a_crash_even_after_its_deadline(shared_db: AppDatabase,
                                                                      tmp_path: Path) -> None:
    clock = FixedClock(datetime.now(UTC))
    env = Env(shared_db, tmp_path, clock=FixedLeaseClock(clock))
    first = env.run(docs(edit={0: "Original rule."}), caps=paid())
    assert first.outcome == "activated"

    def crash(connection: Connection, generation: UUID) -> None:
        raise RuntimeError("simulated crash inside publication")

    with pytest.raises(RuntimeError, match="simulated crash"):
        env.run(docs(), caps=paid(), before_verify=crash)
    assert env.statuses() == ["ready"] and env.pointer()[1] == 2  # rolled back: the old generation stays active
    clock.advance(timedelta(hours=2))  # far past the job's immutable 900-second window
    requests, reads = len(env.provider.requests), env.credentials.reads
    resumed = env.run(docs())  # execute without paid: no provider work remains
    assert resumed.outcome == "activated", resumed.to_json()
    assert len(env.provider.requests) == requests and env.credentials.reads == reads
    assert env.statuses() == ["ready", "retired"]
    with workspace_transaction(env.engine, env.ws) as conn:
        jobs = conn.execute(text("SELECT count(*), max(deadline_at) FROM app.embedding_jobs")).one()
    assert jobs[0] == 2  # no new job; the deadline was not extended


def test_an_expired_incomplete_job_stays_blocked_even_when_its_inputs_are_cached(shared_db: AppDatabase,
                                                                                tmp_path: Path) -> None:
    clock = FixedClock(datetime.now(UTC))
    env = Env(shared_db, tmp_path, clock=FixedLeaseClock(clock))
    assert env.run(docs(edit={0: "Original rule."}), caps=paid()).outcome == "activated"
    env.provider.fail_after = len(env.provider.requests)  # the next request's outcome is unknown
    unknown = env.run(docs(), caps=paid())
    assert unknown.outcome == "embedding_incomplete" and unknown.exit_code == 3, unknown.to_json()
    scope = unknown.details["scope"]
    assert Decimal(scope["held_usd"]) > 0 and scope["calls_consumed"] + scope["calls_held"] == 1  # unknown: held
    env.provider.fail_after = None
    # The same exact inputs become cached through another legitimate job (another corpus in this workspace).
    assert env.run(docs(), caps=paid(), key="other-corpus", domain="other_domain").outcome == "activated"
    before, requests, reads = env.counts(), len(env.provider.requests), env.credentials.reads
    pending = env.run(docs())
    assert (pending.outcome, pending.reason) == ("embedding_incomplete", "batches_unresolved"), pending.to_json()
    clock.advance(timedelta(hours=2))
    expired = env.run(docs(), caps=paid())
    assert (expired.outcome, expired.reason) == ("embedding_incomplete", "window_expired"), expired.to_json()
    assert expired.details["scope"]["held_usd"] == scope["held_usd"]  # accounting preserved
    assert env.counts() == before and len(env.provider.requests) == requests and env.credentials.reads == reads
    assert env.pointer(KEY)[1] == 2 and "Original rule." in "".join(env.visible_chunks())


def test_the_token_ceiling_is_a_cumulative_budget_over_the_frozen_plan(env: Env) -> None:
    documents = docs(70)  # two frozen batches
    expected = env.expected(documents)
    caps = paid()
    configuration = caps.configuration()
    store = EmbeddingStore(env.engine, env.ws, env="test")
    job_input = EmbeddingJob(purpose=PURPOSE, subject_key=expected.subject_key, inputs=expected.inputs)
    prepared = prepare_job(job_input, configuration, TOKENIZER, deadline=time.monotonic() + 60)
    job, batches = store.plan_job(prepared.identity, prepared.inputs, pack(prepared, configuration),
                                  window_seconds=caps.max_seconds)
    assert len(batches) == 2
    blocker = store.claim_lease(job.id, 1, uuid4(), 60)  # another live owner holds the second batch
    assert blocker is not None
    ledger = build_app_ledger(env="test", engine=env.engine, workspace_id=env.ws, configuration=configuration)
    report = asyncio.run(run_job(ledger, store, env.credentials(), prepared, deadline=time.monotonic() + 60,
                                 limits=EmbedLimits(lease_seconds=60, wait_seconds=0.3, poll_seconds=0.05,
                                                    attempt_seconds=30)))
    assert report.status == "in_progress_elsewhere" and len(env.provider.requests) == 1
    assert store.release_lease(blocker)
    frozen = sum(b.plan.local_tokens for b in batches)
    remaining = batches[1].plan.local_tokens
    before, reads = env.counts(), env.credentials.reads
    low = env.run(documents, caps=paid(max_input_tokens=remaining))  # covers the rest, not the frozen total
    assert (low.outcome, low.reason) == ("refused", "plan_exceeds_token_cap"), low.to_json()
    estimate = low.details["estimate"]
    assert (estimate["frozen_total_local_tokens"], estimate["local_tokens"],
            estimate["requested_token_ceiling"]) == (frozen, remaining, remaining)
    assert env.counts() == before and env.credentials.reads == reads and len(env.provider.requests) == 1
    full = env.run(documents, caps=paid(max_input_tokens=frozen))
    assert full.outcome == "activated", full.to_json()
    assert len(env.provider.requests) == 2  # only the remaining batch was sent


def test_a_resume_with_changed_caps_or_window_is_refused(env: Env) -> None:
    env.provider.fail_after = 0
    first = env.run(docs(70), caps=paid())
    assert first.outcome == "embedding_incomplete"
    env.provider.fail_after = None
    for caps in (paid(max_usd=Decimal("0.02")), paid(max_seconds=1200)):
        outcome = env.run(docs(70), caps=caps)
        assert outcome.reason in ("resume_configuration_changed", "batches_unresolved"), outcome.to_json()


def test_a_stale_snapshot_is_refused_and_nothing_is_written(env: Env) -> None:
    assert env.run(docs(), caps=paid()).outcome == "activated"
    expected = env.expected(docs(edit={2: "Rule 2 changed."}))
    assert env.run(docs(edit={2: "Rule 2 changed."}), caps=paid(), mode="execute").outcome == "activated"
    corpora = CorpusStore(env.engine, env.ws)
    stale = corpora.snapshot(KEY)
    assert env.run(docs(), caps=paid()).outcome == "activated"  # the corpus moved on after `stale`
    vectors = EmbeddingStore(env.engine, env.ws, env="test").cached(
        expected.request_config_sha256, [c.embed_input_sha256 for c in expected.chunks])
    before = env.counts()
    with pytest.raises(StaleActivation):
        corpora.publish(expected, vectors, stale)
    assert env.counts() == before


def _race(env: Env, first: Expected, second: Expected, snapshot: Any) -> list[str]:
    corpora = CorpusStore(env.engine, env.ws)
    vectors = EmbeddingStore(env.engine, env.ws, env="test").cached(
        first.request_config_sha256, [c.embed_input_sha256 for c in (*first.chunks, *second.chunks)])
    holding, release = threading.Event(), threading.Event()
    results: list[str] = []

    def hold(connection: Connection, generation: UUID) -> None:
        holding.set()
        assert release.wait(20)

    def publish(expected: Expected, hook: Any) -> None:
        try:
            corpora.publish(expected, vectors, snapshot, before_verify=hook)
            results.append("activated")
        except StaleActivation:
            results.append("stale")

    winner = threading.Thread(target=publish, args=(first, hold))
    loser = threading.Thread(target=publish, args=(second, None))
    try:
        winner.start()
        assert holding.wait(20)
        loser.start()
        time.sleep(0.5)  # the second publication is now blocked on the corpus row (or its insert conflict)
    finally:  # bounded cleanup on every path: release the holder, then join both threads
        release.set()
        for thread in (winner, loser):
            if thread.ident is not None:
                thread.join(30)
    assert not winner.is_alive() and not loser.is_alive()
    return results


def test_concurrent_first_activations_have_exactly_one_winner(env: Env) -> None:
    a, b = docs(edit={0: "Variant A."}), docs(edit={0: "Variant B."})
    for index, content in enumerate((a, b)):  # cache both variants' vectors through other corpora
        assert env.run(content, caps=paid(), key=f"cache-{index}", domain=f"cache_{index}").outcome == "activated"
    snapshot = CorpusStore(env.engine, env.ws).snapshot(KEY)
    assert not snapshot.exists
    results = _race(env, env.expected(a), env.expected(b), snapshot)
    assert sorted(results) == ["activated", "stale"]
    with workspace_transaction(env.engine, env.ws) as conn:
        ready = conn.execute(text("SELECT count(*) FROM app.index_generations WHERE corpus_key = :k AND status = "
                                  "'ready'"), {"k": KEY}).scalar_one()
    assert ready == 1 and env.pointer()[1] == 2


def test_concurrent_re_activations_have_exactly_one_winner(env: Env) -> None:
    assert env.run(docs(), caps=paid()).outcome == "activated"
    a, b = docs(edit={1: "Variant A."}), docs(edit={1: "Variant B."})
    for index, content in enumerate((a, b)):
        assert env.run(content, caps=paid(), key=f"cache-{index}", domain=f"cache_{index}").outcome == "activated"
    snapshot = CorpusStore(env.engine, env.ws).snapshot(KEY)
    results = _race(env, env.expected(a), env.expected(b), snapshot)
    assert sorted(results) == ["activated", "stale"] and env.pointer()[1] == snapshot.version + 1  # type: ignore[operator]
    assert env.statuses().count("ready") == 1 + 2  # this corpus's one ready generation plus the two cache corpora


def test_an_exact_set_mismatch_rolls_back_and_keeps_the_old_generation(env: Env) -> None:
    assert env.run(docs(), caps=paid()).outcome == "activated"
    assert env.run(docs(edit={0: "Changed."}), caps=paid(), key="cache-0", domain="cache_0").outcome == "activated"
    expected = env.expected(docs(edit={0: "Changed."}))
    tampered = replace(expected, expected_set_sha256="0" * 64)
    corpora = CorpusStore(env.engine, env.ws)
    before, pointer = env.counts(), env.pointer()
    vectors = EmbeddingStore(env.engine, env.ws, env="test").cached(
        expected.request_config_sha256, [c.embed_input_sha256 for c in expected.chunks])
    with pytest.raises(VerificationMismatch, match="expected_set_mismatch"):
        corpora.publish(tampered, vectors, corpora.snapshot(KEY))
    assert env.counts() == before and env.pointer() == pointer


def test_a_stored_version_whose_body_disagrees_with_its_digest_is_never_reused(env: Env) -> None:
    assert env.run(docs(edit={0: "Original."}), caps=paid()).outcome == "activated"
    target = docs(edit={0: " \n "})  # the next import: document d000 renders to a body producing no chunk
    expected = env.expected(target)
    source = next(d for d in expected.documents if d.source.document_key == "d000").source
    with workspace_transaction(env.engine, env.ws) as conn:
        document = conn.execute(text("SELECT id FROM app.documents WHERE source_uri = :u"),
                                {"u": source.source_uri}).scalar_one()
        for number, (digest, body) in enumerate([("9" * 64, "an unrelated corrupt old version"),
                                                 (source.version_sha256, "not the claimed body")], start=10):
            conn.execute(text("INSERT INTO app.document_versions (id, workspace_id, document_id, version, sha256, "
                              "body, status, effective_from, created_at) VALUES (:id, app.current_workspace(), "
                              ":d, :n, :s, :b, 'retired', now(), now())"),
                         {"id": uuid4(), "d": document, "n": number, "s": digest, "b": body})
    before, pointer = env.counts(), env.pointer()
    refused = env.run(target, caps=paid())
    assert (refused.outcome, refused.reason) == ("refused", "version_body_digest_mismatch"), refused.to_json()
    assert env.counts() == before and env.pointer() == pointer
    unrelated_only = env.run(docs(edit={0: "A new valid body."}), caps=paid())  # the corrupt old row is unrelated
    assert unrelated_only.outcome == "activated" and unrelated_only.details["versions_new"] == 1
    with workspace_transaction(env.engine, env.ws) as conn:
        latest = conn.execute(text("SELECT max(version) FROM app.document_versions WHERE document_id = :d"),
                              {"d": document}).scalar_one()
    assert latest == 12  # numbered after the highest existing version, history untouched


def test_source_identity_ownership_and_metadata_are_enforced(env: Env) -> None:
    assert env.run(docs(), caps=paid()).outcome == "activated"
    other = env.run(docs(), caps=paid(), key="other-corpus")  # same domain and keys: same source identities
    assert (other.outcome, other.reason) == ("refused", "source_identity_owned_by_other_corpus")
    with workspace_transaction(env.engine, env.ws) as conn:
        conn.execute(text("INSERT INTO app.documents (id, workspace_id, domain, publisher, source_uri, license, "
                          "created_at) VALUES (:id, app.current_workspace(), 'legacy_domain', 'Old', "
                          "'tau2:legacy_domain/d000', 'CC0', now())"), {"id": uuid4()})
    legacy = env.run(docs(), caps=paid(), key="legacy-corpus", domain="legacy_domain")
    assert (legacy.outcome, legacy.reason) == ("refused", "source_identity_legacy_conflict")


def test_tenants_never_share_corpora_chunks_or_vectors(shared_db: AppDatabase, tmp_path: Path) -> None:
    first, second = Env(shared_db, tmp_path / "a"), Env(shared_db, tmp_path / "b")
    assert first.run(docs(), caps=paid()).outcome == "activated"
    assert second.visible_chunks() == []
    with workspace_transaction(second.engine, second.ws) as conn:
        for table in ("app.corpora", "app.generation_documents", "app.embedding_cache", "app.index_generations"):
            assert conn.exec_driver_sql(f"SELECT count(*) FROM {table}").scalar_one() == 0  # noqa: S608
    outcome = second.run(docs(), caps=paid())
    assert outcome.outcome == "activated" and outcome.details["missing_inputs"] == 3
    assert len(second.provider.requests) == 1  # the same text in another workspace costs its own embedding
