"""Bounded local query-plan and timing diagnostics for the retrieval branches (T15a).

Only two named operations exist: the fixed lexical and dense branch statements of `persistence.retrieval` (exact
search), each run as `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` against the corpus's current generation, as the app
runtime (verified), inside a workspace-scoped READ ONLY transaction. There is no arbitrary SQL, table or URL input; the
query text and vector are bound parameters. A lexical query is bounded by character count and allowed characters, a
dense vector by its dimension and value validity, and the branch size, chunks per document and repeat count by small
fixed limits. Those are input bounds only: this module performs no retrieval-step token admission and no embedding
call. The bounded repeats and inputs do not establish a hard wall-clock interruption of the SQL; a statement that is
running is not cancelled by them.

The output is a local diagnostic: the node types, planning and execution times PostgreSQL reported on this machine and
database, and the row count. It is not a production latency figure, a load test or any quality claim. Diagnostic
queries in tests are synthetic; public-title probes, if ever used, remain diagnostics too.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from decimal import Decimal
import json
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import Engine, text

from policyops.persistence.database import workspace_transaction
from policyops.persistence.embeddings import vector_text
from policyops.persistence.retrieval import DENSE_SQL, LEXICAL_SQL, RetrievalStore
from policyops.retrieval.search import valid_vector
from policyops_contracts.retrieval import MAX_QUERY_CODE_POINTS


Operation = Literal["lexical_branch", "dense_branch"]
STATEMENTS: dict[str, str] = {"lexical_branch": LEXICAL_SQL, "dense_branch": DENSE_SQL}
MAX_REPEAT = 10


class DiagnosticRefused(ValueError):
    pass


@dataclass(frozen=True)
class PlanSample:
    operation: Operation
    generation_id: UUID
    node_types: tuple[str, ...]
    planning_ms: tuple[Decimal, ...]
    execution_ms: tuple[Decimal, ...]
    rows: int
    label: Literal["local diagnostic; not a production latency or quality claim"] = (
        "local diagnostic; not a production latency or quality claim")


def _nodes(plan: Any) -> Iterator[str]:
    yield str(plan["Node Type"])
    for child in plan.get("Plans", ()):
        yield from _nodes(child)


def _check(operation: str, query: str | None, vector: Sequence[float] | None, branch_documents: int,
           chunks_per_document: int, repeat: int) -> dict[str, Any]:
    if operation not in STATEMENTS:
        raise DiagnosticRefused("unknown operation")
    bounded = ((branch_documents, 1, 50, "branch_documents"), (chunks_per_document, 1, 3, "chunks_per_document"),
               (repeat, 1, MAX_REPEAT, "repeat"))
    for value, low, high, what in bounded:
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise DiagnosticRefused(f"{what} is an integer from {low} to {high}")
    params: dict[str, Any] = {"n": branch_documents, "per": chunks_per_document, "docs": None}
    if operation == "lexical_branch":
        if (not isinstance(query, str) or not query.strip() or len(query) > MAX_QUERY_CODE_POINTS
                or any(ord(c) < 32 and c not in "\t\n\r" for c in query) or "\x7f" in query):
            raise DiagnosticRefused("a lexical diagnostic needs a bounded query text")
        params["q"] = query
    else:
        if vector is None or not valid_vector(vector):
            raise DiagnosticRefused("a dense diagnostic needs a valid 1536-dimension vector")
        params["qv"] = vector_text(tuple(vector))
    return params


def explain(engine: Engine, workspace_id: UUID, corpus_key: str, operation: Operation, *, query: str | None = None,
            vector: Sequence[float] | None = None, branch_documents: int = 20, chunks_per_document: int = 2,
            repeat: int = 3) -> PlanSample:
    params = _check(operation, query, vector, branch_documents, chunks_per_document, repeat)
    store = RetrievalStore(engine, workspace_id)  # verifies the app runtime role
    generation = store.pointer(corpus_key)
    if generation is None:
        raise DiagnosticRefused("the corpus has no active generation")
    params["g"] = generation
    planning: list[Decimal] = []
    execution: list[Decimal] = []
    nodes: set[str] = set()
    rows = 0
    statement = text("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + STATEMENTS[operation])
    for _ in range(repeat):
        with workspace_transaction(engine, workspace_id) as connection:
            connection.execute(text("SET TRANSACTION READ ONLY"))
            raw = connection.execute(statement, params).scalar_one()
        document = (raw if isinstance(raw, list) else json.loads(raw))[0]
        planning.append(Decimal(str(document["Planning Time"])))
        execution.append(Decimal(str(document["Execution Time"])))
        nodes.update(_nodes(document["Plan"]))
        rows = int(document["Plan"].get("Actual Rows", 0))
    return PlanSample(operation, generation, tuple(sorted(nodes)), tuple(planning), tuple(execution), rows)
