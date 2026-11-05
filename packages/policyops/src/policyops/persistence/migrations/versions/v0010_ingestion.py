"""Versioned corpus ingestion (T12): corpora, generation provenance and membership, chunk section and embedding
provenance, and database guards for publication and citations. Forward-only by default.

* `app.corpora`: one stable slot per `(workspace, corpus_key)` with the active generation pointer and an optimistic
  `version`; activation is a compare-and-swap on this row. The pointer references `(workspace, corpus_key, id)` of
  a generation, so it can only name a generation of the same corpus. Runtime: SELECT, INSERT and
  `UPDATE (active_generation_id, version, updated_at)`.
* `app.index_generations` gains corpus provenance (source repository, commit and tree, manifest digests, license
  scope, render, chunk configuration, tokenizer, request configuration, expected-set and generation-key digests and
  counts). They are all NULL (legacy rows) or all set. At most one `ready` generation per corpus.
* `app.generation_documents`: the exact document membership of a generation (including documents without chunks)
  with per-revision path, git blob and raw file digest and size. Select and insert only.
* `app.documents` gains the owning `corpus_key` (NULL for legacy rows) and a unique stable `source_uri` per
  workspace.
* `app.chunks` gains section metadata, the plain text digest (a CHECK ties it to the text), the exact embedding
  input digest and request configuration (a foreign key to the immutable embedding cache entry), a unique
  position identity per generation, and a key for the citation foreign key.
* `app.citations` gains a composite foreign key: the cited document version must be the cited chunk's.

Guards (PL/pgSQL, SECURITY INVOKER, `search_path = pg_catalog`, no EXECUTE for PUBLIC; they run with the inserting
role's own privileges and row-level security):

* `guard_generation_member` (BEFORE INSERT on `chunks` and `generation_documents`): the generation must be visible
  and `building`, read `FOR SHARE`. That lock conflicts with the `FOR NO KEY UPDATE` of a status change and is held
  until the inserting transaction ends, so no row can be added to a generation after another transaction verified
  and activated it (an FK check alone takes only `FOR KEY SHARE`).
* `guard_generation_insert` (BEFORE INSERT on `index_generations`): a corpus generation starts `building`.
* `guard_generation_transition` (BEFORE UPDATE on `index_generations`, every row including legacy ones): only
  building -> ready, building -> failed and ready -> retired; `ready_at` changes only with building -> ready.
* `check_generation_publication` (deferred constraint trigger on `index_generations` and `corpora`): at commit a
  corpus generation is never `building`, and it is `ready` exactly when its corpus points at it. A structural
  invariant only: it does not inspect chunk contents.
* `guard_citation_insert` (BEFORE INSERT on `citations`): the chunk must be visible to the inserting role (for the
  app runtime: in a ready generation), in the trace's generation and document version, and contain the span.

The upgrade first checks existing rows: duplicate document source identities, duplicate chunk positions, and
citations whose document version, trace generation or span disagree with their chunk. Any of these refuses the whole
upgrade with the counts (no IDs or text); nothing is repaired or dropped. Passing validates structural agreement only.

The downgrade is refused by default while any ingestion data exists (new tables or new columns set); with the
explicit destructive override it drops the guards, constraints, columns and tables, and ingested chunks, versions and
documents remain as legacy rows without their provenance.

Revision ID: 0010
"""

from alembic import context, op
from sqlalchemy import Connection

from policyops.persistence.migration_guard import DataLossRefused, refuse_data_loss


revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

APP = "policyops_app_runtime"
SHA = "~ '^[0-9a-f]{64}$'"
HEX40 = "~ '^[0-9a-f]{40}$'"
SLUG = "~ '^[a-z][a-z0-9_.-]{0,63}$'"
GENERATION_COLUMNS = ("corpus_key", "source_repository", "source_commit", "source_tree", "source_manifest_sha256",
                      "corpus_manifest_sha256", "license_scope", "render", "chunk_config", "tokenizer_sha256",
                      "request_config_sha256", "expected_set_sha256", "generation_key_sha256", "document_count",
                      "chunk_count")
CHUNK_COLUMNS = ("section_ordinal", "section_start", "section_end", "text_sha256", "embed_input_sha256",
                 "request_config_sha256")


class LegacyIncompatible(RuntimeError):
    """Existing rows violate a constraint this revision adds; the upgrade is refused and nothing is changed."""


SCHEMA = rf"""
CREATE TABLE app.corpora (
    workspace_id uuid NOT NULL REFERENCES identity.workspaces (id),
    corpus_key text NOT NULL CONSTRAINT corpora_key_format CHECK (corpus_key {SLUG}),
    domain text NOT NULL CONSTRAINT corpora_domain_format CHECK (domain {SLUG}),
    active_generation_id uuid,
    version bigint NOT NULL DEFAULT 1 CONSTRAINT corpora_version_positive CHECK (version >= 1),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL CONSTRAINT corpora_updated_after_created CHECK (updated_at >= created_at),
    CONSTRAINT corpora_pkey PRIMARY KEY (workspace_id, corpus_key)
);
ALTER TABLE app.index_generations
    ADD COLUMN corpus_key text CONSTRAINT index_generations_corpus_key_format CHECK (corpus_key {SLUG}),
    ADD COLUMN source_repository text CONSTRAINT index_generations_source_repository_length
        CHECK (char_length(source_repository) >= 1 AND char_length(source_repository) <= 200),
    ADD COLUMN source_commit text CONSTRAINT index_generations_source_commit CHECK (source_commit {HEX40}),
    ADD COLUMN source_tree text CONSTRAINT index_generations_source_tree CHECK (source_tree {HEX40}),
    ADD COLUMN source_manifest_sha256 text
        CONSTRAINT index_generations_source_manifest_digest CHECK (source_manifest_sha256 {SHA}),
    ADD COLUMN corpus_manifest_sha256 text
        CONSTRAINT index_generations_corpus_manifest_digest CHECK (corpus_manifest_sha256 {SHA}),
    ADD COLUMN license_scope text CONSTRAINT index_generations_license_scope_length
        CHECK (char_length(license_scope) >= 1 AND char_length(license_scope) <= 2000),
    ADD COLUMN render text CONSTRAINT index_generations_render_values
        CHECK (render IN ('identity', 'tau2-banking/v1')),
    ADD COLUMN chunk_config text CONSTRAINT index_generations_chunk_config_length
        CHECK (char_length(chunk_config) >= 1 AND char_length(chunk_config) <= 100),
    ADD COLUMN tokenizer_sha256 text CONSTRAINT index_generations_tokenizer_digest CHECK (tokenizer_sha256 {SHA}),
    ADD COLUMN request_config_sha256 text
        CONSTRAINT index_generations_request_config_digest CHECK (request_config_sha256 {SHA}),
    ADD COLUMN expected_set_sha256 text
        CONSTRAINT index_generations_expected_set_digest CHECK (expected_set_sha256 {SHA}),
    ADD COLUMN generation_key_sha256 text
        CONSTRAINT index_generations_generation_key_digest CHECK (generation_key_sha256 {SHA}),
    ADD COLUMN document_count integer CONSTRAINT index_generations_document_count
        CHECK (document_count >= 0 AND document_count <= 2000),
    ADD COLUMN chunk_count integer CONSTRAINT index_generations_chunk_count
        CHECK (chunk_count >= 0 AND chunk_count <= 10000),
    ADD CONSTRAINT index_generations_corpus_all_or_none
        CHECK (num_nulls({", ".join(GENERATION_COLUMNS)}) IN (0, {len(GENERATION_COLUMNS)})),
    ADD CONSTRAINT index_generations_corpus FOREIGN KEY (workspace_id, corpus_key)
        REFERENCES app.corpora (workspace_id, corpus_key),
    ADD CONSTRAINT index_generations_corpus_id_unique UNIQUE (workspace_id, corpus_key, id);
CREATE UNIQUE INDEX index_generations_one_ready_per_corpus ON app.index_generations (workspace_id, corpus_key)
    WHERE status = 'ready' AND corpus_key IS NOT NULL;
ALTER TABLE app.corpora ADD CONSTRAINT corpora_active_generation
    FOREIGN KEY (workspace_id, corpus_key, active_generation_id)
    REFERENCES app.index_generations (workspace_id, corpus_key, id);
ALTER TABLE app.documents
    ADD COLUMN corpus_key text CONSTRAINT documents_corpus_key_format CHECK (corpus_key {SLUG}),
    ADD CONSTRAINT documents_corpus FOREIGN KEY (workspace_id, corpus_key)
        REFERENCES app.corpora (workspace_id, corpus_key),
    ADD CONSTRAINT documents_source_unique UNIQUE (workspace_id, source_uri);
CREATE TABLE app.generation_documents (
    workspace_id uuid NOT NULL,
    generation_id uuid NOT NULL,
    document_version_id uuid NOT NULL,
    ordinal integer NOT NULL CONSTRAINT generation_documents_ordinal CHECK (ordinal >= 0 AND ordinal <= 1999),
    source_uri text NOT NULL CONSTRAINT generation_documents_source_uri_length
        CHECK (char_length(source_uri) >= 1 AND char_length(source_uri) <= 2000),
    source_path text NOT NULL CONSTRAINT generation_documents_source_path_length
        CHECK (char_length(source_path) >= 1 AND char_length(source_path) <= 1000),
    git_blob text NOT NULL CONSTRAINT generation_documents_git_blob CHECK (git_blob {HEX40}),
    raw_sha256 text NOT NULL CONSTRAINT generation_documents_raw_digest CHECK (raw_sha256 {SHA}),
    raw_bytes integer NOT NULL CONSTRAINT generation_documents_raw_bytes
        CHECK (raw_bytes >= 1 AND raw_bytes <= 4194304),
    chunk_count integer NOT NULL CONSTRAINT generation_documents_chunk_count
        CHECK (chunk_count >= 0 AND chunk_count <= 10000),
    created_at timestamptz NOT NULL,
    CONSTRAINT generation_documents_pkey PRIMARY KEY (workspace_id, generation_id, document_version_id),
    CONSTRAINT generation_documents_source_unique UNIQUE (workspace_id, generation_id, source_uri),
    CONSTRAINT generation_documents_ordinal_unique UNIQUE (workspace_id, generation_id, ordinal),
    CONSTRAINT generation_documents_generation FOREIGN KEY (workspace_id, generation_id)
        REFERENCES app.index_generations (workspace_id, id),
    CONSTRAINT generation_documents_version FOREIGN KEY (workspace_id, document_version_id)
        REFERENCES app.document_versions (workspace_id, id)
);
ALTER TABLE app.chunks
    ADD COLUMN section_ordinal integer CONSTRAINT chunks_section_ordinal CHECK (section_ordinal >= 0),
    ADD COLUMN section_start integer,
    ADD COLUMN section_end integer,
    ADD COLUMN text_sha256 text CONSTRAINT chunks_text_digest
        CHECK (text_sha256 = encode(sha256(convert_to(text, 'UTF8')), 'hex')),
    ADD COLUMN embed_input_sha256 text CONSTRAINT chunks_embed_input_digest CHECK (embed_input_sha256 {SHA}),
    ADD COLUMN request_config_sha256 text CONSTRAINT chunks_request_config_digest CHECK (request_config_sha256 {SHA}),
    ADD CONSTRAINT chunks_ingestion_all_or_none
        CHECK (num_nulls({", ".join(CHUNK_COLUMNS)}) IN (0, {len(CHUNK_COLUMNS)})),
    ADD CONSTRAINT chunks_within_section CHECK (section_start <= start_offset AND end_offset <= section_end),
    ADD CONSTRAINT chunks_ingested_vector CHECK (embed_input_sha256 IS NULL OR embedding IS NOT NULL),
    ADD CONSTRAINT chunks_position_unique
        UNIQUE (workspace_id, generation_id, document_version_id, start_offset, end_offset),
    ADD CONSTRAINT chunks_version_key UNIQUE (workspace_id, id, document_version_id),
    ADD CONSTRAINT chunks_cached_vector FOREIGN KEY (workspace_id, embed_input_sha256, request_config_sha256)
        REFERENCES app.embedding_cache (workspace_id, input_sha256, request_config_sha256);
ALTER TABLE app.citations ADD CONSTRAINT citations_chunk_version
    FOREIGN KEY (workspace_id, chunk_id, document_version_id)
    REFERENCES app.chunks (workspace_id, id, document_version_id) NOT VALID;
ALTER TABLE app.citations VALIDATE CONSTRAINT citations_chunk_version;
"""

GUARDS = r"""
CREATE FUNCTION app.guard_generation_member() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
    SET search_path = pg_catalog AS $$
DECLARE
    state text;
BEGIN
    SELECT g.status INTO state FROM app.index_generations g
        WHERE g.workspace_id = NEW.workspace_id AND g.id = NEW.generation_id FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'generation_not_visible' USING ERRCODE = 'check_violation';
    END IF;
    IF state <> 'building' THEN
        RAISE EXCEPTION 'generation_not_building' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;
CREATE FUNCTION app.guard_generation_insert() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
    SET search_path = pg_catalog AS $$
BEGIN
    IF NEW.corpus_key IS NOT NULL AND (NEW.status <> 'building' OR NEW.ready_at IS NOT NULL) THEN
        RAISE EXCEPTION 'generation_must_start_building' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;
CREATE FUNCTION app.guard_generation_transition() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
    SET search_path = pg_catalog AS $$
BEGIN
    IF NEW.status = OLD.status THEN
        IF NEW.ready_at IS DISTINCT FROM OLD.ready_at THEN
            RAISE EXCEPTION 'generation_ready_at_immutable' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF NOT ((OLD.status = 'building' AND NEW.status IN ('ready', 'failed'))
            OR (OLD.status = 'ready' AND NEW.status = 'retired')) THEN
        RAISE EXCEPTION 'generation_transition_refused' USING ERRCODE = 'check_violation';
    END IF;
    IF NOT (OLD.status = 'building' AND NEW.status = 'ready') AND NEW.ready_at IS DISTINCT FROM OLD.ready_at THEN
        RAISE EXCEPTION 'generation_ready_at_immutable' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;
CREATE FUNCTION app.check_generation_publication() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
    SET search_path = pg_catalog AS $$
DECLARE
    gen_status text;
    gen_corpus text;
    pointer uuid;
    has_corpus boolean;
BEGIN
    IF TG_TABLE_NAME = 'index_generations' THEN
        SELECT g.status, g.corpus_key INTO gen_status, gen_corpus FROM app.index_generations g
            WHERE g.workspace_id = NEW.workspace_id AND g.id = NEW.id;
        IF NOT FOUND OR gen_corpus IS NULL THEN
            RETURN NULL;
        END IF;
        IF gen_status = 'building' THEN
            RAISE EXCEPTION 'generation_left_building' USING ERRCODE = 'check_violation';
        END IF;
        SELECT c.active_generation_id INTO pointer FROM app.corpora c
            WHERE c.workspace_id = NEW.workspace_id AND c.corpus_key = gen_corpus;
        has_corpus := FOUND;
        IF (gen_status = 'ready') <> (has_corpus AND pointer IS NOT DISTINCT FROM NEW.id) THEN
            RAISE EXCEPTION 'generation_pointer_mismatch' USING ERRCODE = 'check_violation';
        END IF;
    ELSE
        SELECT c.active_generation_id INTO pointer FROM app.corpora c
            WHERE c.workspace_id = NEW.workspace_id AND c.corpus_key = NEW.corpus_key;
        IF FOUND AND pointer IS NOT NULL THEN
            SELECT g.status INTO gen_status FROM app.index_generations g
                WHERE g.workspace_id = NEW.workspace_id AND g.id = pointer;
            IF gen_status IS DISTINCT FROM 'ready' THEN
                RAISE EXCEPTION 'corpus_pointer_not_ready' USING ERRCODE = 'check_violation';
            END IF;
        END IF;
    END IF;
    RETURN NULL;
END $$;
CREATE FUNCTION app.guard_citation_insert() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
    SET search_path = pg_catalog AS $$
DECLARE
    chunk_generation uuid;
    chunk_version uuid;
    chunk_start integer;
    chunk_end integer;
    trace_generation uuid;
BEGIN
    SELECT k.generation_id, k.document_version_id, k.start_offset, k.end_offset
        INTO chunk_generation, chunk_version, chunk_start, chunk_end
        FROM app.chunks k WHERE k.workspace_id = NEW.workspace_id AND k.id = NEW.chunk_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'citation_chunk_not_ready' USING ERRCODE = 'check_violation';
    END IF;
    SELECT t.generation_id INTO trace_generation FROM app.retrieval_traces t
        WHERE t.workspace_id = NEW.workspace_id AND t.id = NEW.trace_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'citation_trace_not_visible' USING ERRCODE = 'check_violation';
    END IF;
    IF trace_generation <> chunk_generation THEN
        RAISE EXCEPTION 'citation_generation_mismatch' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.document_version_id <> chunk_version THEN
        RAISE EXCEPTION 'citation_version_mismatch' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.span_start < chunk_start OR NEW.span_end > chunk_end THEN
        RAISE EXCEPTION 'citation_span_outside_chunk' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER chunks_generation_member BEFORE INSERT ON app.chunks
    FOR EACH ROW EXECUTE FUNCTION app.guard_generation_member();
CREATE TRIGGER generation_documents_generation_member BEFORE INSERT ON app.generation_documents
    FOR EACH ROW EXECUTE FUNCTION app.guard_generation_member();
CREATE TRIGGER index_generations_insert_guard BEFORE INSERT ON app.index_generations
    FOR EACH ROW EXECUTE FUNCTION app.guard_generation_insert();
CREATE TRIGGER index_generations_transition_guard BEFORE UPDATE ON app.index_generations
    FOR EACH ROW EXECUTE FUNCTION app.guard_generation_transition();
CREATE CONSTRAINT TRIGGER index_generations_publication AFTER INSERT OR UPDATE ON app.index_generations
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION app.check_generation_publication();
CREATE CONSTRAINT TRIGGER corpora_publication AFTER INSERT OR UPDATE ON app.corpora
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION app.check_generation_publication();
CREATE TRIGGER citations_insert_guard BEFORE INSERT ON app.citations
    FOR EACH ROW EXECUTE FUNCTION app.guard_citation_insert();
"""

FUNCTIONS = ("app.guard_generation_member()", "app.guard_generation_insert()", "app.guard_generation_transition()",
             "app.check_generation_publication()", "app.guard_citation_insert()")
NEW_TABLES = ("app.corpora", "app.generation_documents")

LEGACY_CHECKS = {
    # Each query counts violating rows of a constraint this revision adds; table and column names are fixed.
    "duplicate_document_source": "SELECT count(*) FROM (SELECT 1 FROM app.documents "
                                 "GROUP BY workspace_id, source_uri HAVING count(*) > 1) d",
    "duplicate_chunk_position": "SELECT count(*) FROM (SELECT 1 FROM app.chunks GROUP BY workspace_id, generation_id, "
                                "document_version_id, start_offset, end_offset HAVING count(*) > 1) d",
    "citation_version_mismatch": "SELECT count(*) FROM app.citations c JOIN app.chunks k "
                                 "ON k.workspace_id = c.workspace_id AND k.id = c.chunk_id "
                                 "WHERE k.document_version_id <> c.document_version_id",
    "citation_generation_mismatch": "SELECT count(*) FROM app.citations c JOIN app.chunks k "
                                    "ON k.workspace_id = c.workspace_id AND k.id = c.chunk_id "
                                    "JOIN app.retrieval_traces t ON t.workspace_id = c.workspace_id "
                                    "AND t.id = c.trace_id WHERE t.generation_id <> k.generation_id",
    "citation_span_outside_chunk": "SELECT count(*) FROM app.citations c JOIN app.chunks k "
                                   "ON k.workspace_id = c.workspace_id AND k.id = c.chunk_id "
                                   "WHERE c.span_start < k.start_offset OR c.span_end > k.end_offset",
}
INGESTION_DATA = {
    "app.index_generations": "SELECT EXISTS (SELECT 1 FROM app.index_generations WHERE corpus_key IS NOT NULL)",
    "app.chunks": "SELECT EXISTS (SELECT 1 FROM app.chunks WHERE text_sha256 IS NOT NULL)",
    "app.documents": "SELECT EXISTS (SELECT 1 FROM app.documents WHERE corpus_key IS NOT NULL)",
}


def _unforced(connection: Connection, tables: tuple[str, ...], queries: dict[str, str]) -> dict[str, object]:
    """Run fixed queries with FORCE ROW LEVEL SECURITY lifted on `tables` (the owning migrator has no data policy),
    then restore each table's previous FORCE state exactly; a raise rolls the whole migration back anyway."""
    forced = {table: connection.exec_driver_sql(
        "SELECT relforcerowsecurity FROM pg_class WHERE oid = %s::regclass", (table,)).scalar() for table in tables}
    for table in tables:
        connection.exec_driver_sql(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
    results = {name: connection.exec_driver_sql(query).scalar() for name, query in queries.items()}
    for table, was_forced in forced.items():
        if was_forced:
            connection.exec_driver_sql(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
    return results


def upgrade() -> None:
    connection = op.get_bind()
    counts = _unforced(connection, ("app.documents", "app.chunks", "app.citations", "app.retrieval_traces"),
                       LEGACY_CHECKS)
    violations = {name: count for name, count in counts.items() if count}
    if violations:
        raise LegacyIncompatible(f"existing rows are incompatible with revision 0010: {violations}; "
                                 "nothing was changed (repair is an operator decision outside the migration)")
    op.execute(SCHEMA)
    for table in NEW_TABLES:
        name = table.split(".")[1]
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; ALTER TABLE {table} FORCE ROW LEVEL SECURITY; "
                   f"CREATE POLICY {name}_app_workspace ON {table} TO {APP} "
                   "USING (workspace_id = app.current_workspace()) "
                   "WITH CHECK (workspace_id = app.current_workspace())")
    op.execute(f"GRANT SELECT, INSERT, UPDATE (active_generation_id, version, updated_at) ON app.corpora TO {APP}; "
               f"GRANT SELECT, INSERT ON app.generation_documents TO {APP}")
    op.execute(GUARDS)
    for function in FUNCTIONS:
        op.execute(f"REVOKE ALL ON FUNCTION {function} FROM PUBLIC")


def downgrade() -> None:
    connection = op.get_bind()
    refuse_data_loss(NEW_TABLES)  # rows in the two new tables (unless allow_data_loss)
    if not context.config.attributes.get("allow_data_loss"):
        present = _unforced(connection, tuple(INGESTION_DATA), INGESTION_DATA)  # new columns set on old tables
        held = sorted(table for table, found in present.items() if found)
        if held:
            raise DataLossRefused(f"downgrade would drop ingestion data in {', '.join(held)}; "
                                  "pass allow_data_loss=True to accept that")
    op.execute("""
        DROP TRIGGER citations_insert_guard ON app.citations;
        DROP TRIGGER corpora_publication ON app.corpora;
        DROP TRIGGER index_generations_publication ON app.index_generations;
        DROP TRIGGER index_generations_transition_guard ON app.index_generations;
        DROP TRIGGER index_generations_insert_guard ON app.index_generations;
        DROP TRIGGER generation_documents_generation_member ON app.generation_documents;
        DROP TRIGGER chunks_generation_member ON app.chunks;
        ALTER TABLE app.citations DROP CONSTRAINT citations_chunk_version;
        ALTER TABLE app.chunks DROP CONSTRAINT chunks_cached_vector, DROP CONSTRAINT chunks_version_key,
            DROP CONSTRAINT chunks_position_unique, DROP CONSTRAINT chunks_ingested_vector,
            DROP CONSTRAINT chunks_within_section, DROP CONSTRAINT chunks_ingestion_all_or_none,
            DROP COLUMN request_config_sha256, DROP COLUMN embed_input_sha256, DROP COLUMN text_sha256,
            DROP COLUMN section_end, DROP COLUMN section_start, DROP COLUMN section_ordinal;
        DROP TABLE app.generation_documents;
        ALTER TABLE app.documents DROP CONSTRAINT documents_source_unique, DROP CONSTRAINT documents_corpus,
            DROP COLUMN corpus_key;
        ALTER TABLE app.corpora DROP CONSTRAINT corpora_active_generation;
        DROP INDEX app.index_generations_one_ready_per_corpus;
        ALTER TABLE app.index_generations DROP CONSTRAINT index_generations_corpus_id_unique,
            DROP CONSTRAINT index_generations_corpus, DROP CONSTRAINT index_generations_corpus_all_or_none,
            DROP COLUMN chunk_count, DROP COLUMN document_count, DROP COLUMN generation_key_sha256,
            DROP COLUMN expected_set_sha256, DROP COLUMN request_config_sha256, DROP COLUMN tokenizer_sha256,
            DROP COLUMN chunk_config, DROP COLUMN render, DROP COLUMN license_scope,
            DROP COLUMN corpus_manifest_sha256, DROP COLUMN source_manifest_sha256, DROP COLUMN source_tree,
            DROP COLUMN source_commit, DROP COLUMN source_repository, DROP COLUMN corpus_key;
        DROP TABLE app.corpora;
    """)
    for function in reversed(FUNCTIONS):
        op.execute(f"DROP FUNCTION {function}")
