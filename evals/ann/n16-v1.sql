-- Disposable benchmark schema. The bootstrap administrator owns the tables
-- and provides the explicitly unfiltered owner control.
CREATE SCHEMA n16;
REVOKE ALL ON SCHEMA n16 FROM PUBLIC;
GRANT USAGE ON SCHEMA n16 TO policyops_app_runtime;

CREATE TABLE n16.generations (
    workspace_id uuid NOT NULL,
    id integer NOT NULL,
    status text NOT NULL CHECK (status IN ('ready', 'retired')),
    PRIMARY KEY (workspace_id, id)
);
CREATE TABLE n16.chunks (
    id text COLLATE "C" PRIMARY KEY,
    workspace_id uuid NOT NULL,
    generation_id integer NOT NULL,
    embedding public.vector(1536) NOT NULL,
    FOREIGN KEY (workspace_id, generation_id) REFERENCES n16.generations (workspace_id, id)
);
CREATE INDEX n16_chunks_workspace_generation ON n16.chunks (workspace_id, generation_id);

ALTER TABLE n16.generations ENABLE ROW LEVEL SECURITY;
ALTER TABLE n16.generations FORCE ROW LEVEL SECURITY;
CREATE POLICY generations_workspace ON n16.generations FOR SELECT TO policyops_app_runtime
    USING (workspace_id = app.current_workspace());

ALTER TABLE n16.chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE n16.chunks FORCE ROW LEVEL SECURITY;
CREATE POLICY chunks_ready ON n16.chunks FOR SELECT TO policyops_app_runtime
    USING (
        workspace_id = app.current_workspace() AND EXISTS (
            SELECT 1 FROM n16.generations g
            WHERE g.workspace_id = chunks.workspace_id AND g.id = chunks.generation_id AND g.status = 'ready'
        )
    );
GRANT SELECT ON n16.generations, n16.chunks TO policyops_app_runtime;
