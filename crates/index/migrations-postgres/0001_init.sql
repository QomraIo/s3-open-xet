-- openxet index schema on Postgres: the end state of SQLite's migrations
-- 0001 to 0007 (ruling M3-R2). The bucket is the source of truth (design
-- §5.3); every row here can be rebuilt from stored xorbs and shards and the
-- bucket's records. Hashes are the 32 raw bytes of a MerkleHash, repository
-- and pack ids the 16 raw bytes of a UUIDv7, object ids the 20 raw bytes of
-- a SHA-1. Times are Unix seconds unless named otherwise.
--
-- The tables a dedup query or a reconstruction reads by hash are
-- PARTITION BY HASH on that hash, 16 ways (design §5.8). Changing the
-- count is a migration.

-- Content-addressed xorbs. chunk_table is (hash 32 B, uncompressed length
-- u32 LE, offset u32 LE) per chunk, then the final offset (u32 LE).
-- ingested_seq orders xorbs by first ingestion for dedup answers; it comes
-- from a sequence, since nodes insert concurrently.
CREATE SEQUENCE xorbs_ingested_seq;

CREATE TABLE xorbs (
    hash BYTEA NOT NULL,
    size BIGINT NOT NULL,
    chunk_count BIGINT NOT NULL,
    chunk_table BYTEA NOT NULL,
    ingested_seq BIGINT NOT NULL,
    PRIMARY KEY (hash)
) PARTITION BY HASH (hash);

-- What reconstruction planning reads of a xorb's chunk table, without the
-- chunk hashes: (uncompressed length u32 LE, offset u32 LE) per chunk, then
-- the final offset (u32 LE).
CREATE TABLE xorb_layouts (
    xorb BYTEA NOT NULL REFERENCES xorbs (hash),
    chunk_layout BYTEA NOT NULL,
    PRIMARY KEY (xorb)
) PARTITION BY HASH (xorb);

-- The tenants a xorb is owned by (rulings M1-R38, M1-R39).
CREATE TABLE xorb_owners (
    xorb BYTEA NOT NULL REFERENCES xorbs (hash),
    tenant TEXT NOT NULL,
    PRIMARY KEY (xorb, tenant)
) PARTITION BY HASH (xorb);

-- Files registered to a scope, each with that scope's own reconstruction
-- (ruling M1-R16). terms is (xorb 32 B, chunk start u32 LE, chunk end u32
-- LE, unpacked bytes u32 LE) per term; term_bytes (start u32 LE, end u32 LE)
-- per term. Of two registrations of one file to one scope, the row of the
-- lowest (registered_seq, shard, registered_tenant) is kept (ruling M1-R37).
CREATE TABLE file_scopes (
    file BYTEA NOT NULL,
    scope TEXT NOT NULL,
    size BIGINT NOT NULL,
    terms BYTEA NOT NULL,
    sha256 BYTEA,
    shard BYTEA NOT NULL,
    term_bytes BYTEA,
    registered_seq BIGINT NOT NULL,
    registered_tenant TEXT NOT NULL,
    PRIMARY KEY (file, scope)
) PARTITION BY HASH (file);

-- file_by_sha256 looks a file up by its client-asserted SHA-256 within one
-- scope (design §5.4).
CREATE INDEX file_scopes_scope_sha256 ON file_scopes (scope, sha256);

-- Global dedup candidates: eligible chunks and files' first chunks.
CREATE TABLE dedup (
    chunk BYTEA NOT NULL,
    xorb BYTEA NOT NULL REFERENCES xorbs (hash),
    PRIMARY KEY (chunk, xorb)
) PARTITION BY HASH (chunk);

DO $$
BEGIN
    FOR i IN 0..15 LOOP
        EXECUTE format(
            'CREATE TABLE xorbs_p%s PARTITION OF xorbs FOR VALUES WITH (MODULUS 16, REMAINDER %s)',
            i, i);
        EXECUTE format(
            'CREATE TABLE xorb_layouts_p%s PARTITION OF xorb_layouts FOR VALUES WITH (MODULUS 16, REMAINDER %s)',
            i, i);
        EXECUTE format(
            'CREATE TABLE xorb_owners_p%s PARTITION OF xorb_owners FOR VALUES WITH (MODULUS 16, REMAINDER %s)',
            i, i);
        EXECUTE format(
            'CREATE TABLE file_scopes_p%s PARTITION OF file_scopes FOR VALUES WITH (MODULUS 16, REMAINDER %s)',
            i, i);
        EXECUTE format(
            'CREATE TABLE dedup_p%s PARTITION OF dedup FOR VALUES WITH (MODULUS 16, REMAINDER %s)',
            i, i);
    END LOOP;
END
$$;

-- Orders the newest-xorb lookup of dedup answers.
CREATE INDEX xorbs_ingested_seq_idx ON xorbs (ingested_seq);

-- One row per registration of a shard to a scope for a tenant, as one
-- bucket record names it.
CREATE TABLE shard_registrations (
    shard BYTEA NOT NULL,
    scope TEXT NOT NULL,
    tenant TEXT NOT NULL,
    registered_seq BIGINT NOT NULL,
    PRIMARY KEY (shard, scope, tenant)
);

CREATE INDEX shard_registrations_registered_seq ON shard_registrations (registered_seq);

-- The distinct xorbs a shard's files reference, pos counting from 0 in the
-- shard's term order (ruling M1-R30).
CREATE TABLE shard_xorbs (
    shard BYTEA NOT NULL,
    pos BIGINT NOT NULL,
    xorb BYTEA NOT NULL REFERENCES xorbs (hash),
    PRIMARY KEY (shard, pos)
);

CREATE INDEX shard_xorbs_xorb ON shard_xorbs (xorb);

-- The registration sequence numbers handed out (ruling M1-R37).
CREATE SEQUENCE registration_seq;

-- Repositories (ADR 0004, rulings M2-R2, M2-R12). name_key is
-- lower(namespace) || '/' || lower(name), ASCII only, computed by openxet so
-- SQLite and Postgres agree; collated "C" so listings and their namespace
-- ranges order by bytes, as SQLite's do. labels is a JSON array of strings.
CREATE TABLE repos (
    id BYTEA PRIMARY KEY,
    namespace TEXT NOT NULL,
    name TEXT NOT NULL,
    name_key TEXT COLLATE "C" NOT NULL UNIQUE,
    private BOOLEAN NOT NULL,
    labels JSONB NOT NULL,
    created_at BIGINT NOT NULL,
    full_repack_gen BIGINT NOT NULL
);

CREATE TABLE refs (
    repo BYTEA NOT NULL REFERENCES repos (id),
    name TEXT NOT NULL,
    oid BYTEA NOT NULL,
    PRIMARY KEY (repo, name)
);

-- One row per ref command of every committed transaction (ADR 0004 item
-- 3). The identity never hands a number out twice, even after old rows are
-- pruned; reindex, which writes numbers of its own, moves it past them.
-- old is NULL for a create, new for a delete.
CREATE TABLE ref_log (
    seq BIGINT GENERATED BY DEFAULT AS IDENTITY (SEQUENCE NAME ref_log_seq_seq) PRIMARY KEY,
    repo BYTEA NOT NULL,
    ref TEXT NOT NULL,
    old BYTEA,
    new BYTEA,
    actor TEXT NOT NULL,
    request TEXT NOT NULL,
    at BIGINT NOT NULL
);

CREATE INDEX ref_log_repo_seq ON ref_log (repo, seq);

-- ADR 0004 items 3 to 5. committed_at, superseded_at and inserted_at are on
-- the database clock: GC's grace periods compare against it.
CREATE TABLE packs (
    id BYTEA PRIMARY KEY,
    repo BYTEA NOT NULL,
    name TEXT NOT NULL,
    state TEXT NOT NULL CHECK (
        state IN ('pending', 'committed', 'lost', 'expired', 'superseded', 'recovered')
    ),
    created_at BIGINT NOT NULL,
    bytes BIGINT NOT NULL,
    midx_gen BIGINT,
    superseded_at BIGINT,
    committed_at BIGINT,
    inserted_at BIGINT NOT NULL
);

CREATE INDEX packs_repo_state ON packs (repo, state);

-- One repack leaseholder per repository (ADR 0004 item 5). expires_at is
-- Unix milliseconds on the database clock.
CREATE TABLE repo_leases (
    repo BYTEA PRIMARY KEY REFERENCES repos (id),
    holder TEXT NOT NULL,
    epoch BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);

-- What reindex could not place (ADR 0004 item 4, ruling R24). id orders
-- entries found at the same second, as SQLite's rowid does.
CREATE TABLE reindex_unplaced (
    id BIGINT GENERATED ALWAYS AS IDENTITY,
    repo BYTEA NOT NULL REFERENCES repos (id),
    kind TEXT NOT NULL CHECK (kind IN ('commit', 'tag', 'edge', 'pack')),
    oid BYTEA,
    pack BYTEA NOT NULL,
    found_at BIGINT NOT NULL,
    CHECK ((kind = 'pack') = (oid IS NULL))
);

CREATE UNIQUE INDEX reindex_unplaced_entry
    ON reindex_unplaced (repo, kind, COALESCE(oid, '\x'::BYTEA), pack);

-- Append-only (ruling M2-R12): the trigger refuses every change to a
-- written row. repo is NULL for an action on no repository.
CREATE TABLE audit_log (
    seq BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    repo BYTEA,
    detail JSONB NOT NULL,
    at BIGINT NOT NULL
);

CREATE FUNCTION audit_log_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END
$$;

CREATE TRIGGER audit_log_no_change BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_append_only();

-- Files purged (ruling M2-R13), as the bucket's purges/ records name them.
CREATE TABLE purges (
    file BYTEA PRIMARY KEY,
    at BIGINT NOT NULL
);

-- A pack name the sweep is deleting the files of (ADR 0004 item 5).
CREATE TABLE pack_deletions (
    repo BYTEA NOT NULL,
    name TEXT NOT NULL,
    claimed_at BIGINT NOT NULL,
    PRIMARY KEY (repo, name)
);
