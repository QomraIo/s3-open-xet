//! The Postgres implementation of [`Index`], and in its submodules of
//! [`Repos`](crate::Repos) and [`GitStore`](crate::GitStore): one database
//! that every node of a deployment shares (ruling M3-R2).
//!
//! Transactions run at `READ COMMITTED`. Content-addressed rows are inserted
//! with `ON CONFLICT DO NOTHING`, so a writer that loses a race to an
//! identical row succeeds. What SQLite serializes with its one write lock
//! is serialized here per repository with a transaction-scoped advisory
//! lock (`postgres::git`). A transaction that still fails with a
//! serialization failure or a deadlock is retried up to [`RETRIES`] times,
//! then answered [`IndexError::Busy`].

mod git;
mod repos;

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use openxet_protocol::MerkleHash;
use sqlx::postgres::{PgConnectOptions, PgConnection, PgPool, PgPoolOptions};
use sqlx::{Postgres, Row as _, Transaction};

use crate::common::{
    fault_point, term_bytes, to_i64, to_u64, to_usize, unknown_xorb_on_fk_violation,
};
use crate::git::CommitError;
use crate::types::{
    TERM_LEN, decode_chunk_layout, decode_chunk_table, decode_layout_of_chunk_table,
    decode_term_bytes, decode_terms, encode_chunk_layout, encode_chunk_table, encode_term_bytes,
    encode_terms, hash_from,
};
use crate::{
    ChunkLayout, ChunkTable, FileRecord, Index, IndexError, NewFile, Registrant, TermBytes,
    Visibility,
};

/// How many times a transaction that hit a serialization failure or a
/// deadlock is run again before the caller gets [`IndexError::Busy`]
/// (ruling M3-R2).
const RETRIES: u32 = 3;

/// How long an operation waits for a pooled connection before failing.
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(10);

/// The database clock in Unix seconds, as SQLite's `unixepoch()`. A macro,
/// so queries using it stay `&'static str`.
macro_rules! now_s {
    () => {
        "FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT"
    };
}
pub(crate) use now_s;

/// The SQL condition under which xorb `x` is visible: visibility is global
/// (`$g`) or `x` is owned by the caller's tenant (`$t`), with the two
/// parameter numbers given.
macro_rules! visible {
    ($g:literal, $t:literal) => {
        concat!(
            "($",
            $g,
            " OR EXISTS (SELECT 1 FROM xorb_owners o WHERE o.xorb = x.hash AND o.tenant = $",
            $t,
            "))"
        )
    };
}

/// Runs `$attempt` (an expression ending in `.await`) again while it fails
/// with a serialization failure or a deadlock, up to [`RETRIES`] more times,
/// then answers the backend's busy error.
macro_rules! retrying {
    ($attempt:expr) => {{
        let mut retries = 0u32;
        loop {
            match $attempt {
                Err(e) if $crate::postgres::Retry::conflicted(&e) => {
                    if retries == $crate::postgres::RETRIES {
                        break Err($crate::postgres::Retry::busy(e));
                    }
                    retries += 1;
                    tokio::time::sleep($crate::postgres::backoff(retries)).await;
                }
                other => break other,
            }
        }
    }};
}
pub(crate) use retrying;

/// A short, growing pause before retry `n`, so writers that collided don't
/// collide again in step.
fn backoff(n: u32) -> Duration {
    Duration::from_millis(5 * u64::from(n * n))
}

/// Errors a conflicting transaction can end in.
pub(crate) trait Retry: Sized {
    /// Whether this is a serialization failure (`40001`) or a deadlock
    /// (`40P01`), which running the transaction again can clear.
    fn conflicted(&self) -> bool;
    /// The error once retries ran out.
    fn busy(self) -> Self;
}

fn conflict_code(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if matches!(db.code().as_deref(), Some("40001" | "40P01")))
}

impl Retry for IndexError {
    fn conflicted(&self) -> bool {
        matches!(self, Self::Database(e) if conflict_code(e))
    }

    fn busy(self) -> Self {
        match self {
            Self::Database(e) => Self::Busy(e),
            other => other,
        }
    }
}

impl Retry for CommitError {
    fn conflicted(&self) -> bool {
        matches!(self, Self::Database(e) if e.conflicted())
    }

    fn busy(self) -> Self {
        match self {
            Self::Database(e) => Self::Database(e.busy()),
            other => other,
        }
    }
}

/// The index in a Postgres database, shared by every node that connects to
/// it. Every write commits before it is acknowledged; durability is the
/// server's (`synchronous_commit`, replication), which the operator sets.
#[derive(Debug, Clone)]
pub struct PostgresIndex {
    pool: PgPool,
}

impl PostgresIndex {
    /// Connects to the database `options` name with a pool of up to
    /// `max_connections`, and applies pending schema migrations under
    /// Postgres' advisory lock, so nodes starting together migrate once.
    ///
    /// # Errors
    ///
    /// [`IndexError::Database`] if the database can't be reached, and
    /// [`IndexError::Migrate`] if the schema can't be migrated.
    pub async fn connect(
        options: PgConnectOptions,
        max_connections: u32,
    ) -> Result<Self, IndexError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(ACQUIRE_TIMEOUT)
            .connect_with(options)
            .await?;
        sqlx::migrate!("./migrations-postgres")
            .run(&pool)
            .await
            .map_err(IndexError::Migrate)?;
        Ok(Self { pool })
    }

    /// The options this index connected with, so a test can open a second
    /// handle on its database, as a second node would.
    #[cfg(feature = "test-support")]
    #[must_use]
    pub fn connect_options(&self) -> PgConnectOptions {
        (*self.pool.connect_options()).clone()
    }

    async fn begin(&self) -> Result<Transaction<'static, Postgres>, IndexError> {
        Ok(self.pool.begin().await?)
    }

    async fn put_xorb_once(
        &self,
        xorb: &MerkleHash,
        row: &XorbRow,
        eligible: &[MerkleHash],
        tenant: &str,
    ) -> Result<bool, IndexError> {
        let mut tx = self.begin().await?;
        sqlx::query(
            "INSERT INTO xorbs (hash, size, chunk_count, chunk_table, ingested_seq) \
             VALUES ($1, $2, $3, $4, nextval('xorbs_ingested_seq')) ON CONFLICT DO NOTHING",
        )
        .bind(xorb.as_bytes())
        .bind(row.size)
        .bind(row.count)
        .bind(&row.table)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO xorb_layouts (xorb, chunk_layout) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(xorb.as_bytes())
        .bind(&row.layout)
        .execute(&mut *tx)
        .await?;
        let new_for_tenant = sqlx::query(
            "INSERT INTO xorb_owners (xorb, tenant) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(xorb.as_bytes())
        .bind(tenant)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            > 0;
        insert_dedup(&mut tx, eligible, xorb).await?;
        tx.commit().await?;
        Ok(new_for_tenant)
    }

    async fn register_shard_once(
        &self,
        shard: &MerkleHash,
        files: &[NewFile],
        sizes: &[i64],
        by: Registrant<'_>,
        vis: Visibility,
    ) -> Result<bool, IndexError> {
        let Registrant { scope, tenant, seq } = by;
        let seq = to_i64(seq, "registration sequence number")?;
        let referenced: Vec<MerkleHash> = files
            .iter()
            .flat_map(|f| f.record.terms.iter().map(|t| t.xorb))
            .collect();
        let mut tx = self.begin().await?;
        if let Some(xorb) = first_invisible(&mut tx, &referenced, tenant, vis).await? {
            return Err(IndexError::UnknownXorb { xorb });
        }
        let mut new_for_scope = sqlx::query(
            "INSERT INTO shard_registrations (shard, scope, tenant, registered_seq) \
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        )
        .bind(shard.as_bytes())
        .bind(scope)
        .bind(tenant)
        .bind(seq)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            > 0;
        insert_shard_xorbs(&mut tx, shard, &referenced).await?;
        insert_owners(&mut tx, &referenced, tenant).await?;
        // Every term xorb is visible (checked above), so every layout is
        // found.
        let layouts = layouts_in(&mut tx, &referenced, tenant, vis).await?;
        // Rows are written in hash order, so two registrations sharing files
        // take their row locks in one order and never deadlock on them.
        let mut order: Vec<usize> = (0..files.len()).collect();
        order.sort_by_key(|&i| files[i].record.hash);
        for (n, &i) in order.iter().enumerate() {
            let (file, size) = (&files[i], sizes[i]);
            let record = &file.record;
            let terms = encode_terms(&record.terms);
            let sha256 = file.sha256.as_ref().map(<[u8; 32]>::as_slice);
            let bytes = encode_term_bytes(&term_bytes(&record.terms, &layouts)?);
            let inserted = sqlx::query(
                "INSERT INTO file_scopes \
                 (file, scope, size, terms, sha256, shard, term_bytes, registered_seq, \
                 registered_tenant) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING",
            )
            .bind(record.hash.as_bytes())
            .bind(scope)
            .bind(size)
            .bind(&terms)
            .bind(sha256)
            .bind(shard.as_bytes())
            .bind(&bytes)
            .bind(seq)
            .bind(tenant)
            .execute(&mut *tx)
            .await?
            .rows_affected()
                > 0;
            if !inserted {
                // Registered already. The row of the lowest (number, shard,
                // tenant) is kept whichever committed first, as a rebuild from
                // the bucket keeps it (ruling M1-R37). Bytes compare as
                // unsigned bytes and the tenant under "C", as SQLite compares
                // them.
                sqlx::query(
                    "UPDATE file_scopes SET size = $1, terms = $2, sha256 = $3, shard = $4, \
                     term_bytes = $5, registered_seq = $6, registered_tenant = $7 \
                     WHERE file = $8 AND scope = $9 \
                     AND (registered_seq, shard, registered_tenant COLLATE \"C\") \
                     > ($6, $4, $7 COLLATE \"C\")",
                )
                .bind(size)
                .bind(&terms)
                .bind(sha256)
                .bind(shard.as_bytes())
                .bind(&bytes)
                .bind(seq)
                .bind(tenant)
                .bind(record.hash.as_bytes())
                .bind(scope)
                .execute(&mut *tx)
                .await?;
            }
            new_for_scope |= inserted;
            if let (Some(first), Some(term)) = (file.first_chunk, record.terms.first()) {
                insert_dedup(&mut tx, &[first], &term.xorb)
                    .await
                    .map_err(|e| unknown_xorb_on_fk_violation(e, term.xorb))?;
            }
            fault_point(n, scope)?;
        }
        tx.commit().await?;
        Ok(new_for_scope)
    }
}

/// A xorb's row, encoded once for every attempt.
struct XorbRow {
    size: i64,
    count: i64,
    table: Vec<u8>,
    layout: Vec<u8>,
}

/// The distinct hashes of `hashes`, in order of first appearance.
fn distinct(hashes: &[MerkleHash]) -> Vec<MerkleHash> {
    let mut seen = HashSet::with_capacity(hashes.len());
    hashes.iter().copied().filter(|h| seen.insert(*h)).collect()
}

/// `hashes` as a `BYTEA[]` parameter.
fn byte_array(hashes: &[MerkleHash]) -> Vec<&[u8]> {
    hashes.iter().map(MerkleHash::as_bytes).collect()
}

/// The first of `xorbs`, in order, that isn't visible to `tenant` under `vis`.
/// Xorbs are only ever removed by garbage collection, which never removes
/// one a registration can still name, so the answer holds until commit.
async fn first_invisible(
    tx: &mut Transaction<'_, Postgres>,
    xorbs: &[MerkleHash],
    tenant: &str,
    vis: Visibility,
) -> Result<Option<MerkleHash>, IndexError> {
    let ordered = distinct(xorbs);
    let rows: Vec<Vec<u8>> = sqlx::query_scalar(concat!(
        "SELECT x.hash FROM xorbs x WHERE x.hash = ANY($1) AND ",
        visible!("2", "3")
    ))
    .bind(byte_array(&ordered))
    .bind(vis == Visibility::Global)
    .bind(tenant)
    .fetch_all(&mut **tx)
    .await?;
    let visible = rows
        .iter()
        .map(|r| hash_from(r))
        .collect::<Result<HashSet<_>, _>>()?;
    Ok(ordered.into_iter().find(|x| !visible.contains(x)))
}

/// The layouts of `xorbs` visible to `tenant` under `vis`, read on `conn`,
/// as [`Index::chunk_layouts`] answers them.
async fn layouts_in(
    conn: &mut PgConnection,
    xorbs: &[MerkleHash],
    tenant: &str,
    vis: Visibility,
) -> Result<HashMap<MerkleHash, ChunkLayout>, IndexError> {
    let unique = distinct(xorbs);
    let rows = sqlx::query(concat!(
        "SELECT x.hash, x.chunk_count, l.chunk_layout, \
         CASE WHEN l.chunk_layout IS NULL THEN x.chunk_table END \
         FROM xorbs x LEFT JOIN xorb_layouts l ON l.xorb = x.hash WHERE x.hash = ANY($1) AND ",
        visible!("2", "3")
    ))
    .bind(byte_array(&unique))
    .bind(vis == Visibility::Global)
    .bind(tenant)
    .fetch_all(&mut *conn)
    .await?;
    let mut layouts = HashMap::with_capacity(rows.len());
    for row in rows {
        let hash = hash_from(row.try_get::<&[u8], _>(0)?)?;
        let count = to_usize(row.try_get(1)?, "chunk count")?;
        let layout = match row.try_get::<Option<&[u8]>, _>(2)? {
            Some(layout) => decode_chunk_layout(layout, count)?,
            None => decode_layout_of_chunk_table(row.try_get::<&[u8], _>(3)?, count)?,
        };
        layouts.insert(hash, layout);
    }
    Ok(layouts)
}

/// Inserts `(chunk, xorb)` dedup candidates in chunk order, skipping ones
/// already present.
async fn insert_dedup(
    tx: &mut Transaction<'_, Postgres>,
    chunks: &[MerkleHash],
    xorb: &MerkleHash,
) -> Result<(), IndexError> {
    let mut sorted = distinct(chunks);
    sorted.sort_unstable();
    sqlx::query(
        "INSERT INTO dedup (chunk, xorb) SELECT c, $2 FROM UNNEST($1::BYTEA[]) AS c \
         ON CONFLICT DO NOTHING",
    )
    .bind(byte_array(&sorted))
    .bind(xorb.as_bytes())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Records the distinct xorbs of `referenced` as `shard`'s, in order of
/// first appearance. A shard's rows depend only on its content, so rows
/// already present are kept.
async fn insert_shard_xorbs(
    tx: &mut Transaction<'_, Postgres>,
    shard: &MerkleHash,
    referenced: &[MerkleHash],
) -> Result<(), IndexError> {
    let ordered = distinct(referenced);
    sqlx::query(
        "INSERT INTO shard_xorbs (shard, pos, xorb) \
         SELECT $1, x.pos - 1, x.hash FROM UNNEST($2::BYTEA[]) WITH ORDINALITY AS x (hash, pos) \
         ON CONFLICT DO NOTHING",
    )
    .bind(shard.as_bytes())
    .bind(byte_array(&ordered))
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Records `tenant` as an owner of each of `xorbs` (ruling M1-R39), in hash
/// order.
async fn insert_owners(
    tx: &mut Transaction<'_, Postgres>,
    xorbs: &[MerkleHash],
    tenant: &str,
) -> Result<(), IndexError> {
    let mut sorted = distinct(xorbs);
    sorted.sort_unstable();
    sqlx::query(
        "INSERT INTO xorb_owners (xorb, tenant) SELECT x, $2 FROM UNNEST($1::BYTEA[]) AS x \
         ON CONFLICT DO NOTHING",
    )
    .bind(byte_array(&sorted))
    .bind(tenant)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[async_trait::async_trait]
impl Index for PostgresIndex {
    async fn probe(&self) -> Result<(), IndexError> {
        // A real table, so a database without the schema fails here.
        sqlx::query("SELECT 1 FROM xorbs LIMIT 1")
            .fetch_optional(&self.pool)
            .await?;
        Ok(())
    }

    async fn put_xorb(
        &self,
        xorb: &MerkleHash,
        size: u64,
        table: &ChunkTable,
        eligible: &[MerkleHash],
        tenant: &str,
    ) -> Result<bool, IndexError> {
        let row = XorbRow {
            table: encode_chunk_table(table)?,
            layout: encode_chunk_layout(table),
            size: to_i64(size, "xorb size")?,
            count: i64::try_from(table.hashes.len())
                .map_err(|_| IndexError::InvalidInput("chunk count is over i64::MAX".to_owned()))?,
        };
        retrying!(self.put_xorb_once(xorb, &row, eligible, tenant).await)
    }

    async fn xorb_size(
        &self,
        xorb: &MerkleHash,
        tenant: &str,
        vis: Visibility,
    ) -> Result<Option<u64>, IndexError> {
        let size: Option<i64> = sqlx::query_scalar(concat!(
            "SELECT x.size FROM xorbs x WHERE x.hash = $1 AND ",
            visible!("2", "3")
        ))
        .bind(xorb.as_bytes())
        .bind(vis == Visibility::Global)
        .bind(tenant)
        .fetch_optional(&self.pool)
        .await?;
        size.map(|s| to_u64(s, "xorb size")).transpose()
    }

    async fn chunk_tables(
        &self,
        xorbs: &[MerkleHash],
        tenant: &str,
        vis: Visibility,
    ) -> Result<HashMap<MerkleHash, ChunkTable>, IndexError> {
        let unique = distinct(xorbs);
        let rows = sqlx::query(concat!(
            "SELECT x.hash, x.chunk_count, x.chunk_table FROM xorbs x WHERE x.hash = ANY($1) AND ",
            visible!("2", "3")
        ))
        .bind(byte_array(&unique))
        .bind(vis == Visibility::Global)
        .bind(tenant)
        .fetch_all(&self.pool)
        .await?;
        let mut tables = HashMap::with_capacity(rows.len());
        for row in rows {
            let hash = hash_from(row.try_get::<&[u8], _>(0)?)?;
            let count = to_usize(row.try_get(1)?, "chunk count")?;
            let table = decode_chunk_table(row.try_get::<&[u8], _>(2)?, count)?;
            tables.insert(hash, table);
        }
        Ok(tables)
    }

    async fn chunk_layouts(
        &self,
        xorbs: &[MerkleHash],
        tenant: &str,
        vis: Visibility,
    ) -> Result<HashMap<MerkleHash, ChunkLayout>, IndexError> {
        let mut conn = self.pool.acquire().await?;
        layouts_in(&mut conn, xorbs, tenant, vis).await
    }

    async fn next_registration_seq(&self) -> Result<u64, IndexError> {
        let seq: i64 = sqlx::query_scalar("SELECT nextval('registration_seq')")
            .fetch_one(&self.pool)
            .await?;
        to_u64(seq, "registration sequence number")
    }

    async fn register_shard(
        &self,
        shard: &MerkleHash,
        files: &[NewFile],
        by: Registrant<'_>,
        vis: Visibility,
    ) -> Result<bool, IndexError> {
        let sizes = files
            .iter()
            .map(|f| to_i64(f.record.size, "file size"))
            .collect::<Result<Vec<_>, _>>()?;
        retrying!(
            self.register_shard_once(shard, files, &sizes, by, vis)
                .await
        )
    }

    async fn file_with_bytes(
        &self,
        file: &MerkleHash,
        scope: &str,
    ) -> Result<Option<(FileRecord, Option<TermBytes>)>, IndexError> {
        let row = sqlx::query(
            "SELECT size, terms, term_bytes FROM file_scopes WHERE file = $1 AND scope = $2",
        )
        .bind(file.as_bytes())
        .bind(scope)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            let record = FileRecord {
                hash: *file,
                size: to_u64(row.try_get(0)?, "file size")?,
                terms: decode_terms(row.try_get::<&[u8], _>(1)?)?,
            };
            let bytes = row
                .try_get::<Option<&[u8]>, _>(2)?
                .map(|b| decode_term_bytes(b, record.terms.len()))
                .transpose()?;
            Ok((record, bytes))
        })
        .transpose()
    }

    async fn file(&self, file: &MerkleHash, scope: &str) -> Result<Option<FileRecord>, IndexError> {
        let row = sqlx::query("SELECT size, terms FROM file_scopes WHERE file = $1 AND scope = $2")
            .bind(file.as_bytes())
            .bind(scope)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            Ok(FileRecord {
                hash: *file,
                size: to_u64(row.try_get(0)?, "file size")?,
                terms: decode_terms(row.try_get::<&[u8], _>(1)?)?,
            })
        })
        .transpose()
    }

    async fn files(
        &self,
        files: &[MerkleHash],
        scope: &str,
    ) -> Result<HashMap<MerkleHash, FileRecord>, IndexError> {
        let unique = distinct(files);
        let rows = sqlx::query(
            "SELECT file, size, terms FROM file_scopes WHERE scope = $1 AND file = ANY($2)",
        )
        .bind(scope)
        .bind(byte_array(&unique))
        .fetch_all(&self.pool)
        .await?;
        let mut records = HashMap::with_capacity(rows.len());
        for row in rows {
            let hash = hash_from(row.try_get::<&[u8], _>(0)?)?;
            let record = FileRecord {
                hash,
                size: to_u64(row.try_get(1)?, "file size")?,
                terms: decode_terms(row.try_get::<&[u8], _>(2)?)?,
            };
            records.insert(hash, record);
        }
        Ok(records)
    }

    async fn term_count(&self, files: &[MerkleHash], scope: &str) -> Result<u64, IndexError> {
        let unique = distinct(files);
        // `octet_length` of a TOASTed value reads its stored length, not its
        // content, so this loads no term list.
        let bytes: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(octet_length(terms)), 0)::BIGINT FROM file_scopes \
             WHERE scope = $1 AND file = ANY($2)",
        )
        .bind(scope)
        .bind(byte_array(&unique))
        .fetch_one(&self.pool)
        .await?;
        let bytes = to_u64(bytes, "term list length")?;
        if !bytes.is_multiple_of(TERM_LEN as u64) {
            return Err(IndexError::Corrupt(format!(
                "term lists total {bytes} bytes, not a multiple of {TERM_LEN}"
            )));
        }
        Ok(bytes / TERM_LEN as u64)
    }

    async fn dedup_xorb(
        &self,
        chunk: &MerkleHash,
        tenant: &str,
        vis: Visibility,
    ) -> Result<Option<MerkleHash>, IndexError> {
        let xorb: Option<Vec<u8>> = sqlx::query_scalar(concat!(
            "SELECT x.hash FROM dedup d JOIN xorbs x ON x.hash = d.xorb WHERE d.chunk = $1 AND ",
            visible!("2", "3"),
            " ORDER BY x.ingested_seq DESC LIMIT 1"
        ))
        .bind(chunk.as_bytes())
        .bind(vis == Visibility::Global)
        .bind(tenant)
        .fetch_optional(&self.pool)
        .await?;
        xorb.as_deref().map(hash_from).transpose()
    }

    async fn dedup_shard_xorbs(
        &self,
        xorb: &MerkleHash,
        tenant: &str,
        vis: Visibility,
    ) -> Result<Option<Vec<MerkleHash>>, IndexError> {
        // One statement, so the shard and its xorbs come from one snapshot.
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(concat!(
            "SELECT x.hash FROM shard_xorbs sx JOIN xorbs x ON x.hash = sx.xorb \
             WHERE sx.shard = (\
                 SELECT ss.shard FROM shard_xorbs m \
                 JOIN shard_registrations ss ON ss.shard = m.shard \
                 WHERE m.xorb = $1 AND ($2 OR ss.tenant = $3) \
                 ORDER BY ss.registered_seq DESC LIMIT 1\
             ) AND ",
            visible!("2", "3"),
            " ORDER BY sx.pos"
        ))
        .bind(xorb.as_bytes())
        .bind(vis == Visibility::Global)
        .bind(tenant)
        .fetch_all(&self.pool)
        .await?;
        if rows.is_empty() {
            return Ok(None);
        }
        rows.iter()
            .map(|row| hash_from(row))
            .collect::<Result<_, _>>()
            .map(Some)
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::sync::atomic::{AtomicU32, Ordering};

    use sqlx::error::{DatabaseError, ErrorKind};

    use super::*;

    /// A database error carrying only a SQLSTATE, as Postgres reports a
    /// conflict.
    #[derive(Debug)]
    struct State(&'static str);

    impl std::fmt::Display for State {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "SQLSTATE {}", self.0)
        }
    }

    impl std::error::Error for State {}

    impl DatabaseError for State {
        fn message(&self) -> &str {
            self.0
        }
        fn code(&self) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed(self.0))
        }
        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }
        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }
        fn kind(&self) -> ErrorKind {
            ErrorKind::Other
        }
    }

    fn failing(state: &'static str) -> IndexError {
        IndexError::Database(sqlx::Error::Database(Box::new(State(state))))
    }

    /// An attempt that fails with `state` its first `fails` times.
    #[expect(
        clippy::unused_async,
        reason = "`retrying!` awaits each attempt, as it awaits the index's"
    )]
    async fn attempt(
        calls: &AtomicU32,
        fails: u32,
        state: &'static str,
    ) -> Result<u32, IndexError> {
        let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
        if n <= fails {
            Err(failing(state))
        } else {
            Ok(n)
        }
    }

    /// Ruling M3-R2: a serialization failure or deadlock is retried up to
    /// three times; the fourth failure is `Busy`.
    #[tokio::test]
    async fn serialization_failures_retry_then_busy() {
        for state in ["40001", "40P01"] {
            let calls = AtomicU32::new(0);
            let answer: Result<u32, IndexError> = retrying!(attempt(&calls, 3, state).await);
            assert!(
                matches!(answer, Ok(4)),
                "{state}: the fourth attempt succeeds"
            );

            let calls = AtomicU32::new(0);
            let answer: Result<u32, IndexError> = retrying!(attempt(&calls, 4, state).await);
            assert!(
                matches!(answer, Err(IndexError::Busy(_))),
                "{state}: busy after 4"
            );
            assert_eq!(
                calls.load(Ordering::SeqCst),
                4,
                "{state}: one try and three retries"
            );
        }
    }

    /// Other database errors are answered at once, as they are.
    #[tokio::test]
    async fn other_errors_are_not_retried() {
        let calls = AtomicU32::new(0);
        let answer: Result<u32, IndexError> = retrying!(attempt(&calls, 1, "23505").await);
        assert!(matches!(answer, Err(IndexError::Database(_))));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
