//! The Postgres implementation of [`Repos`]. A write of one statement is
//! atomic on its own; `delete_repo` and `purge_file`, which write several,
//! run in one transaction, `delete_repo` under the repository's lock.

use std::collections::HashMap;

use openxet_protocol::MerkleHash;
use sqlx::Row as _;
use sqlx::postgres::PgRow;

use super::git::lock_repo;
use super::{PostgresIndex, now_s, retrying};
use crate::common::{to_i64, to_u64};
use crate::types::{decode_terms, hash_from};
use crate::{
    AuditEntry, FileRecord, FileSummary, IndexError, Page, Repo, RepoFilter, RepoId, Repos, XetFile,
};

const REPO_COLUMNS: &str =
    "id, namespace, name, private, labels::TEXT, created_at, full_repack_gen";

/// The unique key of `{namespace}/{name}`: ASCII lowercase, since names are
/// ASCII (ruling M2-R2), as SQLite computes it.
fn name_key(namespace: &str, name: &str) -> String {
    format!(
        "{}/{}",
        namespace.to_ascii_lowercase(),
        name.to_ascii_lowercase()
    )
}

fn repo_from(row: &PgRow) -> Result<Repo, IndexError> {
    let labels: &str = row.try_get(4)?;
    Ok(Repo {
        id: RepoId::from_slice(row.try_get(0)?, "a repository id")?,
        namespace: row.try_get(1)?,
        name: row.try_get(2)?,
        private: row.try_get(3)?,
        labels: serde_json::from_str(labels)
            .map_err(|e| IndexError::Corrupt(format!("repository labels {labels:?}: {e}")))?,
        created_at: to_u64(row.try_get(5)?, "repository creation time")?,
        full_repack_gen: to_u64(row.try_get(6)?, "full-repack generation")?,
    })
}

fn labels_json(labels: &[String]) -> String {
    serde_json::Value::from(labels).to_string()
}

impl PostgresIndex {
    async fn delete_repo_once(&self, id: RepoId) -> Result<bool, IndexError> {
        let mut tx = self.begin().await?;
        lock_repo(&mut tx, id).await?;
        for statement in [
            "DELETE FROM refs WHERE repo = $1",
            "DELETE FROM repo_leases WHERE repo = $1",
            "DELETE FROM reindex_unplaced WHERE repo = $1",
            concat!(
                "UPDATE packs SET state = 'superseded', superseded_at = ",
                now_s!(),
                " WHERE repo = $1 AND state = 'committed'"
            ),
            "UPDATE packs SET state = 'lost' WHERE repo = $1 AND state = 'recovered'",
        ] {
            sqlx::query(statement)
                .bind(&id.0[..])
                .execute(&mut *tx)
                .await?;
        }
        let deleted = sqlx::query("DELETE FROM repos WHERE id = $1")
            .bind(&id.0[..])
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        Ok(deleted > 0)
    }

    async fn purge_file_once(&self, file: &MerkleHash) -> Result<u64, IndexError> {
        let mut tx = self.begin().await?;
        let removed = sqlx::query("DELETE FROM file_scopes WHERE file = $1")
            .bind(file.as_bytes())
            .execute(&mut *tx)
            .await?
            .rows_affected();
        sqlx::query(concat!(
            "INSERT INTO purges (file, at) VALUES ($1, ",
            now_s!(),
            ") ON CONFLICT DO NOTHING"
        ))
        .bind(file.as_bytes())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(removed)
    }
}

#[async_trait::async_trait]
impl Repos for PostgresIndex {
    async fn create_repo(&self, repo: &Repo) -> Result<(), IndexError> {
        let created_at = to_i64(repo.created_at, "repository creation time")?;
        let generation = to_i64(repo.full_repack_gen, "full-repack generation")?;
        let inserted = sqlx::query(
            "INSERT INTO repos \
             (id, namespace, name, name_key, private, labels, created_at, full_repack_gen) \
             VALUES ($1, $2, $3, $4, $5, $6::JSONB, $7, $8) ON CONFLICT (name_key) DO NOTHING",
        )
        .bind(&repo.id.0[..])
        .bind(&repo.namespace)
        .bind(&repo.name)
        .bind(name_key(&repo.namespace, &repo.name))
        .bind(repo.private)
        .bind(labels_json(&repo.labels))
        .bind(created_at)
        .bind(generation)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if inserted == 0 {
            return Err(IndexError::NameTaken {
                name: format!("{}/{}", repo.namespace, repo.name),
            });
        }
        Ok(())
    }

    async fn repo_by_name(&self, namespace: &str, name: &str) -> Result<Option<Repo>, IndexError> {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {REPO_COLUMNS} FROM repos WHERE name_key = $1"
        )))
        .bind(name_key(namespace, name))
        .fetch_optional(&self.pool)
        .await?
        .as_ref()
        .map(repo_from)
        .transpose()
    }

    async fn repo_by_id(&self, id: RepoId) -> Result<Option<Repo>, IndexError> {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {REPO_COLUMNS} FROM repos WHERE id = $1"
        )))
        .bind(&id.0[..])
        .fetch_optional(&self.pool)
        .await?
        .as_ref()
        .map(repo_from)
        .transpose()
    }

    async fn list_repos(
        &self,
        filter: RepoFilter,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<Page<Repo>, IndexError> {
        if limit == 0 {
            // An empty page would carry no cursor and read as the end.
            return Err(IndexError::InvalidInput(
                "a repository listing needs a limit of at least 1".to_owned(),
            ));
        }
        // One more than asked, to know whether a next page exists.
        let fetch = i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX);
        // A namespace's keys are those from `ns/` up to `ns0` exclusive ('0'
        // follows '/' in ASCII), a range of the unique index on name_key,
        // whose "C" collation orders by bytes.
        let (from, until) = match &filter.namespace {
            Some(ns) => {
                let ns = ns.to_ascii_lowercase();
                (Some(format!("{ns}/")), Some(format!("{ns}0")))
            }
            None => (None, None),
        };
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {REPO_COLUMNS}, name_key FROM repos r \
             WHERE ($1::TEXT IS NULL OR name_key > $1) \
             AND ($2::TEXT IS NULL OR name_key >= $2) AND ($3::TEXT IS NULL OR name_key < $3) \
             AND ($4::TEXT IS NULL OR r.labels ? $4) \
             ORDER BY name_key LIMIT $5"
        )))
        .bind(cursor)
        .bind(&from)
        .bind(&until)
        .bind(&filter.label)
        .bind(fetch)
        .fetch_all(&self.pool)
        .await?;
        let more = rows.len() > limit;
        let page = &rows[..rows.len().min(limit)];
        let next = match page.last() {
            Some(last) if more => Some(last.try_get::<String, _>(7)?),
            _ => None,
        };
        let items = page.iter().map(repo_from).collect::<Result<_, _>>()?;
        Ok(Page { items, next })
    }

    async fn set_labels(
        &self,
        id: RepoId,
        expected: &[String],
        labels: &[String],
    ) -> Result<(), IndexError> {
        // JSONB arrays are equal when their elements are, in order, so the
        // comparison runs in the one statement.
        let updated =
            sqlx::query("UPDATE repos SET labels = $1::JSONB WHERE id = $2 AND labels = $3::JSONB")
                .bind(labels_json(labels))
                .bind(&id.0[..])
                .bind(labels_json(expected))
                .execute(&self.pool)
                .await?
                .rows_affected();
        if updated == 0 {
            return Err(match self.repo_by_id(id).await? {
                Some(_) => IndexError::LabelsChanged { repo: id },
                None => IndexError::UnknownRepo { repo: id },
            });
        }
        Ok(())
    }

    async fn delete_repo(&self, id: RepoId) -> Result<bool, IndexError> {
        retrying!(self.delete_repo_once(id).await)
    }

    async fn file_by_sha256(
        &self,
        scope: &str,
        sha256: &[u8; 32],
    ) -> Result<Option<FileRecord>, IndexError> {
        let row = sqlx::query(
            "SELECT file, size, terms FROM file_scopes WHERE scope = $1 AND sha256 = $2 \
             ORDER BY registered_seq, file LIMIT 1",
        )
        .bind(scope)
        .bind(&sha256[..])
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(FileRecord {
                hash: hash_from(row.try_get::<&[u8], _>(0)?)?,
                size: to_u64(row.try_get(1)?, "file size")?,
                terms: decode_terms(row.try_get::<&[u8], _>(2)?)?,
            })
        })
        .transpose()
    }

    async fn xet_files_by_sha256(
        &self,
        scope: &str,
        sha256s: &[[u8; 32]],
    ) -> Result<HashMap<[u8; 32], XetFile>, IndexError> {
        if sha256s.is_empty() {
            return Ok(HashMap::new());
        }
        // Of several files claiming one SHA-256, the earliest registration
        // answers: the least (registered_seq, file), as `file_by_sha256`
        // orders them.
        let asked: Vec<&[u8]> = sha256s.iter().map(<[u8; 32]>::as_slice).collect();
        let rows = sqlx::query(
            "SELECT DISTINCT ON (sha256) sha256, file, size FROM file_scopes \
             WHERE scope = $1 AND sha256 = ANY($2) ORDER BY sha256, registered_seq, file",
        )
        .bind(scope)
        .bind(asked)
        .fetch_all(&self.pool)
        .await?;
        let corrupt = |what: &str| IndexError::Corrupt(format!("a file's {what} is not 32 bytes"));
        rows.iter()
            .map(|row| {
                let sha256 = <[u8; 32]>::try_from(row.try_get::<&[u8], _>(0)?)
                    .map_err(|_| corrupt("SHA-256"))?;
                let file = XetFile {
                    hash: hash_from(row.try_get::<&[u8], _>(1)?)?,
                    size: to_u64(row.try_get(2)?, "file size")?,
                };
                Ok((sha256, file))
            })
            .collect()
    }

    async fn file_summary(
        &self,
        scope: &str,
        file: &MerkleHash,
    ) -> Result<Option<FileSummary>, IndexError> {
        let row: Option<(i64, Option<Vec<u8>>)> =
            sqlx::query_as("SELECT size, sha256 FROM file_scopes WHERE file = $1 AND scope = $2")
                .bind(file.as_bytes())
                .bind(scope)
                .fetch_optional(&self.pool)
                .await?;
        row.map(|(size, sha256)| {
            let size = to_u64(size, "a file's size")?;
            let sha256 = sha256
                .map(|bytes| {
                    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                        IndexError::Corrupt(format!(
                            "a file's SHA-256 is {} bytes, not 32",
                            bytes.len()
                        ))
                    })
                })
                .transpose()?;
            Ok(FileSummary { size, sha256 })
        })
        .transpose()
    }

    async fn file_scope_count(&self, file: &MerkleHash) -> Result<u64, IndexError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM file_scopes WHERE file = $1")
            .bind(file.as_bytes())
            .fetch_one(&self.pool)
            .await?;
        to_u64(count, "file scope count")
    }

    async fn purge_file(&self, file: &MerkleHash) -> Result<u64, IndexError> {
        retrying!(self.purge_file_once(file).await)
    }

    async fn audit(&self, entry: &AuditEntry) -> Result<(), IndexError> {
        sqlx::query(concat!(
            "INSERT INTO audit_log (actor, action, repo, detail, at) \
             VALUES ($1, $2, $3, $4::JSONB, ",
            now_s!(),
            ")"
        ))
        .bind(&entry.actor)
        .bind(&entry.action)
        .bind(entry.repo.as_ref().map(|r| &r.0[..]))
        .bind(entry.detail.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
