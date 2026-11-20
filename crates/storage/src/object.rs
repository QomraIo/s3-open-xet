//! Object-store bucket: S3 and S3-compatible stores (ADR 0015 item 5).
//!
//! The key layout is [`LocalBucket`](crate::LocalBucket)'s, under the
//! URL's prefix, so a local bucket copied to a store with `aws s3 sync` or
//! `rclone` is read as it is:
//!
//! ```text
//! {prefix}/xorbs/default/{hex[0..2]}/{hex}                        Key::Xorb
//! {prefix}/shards/{hex[0..2]}/{hex}                               Key::Shard
//! {prefix}/registrations/{scope}/{tenant}/{hex[0..2]}/{hex}       Key::Registration
//! {prefix}/xorb-owners/{tenant}/{hex[0..2]}/{hex}                 Key::XorbOwner
//! {prefix}/repos/{id}/meta                                        Key::RepoMeta
//! {prefix}/repos/{id}/packs/{name}.{ext}                          Key::Pack
//! {prefix}/repos/{id}/midx/{generation}.{ext}                     Key::Midx
//! {prefix}/repos/{id}/reflog/{seq:020}                            Key::RefLog
//! {prefix}/purges/{hex[0..2]}/{hex}                               Key::Purge
//! {prefix}/probe/{node}/create                                    the conditional-create probe
//! {prefix}/.tmp/{uuid}.ready-probe                                `probe`'s write, removed
//! ```
//!
//! How each write is made durable and atomic:
//! - [`Bucket::put`] and [`Bucket::create`] use a conditional create
//!   (`If-None-Match: *`), so an object is never overwritten. A store that
//!   accepts the condition and overwrites anyway would let two writers'
//!   registrations diverge, which [`ObjectBucket::probe_conditional_create`]
//!   catches before the server takes traffic (ADR 0015 item 6).
//! - [`Bucket::put_replace`] is one plain `PUT`: object stores replace an
//!   object whole, so readers see the old or the new one.
//! - [`Bucket::put_stream`] sends a body of up to [`PART_BYTES`] as one
//!   `PUT` and a larger one as a multipart upload of [`PART_BYTES`] parts,
//!   which publishes nothing until it completes and is aborted on error.
//!
//! Credentials come from `storage.credentials_file` (passed to
//! [`ObjectBucket::open`] as [`S3Credentials`]), the environment
//! (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`), web
//! identity or instance metadata, never from the configuration file (ADR
//! 0015 item 5).

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use futures_util::{StreamExt as _, TryStreamExt as _};
use object_store::aws::{AmazonS3Builder, AmazonS3ConfigKey, S3ConditionalPut};
use object_store::path::Path as StorePath;
use object_store::{
    GetOptions, GetRange, ObjectStore, PutMode, PutOptions, PutPayload, WriteMultipart,
};
use openxet_protocol::hash_to_hex;
use url::Url;

use crate::bucket_admin::{BucketAdmin, BucketCreated};
use crate::local::{create_private_file, io, object_hash, repo_depth, repo_key};
use crate::{
    BodyStream, Bucket, Key, KeyKind, NameHash, RangeStream, RepoIdHex, STREAM_BLOCK_BYTES,
    StorageError, WriteMode,
};

/// The part size of a multipart upload, and the largest body
/// [`Bucket::put_stream`] sends as one `PUT`: 8 MiB. S3 takes parts of
/// 5 MiB to 5 GiB and at most 10,000 of them, so an object can reach
/// 78 GiB.
pub const PART_BYTES: usize = 8 * 1024 * 1024;

/// How many parts of one upload are in flight at once.
const PARTS_IN_FLIGHT: usize = 2;

/// Static S3 credentials, as `storage.credentials_file` holds them. `Debug`
/// shows the access key id only.
#[derive(Clone, PartialEq, Eq)]
pub struct S3Credentials {
    /// `AWS_ACCESS_KEY_ID`.
    pub key_id: String,
    /// `AWS_SECRET_ACCESS_KEY`.
    pub secret_key: String,
    /// `AWS_SESSION_TOKEN`, for temporary credentials.
    pub session_token: Option<String>,
}

impl std::fmt::Debug for S3Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Credentials")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// A bucket in an object store. Opened from `storage.url` with
/// [`ObjectBucket::open`], or around any [`ObjectStore`] with
/// [`ObjectBucket::with_store`].
#[derive(Debug, Clone)]
pub struct ObjectBucket {
    store: Arc<dyn ObjectStore>,
    /// The bucket's own requests; `None` for [`ObjectBucket::with_store`].
    admin: Option<Arc<BucketAdmin>>,
    /// The prefix every key is stored under, without slashes at either
    /// end; empty for the bucket's root.
    prefix: String,
    /// The URL the bucket was opened from, for messages. Never holds a
    /// credential: those come from the environment.
    url: String,
}

impl ObjectBucket {
    /// Opens the bucket at `url`, `s3://{bucket}/{prefix}`, with
    /// `object_store`'s S3 options (`endpoint`, `region`, `allow_http`,
    /// `virtual_hosted_style_request`, …) from `options`. Credentials are
    /// `credentials` if given; they and any option not given are otherwise
    /// read from the environment (`AWS_*`).
    ///
    /// Conditional creates are on (`conditional_put = "etag"`) unless
    /// `options` says otherwise; a store that can't honour them is refused
    /// by [`ObjectBucket::probe_conditional_create`].
    ///
    /// Nothing is requested from the store here.
    ///
    /// # Errors
    ///
    /// [`StorageError::UnsupportedUrl`] for another scheme, a URL without a
    /// bucket, an unknown option or a store the options can't build.
    pub fn open(
        url: &Url,
        options: &BTreeMap<String, String>,
        credentials: Option<&S3Credentials>,
    ) -> Result<Self, StorageError> {
        let unsupported = |reason: String| StorageError::UnsupportedUrl {
            url: url.to_string(),
            reason,
        };
        if url.scheme() != "s3" {
            return Err(unsupported(format!(
                "the scheme `{}` is not supported; use s3://bucket/prefix for S3 or an \
                 S3-compatible store (MinIO, R2, Garage, …), or leave storage.url out for the \
                 local bucket in the data directory",
                url.scheme()
            )));
        }
        let Some(bucket) = url.host_str().filter(|b| !b.is_empty()) else {
            return Err(unsupported(
                "it names no bucket; write s3://bucket or s3://bucket/prefix".to_owned(),
            ));
        };
        if url.query().is_some() || url.fragment().is_some() || !url.username().is_empty() {
            return Err(unsupported(
                "it carries a query, a fragment or user info; put options under \
                 [storage.options] and credentials in storage.credentials_file or the environment"
                    .to_owned(),
            ));
        }
        // `Url::parse` has already resolved any `.` and `..` in the path.
        let prefix = url.path().trim_matches('/').to_owned();
        let mut builder = AmazonS3Builder::from_env()
            .with_bucket_name(bucket)
            .with_conditional_put(S3ConditionalPut::ETagMatch);
        for (name, value) in options {
            let key: AmazonS3ConfigKey = name.parse().map_err(|_| {
                unsupported(format!(
                    "[storage.options] has `{name}`, which is not an S3 option; see \
                     docs/reference/config.md#storage for the options"
                ))
            })?;
            builder = builder.with_config(key, value);
        }
        if let Some(credentials) = credentials {
            builder = builder
                .with_access_key_id(&credentials.key_id)
                .with_secret_access_key(&credentials.secret_key);
            if let Some(token) = &credentials.session_token {
                builder = builder.with_token(token);
            }
        }
        let store = builder
            .clone()
            .build()
            .map_err(|err| unsupported(err.to_string()))?;
        let admin = BucketAdmin::new(&builder, store.clone(), bucket).map_err(unsupported)?;
        Ok(Self {
            store: Arc::new(store),
            admin: Some(Arc::new(admin)),
            prefix,
            url: url.to_string(),
        })
    }

    /// The bucket over `store`, every key under `prefix` (`""` for the
    /// store's root): for tests, and stores this crate doesn't open itself.
    #[must_use]
    pub fn with_store(store: Arc<dyn ObjectStore>, prefix: &str, url: &str) -> Self {
        Self {
            store,
            admin: None,
            prefix: prefix.trim_matches('/').to_owned(),
            url: url.to_owned(),
        }
    }

    /// The store and the prefix, for the presigners of ADR 0015 item 7.
    #[must_use]
    pub fn store(&self) -> (Arc<dyn ObjectStore>, &str) {
        (Arc::clone(&self.store), &self.prefix)
    }

    /// Whether the bucket itself exists. A bucket these credentials may not
    /// read is an error, never reported as missing.
    ///
    /// # Errors
    ///
    /// [`StorageError::Remote`] if the store refuses or can't be reached,
    /// and [`StorageError::UnsupportedUrl`] for a bucket from
    /// [`ObjectBucket::with_store`].
    pub async fn bucket_exists(&self) -> Result<bool, StorageError> {
        self.admin()?.exists().await
    }

    /// Creates the bucket itself, in the configured region.
    ///
    /// # Errors
    ///
    /// As [`ObjectBucket::bucket_exists`], and [`StorageError::Remote`] if
    /// another account owns a bucket of this name.
    pub async fn create_bucket(&self) -> Result<BucketCreated, StorageError> {
        self.admin()?.create().await
    }

    fn admin(&self) -> Result<&BucketAdmin, StorageError> {
        self.admin
            .as_deref()
            .ok_or_else(|| StorageError::UnsupportedUrl {
                url: self.url.clone(),
                reason: "this bucket was opened around a store, not from an s3:// URL".to_owned(),
            })
    }

    /// Checks that the store honours conditional creates, which
    /// registration records rely on (ruling M1-R37, ADR 0015 item 6): it
    /// creates `probe/{node}/create` twice and requires the second call to
    /// find the object. The probe object is kept and reused on the next
    /// start.
    ///
    /// # Errors
    ///
    /// [`StorageError::Unsafe`] if the second create stores, or the store
    /// doesn't implement conditional creates, and [`StorageError::Remote`]
    /// if a request fails.
    pub async fn probe_conditional_create(&self, node: uuid::Uuid) -> Result<(), StorageError> {
        let location = self.location(&format!("probe/{}/create", node.simple()));
        let payload = || PutPayload::from(Bytes::from_static(b"openxet conditional-create probe"));
        let create = || PutOptions::from(PutMode::Create);
        match self.store.put_opts(&location, payload(), create()).await {
            // Absent, or left by an earlier start of this node.
            Ok(_) | Err(object_store::Error::AlreadyExists { .. }) => {}
            Err(err) => return Err(self.unsafe_or_remote("probe", &location, err)),
        }
        match self.store.put_opts(&location, payload(), create()).await {
            Err(
                object_store::Error::AlreadyExists { .. }
                | object_store::Error::Precondition { .. },
            ) => Ok(()),
            Ok(_) => Err(StorageError::Unsafe {
                url: self.url.clone(),
                check: "a conditional create (If-None-Match: *) of an existing object stored it \
                        again, so two writers' registration records could diverge",
                hint: "use a store that honours If-None-Match on PUT (AWS S3, R2, MinIO, Garage \
                       and others do), or set [storage.options] conditional_put for it"
                    .to_owned(),
            }),
            Err(err) => Err(self.unsafe_or_remote("probe", &location, err)),
        }
    }

    /// `rel` under the prefix.
    fn location(&self, rel: &str) -> StorePath {
        if self.prefix.is_empty() {
            StorePath::from(rel)
        } else {
            StorePath::from(format!("{}/{rel}", self.prefix))
        }
    }

    fn key_location(&self, key: &Key) -> StorePath {
        self.location(&relative(key))
    }

    /// `location` as a key's path below the prefix, or `None` if it isn't
    /// below it.
    fn strip<'a>(&self, location: &'a str) -> Option<&'a str> {
        if self.prefix.is_empty() {
            Some(location)
        } else {
            location.strip_prefix(&self.prefix)?.strip_prefix('/')
        }
    }

    fn unsafe_or_remote(
        &self,
        op: &'static str,
        location: &StorePath,
        err: object_store::Error,
    ) -> StorageError {
        if matches!(err, object_store::Error::NotImplemented) {
            StorageError::Unsafe {
                url: self.url.clone(),
                check: "the store does not implement conditional creates (If-None-Match: *)",
                hint: "leave [storage.options] conditional_put out, or set it to `etag`".to_owned(),
            }
        } else {
            remote(op, location, err)
        }
    }

    /// The object's size, or `None` if it does not exist.
    async fn head_size(&self, location: &StorePath) -> Result<Option<u64>, StorageError> {
        match self.store.head(location).await {
            Ok(meta) => Ok(Some(meta.size)),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(err) => Err(remote("look up", location, err)),
        }
    }

    /// The size of `key`'s object, checked against `start..=end_inclusive`.
    async fn checked_size(
        &self,
        key: &Key,
        location: &StorePath,
        start: u64,
        end_inclusive: u64,
    ) -> Result<u64, StorageError> {
        let Some(size) = self.head_size(location).await? else {
            return Err(StorageError::NotFound {
                key: Box::new(key.clone()),
            });
        };
        if start > end_inclusive || end_inclusive >= size {
            return Err(StorageError::RangeOutOfBounds {
                key: Box::new(key.clone()),
                start,
                end_inclusive,
                size,
            });
        }
        Ok(size)
    }

    /// Stores `bytes` at `key` unless an object is there. `Ok(true)` if
    /// this call stored them, `Ok(false)` with the existing object's size
    /// checked if one was there.
    async fn create_or_check(
        &self,
        key: &Key,
        bytes: Bytes,
        check_size: bool,
    ) -> Result<bool, StorageError> {
        let location = self.key_location(key);
        let new = bytes.len() as u64;
        match self
            .store
            .put_opts(
                &location,
                PutPayload::from(bytes),
                PutOptions::from(PutMode::Create),
            )
            .await
        {
            Ok(_) => Ok(true),
            Err(
                object_store::Error::AlreadyExists { .. }
                | object_store::Error::Precondition { .. },
            ) => {
                if check_size {
                    self.check_existing(key, &location, new).await?;
                }
                Ok(false)
            }
            Err(err) => Err(self.unsafe_or_remote("write", &location, err)),
        }
    }

    /// Refuses `new` bytes for `key` if an object of another size is there.
    async fn check_existing(
        &self,
        key: &Key,
        location: &StorePath,
        new: u64,
    ) -> Result<Option<u64>, StorageError> {
        let existing = self.head_size(location).await?;
        match existing {
            Some(existing) if existing != new => Err(StorageError::SizeConflict {
                key: Box::new(key.clone()),
                existing,
                new,
            }),
            other => Ok(other),
        }
    }

    /// Every key of `kind` stored under `base`, `depth` names below it.
    async fn list_at(&self, base: &str, depth: usize) -> Result<Vec<Vec<String>>, StorageError> {
        let base_location = self.location(base);
        let mut objects = self.store.list(Some(&base_location));
        let mut found = Vec::new();
        while let Some(meta) = objects
            .try_next()
            .await
            .map_err(|err| remote("list", &base_location, err))?
        {
            let location = meta.location.to_string();
            let Some(rel) = self.strip(&location) else {
                continue;
            };
            let Some(below) = rel.strip_prefix(base).and_then(|r| r.strip_prefix('/')) else {
                continue;
            };
            let names: Vec<String> = below.split('/').map(str::to_owned).collect();
            if names.len() == depth {
                found.push(names);
            }
        }
        Ok(found)
    }

    /// Sends `body` as a multipart upload in [`PART_BYTES`] parts, `first`
    /// already read from it; aborts the upload on any error, so nothing is
    /// published.
    async fn multipart(
        &self,
        key: &Key,
        location: &StorePath,
        first: Bytes,
        body: &mut BodyStream,
        len: u64,
    ) -> Result<(), StorageError> {
        let upload = self
            .store
            .put_multipart(location)
            .await
            .map_err(|err| remote("start an upload of", location, err))?;
        let mut writer = WriteMultipart::new_with_chunk_size(upload, PART_BYTES);
        let result = async {
            let mut received = first.len() as u64;
            writer.write(&first);
            drop(first);
            while let Some(block) = body.next().await {
                let block = block.map_err(|err| StorageError::Remote {
                    op: "read the body for",
                    location: location.to_string(),
                    source: Box::new(err),
                })?;
                received += block.len() as u64;
                if received > len {
                    return Err(StorageError::LengthMismatch {
                        key: Box::new(key.clone()),
                        expected: len,
                        received,
                    });
                }
                // Holds at most PARTS_IN_FLIGHT parts and one block.
                writer
                    .wait_for_capacity(PARTS_IN_FLIGHT)
                    .await
                    .map_err(|err| remote("upload a part of", location, err))?;
                writer.write(&block);
            }
            if received == len {
                Ok(())
            } else {
                Err(StorageError::LengthMismatch {
                    key: Box::new(key.clone()),
                    expected: len,
                    received,
                })
            }
        }
        .await;
        match result {
            Ok(()) => writer
                .finish()
                .await
                .map(drop)
                .map_err(|err| remote("complete the upload of", location, err)),
            Err(err) => {
                // Best effort: an upload left behind publishes nothing, and
                // a bucket lifecycle rule removes incomplete uploads.
                let _ = writer.abort().await;
                Err(err)
            }
        }
    }
}

fn remote(op: &'static str, location: &StorePath, err: object_store::Error) -> StorageError {
    StorageError::Remote {
        op,
        location: location.to_string(),
        source: Box::new(err),
    }
}

/// A key's path below the prefix: [`LocalBucket`](crate::LocalBucket)'s
/// layout.
fn relative(key: &Key) -> String {
    let (dir, hash) = match key {
        Key::Xorb(h) => ("xorbs/default".to_owned(), h),
        Key::Shard(h) => ("shards".to_owned(), h),
        Key::Registration {
            scope,
            tenant,
            shard,
        } => (format!("registrations/{scope}/{tenant}"), shard),
        Key::XorbOwner { tenant, xorb } => (format!("xorb-owners/{tenant}"), xorb),
        Key::Purge(h) => ("purges".to_owned(), h),
        // A repository's keys are their own paths.
        Key::RepoMeta { .. } | Key::Pack { .. } | Key::Midx { .. } | Key::RefLog { .. } => {
            return key.to_string();
        }
    };
    let hex = hash_to_hex(hash);
    format!("{dir}/{}/{hex}", &hex[..2])
}

/// The key of `kind` at `names` below its kind's base, if they are names
/// this bucket writes.
fn hashed_key(kind: KeyKind, names: &[String]) -> Option<Key> {
    let [dirs @ .., prefix, file] = names else {
        return None;
    };
    let hash = object_hash(prefix, file)?;
    Some(match (kind, dirs) {
        (KeyKind::Xorb, []) => Key::Xorb(hash),
        (KeyKind::Shard, []) => Key::Shard(hash),
        (KeyKind::Registration, [scope, tenant]) => Key::Registration {
            scope: NameHash::from_hex(scope)?,
            tenant: NameHash::from_hex(tenant)?,
            shard: hash,
        },
        (KeyKind::XorbOwner, [tenant]) => Key::XorbOwner {
            tenant: NameHash::from_hex(tenant)?,
            xorb: hash,
        },
        (KeyKind::Purge, []) => Key::Purge(hash),
        _ => return None,
    })
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, StorageError> + Send + 'static,
) -> Result<T, StorageError> {
    tokio::task::spawn_blocking(f).await.unwrap_or_else(|err| {
        Err(StorageError::Io {
            op: "run blocking file work for",
            path: PathBuf::new(),
            source: std::io::Error::other(err.to_string()),
        })
    })
}

/// Removes a temp file left by a failed [`Bucket::get_to_file`], unless
/// [`TempFile::keep`] was called.
struct TempFile(Option<PathBuf>);

impl TempFile {
    fn path(&self) -> PathBuf {
        self.0.clone().unwrap_or_default()
    }

    fn keep(mut self) {
        self.0 = None;
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[async_trait::async_trait]
impl Bucket for ObjectBucket {
    async fn probe(&self) -> Result<(), StorageError> {
        let location = self.location(&format!(
            ".tmp/{}.ready-probe",
            uuid::Uuid::new_v4().simple()
        ));
        self.store
            .put(&location, PutPayload::from(Bytes::from_static(b"ready")))
            .await
            .map_err(|err| remote("write", &location, err))?;
        self.store
            .delete(&location)
            .await
            .map_err(|err| remote("delete", &location, err))
    }

    async fn put(&self, key: &Key, bytes: Bytes) -> Result<(), StorageError> {
        key.check_write(WriteMode::Put)?;
        self.create_or_check(key, bytes, true).await.map(drop)
    }

    async fn create(&self, key: &Key, bytes: Bytes) -> Result<bool, StorageError> {
        key.check_write(WriteMode::Create)?;
        self.create_or_check(key, bytes, false).await
    }

    async fn get(&self, key: &Key) -> Result<Option<Bytes>, StorageError> {
        let location = self.key_location(key);
        let result = match self.store.get(&location).await {
            Ok(result) => result,
            Err(object_store::Error::NotFound { .. }) => return Ok(None),
            Err(err) => return Err(remote("read", &location, err)),
        };
        result
            .bytes()
            .await
            .map(Some)
            .map_err(|err| remote("read", &location, err))
    }

    async fn list(&self, kind: KeyKind) -> Result<Vec<Key>, StorageError> {
        let (base, depth) = match kind {
            KeyKind::Xorb => ("xorbs/default", 2),
            KeyKind::Shard => ("shards", 2),
            KeyKind::Registration => ("registrations", 4),
            KeyKind::XorbOwner => ("xorb-owners", 3),
            KeyKind::Purge => ("purges", 2),
            KeyKind::RepoMeta | KeyKind::Pack | KeyKind::Midx | KeyKind::RefLog => {
                let mut keys = Vec::new();
                for names in self.list_at("repos", 1 + repo_depth(kind)).await? {
                    let [id, rest @ ..] = names.as_slice() else {
                        continue;
                    };
                    let Ok(repo) = RepoIdHex::parse(id) else {
                        continue;
                    };
                    keys.extend(repo_key(repo, kind, rest));
                }
                return Ok(keys);
            }
        };
        Ok(self
            .list_at(base, depth)
            .await?
            .iter()
            .filter_map(|names| hashed_key(kind, names))
            .collect())
    }

    async fn get_range(
        &self,
        key: &Key,
        start: u64,
        end_inclusive: u64,
    ) -> Result<Bytes, StorageError> {
        let location = self.key_location(key);
        self.checked_size(key, &location, start, end_inclusive)
            .await?;
        match self
            .store
            .get_range(&location, start..end_inclusive + 1)
            .await
        {
            Ok(bytes) => Ok(bytes),
            Err(object_store::Error::NotFound { .. }) => Err(StorageError::NotFound {
                key: Box::new(key.clone()),
            }),
            Err(err) => Err(remote("read", &location, err)),
        }
    }

    async fn get_range_stream(
        &self,
        key: &Key,
        start: u64,
        end_inclusive: u64,
    ) -> Result<RangeStream, StorageError> {
        let location = self.key_location(key);
        let size = self
            .checked_size(key, &location, start, end_inclusive)
            .await?;
        let options = GetOptions {
            range: Some(GetRange::Bounded(start..end_inclusive + 1)),
            ..GetOptions::default()
        };
        let result = match self.store.get_opts(&location, options).await {
            Ok(result) => result,
            Err(object_store::Error::NotFound { .. }) => {
                return Err(StorageError::NotFound {
                    key: Box::new(key.clone()),
                });
            }
            Err(err) => return Err(remote("read", &location, err)),
        };
        let shown = location.to_string();
        // The store yields blocks of its own size; re-cut them to at most
        // STREAM_BLOCK_BYTES so a reader holds one block (ruling M1-R27).
        let blocks = result
            .into_stream()
            .map_err(move |err| StorageError::Remote {
                op: "read",
                location: shown.clone(),
                source: Box::new(err),
            })
            .map_ok(|bytes| {
                let mut parts: Vec<Result<Bytes, StorageError>> =
                    Vec::with_capacity(bytes.len().div_ceil(STREAM_BLOCK_BYTES).max(1));
                let mut rest = bytes;
                while rest.len() > STREAM_BLOCK_BYTES {
                    parts.push(Ok(rest.split_to(STREAM_BLOCK_BYTES)));
                }
                parts.push(Ok(rest));
                futures_util::stream::iter(parts)
            })
            .try_flatten();
        Ok(RangeStream {
            size,
            blocks: Box::pin(blocks),
        })
    }

    async fn size(&self, key: &Key) -> Result<Option<u64>, StorageError> {
        self.head_size(&self.key_location(key)).await
    }

    async fn put_replace(&self, key: Key, bytes: Bytes) -> Result<(), StorageError> {
        key.check_write(WriteMode::Replace)?;
        let location = self.key_location(&key);
        self.store
            .put(&location, PutPayload::from(bytes))
            .await
            .map(drop)
            .map_err(|err| remote("write", &location, err))
    }

    async fn put_stream(
        &self,
        key: Key,
        mut body: BodyStream,
        len: u64,
    ) -> Result<(), StorageError> {
        key.check_write(WriteMode::Put)?;
        let location = self.key_location(&key);
        let length_mismatch = |received| StorageError::LengthMismatch {
            key: Box::new(key.clone()),
            expected: len,
            received,
        };
        let read_error = |err: std::io::Error| StorageError::Remote {
            op: "read the body for",
            location: location.to_string(),
            source: Box::new(err),
        };
        if self.check_existing(&key, &location, len).await?.is_some() {
            // Written once: the first object stays, so its last_modified
            // stays its publish time. The body is still read for its length.
            let mut received = 0u64;
            while let Some(block) = body.next().await {
                received += block.map_err(read_error)?.len() as u64;
                if received > len {
                    return Err(length_mismatch(received));
                }
            }
            return if received == len {
                Ok(())
            } else {
                Err(length_mismatch(received))
            };
        }
        // Up to PART_BYTES is one PUT; past that, a multipart upload.
        let mut head = BytesMut::new();
        while let Some(block) = body.next().await {
            let block = block.map_err(read_error)?;
            if (head.len() + block.len()) as u64 > len {
                return Err(length_mismatch((head.len() + block.len()) as u64));
            }
            head.extend_from_slice(&block);
            if head.len() > PART_BYTES {
                return self
                    .multipart(&key, &location, head.freeze(), &mut body, len)
                    .await;
            }
        }
        if head.len() as u64 != len {
            return Err(length_mismatch(head.len() as u64));
        }
        self.store
            .put(&location, PutPayload::from(head.freeze()))
            .await
            .map(drop)
            .map_err(|err| remote("write", &location, err))
    }

    async fn get_to_file(&self, key: Key, path: &Path) -> Result<u64, StorageError> {
        let size = self
            .size(&key)
            .await?
            .ok_or_else(|| StorageError::NotFound {
                key: Box::new(key.clone()),
            })?;
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_path_buf();
        let name = path
            .file_name()
            .map_or_else(|| "object".into(), |n| n.to_string_lossy().into_owned());
        let temp = TempFile(Some(
            dir.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4().simple())),
        ));
        let temp_path = temp.path();
        let mut file = blocking(move || {
            create_private_file(&temp_path).map_err(io("create temp file", &temp_path))
        })
        .await?;
        if size > 0 {
            let mut stream = self.get_range_stream(&key, 0, size - 1).await?.blocks;
            while let Some(block) = stream.next().await {
                let block = block?;
                let temp_path = temp.path();
                file = blocking(move || {
                    file.write_all(&block)
                        .map_err(io("write temp file", &temp_path))?;
                    Ok(file)
                })
                .await?;
            }
        }
        let dest = path.to_path_buf();
        let temp_path = temp.path();
        blocking(move || {
            file.sync_all().map_err(io("fsync temp file", &temp_path))?;
            drop(file);
            std::fs::rename(&temp_path, &dest).map_err(io("rename into place", &dest))?;
            #[cfg(unix)]
            File::open(&dir)
                .and_then(|d| d.sync_all())
                .map_err(io("fsync directory", &dir))?;
            Ok(())
        })
        .await?;
        // Renamed: nothing left to remove.
        temp.keep();
        Ok(size)
    }

    async fn last_modified(&self, key: Key) -> Result<Option<u64>, StorageError> {
        let location = self.key_location(&key);
        match self.store.head(&location).await {
            Ok(meta) => Ok(Some(
                u64::try_from(meta.last_modified.timestamp()).unwrap_or(0),
            )),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(err) => Err(remote("look up", &location, err)),
        }
    }

    async fn list_under(&self, repo: RepoIdHex, kind: KeyKind) -> Result<Vec<Key>, StorageError> {
        if !kind.is_per_repo() {
            return Err(StorageError::InvalidKey {
                key: format!("{kind:?}"),
                reason: "list_under lists one repository's metadata, packs, multi-pack indexes or ref log; list every other kind with list",
            });
        }
        Ok(self
            .list_at(&format!("repos/{repo}"), repo_depth(kind))
            .await?
            .iter()
            .filter_map(|names| repo_key(repo, kind, names))
            .collect())
    }

    async fn delete(&self, key: &Key) -> Result<bool, StorageError> {
        if !matches!(key.kind(), KeyKind::Pack | KeyKind::Midx) {
            return Err(StorageError::InvalidKey {
                key: key.to_string(),
                reason: "only a Git pack's or multi-pack index's files are deleted, by the pack sweep",
            });
        }
        let location = self.key_location(key);
        // S3 answers a delete of a missing object as a success, so look first.
        if self.head_size(&location).await?.is_none() {
            return Ok(false);
        }
        match self.store.delete(&location).await {
            Ok(()) | Err(object_store::Error::NotFound { .. }) => Ok(true),
            Err(err) => Err(remote("delete", &location, err)),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use openxet_protocol::chunk_hash;

    use super::*;
    use crate::{MidxExt, PackExt, PackName};

    #[test]
    fn layout_is_local_buckets() {
        let h = chunk_hash(b"x");
        let hex = hash_to_hex(&h);
        let p = &hex[..2];
        let repo = RepoIdHex::parse("0123456789abcdef0123456789abcdef").unwrap();
        let scope = NameHash::of("s");
        let tenant = NameHash::of("t");
        assert_eq!(relative(&Key::Xorb(h)), format!("xorbs/default/{p}/{hex}"));
        assert_eq!(relative(&Key::Shard(h)), format!("shards/{p}/{hex}"));
        assert_eq!(
            relative(&Key::registration("s", "t", h)),
            format!("registrations/{scope}/{tenant}/{p}/{hex}")
        );
        assert_eq!(
            relative(&Key::xorb_owner("t", h)),
            format!("xorb-owners/{tenant}/{p}/{hex}")
        );
        assert_eq!(relative(&Key::Purge(h)), format!("purges/{p}/{hex}"));
        assert_eq!(
            relative(&Key::RepoMeta { repo }),
            "repos/0123456789abcdef0123456789abcdef/meta"
        );
        let name = PackName::parse(&format!("pack-{}", "a".repeat(40))).unwrap();
        assert_eq!(
            relative(&Key::Pack {
                repo,
                name,
                ext: PackExt::Idx
            }),
            format!("repos/{repo}/packs/pack-{}.idx", "a".repeat(40))
        );
        assert_eq!(
            relative(&Key::Midx {
                repo,
                generation: 3,
                ext: MidxExt::Bitmap
            }),
            format!("repos/{repo}/midx/3.bitmap")
        );
    }

    #[test]
    fn open_refuses_other_schemes_and_bare_urls() {
        let none = BTreeMap::new();
        for url in [
            "gs://b/p",
            "file:///tmp/b",
            "s3:///p",
            "s3://b/p?endpoint=x",
            "s3://user@b/p",
        ] {
            let err = ObjectBucket::open(&Url::parse(url).unwrap(), &none, None).unwrap_err();
            assert!(
                matches!(err, StorageError::UnsupportedUrl { .. }),
                "{url}: {err}"
            );
        }
    }

    #[test]
    fn open_refuses_unknown_options() {
        let options = BTreeMap::from([("no_such_option".to_owned(), "1".to_owned())]);
        let err = ObjectBucket::open(&Url::parse("s3://b/p").unwrap(), &options, None).unwrap_err();
        assert!(err.to_string().contains("no_such_option"), "{err}");
    }

    #[test]
    fn open_takes_minio_options_and_keeps_the_prefix() {
        let options = BTreeMap::from([
            ("endpoint".to_owned(), "http://127.0.0.1:9000".to_owned()),
            ("allow_http".to_owned(), "true".to_owned()),
            ("region".to_owned(), "us-east-1".to_owned()),
        ]);
        let bucket =
            ObjectBucket::open(&Url::parse("s3://b/a/b/").unwrap(), &options, None).unwrap();
        assert_eq!(bucket.store().1, "a/b");
    }
}
