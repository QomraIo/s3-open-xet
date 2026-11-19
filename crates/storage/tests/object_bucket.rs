//! `ObjectBucket` against `object_store`'s in-memory store, always, and
//! against a real store when `OPENXET_TEST_STORAGE_URL` names one (M3 plan,
//! Task 6), for example `MinIO`:
//!
//! ```bash
//! docker run -d -p 9000:9000 -e MINIO_ROOT_USER=minio -e MINIO_ROOT_PASSWORD=minio123 \
//!   minio/minio server /data
//! # create the bucket `openxet-test`, then:
//! AWS_ACCESS_KEY_ID=minio AWS_SECRET_ACCESS_KEY=minio123 \
//! OPENXET_TEST_STORAGE_URL=s3://openxet-test/ci \
//! OPENXET_TEST_STORAGE_OPTIONS='endpoint=http://127.0.0.1:9000,allow_http=true,region=us-east-1' \
//!   cargo nextest run -p openxet-storage -E 'binary(object_bucket)'
//! ```
//!
//! Every case runs under a fresh random prefix, so runs never see each
//! other's objects.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation
)]

use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::StreamExt as _;
use object_store::ObjectStore;
use object_store::memory::InMemory;
use object_store::path::Path as StorePath;
use openxet_protocol::chunk_hash;
use openxet_storage::{
    Bucket, Key, KeyKind, LocalBucket, ObjectBucket, PackExt, PackName, RepoIdHex,
    STREAM_BLOCK_BYTES, StorageError,
};

/// The buckets each case runs against: in-memory, and the store named by
/// `OPENXET_TEST_STORAGE_URL` if set.
fn buckets() -> Vec<ObjectBucket> {
    let run = uuid::Uuid::new_v4().simple().to_string();
    let mut out = vec![ObjectBucket::with_store(
        Arc::new(InMemory::new()),
        &format!("test/{run}"),
        "memory://test",
    )];
    if let Ok(url) = std::env::var("OPENXET_TEST_STORAGE_URL") {
        let options: BTreeMap<String, String> = std::env::var("OPENXET_TEST_STORAGE_OPTIONS")
            .unwrap_or_default()
            .split(',')
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
            .collect();
        let url = url::Url::parse(&format!("{}/{run}", url.trim_end_matches('/'))).unwrap();
        out.push(ObjectBucket::open(&url, &options).unwrap());
    }
    out
}

fn repo() -> RepoIdHex {
    RepoIdHex::parse(&uuid::Uuid::new_v4().simple().to_string()).unwrap()
}

fn pack(repo: RepoIdHex, n: u8, ext: PackExt) -> Key {
    Key::Pack {
        repo,
        name: PackName::parse(&format!("pack-{}", hex_byte(n).repeat(20))).unwrap(),
        ext,
    }
}

fn hex_byte(n: u8) -> String {
    format!("{n:02x}")
}

fn body(blocks: Vec<Bytes>) -> openxet_storage::BodyStream {
    futures_util::stream::iter(blocks.into_iter().map(Ok)).boxed()
}

#[tokio::test]
async fn conditional_create_probe_passes() {
    for bucket in buckets() {
        let node = uuid::Uuid::new_v4();
        bucket.probe_conditional_create(node).await.unwrap();
        // The probe object is reused on the next start.
        bucket.probe_conditional_create(node).await.unwrap();
        bucket.probe().await.unwrap();
    }
}

/// A store that takes `If-None-Match: *` and overwrites anyway: the
/// conditional create every registration relies on is a no-op.
#[derive(Debug)]
struct IgnoresCreate(InMemory);

impl std::fmt::Display for IgnoresCreate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IgnoresCreate")
    }
}

#[async_trait::async_trait]
impl ObjectStore for IgnoresCreate {
    async fn put_opts(
        &self,
        location: &StorePath,
        payload: object_store::PutPayload,
        _opts: object_store::PutOptions,
    ) -> object_store::Result<object_store::PutResult> {
        self.0.put(location, payload).await
    }

    async fn put_multipart_opts(
        &self,
        location: &StorePath,
        opts: object_store::PutMultipartOptions,
    ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
        self.0.put_multipart_opts(location, opts).await
    }

    async fn get_opts(
        &self,
        location: &StorePath,
        options: object_store::GetOptions,
    ) -> object_store::Result<object_store::GetResult> {
        self.0.get_opts(location, options).await
    }

    async fn delete(&self, location: &StorePath) -> object_store::Result<()> {
        self.0.delete(location).await
    }

    fn list(
        &self,
        prefix: Option<&StorePath>,
    ) -> futures_util::stream::BoxStream<'static, object_store::Result<object_store::ObjectMeta>>
    {
        self.0.list(prefix)
    }

    async fn list_with_delimiter(
        &self,
        prefix: Option<&StorePath>,
    ) -> object_store::Result<object_store::ListResult> {
        self.0.list_with_delimiter(prefix).await
    }

    async fn copy(&self, from: &StorePath, to: &StorePath) -> object_store::Result<()> {
        self.0.copy(from, to).await
    }

    async fn copy_if_not_exists(
        &self,
        from: &StorePath,
        to: &StorePath,
    ) -> object_store::Result<()> {
        self.0.copy_if_not_exists(from, to).await
    }
}

/// ADR 0015 item 6: a store that overwrites on a conditional create is
/// refused before the server takes traffic, naming the check and the
/// setting.
#[tokio::test]
async fn start_refuses_store_without_conditional_create() {
    let bucket = ObjectBucket::with_store(
        Arc::new(IgnoresCreate(InMemory::new())),
        "p",
        "s3://ignores-create/p",
    );
    let err = bucket
        .probe_conditional_create(uuid::Uuid::new_v4())
        .await
        .unwrap_err();
    let StorageError::Unsafe { check, hint, .. } = &err else {
        panic!("expected Unsafe, got {err}");
    };
    assert!(check.contains("If-None-Match"), "{check}");
    assert!(hint.contains("[storage.options]"), "{hint}");
}

#[tokio::test]
async fn put_is_idempotent_and_refuses_another_size() {
    for bucket in buckets() {
        let key = Key::Xorb(chunk_hash(b"put"));
        bucket.put(&key, Bytes::from_static(b"abc")).await.unwrap();
        bucket.put(&key, Bytes::from_static(b"abc")).await.unwrap();
        let err = bucket
            .put(&key, Bytes::from_static(b"abcd"))
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                StorageError::SizeConflict {
                    existing: 3,
                    new: 4,
                    ..
                }
            ),
            "{err}"
        );
        assert_eq!(bucket.get(&key).await.unwrap().unwrap(), "abc");
        assert_eq!(bucket.size(&key).await.unwrap(), Some(3));
        assert!(bucket.last_modified(key).await.unwrap().is_some());
    }
}

#[tokio::test]
async fn create_keeps_the_first_writer() {
    for bucket in buckets() {
        let key = Key::registration("scope", "tenant", chunk_hash(b"create"));
        assert!(
            bucket
                .create(&key, Bytes::from_static(b"first"))
                .await
                .unwrap()
        );
        assert!(
            !bucket
                .create(&key, Bytes::from_static(b"second!"))
                .await
                .unwrap()
        );
        assert_eq!(bucket.get(&key).await.unwrap().unwrap(), "first");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_race_one_winner_on_object_store() {
    for bucket in buckets() {
        let bucket = Arc::new(bucket);
        let key = Key::registration("race", "tenant", chunk_hash(b"race"));
        let tasks: Vec<_> = (0..32u8)
            .map(|i| {
                let (bucket, key) = (Arc::clone(&bucket), key.clone());
                tokio::spawn(async move {
                    let bytes = Bytes::from(format!("writer {i:02}"));
                    (bucket.create(&key, bytes.clone()).await.unwrap(), bytes)
                })
            })
            .collect();
        let mut winners = Vec::new();
        for task in tasks {
            let (stored, bytes) = task.await.unwrap();
            if stored {
                winners.push(bytes);
            }
        }
        assert_eq!(winners.len(), 1);
        assert_eq!(bucket.get(&key).await.unwrap().unwrap(), winners[0]);
    }
}

#[tokio::test]
async fn put_replace_is_only_for_repo_meta() {
    for bucket in buckets() {
        let meta = Key::RepoMeta { repo: repo() };
        bucket
            .put_replace(meta.clone(), Bytes::from_static(b"one"))
            .await
            .unwrap();
        bucket
            .put_replace(meta.clone(), Bytes::from_static(b"two!"))
            .await
            .unwrap();
        assert_eq!(bucket.get(&meta).await.unwrap().unwrap(), "two!");
        let xorb = Key::Xorb(chunk_hash(b"replace"));
        assert!(matches!(
            bucket.put_replace(xorb, Bytes::new()).await,
            Err(StorageError::InvalidKey { .. })
        ));
        assert!(matches!(
            bucket.put(&meta, Bytes::new()).await,
            Err(StorageError::InvalidKey { .. })
        ));
    }
}

#[tokio::test]
async fn ranges_are_inclusive_and_checked() {
    for bucket in buckets() {
        let key = Key::Xorb(chunk_hash(b"range"));
        let missing = Key::Xorb(chunk_hash(b"missing"));
        bucket
            .put(&key, Bytes::from_static(b"0123456789"))
            .await
            .unwrap();
        assert_eq!(bucket.get_range(&key, 2, 4).await.unwrap(), "234");
        assert_eq!(bucket.get_range(&key, 9, 9).await.unwrap(), "9");
        for (start, end) in [(5, 4), (0, 10), (10, 10)] {
            assert!(matches!(
                bucket.get_range(&key, start, end).await,
                Err(StorageError::RangeOutOfBounds { size: 10, .. })
            ));
        }
        assert!(matches!(
            bucket.get_range(&missing, 0, 0).await,
            Err(StorageError::NotFound { .. })
        ));
        assert!(bucket.get(&missing).await.unwrap().is_none());
        assert!(bucket.size(&missing).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn range_streams_yield_blocks_of_at_most_a_mib() {
    for bucket in buckets() {
        let key = Key::Xorb(chunk_hash(b"stream"));
        let data: Bytes = (0..(3 * STREAM_BLOCK_BYTES + 17))
            .map(|i| (i % 251) as u8)
            .collect::<Vec<_>>()
            .into();
        bucket.put(&key, data.clone()).await.unwrap();
        let end = data.len() as u64 - 2;
        let stream = bucket.get_range_stream(&key, 1, end).await.unwrap();
        assert_eq!(stream.size, data.len() as u64);
        let blocks: Vec<Bytes> = stream.blocks.map(Result::unwrap).collect().await;
        assert!(blocks.iter().all(|b| b.len() <= STREAM_BLOCK_BYTES));
        assert_eq!(blocks.concat(), data[1..=end as usize]);
    }
}

#[tokio::test]
async fn put_stream_small_and_multipart() {
    for bucket in buckets() {
        let r = repo();
        let small = pack(r, 1, PackExt::Idx);
        bucket
            .put_stream(small.clone(), body(vec!["ab".into(), "cd".into()]), 4)
            .await
            .unwrap();
        assert_eq!(bucket.get(&small).await.unwrap().unwrap(), "abcd");

        // Past one part: a multipart upload.
        let block = Bytes::from(vec![7u8; STREAM_BLOCK_BYTES]);
        let blocks = vec![block; 20];
        let len = (20 * STREAM_BLOCK_BYTES) as u64;
        let large = pack(r, 2, PackExt::Pack);
        bucket
            .put_stream(large.clone(), body(blocks.clone()), len)
            .await
            .unwrap();
        assert_eq!(bucket.size(&large).await.unwrap(), Some(len));

        // Written once: a second write of the same length keeps the first.
        bucket
            .put_stream(large.clone(), body(blocks), len)
            .await
            .unwrap();
        assert!(matches!(
            bucket.put_stream(large, body(vec!["x".into()]), 1).await,
            Err(StorageError::SizeConflict { .. })
        ));
    }
}

#[tokio::test]
async fn put_stream_with_the_wrong_length_stores_nothing() {
    for bucket in buckets() {
        let r = repo();
        let short = pack(r, 3, PackExt::Pack);
        assert!(matches!(
            bucket
                .put_stream(short.clone(), body(vec!["abc".into()]), 4)
                .await,
            Err(StorageError::LengthMismatch { .. })
        ));
        assert!(bucket.size(&short).await.unwrap().is_none());

        // Fails partway through a multipart upload, which is aborted.
        let long = pack(r, 4, PackExt::Pack);
        let blocks = vec![Bytes::from(vec![1u8; STREAM_BLOCK_BYTES]); 12];
        assert!(matches!(
            bucket
                .put_stream(long.clone(), body(blocks), (10 * STREAM_BLOCK_BYTES) as u64)
                .await,
            Err(StorageError::LengthMismatch { .. })
        ));
        assert!(bucket.size(&long).await.unwrap().is_none());

        let failing = pack(r, 5, PackExt::Pack);
        let blocks = futures_util::stream::iter(
            (0..12)
                .map(|_| Ok(Bytes::from(vec![2u8; STREAM_BLOCK_BYTES])))
                .chain([Err(std::io::Error::other("client went away"))]),
        )
        .boxed();
        assert!(
            bucket
                .put_stream(failing.clone(), blocks, (13 * STREAM_BLOCK_BYTES) as u64)
                .await
                .is_err()
        );
        assert!(bucket.size(&failing).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn list_and_list_under_find_what_was_written() {
    for bucket in buckets() {
        let xorb = Key::Xorb(chunk_hash(b"list xorb"));
        let shard = Key::Shard(chunk_hash(b"list shard"));
        let reg = Key::registration("s", "t", chunk_hash(b"list shard"));
        let owner = Key::xorb_owner("t", chunk_hash(b"list xorb"));
        let r = repo();
        let meta = Key::RepoMeta { repo: r };
        let idx = pack(r, 6, PackExt::Idx);
        bucket.put(&xorb, "x".into()).await.unwrap();
        bucket.put(&shard, "s".into()).await.unwrap();
        bucket.create(&reg, "r".into()).await.unwrap();
        bucket.put(&owner, "o".into()).await.unwrap();
        bucket.put_replace(meta.clone(), "m".into()).await.unwrap();
        bucket
            .put_stream(idx.clone(), body(vec!["i".into()]), 1)
            .await
            .unwrap();
        // A name no key has is skipped.
        let (store, prefix) = bucket.store();
        store
            .put(
                &StorePath::from(format!("{prefix}/xorbs/default/zz/not-a-hash")),
                Bytes::from_static(b"?").into(),
            )
            .await
            .unwrap();

        assert_eq!(bucket.list(KeyKind::Xorb).await.unwrap(), vec![xorb]);
        assert_eq!(bucket.list(KeyKind::Shard).await.unwrap(), vec![shard]);
        assert_eq!(bucket.list(KeyKind::Registration).await.unwrap(), vec![reg]);
        assert_eq!(bucket.list(KeyKind::XorbOwner).await.unwrap(), vec![owner]);
        assert_eq!(
            bucket.list(KeyKind::RepoMeta).await.unwrap(),
            vec![meta.clone()]
        );
        assert_eq!(bucket.list(KeyKind::Pack).await.unwrap(), vec![idx.clone()]);
        assert_eq!(
            bucket.list_under(r, KeyKind::RepoMeta).await.unwrap(),
            vec![meta]
        );
        assert_eq!(
            bucket.list_under(r, KeyKind::Pack).await.unwrap(),
            vec![idx]
        );
        assert!(
            bucket
                .list_under(r, KeyKind::Midx)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            bucket.list_under(r, KeyKind::Xorb).await,
            Err(StorageError::InvalidKey { .. })
        ));
    }
}

#[tokio::test]
async fn delete_only_packs_and_says_whether_they_existed() {
    for bucket in buckets() {
        let r = repo();
        let p = pack(r, 7, PackExt::Pack);
        bucket
            .put_stream(p.clone(), body(vec!["p".into()]), 1)
            .await
            .unwrap();
        assert!(bucket.delete(&p).await.unwrap());
        assert!(!bucket.delete(&p).await.unwrap());
        assert!(bucket.size(&p).await.unwrap().is_none());
        assert!(matches!(
            bucket.delete(&Key::Xorb(chunk_hash(b"delete"))).await,
            Err(StorageError::InvalidKey { .. })
        ));
    }
}

#[tokio::test]
async fn get_to_file_copies_the_object() {
    for bucket in buckets() {
        let dir = tempfile::tempdir().unwrap();
        let r = repo();
        let p = pack(r, 8, PackExt::Pack);
        let data = Bytes::from(vec![9u8; 2 * STREAM_BLOCK_BYTES + 5]);
        bucket
            .put_stream(p.clone(), body(vec![data.clone()]), data.len() as u64)
            .await
            .unwrap();
        let dest = dir.path().join("copy.pack");
        assert_eq!(
            bucket.get_to_file(p, &dest).await.unwrap(),
            data.len() as u64
        );
        assert_eq!(std::fs::read(&dest).unwrap(), data);
        // No temp file left beside it.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);

        let missing = pack(r, 9, PackExt::Pack);
        assert!(matches!(
            bucket.get_to_file(missing, &dir.path().join("none")).await,
            Err(StorageError::NotFound { .. })
        ));
    }
}

/// A local bucket copied into a store (as `aws s3 sync bucket/
/// s3://b/prefix` does) is read as it is: the layouts are the same.
#[tokio::test]
async fn a_synced_local_bucket_reads_back() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("bucket");
    let local = LocalBucket::open(&root).unwrap();
    let xorb = Key::Xorb(chunk_hash(b"synced"));
    let reg = Key::registration("s", "t", chunk_hash(b"synced shard"));
    let r = repo();
    let meta = Key::RepoMeta { repo: r };
    local.put(&xorb, "xorb".into()).await.unwrap();
    local.create(&reg, "reg".into()).await.unwrap();
    local
        .put_replace(meta.clone(), "meta".into())
        .await
        .unwrap();

    let store = Arc::new(InMemory::new());
    for entry in walk(&root) {
        let rel = entry
            .strip_prefix(&root)
            .unwrap()
            .to_str()
            .unwrap()
            .replace('\\', "/");
        if rel.starts_with(".tmp") {
            continue;
        }
        store
            .put(
                &StorePath::from(format!("synced/{rel}")),
                Bytes::from(std::fs::read(&entry).unwrap()).into(),
            )
            .await
            .unwrap();
    }
    let bucket = ObjectBucket::with_store(store, "synced", "memory://synced");
    assert_eq!(
        bucket.list(KeyKind::Xorb).await.unwrap(),
        vec![xorb.clone()]
    );
    assert_eq!(
        bucket.list(KeyKind::Registration).await.unwrap(),
        vec![reg.clone()]
    );
    assert_eq!(
        bucket.list(KeyKind::RepoMeta).await.unwrap(),
        vec![meta.clone()]
    );
    assert_eq!(bucket.get(&xorb).await.unwrap().unwrap(), "xorb");
    assert_eq!(bucket.get(&reg).await.unwrap().unwrap(), "reg");
    assert_eq!(bucket.get(&meta).await.unwrap().unwrap(), "meta");
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(walk(&path));
        } else {
            files.push(path);
        }
    }
    files
}
