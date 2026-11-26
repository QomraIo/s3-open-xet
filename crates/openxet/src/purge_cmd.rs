//! `openxet purge`: unregisters a file from every scope (ruling M2-R13),
//! working on the server's own index and bucket, as its configuration names
//! them, with or without the server running.
//!
//! The bucket's purge record is written first, then the index rows go,
//! then the audit row: the bucket is the source of truth (design §5.3), so
//! a purge interrupted after its record is finished by running it again,
//! and `reindex` (M4) skips the file's registrations up to the record's
//! `through_seq` either way, keeping a later upload of the same bytes. Nothing is deleted from
//! the bucket (non-negotiable 3): the file's xorbs stay until garbage
//! collection finds them unreferenced.

use std::io::{self, BufRead as _, IsTerminal as _, Write as _};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use openxet_client::ClientError;
use openxet_index::{AuditEntry, HubIndex, IndexError, SqliteIndex};
use openxet_protocol::{MerkleHash, hash_from_hex};
use openxet_storage::{Bucket, Key, LocalBucket, PurgeRecord, StorageError};
use serde::Serialize;
use serde_json::json;
use url::Url;

use crate::config::{self, Config, Overrides};
use crate::error::CliError;
use crate::output::{HumanDisplay, Output};
use crate::serve::{self, BUCKET_DIR, INDEX_FILE};
use crate::transfer_cmd::{client_error, usage_error};

/// `openxet purge`'s options.
#[derive(Debug, clap::Args)]
pub struct PurgeArgs {
    /// The file's Xet hash, as `openxet upload` printed it
    #[arg(value_name = "HASH")]
    hash: String,
    /// The server's TOML configuration file, for its data directory
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// The server's data directory, in place of `server.data_dir`
    #[arg(long, value_name = "DIR")]
    data_dir: Option<PathBuf>,
    /// Report how many scopes the file would be removed from, and change
    /// nothing
    #[arg(long)]
    dry_run: bool,
    /// Purge without asking; required with `--json` and without a terminal
    #[arg(long)]
    yes: bool,
    /// Who is purging, as the audit log and the purge record name it
    /// [default: `cli:` and the operating system user]
    #[arg(long, value_name = "NAME")]
    actor: Option<String>,
}

/// The `openxet.purge.v1` result.
#[derive(Serialize)]
struct Purged {
    schema: &'static str,
    file: String,
    /// The scopes the file was removed from, or with `dry_run` would be.
    scopes_removed: u64,
    dry_run: bool,
}

impl HumanDisplay for Purged {
    fn human(&self) -> String {
        let scopes = scopes(self.scopes_removed);
        if self.dry_run {
            format!(
                "Dry run: purging {} would remove it from {scopes}. Nothing was changed.",
                self.file
            )
        } else {
            format!(
                "Purged {}: removed it from {scopes}. No scope serves it now, and the purge \
                 record in the bucket keeps a reindex from restoring it.",
                self.file
            )
        }
    }
}

fn scopes(n: u64) -> String {
    if n == 1 {
        "1 scope".to_owned()
    } else {
        format!("{n} scopes")
    }
}

pub fn run(args: &PurgeArgs, output: Output) -> Result<(), CliError> {
    if !openxet_client::is_hash(&args.hash) {
        return Err(client_error(&ClientError::InvalidHash));
    }
    let file = hash_from_hex(&args.hash).map_err(|_| client_error(&ClientError::InvalidHash))?;
    if !args.yes && !args.dry_run && output == Output::Json {
        return Err(confirmation_required(
            "`openxet purge --json` never asks for confirmation",
        ));
    }
    let overrides = Overrides {
        data_dir: args.data_dir.clone(),
        ..Overrides::default()
    };
    let loaded = config::load(args.config.as_deref(), std::env::vars_os(), &overrides);
    let config = loaded
        .config
        .ok_or_else(|| CliError::config(&loaded.problems))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| {
            CliError::new(
                "runtime",
                format!("could not start the async runtime: {err}"),
                "Check the process's thread and file-descriptor limits.",
            )
        })?;
    let purged = runtime.block_on(purge(&config, file, args))?;
    output.emit(&purged).map_err(|err| CliError::output(&err))
}

async fn purge(config: &Config, file: MerkleHash, args: &PurgeArgs) -> Result<Purged, CliError> {
    let index = open_index(config).await?;
    let present = index
        .file_scope_count(&file)
        .await
        .map_err(|err| index_error(&err))?;
    let (bucket, place) = open_bucket(config).await?;
    let bucket = bucket.as_ref();
    let key = Key::Purge(file);
    let earlier = read_record(bucket, &key, &place).await?;
    // A record is permanent: one for a hash nothing holds would only skip
    // a later upload's registrations on a reindex.
    if present == 0 && earlier.is_none() {
        return Err(not_found(&args.hash));
    }
    let result = |scopes_removed, dry_run| Purged {
        schema: "openxet.purge.v1",
        file: args.hash.clone(),
        scopes_removed,
        dry_run,
    };
    if args.dry_run {
        return Ok(result(present, true));
    }
    if !args.yes {
        require_terminal()?;
    }
    // A re-run completes the earlier purge under its record, so only a
    // first purge names who runs it.
    let run = match earlier {
        Some(record) => Run::Completion(record),
        None => Run::First {
            actor: actor(args.actor.as_deref())?,
        },
    };
    if !args.yes {
        confirm(&args.hash, present)?;
    }
    let (record, completes) = match run {
        Run::Completion(record) => (record, true),
        Run::First { actor } => {
            let through_seq = index
                .next_registration_seq()
                .await
                .map_err(|err| index_error(&err))?;
            let record = PurgeRecord {
                file,
                actor,
                at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()),
                through_seq: Some(through_seq),
            };
            // Bucket first (ruling M2-R13). Losing the create to a
            // concurrent purge completes that one's record instead.
            let created = bucket
                .create(&key, record.to_bytes())
                .await
                .map_err(|err| storage_error(&place, &err))?;
            if created {
                (record, false)
            } else {
                let stored = read_record(bucket, &key, &place).await?;
                (stored.unwrap_or(record), true)
            }
        }
    };
    let removed = index
        .purge_file(&file)
        .await
        .map_err(|err| index_error(&err))?;
    index
        .audit(&AuditEntry {
            actor: record.actor,
            action: "purge".to_owned(),
            repo: None,
            detail: json!({
                "file": args.hash,
                "scopes_removed": removed,
                "through_seq": record.through_seq,
                "completes_earlier_purge": completes,
                "purged_at": record.at,
            }),
        })
        .await
        .map_err(|err| index_error(&err))?;
    Ok(result(removed, false))
}

/// A purge's first run, or a run completing an earlier one.
enum Run {
    First { actor: String },
    Completion(PurgeRecord),
}

/// The purge record already in the bucket, if any.
async fn read_record(
    bucket: &dyn Bucket,
    key: &Key,
    place: &Place,
) -> Result<Option<PurgeRecord>, CliError> {
    let Some(bytes) = bucket
        .get(key)
        .await
        .map_err(|err| storage_error(place, &err))?
    else {
        return Ok(None);
    };
    PurgeRecord::from_bytes(key, &bytes)
        .map(Some)
        .map_err(|err| storage_error(place, &err))
}

fn not_found(hash: &str) -> CliError {
    CliError::new(
        "not_found",
        format!("no scope holds {hash}, and it was never purged; nothing was purged"),
        "Check the hash `openxet upload` printed. A purge of a file no scope holds writes \
         nothing, so it never blocks a later upload of those bytes.",
    )
}

/// The longest actor the audit log and the purge record take.
const MAX_ACTOR_BYTES: usize = 256;

/// `--actor`, or `cli:` and the operating system user.
fn actor(flag: Option<&str>) -> Result<String, CliError> {
    let actor = if let Some(actor) = flag {
        actor.to_owned()
    } else {
        let user = ["USER", "LOGNAME", "USERNAME"]
            .into_iter()
            .find_map(|var| std::env::var(var).ok().filter(|v| !v.is_empty()))
            .ok_or_else(|| {
                usage_error(
                    "no_actor",
                    "could not tell who is purging: none of USER, LOGNAME and USERNAME is set",
                    "Pass `--actor NAME`; the audit log and the purge record name it.",
                )
            })?;
        format!("cli:{user}")
    };
    if actor.is_empty() || actor.len() > MAX_ACTOR_BYTES || actor.chars().any(char::is_control) {
        return Err(usage_error(
            "invalid_actor",
            "the actor is empty, longer than 256 bytes, or holds a control character",
            "Pass `--actor NAME` with a printable name of at most 256 bytes, such as your user \
             name.",
        ));
    }
    Ok(actor)
}

fn confirmation_required(why: &str) -> CliError {
    usage_error(
        "confirmation_required",
        &format!("{why}; nothing was purged"),
        "Pass `--yes` to purge, or `--dry-run` to see how many scopes it would remove the \
         file from.",
    )
}

/// A run without `--yes` needs a terminal to ask on.
fn require_terminal() -> Result<(), CliError> {
    if io::stdin().is_terminal() && io::stderr().is_terminal() {
        Ok(())
    } else {
        Err(confirmation_required(
            "there is no terminal to confirm the purge on",
        ))
    }
}

/// Asks on the terminal [`require_terminal`] found.
fn confirm(hash: &str, present: u64) -> Result<(), CliError> {
    eprint!(
        "Purge {hash} from {}? No scope will serve it again. Type `yes` to purge: ",
        scopes(present)
    );
    let _ = io::stderr().flush();
    let mut answer = String::new();
    io::stdin().lock().read_line(&mut answer).map_err(|err| {
        CliError::new(
            "io",
            format!("could not read the answer: {err}"),
            "Pass `--yes` to purge without asking.",
        )
    })?;
    if answer.trim() == "yes" {
        Ok(())
    } else {
        Err(CliError::new(
            "declined",
            "the purge was not confirmed; nothing was purged",
            "Type `yes` to purge, or pass `--yes`.",
        ))
    }
}

const DATA_DIR_HINT: &str = "Pass the server's `--config`, or `--data-dir` with the directory \
     `openxet serve` uses (it prints it on startup).";

/// The server's index: its Postgres database, or the SQLite file in the
/// data directory. A data directory without one was never served from: it
/// is refused rather than given a new, empty index.
async fn open_index(config: &Config) -> Result<Arc<dyn HubIndex>, CliError> {
    if config.index.is_some() {
        return serve::open_index(config).await;
    }
    let dir = &config.data_dir;
    let path = dir.join(INDEX_FILE);
    if !path.is_file() {
        return Err(CliError::new(
            "index",
            format!("{} holds no openxet index ({INDEX_FILE})", dir.display()),
            DATA_DIR_HINT,
        ));
    }
    let index = SqliteIndex::open(&path).await.map_err(|err| {
        CliError::new(
            "index",
            format!("could not open the index in {}: {err}", dir.display()),
            "Check that you may write the data directory, as the server's user does.",
        )
    })?;
    Ok(Arc::new(index))
}

/// Where the bucket is, for messages: the purge record must land in the
/// bucket the server reads, or a reindex would restore the file.
enum Place {
    /// The local bucket in this data directory.
    Local(PathBuf),
    /// The object-store bucket `storage.url` names.
    Object(Url),
}

impl std::fmt::Display for Place {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local(dir) => write!(f, "the bucket in {}", dir.display()),
            Self::Object(url) => write!(f, "the bucket at {url}"),
        }
    }
}

/// The server's bucket, as the configuration names it: with `storage.url`
/// the object-store bucket, never a local one a data directory may still
/// hold; otherwise the local bucket, which must exist, since a directory
/// without one was never served from.
async fn open_bucket(config: &Config) -> Result<(Arc<dyn Bucket>, Place), CliError> {
    if let Some(url) = &config.storage_url {
        return Ok((
            serve::open_bucket(config).await?,
            Place::Object(url.clone()),
        ));
    }
    let dir = &config.data_dir;
    let path = dir.join(BUCKET_DIR);
    if !path.is_dir() {
        return Err(CliError::new(
            "storage",
            format!("{} holds no openxet bucket ({BUCKET_DIR}/)", dir.display()),
            DATA_DIR_HINT,
        ));
    }
    let place = Place::Local(dir.clone());
    let bucket = LocalBucket::open(&path).map_err(|err| storage_error(&place, &err))?;
    Ok((Arc::new(bucket), place))
}

fn storage_error(place: &Place, err: &StorageError) -> CliError {
    let hint = match place {
        Place::Local(_) => {
            "Check that you may write the data directory, as the server's user does, and that \
             its disk has space; then run the purge again."
        }
        Place::Object(_) => {
            "Check the credentials (storage.credentials_file, or AWS_* in the environment) and \
             that this machine reaches the store; then run the purge again."
        }
    };
    CliError::new(
        "storage",
        format!("{place} failed: {err}; nothing was purged"),
        hint,
    )
}

fn index_error(err: &IndexError) -> CliError {
    CliError::new(
        "index",
        format!("the index failed: {err}"),
        "Check that you may write the data directory, as the server's user does, then run the \
         purge again: repeating it is safe, and finishes a purge whose bucket record was \
         already written.",
    )
}
