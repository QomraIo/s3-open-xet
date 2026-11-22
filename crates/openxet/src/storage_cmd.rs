//! `openxet storage setup`: connect the server to an S3 or S3-compatible
//! bucket before its first start.
//!
//! It checks the bucket, creating it with `--create-bucket`, runs the
//! conditional-create probe `serve` runs (ADR 0015 item 6), then stores the
//! credentials in a `0600` file and writes the configuration that names it.
//! The configuration itself never holds a credential (ADR 0015 item 5).
//! Nothing is written until every check has passed.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{self, BufRead as _, IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};

use openxet_storage::{BucketCreated, ObjectBucket, S3Credentials, StorageError};
use serde::Serialize;
use url::Url;
use zeroize::Zeroizing;

use crate::error::{CliError, ExitCode};
use crate::output::{HumanDisplay, Output};
use crate::secret;

#[derive(Debug, clap::Subcommand)]
pub enum StorageCommand {
    /// Connect the server to an S3 or S3-compatible bucket: check or create
    /// the bucket, store the credentials and write the configuration
    Setup(SetupArgs),
}

#[derive(Debug, clap::Args)]
pub struct SetupArgs {
    /// The bucket, as `s3://bucket` or `s3://bucket/prefix`
    url: String,
    /// The endpoint of an S3-compatible store, such as
    /// `http://127.0.0.1:9000` for a local `MinIO` [default: AWS S3]
    #[arg(long, value_name = "URL")]
    endpoint: Option<String>,
    /// The bucket's region [default: `$AWS_REGION`, or `us-east-1`]
    #[arg(long)]
    region: Option<String>,
    /// Create the bucket if it doesn't exist
    #[arg(long)]
    create_bucket: bool,
    /// The configuration file to write; an existing one is never changed
    /// [default: `$XDG_CONFIG_HOME/openxet/openxet.toml`, or
    /// `~/.config/openxet/openxet.toml`]
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Where to store the credentials, mode 0600 [default: `s3-credentials`
    /// beside the default configuration]
    #[arg(long, value_name = "FILE")]
    credentials_file: Option<PathBuf>,
    /// Check the credentials and the bucket; create, probe and write nothing
    #[arg(long)]
    dry_run: bool,
}

/// The directory `storage setup` keeps its files in by default, as `token
/// keygen` does: never the working directory, where a credential would be
/// one `git add` from a commit.
pub(crate) fn default_dir() -> Result<PathBuf, CliError> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .map(|h| h.join(".config"))
        });
    config.map(|c| c.join("openxet")).ok_or_else(|| {
        CliError::new(
            "io",
            "neither XDG_CONFIG_HOME nor HOME names a directory for the configuration",
            "Pass `--config FILE` and `--credentials-file FILE`.",
        )
    })
}

pub fn run(command: &StorageCommand, output: Output) -> Result<(), CliError> {
    match command {
        StorageCommand::Setup(args) => setup(args, output),
    }
}

/// Where the credentials came from.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum CredentialSource {
    /// The credentials file, from an earlier setup.
    File,
    Environment,
    Prompt,
}

/// What happened to the bucket.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum BucketState {
    Existed,
    Created,
    /// `--dry-run --create-bucket` on a missing bucket.
    WouldCreate,
}

#[derive(Serialize)]
struct Setup {
    schema: &'static str,
    url: String,
    bucket: BucketState,
    /// Whether the conditional-create probe ran and passed; `false` only
    /// for `--dry-run`.
    probed: bool,
    credentials: CredentialSource,
    credentials_file: String,
    transfer_key_file: String,
    config_file: String,
    /// Whether this run wrote `config_file`. An existing file is never
    /// changed: `config` is then what to add to it.
    config_written: bool,
    config: String,
    dry_run: bool,
}

impl HumanDisplay for Setup {
    fn human(&self) -> String {
        let bucket = match self.bucket {
            BucketState::Existed => format!("The bucket of {} exists.", self.url),
            BucketState::Created => format!("Created the bucket of {}.", self.url),
            BucketState::WouldCreate => format!(
                "The bucket of {} does not exist; a run without --dry-run creates it.",
                self.url
            ),
        };
        if self.dry_run {
            return format!(
                "{bucket}\nThe credentials ({}) reach it. Nothing was created or written.",
                source_name(self.credentials)
            );
        }
        let config = if self.config_written {
            format!("Wrote the configuration to {}.", self.config_file)
        } else {
            format!(
                "{} exists and was not changed. Add these settings to it:\n\n{}",
                self.config_file,
                self.config.trim_end()
            )
        };
        format!(
            "{bucket}\nThe store honours conditional creates.\n\
             The credentials are in {} (mode 0600), the transfer key in {}.\n{config}\n\
             \nStart the server with:\n  openxet serve --config {}",
            self.credentials_file, self.transfer_key_file, self.config_file
        )
    }
}

fn source_name(source: CredentialSource) -> &'static str {
    match source {
        CredentialSource::File => "from the credentials file",
        CredentialSource::Environment => "from the environment",
        CredentialSource::Prompt => "as entered",
    }
}

fn setup(args: &SetupArgs, output: Output) -> Result<(), CliError> {
    let url = Url::parse(&args.url).map_err(|err| invalid_url(&args.url, &err.to_string()))?;
    let options = options(args)?;
    // Refuse a URL or option the store can't take before asking for a secret.
    ObjectBucket::open(&url, &options, None)
        .map_err(|err| invalid_url(&args.url, &err.to_string()))?;
    let dir = || default_dir();
    let config_file = match &args.config {
        Some(file) => file.clone(),
        None => dir()?.join("openxet.toml"),
    };
    let credentials_file = match &args.credentials_file {
        Some(file) => file.clone(),
        None => dir()?.join("s3-credentials"),
    };
    let existing = existing_config(&config_file)?;
    let transfer_key_file = existing
        .transfer_key_file
        .clone()
        .unwrap_or_else(|| sibling(&credentials_file, "transfer.key"));
    let (credentials, source) = credentials(&credentials_file, output)?;

    let bucket = ObjectBucket::open(&url, &options, Some(&credentials))
        .map_err(|err| invalid_url(&args.url, &err.to_string()))?;
    let state = check_bucket(&bucket, &url, args)?;

    let shown = |path: &Path| {
        std::path::absolute(path)
            .unwrap_or_else(|_| path.to_owned())
            .display()
            .to_string()
    };
    let config = config_text(
        &url,
        &options,
        &shown(&credentials_file),
        existing
            .transfer_key_file
            .is_none()
            .then(|| shown(&transfer_key_file)),
    );
    let mut config_written = false;
    if !args.dry_run {
        if !matches!(source, CredentialSource::File) {
            secret::create(
                &credentials_file,
                secret::format_s3_credentials(&credentials).as_bytes(),
            )?;
        }
        secret::transfer_key(&transfer_key_file)?;
        if !existing.exists {
            secret::create_with_mode(&config_file, config.as_bytes(), 0o644)?;
            config_written = true;
        }
    }
    output
        .emit(&Setup {
            schema: "openxet.storage-setup.v1",
            url: url.to_string(),
            bucket: state,
            probed: !args.dry_run,
            credentials: source,
            credentials_file: shown(&credentials_file),
            transfer_key_file: shown(&transfer_key_file),
            config_file: shown(&config_file),
            config_written,
            config,
            dry_run: args.dry_run,
        })
        .map_err(|err| CliError::output(&err))
}

/// Checks the bucket, creating it if asked, then probes it unless
/// `--dry-run`.
fn check_bucket(
    bucket: &ObjectBucket,
    url: &Url,
    args: &SetupArgs,
) -> Result<BucketState, CliError> {
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
    runtime.block_on(async {
        let state = if bucket
            .bucket_exists()
            .await
            .map_err(|err| store_error(&err))?
        {
            BucketState::Existed
        } else if !args.create_bucket {
            return Err(CliError::new(
                "no_bucket",
                format!("the bucket of {url} does not exist"),
                "Pass `--create-bucket` to create it, or check the bucket name, --endpoint and \
                 --region.",
            ));
        } else if args.dry_run {
            BucketState::WouldCreate
        } else {
            match bucket
                .create_bucket()
                .await
                .map_err(|err| store_error(&err))?
            {
                BucketCreated::Created => BucketState::Created,
                BucketCreated::AlreadyOwned => BucketState::Existed,
            }
        };
        if !args.dry_run {
            bucket
                .probe_conditional_create(uuid::Uuid::new_v4())
                .await
                .map_err(|err| store_error(&err))?;
            openxet_storage::Bucket::probe(bucket)
                .await
                .map_err(|err| store_error(&err))?;
        }
        Ok(state)
    })
}

/// `[storage.options]` from the flags. An `http://` endpoint is allowed
/// plain HTTP: naming one is the operator's choice of it.
fn options(args: &SetupArgs) -> Result<BTreeMap<String, String>, CliError> {
    let mut options = BTreeMap::new();
    if let Some(endpoint) = &args.endpoint {
        let parsed = Url::parse(endpoint).ok().filter(|u| {
            matches!(u.scheme(), "http" | "https") && u.host_str().is_some() && u.query().is_none()
        });
        let Some(parsed) = parsed else {
            return Err(CliError::new(
                "invalid_endpoint",
                format!("--endpoint {endpoint} is not an http:// or https:// URL"),
                "Pass the store's base URL, as in `--endpoint http://127.0.0.1:9000`.",
            )
            .with_exit(ExitCode::USAGE));
        };
        if parsed.scheme() == "http" {
            options.insert("allow_http".to_owned(), "true".to_owned());
        }
        options.insert(
            "endpoint".to_owned(),
            endpoint.trim_end_matches('/').to_owned(),
        );
    }
    if let Some(region) = &args.region {
        options.insert("region".to_owned(), region.clone());
    }
    Ok(options)
}

fn invalid_url(url: &str, why: &str) -> CliError {
    CliError::new(
        "invalid_url",
        format!("{url} is not a bucket this server can use: {why}"),
        "Pass the bucket as s3://bucket or s3://bucket/prefix.",
    )
    .with_exit(ExitCode::USAGE)
}

fn store_error(err: &StorageError) -> CliError {
    let hint = match err {
        StorageError::Unsafe { .. } => {
            "Use a store that honours conditional creates (AWS S3, R2, MinIO and Garage do)."
        }
        _ => {
            "Check the credentials, --endpoint and --region, and that this machine reaches the \
             store. Nothing was written."
        }
    };
    CliError::new("storage", err.to_string(), hint)
}

/// `path`'s sibling `name`.
fn sibling(path: &Path, name: &str) -> PathBuf {
    path.with_file_name(name)
}

/// What an existing configuration file already holds.
#[derive(Default)]
struct Existing {
    exists: bool,
    transfer_key_file: Option<PathBuf>,
}

/// The configuration at `path`, which must not already name a bucket.
fn existing_config(path: &Path) -> Result<Existing, CliError> {
    let Some(text) = secret::read_unchecked(path)? else {
        return Ok(Existing::default());
    };
    let table: toml::Table = toml::from_str(&text).map_err(|err| {
        CliError::new(
            "config",
            format!("{} is not valid TOML: {}", path.display(), err.message()),
            "Fix it, or pass another `--config`.",
        )
    })?;
    let section = |name: &str| table.get(name).and_then(toml::Value::as_table);
    if section("storage").is_some_and(|s| s.contains_key("url")) {
        return Err(CliError::new(
            "exists",
            format!("{} already sets storage.url", path.display()),
            "Nothing was changed. Remove [storage] from it to set the bucket up again, or pass \
             another `--config`.",
        )
        .with_exit(ExitCode::USAGE));
    }
    let transfer_key_file = section("cas")
        .and_then(|cas| cas.get("transfer_key_file"))
        .and_then(toml::Value::as_str)
        .map(PathBuf::from);
    Ok(Existing {
        exists: true,
        transfer_key_file,
    })
}

/// The configuration's text: `[storage]`, and `[cas]` when the transfer
/// key must be named, since an object-store bucket requires it.
fn config_text(
    url: &Url,
    options: &BTreeMap<String, String>,
    credentials_file: &str,
    transfer_key_file: Option<String>,
) -> String {
    let quoted = |text: &str| toml::Value::String(text.to_owned()).to_string();
    let mut text = String::from(
        "# Written by `openxet storage setup`. The credentials are in storage.credentials_file,\n\
         # never in this file.\n",
    );
    if let Some(key) = transfer_key_file {
        let _ = write!(text, "\n[cas]\ntransfer_key_file = {}\n", quoted(&key));
    }
    let _ = write!(
        text,
        "\n[storage]\nurl = {}\ncredentials_file = {}\n",
        quoted(url.as_str()),
        quoted(credentials_file)
    );
    if !options.is_empty() {
        text.push_str("\n[storage.options]\n");
        for (name, value) in options {
            let value = if name == "allow_http" {
                value.clone()
            } else {
                quoted(value)
            };
            let _ = writeln!(text, "{name} = {value}");
        }
    }
    text
}

/// The credentials: the file from an earlier setup, else `AWS_*` in the
/// environment, else asked for on a terminal.
fn credentials(file: &Path, output: Output) -> Result<(S3Credentials, CredentialSource), CliError> {
    let from_env = env_credentials()?;
    if let Some(stored) = secret::read_s3_credentials(file)? {
        if from_env.as_ref().is_some_and(|env| *env != stored) {
            return Err(CliError::new(
                "exists",
                format!(
                    "{} holds other credentials than AWS_ACCESS_KEY_ID and \
                     AWS_SECRET_ACCESS_KEY in the environment",
                    file.display()
                ),
                "Nothing was changed. Remove the file to store the new credentials, or unset \
                 the variables to use the stored ones.",
            )
            .with_exit(ExitCode::USAGE));
        }
        return Ok((stored, CredentialSource::File));
    }
    if let Some(env) = from_env {
        return Ok((env, CredentialSource::Environment));
    }
    if output == Output::Human && io::stdin().is_terminal() && io::stderr().is_terminal() {
        return Ok((prompt()?, CredentialSource::Prompt));
    }
    Err(CliError::new(
        "no_credentials",
        "no credentials for the object store",
        "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY (and AWS_SESSION_TOKEN for temporary \
         credentials), or run without --json on a terminal to be asked for them.",
    )
    .with_exit(ExitCode::USAGE))
}

fn env_credentials() -> Result<Option<S3Credentials>, CliError> {
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let (Some(key_id), Some(secret_key)) = (var("AWS_ACCESS_KEY_ID"), var("AWS_SECRET_ACCESS_KEY"))
    else {
        return Ok(None);
    };
    let credentials = S3Credentials {
        key_id,
        secret_key,
        session_token: var("AWS_SESSION_TOKEN"),
    };
    check_credentials(&credentials)?;
    Ok(Some(credentials))
}

fn check_credentials(credentials: &S3Credentials) -> Result<(), CliError> {
    let valid = secret::is_credential_value(&credentials.key_id)
        && secret::is_credential_value(&credentials.secret_key)
        && credentials
            .session_token
            .as_deref()
            .is_none_or(secret::is_credential_value);
    if valid {
        Ok(())
    } else {
        Err(CliError::new(
            "invalid_key",
            "a credential is empty or holds spaces or control characters",
            "Copy the access key id and secret access key again, without spaces.",
        )
        .with_exit(ExitCode::USAGE))
    }
}

/// Asks for the credentials on the terminal, the secret without echo.
fn prompt() -> Result<S3Credentials, CliError> {
    let key_id = ask("Access key id: ", false)?;
    let secret_key = ask("Secret access key: ", true)?;
    let credentials = S3Credentials {
        key_id: key_id.trim().to_owned(),
        secret_key: secret_key.trim().to_owned(),
        session_token: None,
    };
    check_credentials(&credentials)?;
    Ok(credentials)
}

fn ask(question: &str, hidden: bool) -> Result<Zeroizing<String>, CliError> {
    let failed = |err: io::Error| {
        CliError::new(
            "io",
            format!("could not read the answer: {err}"),
            "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY instead.",
        )
    };
    eprint!("{question}");
    let _ = io::stderr().flush();
    let echo = if hidden {
        Some(EchoOff::new().map_err(failed)?)
    } else {
        None
    };
    let mut answer = Zeroizing::new(String::new());
    // ECHONL still echoes the newline the user types.
    let read = io::stdin().lock().read_line(&mut answer);
    drop(echo);
    read.map_err(failed)?;
    Ok(answer)
}

/// Turns the terminal's echo off until dropped.
struct EchoOff {
    #[cfg(unix)]
    saved: rustix::termios::Termios,
}

impl EchoOff {
    #[cfg(unix)]
    fn new() -> io::Result<Self> {
        use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};
        let stdin = io::stdin();
        let saved = tcgetattr(&stdin)?;
        let mut quiet = saved.clone();
        quiet.local_modes.remove(LocalModes::ECHO);
        quiet.local_modes.insert(LocalModes::ECHONL);
        tcsetattr(&stdin, OptionalActions::Now, &quiet)?;
        Ok(Self { saved })
    }

    #[cfg(not(unix))]
    fn new() -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "hidden input is not supported on this platform",
        ))
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            let _ = rustix::termios::tcsetattr(
                io::stdin(),
                rustix::termios::OptionalActions::Now,
                &self.saved,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_names_the_credentials_file_and_never_a_credential() {
        let url = Url::parse("s3://bucket/prefix").unwrap();
        let options = BTreeMap::from([
            ("allow_http".to_owned(), "true".to_owned()),
            ("endpoint".to_owned(), "http://127.0.0.1:9000".to_owned()),
        ]);
        let text = config_text(
            &url,
            &options,
            "/c/s3-credentials",
            Some("/c/transfer.key".into()),
        );
        let table: toml::Table = toml::from_str(&text).unwrap();
        assert_eq!(
            table["cas"]["transfer_key_file"].as_str(),
            Some("/c/transfer.key")
        );
        assert_eq!(table["storage"]["url"].as_str(), Some("s3://bucket/prefix"));
        assert_eq!(
            table["storage"]["credentials_file"].as_str(),
            Some("/c/s3-credentials")
        );
        assert_eq!(
            table["storage"]["options"]["allow_http"].as_bool(),
            Some(true)
        );

        let text = config_text(&url, &BTreeMap::new(), "/c/s3-credentials", None);
        let table: toml::Table = toml::from_str(&text).unwrap();
        assert!(!table.contains_key("cas"));
        assert!(!table["storage"].as_table().unwrap().contains_key("options"));
    }

    #[test]
    fn an_existing_config_naming_a_bucket_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("openxet.toml");
        std::fs::write(&file, "[cas]\ntransfer_key_file = \"/k\"\n").unwrap();
        let existing = existing_config(&file).unwrap();
        assert!(existing.exists);
        assert_eq!(existing.transfer_key_file, Some(PathBuf::from("/k")));

        std::fs::write(&file, "[storage]\nurl = \"s3://b\"\n").unwrap();
        assert_eq!(existing_config(&file).err().unwrap().code, "exists");
        assert!(
            !existing_config(&dir.path().join("none.toml"))
                .unwrap()
                .exists
        );
    }
}
