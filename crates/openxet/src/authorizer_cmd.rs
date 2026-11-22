//! `openxet authorizer setup`: hand every authorization decision to the
//! operator's own service (ruling M3-R8, `docs/reference/authorizer.md`).
//!
//! It sends the service one test request, signed as the server will sign
//! them, and needs a valid answer, allow or deny. Only then does it create
//! the signing secret (mode `0600`) and add `[authorizer]` to the
//! configuration: a new file is created, an existing one gains the section
//! at its end and is otherwise left as it is.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use openxet_auth::{
    Action, Authorizer as _, Target, UserPrincipal, WebhookAuthorizer, WebhookConfig,
};
use serde::Serialize;
use url::Url;
use zeroize::Zeroizing;

use crate::error::{CliError, ExitCode};
use crate::output::{HumanDisplay, Output};
use crate::secret;
use crate::storage_cmd::default_dir;

/// Who the test request names, and the repository it asks about, so the
/// service can recognise it.
const SETUP_SUBJECT: &str = "openxet-setup";
const SETUP_NAMESPACE: &str = "openxet-setup";
const SETUP_NAME: &str = "test";

#[derive(Debug, clap::Subcommand)]
pub enum AuthorizerCommand {
    /// Let your own service decide every read, write, create and delete:
    /// test it, create the signing secret and add it to the configuration
    Setup(SetupArgs),
}

#[derive(Debug, clap::Args)]
pub struct SetupArgs {
    /// The service's URL, `https://`, or `http://` to this machine
    url: String,
    /// The configuration file to add `[authorizer]` to, or to create
    /// [default: `$XDG_CONFIG_HOME/openxet/openxet.toml`, or
    /// `~/.config/openxet/openxet.toml`]
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// The secret requests are signed with, mode 0600; created if missing
    /// [default: `authorizer.secret` beside the default configuration]
    #[arg(long, value_name = "FILE")]
    secret_file: Option<PathBuf>,
    /// Send the test request; create and write nothing
    #[arg(long)]
    dry_run: bool,
}

pub fn run(command: &AuthorizerCommand, output: Output) -> Result<(), CliError> {
    match command {
        AuthorizerCommand::Setup(args) => setup(args, output),
    }
}

#[derive(Serialize)]
struct Setup {
    schema: &'static str,
    url: String,
    /// The service's answer to the test request.
    answer: &'static str,
    secret_file: String,
    /// Whether this run created `secret_file`; an existing one is reused.
    secret_created: bool,
    config_file: String,
    /// `created`, `appended`, or `none` for `--dry-run`.
    config_written: &'static str,
    /// The section added.
    config: String,
    dry_run: bool,
}

impl HumanDisplay for Setup {
    fn human(&self) -> String {
        let answered = format!(
            "{} answered the test request ({SETUP_SUBJECT} reading \
             {SETUP_NAMESPACE}/{SETUP_NAME}): {}.",
            self.url, self.answer
        );
        if self.dry_run {
            return format!("{answered}\nNothing was created or written.");
        }
        let secret = if self.secret_created {
            "Created the signing secret"
        } else {
            "Requests are signed with the existing secret"
        };
        let config = match self.config_written {
            "created" => format!("Wrote the configuration to {}.", self.config_file),
            _ => format!("Added [authorizer] to {}.", self.config_file),
        };
        format!(
            "{answered}\n{secret} in {} (mode 0600): check X-Openxet-Signature with it.\n\
             {config}\n\nStart, or restart, the server to use it:\n  openxet serve --config {}",
            self.secret_file, self.config_file
        )
    }
}

fn setup(args: &SetupArgs, output: Output) -> Result<(), CliError> {
    let url = Url::parse(&args.url)
        .map_err(|_| "is not a URL")
        .and_then(|url| WebhookConfig::check_url(&url).map(|()| url))
        .map_err(|why| {
            CliError::new(
                "invalid_url",
                format!("{} {why}", args.url),
                "Pass your service's URL, as in `https://auth.example.com/openxet/authorize`, \
                 or `http://127.0.0.1:8000/authorize` for one on this machine.",
            )
            .with_exit(ExitCode::USAGE)
        })?;
    let config_file = match &args.config {
        Some(file) => file.clone(),
        None => default_dir()?.join("openxet.toml"),
    };
    let secret_file = match &args.secret_file {
        Some(file) => file.clone(),
        None => default_dir()?.join("authorizer.secret"),
    };
    let existing = existing_config(&config_file)?;
    let (secret, secret_created) = match secret::read(&secret_file)? {
        Some(text) if !text.trim().is_empty() => (Zeroizing::new(text.trim().to_owned()), false),
        Some(_) => {
            return Err(CliError::new(
                "invalid_key",
                format!("{} is empty", secret_file.display()),
                "Remove it to create a new secret, or pass another `--secret-file`.",
            ));
        }
        None => (
            Zeroizing::new(secret::hex(secret::random_bytes()?.as_ref())),
            true,
        ),
    };

    let answer = test_request(&url, &secret)?;

    let shown = |path: &Path| {
        std::path::absolute(path)
            .unwrap_or_else(|_| path.to_owned())
            .display()
            .to_string()
    };
    let section = section_text(&url, &shown(&secret_file));
    let mut config_written = "none";
    if !args.dry_run {
        if secret_created {
            secret::create(&secret_file, format!("{}\n", secret.as_str()).as_bytes())?;
        }
        config_written = match existing {
            None => {
                secret::create_with_mode(&config_file, section.as_bytes(), 0o644)?;
                "created"
            }
            Some(text) => {
                append(&config_file, &text, &section)?;
                "appended"
            }
        };
    }
    output
        .emit(&Setup {
            schema: "openxet.authorizer-setup.v1",
            url: url.to_string(),
            answer: if answer { "allow" } else { "deny" },
            secret_file: shown(&secret_file),
            secret_created: secret_created && !args.dry_run,
            config_file: shown(&config_file),
            config_written,
            config: section,
            dry_run: args.dry_run,
        })
        .map_err(|err| CliError::output(&err))
}

/// Asks the service about [`SETUP_SUBJECT`] reading
/// `{SETUP_NAMESPACE}/{SETUP_NAME}`, signed with `secret`, as the server
/// will ask: either answer passes.
fn test_request(url: &Url, secret: &str) -> Result<bool, CliError> {
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| {
            CliError::new(
                "runtime",
                format!("could not start the HTTP client: {err}"),
                "Check the system's TLS and proxy configuration.",
            )
        })?;
    let webhook = WebhookAuthorizer::new(
        WebhookConfig {
            url: url.clone(),
            secret: Some(Zeroizing::new(secret.as_bytes().to_vec())),
            timeout: Duration::from_secs(10),
            allow_ttl: Duration::ZERO,
            deny_ttl: Duration::ZERO,
        },
        http,
    )
    .map_err(|err| {
        CliError::new("invalid_url", err, "Pass another URL.").with_exit(ExitCode::USAGE)
    })?;
    let who = UserPrincipal {
        subject: SETUP_SUBJECT.to_owned(),
        name: SETUP_SUBJECT.to_owned(),
        email: None,
        claims: BTreeMap::new(),
        bearer: None,
    };
    let target = Target {
        namespace: SETUP_NAMESPACE,
        name: Some(SETUP_NAME),
        path: None,
    };
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
    runtime
        .block_on(webhook.allows(&who, Action::Read, target))
        .map_err(|err| {
            CliError::new(
                "authorizer",
                err.to_string(),
                "Check that the service is running and answers a POST with `true`, `false` or \
                 {\"allow\": true|false}; see docs/reference/authorizer.md. Nothing was written.",
            )
        })
}

/// The configuration at `path`, if it exists. It may not already have an
/// `[authorizer]`, nor `[[auth.rules]]`, which the authorizer replaces.
fn existing_config(path: &Path) -> Result<Option<Zeroizing<String>>, CliError> {
    let Some(text) = secret::read_unchecked(path)? else {
        return Ok(None);
    };
    let table: toml::Table = toml::from_str(&text).map_err(|err| {
        CliError::new(
            "config",
            format!("{} is not valid TOML: {}", path.display(), err.message()),
            "Fix it, or pass another `--config`.",
        )
    })?;
    if table.contains_key("authorizer") {
        return Err(CliError::new(
            "exists",
            format!("{} already has an [authorizer]", path.display()),
            "Nothing was changed. Remove the section to set it up again, or pass another \
             `--config`.",
        )
        .with_exit(ExitCode::USAGE));
    }
    let has_rules = table
        .get("auth")
        .and_then(toml::Value::as_table)
        .is_some_and(|auth| auth.contains_key("rules"));
    if has_rules {
        return Err(CliError::new(
            "config",
            format!("{} has [[auth.rules]]", path.display()),
            "Your service would replace them. Remove [[auth.rules]] first, or keep them and \
             leave the authorizer out.",
        ));
    }
    Ok(Some(text))
}

/// `[authorizer]`'s text.
fn section_text(url: &Url, secret_file: &str) -> String {
    let quoted = |text: &str| toml::Value::String(text.to_owned()).to_string();
    format!(
        "# Written by `openxet authorizer setup`. Your service decides every read, write,\n\
         # create and delete; see docs/reference/authorizer.md.\n\
         [authorizer]\nurl = {}\nsecret_file = {}\n",
        quoted(url.as_str()),
        quoted(secret_file)
    )
}

/// Appends `section` to the configuration `text` at `path`: written whole
/// to a temporary file beside it, then renamed over it, so a crash leaves
/// the old file or the new one.
fn append(path: &Path, text: &str, section: &str) -> Result<(), CliError> {
    let failed = |what: &str, err: &std::io::Error| {
        CliError::new(
            "io",
            format!("could not {what} {}: {err}", path.display()),
            "Check the file's permissions. Nothing was changed.",
        )
    };
    let mut new = text.to_owned();
    if !new.is_empty() && !new.ends_with('\n') {
        new.push('\n');
    }
    new.push('\n');
    new.push_str(section);
    let permissions = fs::metadata(path)
        .map_err(|err| failed("inspect", &err))?
        .permissions();
    let name = path
        .file_name()
        .map_or_else(|| "config".into(), |n| n.to_string_lossy().into_owned());
    let temp = path.with_file_name(format!(
        ".{name}.{}.tmp",
        secret::hex(&secret::random_bytes()?[..8])
    ));
    let written = fs::write(&temp, new.as_bytes())
        .and_then(|()| fs::set_permissions(&temp, permissions))
        .and_then(|()| fs::File::open(&temp)?.sync_all())
        .and_then(|()| fs::rename(&temp, path));
    if let Err(err) = written {
        let _ = fs::remove_file(&temp);
        return Err(failed("update", &err));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_existing_config_gains_the_section_and_keeps_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("openxet.toml");
        let before = "# mine\n[storage]\nurl = \"s3://b\"";
        fs::write(&file, before).unwrap();
        let text = existing_config(&file).unwrap().unwrap();
        let url = Url::parse("https://auth.example.com/authorize").unwrap();
        append(&file, &text, &section_text(&url, "/c/authorizer.secret")).unwrap();
        let after = fs::read_to_string(&file).unwrap();
        assert!(after.starts_with(before), "{after}");
        let table: toml::Table = toml::from_str(&after).unwrap();
        assert_eq!(table["storage"]["url"].as_str(), Some("s3://b"));
        assert_eq!(
            table["authorizer"]["url"].as_str(),
            Some("https://auth.example.com/authorize")
        );
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);

        assert_eq!(existing_config(&file).err().unwrap().code, "exists");
        fs::write(
            &file,
            "[[auth.rules]]\nsubjects = [\"a\"]\nrepos = [\"*\"]\nactions = [\"read\"]\n",
        )
        .unwrap();
        assert_eq!(existing_config(&file).err().unwrap().code, "config");
    }
}
