//! The check_expirations module owns the 'check-repo-expirations' subcommand.

use super::RepoTransport;
use crate::config::InfraConfig;
use crate::repo::{compose_repo_urls, error as repo_error};
use crate::Args;
use chrono::{DateTime, Duration, Utc};
use log::{error, info, trace, warn};
use snafu::{OptionExt, ResultExt};
use std::collections::HashMap;
use std::fs::File;
use structopt::StructOpt;
use tempfile::tempdir;
use tough::{ExpirationEnforcement, Limits, Repository, Settings};

type Result<T> = std::result::Result<T, repo_error::Error>;

/// Checks for metadata expirations for a set of TUF repositories
#[derive(Debug, StructOpt)]
#[structopt(setting = clap::AppSettings::DeriveDisplayOrder)]
pub(crate) struct CheckExpirationsArgs {
    #[structopt(long)]
    /// Use this named set of repositories from Infra.toml
    repo: String,

    #[structopt(default_value = "0", long)]
    /// Output a list of metadata files expiring within specified number of days.
    upcoming_expirations_in: u16,
}

/// Checks for upcoming role expirations, gathers them in a list along with their expiration date.
fn find_upcoming_metadata_expiration<T>(
    repo: &Repository<'_, T>,
    days: u16,
) -> HashMap<tough::schema::RoleType, DateTime<Utc>>
where
    T: tough::Transport,
{
    let mut expirations = HashMap::new();
    let time_limit = Utc::now() + Duration::days(i64::from(days));
    info!(
        "Looking for metadata expirations happening from now to {:?}",
        time_limit
    );
    if repo.root().signed.expires <= time_limit {
        expirations.insert(tough::schema::RoleType::Root, repo.root().signed.expires);
    }
    if repo.snapshot().signed.expires <= time_limit {
        expirations.insert(
            tough::schema::RoleType::Snapshot,
            repo.snapshot().signed.expires,
        );
    }
    if repo.targets().signed.expires <= time_limit {
        expirations.insert(
            tough::schema::RoleType::Targets,
            repo.targets().signed.expires,
        );
    }
    if repo.timestamp().signed.expires <= time_limit {
        expirations.insert(
            tough::schema::RoleType::Timestamp,
            repo.timestamp().signed.expires,
        );
    }
    expirations
}

/// Common entrypoint from main()
pub(crate) fn run(args: &Args, check_expirations_args: &CheckExpirationsArgs) -> Result<()> {
    info!(
        "Using infra config from path: {}",
        args.infra_config_path.display()
    );
    let infra_config =
        InfraConfig::from_path(&args.infra_config_path).context(repo_error::Config)?;
    trace!("Parsed infra config: {:?}", infra_config);
    let root_role_path =
        infra_config
            .root_role_path
            .as_ref()
            .context(repo_error::MissingConfig {
                missing: "root_role_path",
            })?;

    let set_of_repos = compose_repo_urls(check_expirations_args.repo.to_string(), &infra_config)?
        .context(repo_error::InvalidRepoConfig)?;
    let transport = RepoTransport::default();

    // Check expirations for each TUF repository
    let mut err_to_return = None;
    for metadata_url in set_of_repos.0 {
        // Create a temporary directory where the TUF client can store metadata
        let workdir = tempdir().context(repo_error::TempDir)?;
        let settings = Settings {
            root: File::open(root_role_path).context(repo_error::File {
                path: root_role_path,
            })?,
            datastore: workdir.path(),
            metadata_base_url: metadata_url.as_str(),
            targets_base_url: set_of_repos.1.as_str(),
            limits: Limits::default(),
            // We're gonna check the expiration ourselves
            expiration_enforcement: ExpirationEnforcement::Unsafe,
        };

        // Load the repository
        let repo = match Repository::load(&transport, settings) {
            Ok(repo) => repo,
            Err(err) => {
                // Unable to load the repository for reasons other than metadata expiration...
                // We still want to check the other repositories so note the error and skip
                error!(
                    "Failed to load repo '{}'. Skipping...: {}",
                    metadata_url, err
                );
                err_to_return = Some(repo_error::Error::RepoCheckExpirations);
                continue;
            }
        };
        info!("Loaded TUF repo:\t{}", metadata_url);
        info!("Root expiration:\t{}", repo.root().signed.expires);
        info!("Snapshot expiration:\t{}", repo.snapshot().signed.expires);
        info!("Targets expiration:\t{}", repo.targets().signed.expires);
        info!("Timestamp expiration:\t{}", repo.timestamp().signed.expires);
        // Check for upcoming metadata expirations if a timeframe is specified
        if check_expirations_args.upcoming_expirations_in != 0 {
            let upcoming_expirations = find_upcoming_metadata_expiration(
                &repo,
                check_expirations_args.upcoming_expirations_in,
            );
            if !upcoming_expirations.is_empty() {
                for (role, date) in upcoming_expirations {
                    if date < Utc::now() {
                        error!("Repo '{}': '{}' expired on {}", metadata_url, role, date)
                    } else {
                        warn!(
                            "Repo '{}': '{}' expiring within {} day(s) on {}",
                            metadata_url,
                            role,
                            check_expirations_args.upcoming_expirations_in,
                            date
                        )
                    }
                }
                // Prepare error for upcoming expiration(s)
                // Don't overwrite existing errors (if any) that might be more serious (e.g. failing to load repo)
                err_to_return = if let Some(err) = err_to_return {
                    Some(err)
                } else {
                    Some(repo_error::Error::RepoExpirations)
                }
            }
        };
    }
    if let Some(err) = err_to_return {
        return Err(err);
    }
    Ok(())
}
