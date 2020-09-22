//! The validate_repo module owns the 'validate-ami' subcommand and provides methods for validating
//! a given set of TUF repositories by downloading its targets and check for metadata expirations.

use super::RepoTransport;
use crate::config::InfraConfig;
use crate::repo::{compose_repo_urls, error as repo_error};
use crate::Args;
use log::{debug, error, info, trace};
use rand::seq::SliceRandom;
use snafu::{OptionExt, ResultExt};
use std::fs::File;
use std::io;
use structopt::StructOpt;
use tempfile::tempdir;
use tough::{ExpirationEnforcement, Limits, Repository, Settings};
use url::Url;

type Result<T> = std::result::Result<T, crate::repo::error::Error>;

/// Validates a set of TUF repositories
#[derive(Debug, StructOpt)]
#[structopt(setting = clap::AppSettings::DeriveDisplayOrder)]
pub(crate) struct ValidateRepoArgs {
    #[structopt(long)]
    /// Use this named set of repositories from Infra.toml
    repo: String,

    #[structopt(default_value = "100", long)]
    /// Randomly samples and retrieves specified percentage of targets
    percent_target_files: u8,
}

/// Randomly samples specified percentage of listed targets in the TUF repo and tries to retrieve them
fn retrieve_percentage_of_targets<T>(
    repo: &Repository<'_, T>,
    percentage: u8,
) -> Option<repo_error::Error>
where
    T: tough::Transport,
{
    let targets = &repo.targets().signed.targets;
    let percentage = f32::from(percentage) / 100.0;
    let num_to_retrieve = (targets.len() as f32 * percentage).ceil();
    let mut rng = &mut rand::thread_rng();
    let mut sampled_targets: Vec<String> = targets.keys().map(|key| key.to_string()).collect();
    sampled_targets = sampled_targets
        .choose_multiple(&mut rng, num_to_retrieve as usize)
        .cloned()
        .collect();
    for target in sampled_targets {
        let max_attempts = 5;
        for attempt in 1..=max_attempts {
            if attempt != 1 {
                debug!(
                    "Starting attempt {} of {} for target {}",
                    attempt, max_attempts, target
                );
            }
            let target_reader = repo.read_target(&target);
            match target_reader {
                Err(err) => match err {
                    tough::error::Error::Transport { .. } => {
                        error!("Fetch failure on attempt {}", attempt);
                        if attempt >= max_attempts {
                            return Some(repo_error::Error::TargetFetch {
                                target,
                                source: err,
                            });
                        }
                        continue;
                    }
                    err => {
                        return Some(repo_error::Error::TargetFetch {
                            target,
                            source: err,
                        })
                    }
                },
                Ok(target_reader) => match target_reader {
                    None => {
                        error!("Missing target: {}", target);
                        return Some(repo_error::Error::TargetMissing { target });
                    }
                    Some(mut reader) => {
                        info!("Downloading target: {}", target);
                        if let Err(err) = io::copy(&mut reader, &mut io::sink()) {
                            error!("Error on attempt {}: {}", attempt, err);
                            if attempt >= max_attempts {
                                return Some(repo_error::Error::TargetDownload {
                                    target,
                                    source: err,
                                });
                            }
                            continue;
                        }
                        // Successfully downloaded target
                        break;
                    }
                },
            };
        }
    }
    None
}

/// Common entrypoint from main()
pub(crate) fn run(args: &Args, validate_repo_args: &ValidateRepoArgs) -> Result<()> {
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

    let set_of_repos = compose_repo_urls(validate_repo_args.repo.to_string(), &infra_config)?
        .context(repo_error::InvalidRepoConfig)?;
    let transport = RepoTransport::default();

    // Validate each TUF repository
    let mut list_of_errors = Vec::new();
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
            expiration_enforcement: ExpirationEnforcement::Safe,
        };

        // Load the repository
        let repo = match Repository::load(&transport, settings) {
            Ok(repo) => repo,
            Err(err) => {
                list_of_errors.push((
                    metadata_url.clone(),
                    repo_error::Error::RepoLoad {
                        metadata_base_url: metadata_url.clone(),
                        source: err,
                    },
                ));
                continue;
            }
        };
        info!("Loaded TUF repo: {}", metadata_url);
        // Try retrieving listed targets
        let percentage = if validate_repo_args.percent_target_files > 100 {
            100
        } else {
            validate_repo_args.percent_target_files
        };
        info!(
            "Downloading {}% of listed targets from {}",
            percentage, metadata_url
        );

        if let Some(err) = retrieve_percentage_of_targets(&repo, percentage) {
            list_of_errors.push((metadata_url, err));
        }
    }
    if !list_of_errors.is_empty() {
        for (url, err) in &list_of_errors {
            error!("Failed to validate '{}': {}", url, err);
        }
        return Err(repo_error::Error::RepoValidate {
            list_of_urls: list_of_errors
                .iter()
                .map(|(url, _)| url.clone())
                .collect::<Vec<Url>>(),
        });
    }
    Ok(())
}
