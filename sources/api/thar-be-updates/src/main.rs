#[macro_use]
extern crate log;

use fs2::FileExt;
use model::modeled_types::FriendlyVersion;
use nix::unistd::{fork, ForkResult};
use signpost::State;
use simplelog::{Config as LogConfig, LevelFilter, TermLogger, TerminalMode};
use snafu::{ensure, OptionExt, ResultExt};
use std::convert::{TryFrom, TryInto};
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::process::Command;
use std::str::FromStr;
use std::{env, fs, process};
use thar_be_updates::error;
use thar_be_updates::error::{Error, Result, TbuErrorStatus};
use thar_be_updates::status::{CommandStatus, UpdateCommand, UpdateState, UpdateStatus};

// FIXME Get this from configuration in the future
const DEFAULT_API_SOCKET: &str = "/run/api.sock";

const UPDATE_LOCKFILE: &str = "/run/lock/thar-be-updates.lock";
const UPDATE_STATUS_FILE: &str = "/run/update-status";

/// Stores the command line arguments
struct Args {
    subcommand: UpdateCommand,
    query_version: Option<FriendlyVersion>,
    log_level: LevelFilter,
    socket_path: String,
}

/// Prints an usage message
fn usage() -> ! {
    let program_name = env::args().next().unwrap_or_else(|| "program".to_string());
    eprintln!(
        r"Usage: {}
            Subcommands:
            refresh-update              Query update repository, store the list of available updates, and check if chosen version is available
                prepare-update          Downloads the chosen update and write the update image to the inactive partition
                activate-update         Marks the inactive partition for boot
                deactivate-update       Reverts update activation by marking current active partition for boot
                get-update-status       Retrieves the update status
                get-available-updates   Retrieves the list available updates and detailed information about them
                get-update-info-about v0.3.0|latest   Retrieves information regarding the specified update version

            Global options:
                    [ --socket-path PATH ]    Bottlerocket API socket path (default {})
                    [ --log-level trace|debug|info|warn|error ]     Logging level (default info)",
        program_name, DEFAULT_API_SOCKET,
    );
    process::exit(2);
}

/// Prints a more specific message before exiting through usage().
fn usage_msg<S: AsRef<str>>(msg: S) -> ! {
    eprintln!("{}\n", msg.as_ref());
    usage();
}

/// Parses the command line arguments
fn parse_args(args: std::env::Args) -> Args {
    let mut subcommand = None;
    let mut log_level = None;
    let mut socket_path = None;
    let mut query_version = None;

    let mut iter = args.skip(1).peekable();
    while let Some(arg) = iter.next() {
        match arg.as_ref() {
            "--log-level" => {
                let log_level_str = iter
                    .next()
                    .unwrap_or_else(|| usage_msg("Did not give argument to --log-level"));
                log_level = Some(LevelFilter::from_str(&log_level_str).unwrap_or_else(|_| {
                    usage_msg(format!("Invalid log level '{}'", log_level_str))
                }));
            }

            "--socket-path" => {
                socket_path = Some(
                    iter.next()
                        .unwrap_or_else(|| usage_msg("Did not give argument to --socket-path")),
                )
            }
            // Assume any arguments not prefixed with '-' is a subcommand
            s if !s.starts_with('-') => {
                if subcommand.is_some() {
                    usage();
                }
                subcommand =
                    Some(serde_plain::from_str::<UpdateCommand>(s).unwrap_or_else(|_| usage()));

                // Get the version argument to 'get-update-info-about'
                if subcommand == Some(UpdateCommand::GetUpdateInfoAbout) {
                    if let Some(version) = iter.peek() {
                        if version.starts_with("--") {
                            usage_msg("Did not give version argument to 'get-update-info-about'")
                        } else {
                            query_version =
                                Some(match FriendlyVersion::try_from(version.as_str()) {
                                    Ok(version) => version,
                                    Err(_) => usage_msg(
                                        "Bad version string passed to 'get-update-info-about'",
                                    ),
                                });
                            iter.next();
                        }
                    } else {
                        usage_msg("Did not give version argument to 'get-update-info-about'")
                    }
                }
            }
            _ => usage(),
        }
    }

    Args {
        subcommand: subcommand.unwrap_or_else(|| usage()),
        log_level: log_level.unwrap_or_else(|| LevelFilter::Info),
        socket_path: socket_path.unwrap_or_else(|| DEFAULT_API_SOCKET.to_string()),
        query_version,
    }
}

// Some simple wrapper functions for locking
// Once we fork, the parent process and child process are going to have duplicate file descriptors
// that refer to the same lock. Once the parent returns and closes its copy of the lockfile fd,
// the child will still hold the lock. The lock is only released when all copies of the file descriptor are closed.
fn lock_exclusive(lockfile: &File) -> Result<()> {
    lockfile.try_lock_exclusive().context(error::LockHeld {
        path: UPDATE_LOCKFILE,
    })?;
    debug!("Obtained exclusive lock");
    Ok(())
}

fn lock_shared(lockfile: &File) -> Result<()> {
    lockfile.try_lock_shared().context(error::LockHeld {
        path: UPDATE_LOCKFILE,
    })?;
    debug!("Obtained shared lock");
    Ok(())
}

fn unlock(lockfile: &File) -> Result<()> {
    lockfile.unlock().context(error::Unlock {
        path: UPDATE_LOCKFILE,
    })?;
    debug!("Released lock");
    Ok(())
}

/// Initializes the update status and creates the update status file
fn initialize_update_status() -> Result<()> {
    debug!("Creating update status file in '{}'", UPDATE_STATUS_FILE);
    let status_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create_new(true)
        .open(UPDATE_STATUS_FILE)
        .context(error::CreateStatusFile {
            path: UPDATE_STATUS_FILE,
        })?;

    let mut new_status = UpdateStatus::new();
    // Initialize active partition set information
    new_status.update_active_partition_info()?;
    serde_json::to_writer_pretty(status_file, &new_status).context(error::StatusWrite)?;
    Ok(())
}

/// Writes out the update status to disk
fn write_update_status(update_status: &UpdateStatus<update_metadata::Update>) -> Result<()> {
    let status_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(UPDATE_STATUS_FILE)
        .context(error::OpenStatusFile {
            path: UPDATE_STATUS_FILE,
        })?;
    Ok(serde_json::to_writer_pretty(status_file, update_status).context(error::StatusWrite)?)
}

/// Loads and returns the update status from disk.
fn get_update_status() -> Result<UpdateStatus<update_metadata::Update>> {
    let status_file = File::open(UPDATE_STATUS_FILE).context(error::OpenStatusFile {
        path: UPDATE_STATUS_FILE,
    })?;
    Ok(serde_json::from_reader(status_file).context(error::StatusParse)?)
}

/// Spawns updog process to get list of updates and check if any of them can be updated to.
/// Returns true if there is an available update, returns false otherwise.
fn refresh_update(
    status: &mut UpdateStatus<update_metadata::Update>,
    socket_path: &str,
) -> Result<bool> {
    debug!("Spawning 'updog whats'");
    let output = Command::new("updog")
        .args(&["whats", "--all", "--json"])
        .output()
        .context(error::Updog)?;
    status.set_recent_command_info(UpdateCommand::RefreshUpdate, Some(&output), None);
    if output.status.success() {
        let update_info: Vec<update_metadata::Update> =
            serde_json::from_slice(&output.stdout).context(error::UpdateInfo)?;
        return status.update_available_updates(socket_path, update_info);
    } else {
        warn!("Failed to check for updates with updog");
    }
    Ok(false)
}

/// Queries the Bottlerocket API and returns the 'ignore-waves' setting. If it doesn't exist for whatever reason, return false
fn get_ignore_waves(socket_path: &str) -> Result<bool> {
    let uri = "/settings";
    let method = "GET";
    let (code, response_body) = apiclient::raw_request(&socket_path, uri, method, None)
        .context(error::APIRequest { method, uri })?;
    ensure!(
        code.is_success(),
        error::APIResponse {
            method,
            uri,
            code,
            response_body,
        }
    );
    let settings: serde_json::Value =
        serde_json::from_str(&response_body).context(error::ResponseJson { uri })?;
    Ok(settings["updates"]["ignore-waves"]
        .as_bool()
        .unwrap_or(false))
}

/// Prepares the update by downloading and writing the update to the staging partition
fn prepare_update(
    status: &mut UpdateStatus<update_metadata::Update>,
    ignore_waves: bool,
) -> Result<()> {
    debug!("Spawning 'updog update-image'");
    let chosen_update = status
        .get_chosen_update()
        .context(error::ChosenUpdate)?
        .clone();
    // Prepare arguments, append '--now' if we're ignoring waves
    let chosen_version = chosen_update.get_version().to_string();
    let mut args = vec!["update-image", "--image", &chosen_version];
    if ignore_waves {
        args.push("--now");
    }
    let output = Command::new("updog")
        .args(args)
        .output()
        .context(error::Updog)?;
    status.set_recent_command_info(UpdateCommand::PrepareUpdate, Some(&output), None);
    if output.status.success() {
        status.set_staging_partition_image_info(chosen_update);
    } else {
        warn!("Failed to prepare the update with updog");
    }
    Ok(())
}

/// "Activates" the staged update by setting the appropriate priority flags in the partition table
fn activate_update(status: &mut UpdateStatus<update_metadata::Update>) -> Result<()> {
    let mut gpt_state = State::load().context(error::PartitionTableRead)?;
    gpt_state
        .upgrade_to_inactive()
        .context(error::InactivePartitionUpgrade)?;
    gpt_state.write().context(error::PartitionTableWrite)?;
    status.mark_staging_partition_next_to_boot()?;
    Ok(())
}

/// "Deactivates" the staged update by rolling back actions done by `activate_update`
fn deactivate_update(status: &mut UpdateStatus<update_metadata::Update>) -> Result<()> {
    let mut gpt_state = State::load().context(error::PartitionTableRead)?;
    // This actually wipes all the priority bits in the inactive partition
    gpt_state.cancel_upgrade();
    // The update image is still there in the inactive partition so mark as valid
    gpt_state.mark_inactive_valid();
    gpt_state.write().context(error::PartitionTableWrite)?;
    status.unmark_staging_partition_next_to_boot()?;
    Ok(())
}

/// Gets the update status, serialize the structure to json and output to stdout.
fn report_update_status(lockfile: File) -> Result<()> {
    lock_shared(&lockfile)?;
    let update_status = get_update_status()?;
    unlock(&lockfile)?;
    println!(
        "{}",
        // We simplify the available_updates information into just the version numbers when reporting status
        serde_json::to_string_pretty(&update_status.simplify_update_info())
            .context(error::StatusSerialize)?
    );
    Ok(())
}

/// Reports all the available updates along with their detailed information
fn report_available_updates(lockfile: File) -> Result<()> {
    lock_shared(&lockfile)?;
    let update_status = get_update_status()?;
    unlock(&lockfile)?;
    println!(
        "{}",
        // We simplify the available_updates information into just the version numbers when reporting status
        serde_json::to_string_pretty(&update_status.get_available_updates())
            .context(error::StatusSerialize)?
    );
    Ok(())
}

/// Reports detailed information about a specific update version
fn report_detailed_update_info(lockfile: File, version: FriendlyVersion) -> Result<()> {
    lock_shared(&lockfile)?;
    let update_status = get_update_status()?;
    unlock(&lockfile)?;
    let version_str: String = version.to_owned().into();
    let update_info = if version_str == "latest" {
        // Get the information for the 'latest' update
        update_status
            .get_latest_update()?
            .context(error::QueriedUpdateVersion { version })?
    } else {
        update_status
            .get_detailed_update_info(version.to_owned().try_into().context(error::SemVer {
                version: version.to_owned(),
            })?)
            .context(error::QueriedUpdateVersion { version })?
    };
    println!(
        "{}",
        // We simplify the available_updates information into just the version numbers when reporting status
        serde_json::to_string_pretty(&update_info).context(error::StatusSerialize)?
    );
    Ok(())
}

fn run() -> Result<()> {
    // Parse and store the args passed to the program
    let args = parse_args(env::args());

    // TerminalMode::Mixed will send errors to stderr and anything less to stdout.
    TermLogger::init(args.log_level, LogConfig::default(), TerminalMode::Mixed)
        .context(error::Logger)?;

    // Open the lockfile for concurrency control, create it if it doesn't exist
    fs::create_dir_all("/run/lock").context(error::CreateLockDir)?;
    let lockfile = File::create(UPDATE_LOCKFILE).context(error::LockFile {
        path: UPDATE_LOCKFILE,
    })?;

    // Check if the update status file exists. If it doesn't, create and initialize it.
    if !Path::new(UPDATE_STATUS_FILE).is_file() {
        // Get an exclusive lock for creating the update status file
        lock_exclusive(&lockfile)?;
        initialize_update_status()?;
        unlock(&lockfile)?;
    }

    match args.subcommand {
        // 'refresh-update' is allowed under every update state
        UpdateCommand::RefreshUpdate => {
            lock_exclusive(&lockfile)?;
            let mut update_status = get_update_status()?;
            match fork() {
                Ok(ForkResult::Parent { child, .. }) => {
                    debug!("forked child pid: {}", child);
                    // Exit immediately as the parent
                    // Parent's lockfile fd will close but child will still have a duplicate fd
                    return Ok(());
                }
                Ok(ForkResult::Child) => {
                    // 'refresh_update' is allowed under every update state
                    let is_chosen_update_availabe =
                        refresh_update(&mut update_status, &args.socket_path)?;
                    // Transition the update state appropriately
                    match update_status.get_state() {
                        UpdateState::Idle => {
                            if is_chosen_update_availabe {
                                update_status.to_available()?;
                            }
                        }
                        UpdateState::Available => {
                            if !is_chosen_update_availabe {
                                update_status.to_idle()?;
                            }
                        }
                        UpdateState::Staged | UpdateState::Ready => {
                            // no transition necessary
                        }
                    }
                    write_update_status(&update_status)?;
                    unlock(&lockfile)?;
                }
                Err(e) => {
                    unlock(&lockfile)?;
                    eprintln!("{}", e);
                    return error::Fork.fail();
                }
            }
        }
        UpdateCommand::PrepareUpdate => {
            lock_exclusive(&lockfile)?;
            let mut update_status = get_update_status()?;
            match update_status.get_state() {
                UpdateState::Available | UpdateState::Staged => {
                    // Make sure the chosen update exists
                    let _ = update_status
                        .get_chosen_update()
                        .context(error::ChosenUpdate)?;
                    match fork() {
                        Ok(ForkResult::Parent { child, .. }) => {
                            debug!("forked child pid: {}", child);
                            // Return immediately as the parent.
                            // Parent's lockfile fd will close but child will still have a duplicate fd
                            return Ok(());
                        }
                        Ok(ForkResult::Child) => {
                            let ignore_waves = get_ignore_waves(&args.socket_path)?;
                            let result = prepare_update(&mut update_status, ignore_waves);
                            // Transition the update state appropriately
                            if let UpdateState::Available = update_status.get_state() {
                                if result.is_ok() {
                                    update_status.to_staged()?;
                                }
                            }
                            write_update_status(&update_status)?;
                            unlock(&lockfile)?;
                        }
                        Err(e) => {
                            unlock(&lockfile)?;
                            eprintln!("{}", e);
                            return error::Fork.fail();
                        }
                    }
                }
                UpdateState::Idle | UpdateState::Ready => {
                    unlock(&lockfile)?;
                    return error::DisallowCommand {
                        command: UpdateCommand::PrepareUpdate,
                        state: update_status.get_state().to_owned(),
                    }
                    .fail();
                }
            }
        }
        // Only allowed when state is 'Staged'
        // No need to fork here, we can directly manipulate the partition table
        UpdateCommand::ActivateUpdate => {
            lock_exclusive(&lockfile)?;
            let mut update_status = get_update_status()?;
            match update_status.get_state() {
                UpdateState::Staged => {
                    // Make sure there's an update image written to the inactive partition
                    let _ = update_status
                        .get_staging_partition_info()
                        .context(error::StagingPartition)?;
                    if let Err(e) = activate_update(&mut update_status) {
                        eprintln!("Failed to activate update: {}", e);
                        update_status.set_recent_command_info(
                            UpdateCommand::ActivateUpdate,
                            None,
                            Some(CommandStatus::Failed),
                        );
                    } else {
                        // Transition the update state appropriately
                        update_status.to_ready()?;
                        update_status.set_recent_command_info(
                            UpdateCommand::ActivateUpdate,
                            None,
                            Some(CommandStatus::Success),
                        );
                    }
                    write_update_status(&update_status)?;
                    unlock(&lockfile)?;
                }
                _ => {
                    unlock(&lockfile)?;
                    return error::DisallowCommand {
                        command: UpdateCommand::ActivateUpdate,
                        state: update_status.get_state().to_owned(),
                    }
                    .fail();
                }
            }
        }
        // Only allowed when state is 'Ready'
        // No need to fork here, we can directly manipulate the partition table
        UpdateCommand::DeactivateUpdate => {
            lock_exclusive(&lockfile)?;
            let mut update_status = get_update_status()?;
            match update_status.get_state() {
                UpdateState::Ready => {
                    // Make sure there's an update image written to the inactive partition
                    let _ = update_status
                        .get_staging_partition_info()
                        .context(error::StagingPartition)?;
                    if let Err(e) = deactivate_update(&mut update_status) {
                        eprintln!("Failed to deactivate update: {}", e);
                        update_status.set_recent_command_info(
                            UpdateCommand::DeactivateUpdate,
                            None,
                            Some(CommandStatus::Failed),
                        );
                    } else {
                        // Transition the update state appropriately
                        update_status.to_staged()?;
                        update_status.set_recent_command_info(
                            UpdateCommand::DeactivateUpdate,
                            None,
                            Some(CommandStatus::Success),
                        );
                    }
                    write_update_status(&update_status)?;
                    unlock(&lockfile)?;
                }
                _ => {
                    unlock(&lockfile)?;
                    return error::DisallowCommand {
                        command: UpdateCommand::ActivateUpdate,
                        state: update_status.get_state().to_owned(),
                    }
                    .fail();
                }
            }
        }
        // We can report then update status whenever
        UpdateCommand::GetUpdateStatus => report_update_status(lockfile)?,
        UpdateCommand::GetAvailableUpdates => report_available_updates(lockfile)?,
        UpdateCommand::GetUpdateInfoAbout => report_detailed_update_info(
            lockfile,
            // The error should theoretically never happen because we would have been caught it when parsing command line arguments
            args.query_version.context(error::UnspecifiedVersion)?,
        )?,
    }
    Ok(())
}

fn match_error_to_exit_status(err: Error) -> i32 {
    (match err {
        Error::LockHeld { .. } => TbuErrorStatus::LockHeld,
        Error::DisallowCommand { .. } => TbuErrorStatus::DisallowedCmd,
        Error::ChosenUpdate { .. } | Error::QueriedUpdateVersion { .. } => {
            TbuErrorStatus::UpdateDoesNotExist
        }
        Error::StagingPartition { .. } => TbuErrorStatus::NoStagedImage,
        _ => TbuErrorStatus::OtherError,
    }) as i32
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{}", e);
        std::process::exit(match_error_to_exit_status(e));
    }
}
