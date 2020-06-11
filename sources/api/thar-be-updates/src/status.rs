use crate::error;
use crate::error::Result;
use bottlerocket_release::BottlerocketRelease;
use chrono::{DateTime, Utc};
use model::modeled_types::FriendlyVersion;
use serde::{Deserialize, Serialize};
use signpost::State;
use snafu::{ensure, OptionExt, ResultExt};
use std::convert::TryInto;
use std::os::unix::process::ExitStatusExt;
use std::process::Output;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum UpdateState {
    Idle,
    Available,
    Staged,
    Ready,
}

/// UpdateImage represents a Bottlerocket update image
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpdateImage {
    arch: String,
    version: semver::Version,
    variant: String,
}

impl UpdateImage {
    pub fn get_version(&self) -> &semver::Version {
        &self.version
    }
}

/// StagedImage represents an Bottlerocket image that is written to a partition set
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StagedImage {
    image: UpdateImage,
    next_to_boot: bool,
}

impl StagedImage {
    pub(crate) fn set_next_to_boot(&mut self, next_to_boot: bool) {
        self.next_to_boot = next_to_boot
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum CommandStatus {
    Success,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpdateCommand {
    RefreshUpdate,
    PrepareUpdate,
    ActivateUpdate,
    DeactivateUpdate,
    GetUpdateStatus,
    GetAvailableUpdates,
    GetUpdateInfoAbout,
}

/// CommandResult represents the result of an issued command
#[derive(Debug, Clone, Deserialize, Serialize)]
struct CommandResult {
    cmd_type: UpdateCommand,
    cmd_status: CommandStatus,
    timestamp: DateTime<Utc>,
    exit_status: Option<i32>,
    stderr: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UpdateStatus<T> {
    update_state: UpdateState,
    available_updates: Vec<T>,
    chosen_update: Option<UpdateImage>,
    active_partition: Option<StagedImage>,
    staging_partition: Option<StagedImage>,
    most_recent_command: Option<CommandResult>,
}

impl Default for UpdateStatus<update_metadata::Update> {
    fn default() -> Self {
        Self::new()
    }
}

// This is how the UpdateStatus is stored on disk
impl UpdateStatus<update_metadata::Update> {
    /// Initializes the update status
    pub fn new() -> Self {
        Self {
            update_state: UpdateState::Idle,
            available_updates: vec![],
            chosen_update: None,
            active_partition: None,
            staging_partition: None,
            most_recent_command: None,
        }
    }

    pub fn get_state(&self) -> &UpdateState {
        &self.update_state
    }

    pub fn get_chosen_update(&self) -> Option<&UpdateImage> {
        match &self.chosen_update {
            Some(update) => Some(&update),
            None => None,
        }
    }

    pub fn get_staging_partition_info(&self) -> Option<&StagedImage> {
        match &self.staging_partition {
            Some(partition_info) => Some(&partition_info),
            None => None,
        }
    }

    /// Returns all the available updates and their information
    pub fn get_available_updates(&self) -> &Vec<update_metadata::Update> {
        &self.available_updates
    }

    /// Returns detailed information about a particular update version
    pub fn get_detailed_update_info(
        &self,
        version: semver::Version,
    ) -> Option<&update_metadata::Update> {
        self.available_updates
            .iter()
            .find(|&update| update.version == version)
    }

    #[allow(clippy::wrong_self_convention)]
    /// Transitions update state to Idle
    pub fn to_idle(&mut self) -> Result<()> {
        match self.update_state {
            UpdateState::Idle | UpdateState::Available => {
                self.update_state = UpdateState::Idle;
                Ok(())
            }
            _ => error::InvalidStateTransition {
                from: self.update_state.to_owned(),
                to: UpdateState::Idle,
            }
            .fail(),
        }
    }

    #[allow(clippy::wrong_self_convention)]
    /// Transitions update state to Available
    pub fn to_available(&mut self) -> Result<()> {
        match self.update_state {
            UpdateState::Idle | UpdateState::Available => {
                self.update_state = UpdateState::Available;
                Ok(())
            }
            _ => error::InvalidStateTransition {
                from: self.update_state.to_owned(),
                to: UpdateState::Available,
            }
            .fail(),
        }
    }

    #[allow(clippy::wrong_self_convention)]
    /// Transitions update state to Staged
    pub fn to_staged(&mut self) -> Result<()> {
        match self.update_state {
            UpdateState::Available | UpdateState::Staged | UpdateState::Ready => {
                self.update_state = UpdateState::Staged;
                Ok(())
            }
            _ => error::InvalidStateTransition {
                from: self.update_state.to_owned(),
                to: UpdateState::Staged,
            }
            .fail(),
        }
    }

    #[allow(clippy::wrong_self_convention)]
    /// Transitions update state to Ready
    pub fn to_ready(&mut self) -> Result<()> {
        match self.update_state {
            UpdateState::Staged | UpdateState::Ready => {
                self.update_state = UpdateState::Ready;
                Ok(())
            }
            _ => error::InvalidStateTransition {
                from: self.update_state.to_owned(),
                to: UpdateState::Ready,
            }
            .fail(),
        }
    }

    /// Simplifies the list of available update information into just their version numbers
    pub fn simplify_update_info(&self) -> UpdateStatus<semver::Version> {
        let simplified_version_list = self
            .available_updates
            .iter()
            .map(|u| u.version.to_owned())
            .collect();
        UpdateStatus {
            update_state: self.update_state.to_owned(),
            available_updates: simplified_version_list,
            chosen_update: self.chosen_update.to_owned(),
            active_partition: self.active_partition.to_owned(),
            staging_partition: self.staging_partition.to_owned(),
            most_recent_command: self.most_recent_command.to_owned(),
        }
    }

    /// Updates the active partition set information
    pub fn update_active_partition_info(&mut self) -> Result<()> {
        // Get current OS release info to determine active partition image information
        let os_info = BottlerocketRelease::new().context(error::ReleaseVersion)?;
        let active_image = UpdateImage {
            arch: os_info.arch,
            version: os_info.version_id,
            variant: os_info.variant_id,
        };

        // Get partition set information. We can infer the version of the image in the active
        // partition set by checking the os release information
        let gpt_state = State::load().context(error::PartitionTableRead)?;
        let active_set = gpt_state.active();
        let next_set = gpt_state.next().context(error::NoneSetToBoot)?;
        self.active_partition = Some(StagedImage {
            image: active_image,
            next_to_boot: active_set == next_set,
        });
        Ok(())
    }

    /// Sets the staging partition image information
    pub fn set_staging_partition_image_info(&mut self, image: UpdateImage) {
        self.staging_partition = Some(StagedImage {
            image,
            next_to_boot: false,
        });
    }

    /// Mark staging partition as next to boot
    pub fn mark_staging_partition_next_to_boot(&mut self) -> Result<()> {
        if let Some(staging_partition) = &mut self.staging_partition {
            staging_partition.set_next_to_boot(true);
        } else {
            return error::StagingPartition {}.fail();
        }
        if let Some(active_partition) = &mut self.active_partition {
            active_partition.set_next_to_boot(false);
        } else {
            return error::ActivePartition {}.fail();
        }
        Ok(())
    }

    /// Unmark staging partition as next to boot
    pub fn unmark_staging_partition_next_to_boot(&mut self) -> Result<()> {
        if let Some(staging_partition) = &mut self.staging_partition {
            staging_partition.set_next_to_boot(false);
        } else {
            return error::StagingPartition {}.fail();
        }
        if let Some(active_partition) = &mut self.active_partition {
            active_partition.set_next_to_boot(true);
        } else {
            return error::ActivePartition {}.fail();
        }
        Ok(())
    }

    /// Sets information regarding the latest command invocation
    /// Derive success/failure status from exit status when possible.
    pub fn set_recent_command_info(
        &mut self,
        cmd_type: UpdateCommand,
        cmd_output: Option<&Output>,
        cmd_status: Option<CommandStatus>,
    ) {
        let command_result = if let Some(output) = cmd_output {
            let exit_status = match output.status.code() {
                Some(code) => code,
                None => output.status.signal().unwrap_or(1),
            };
            CommandResult {
                cmd_type,
                cmd_status: if exit_status == 0 {
                    CommandStatus::Success
                } else {
                    CommandStatus::Failed
                },
                timestamp: Utc::now(),
                exit_status: Some(exit_status),
                stderr: Some(String::from_utf8_lossy(&output.stderr).to_string()),
            }
        } else {
            // Set the status directly
            CommandResult {
                cmd_type,
                cmd_status: cmd_status.unwrap_or(CommandStatus::Unknown),
                timestamp: Utc::now(),
                exit_status: None,
                stderr: None,
            }
        };
        self.most_recent_command = Some(command_result);
    }

    /// Returns the update information of the 'latest' available update
    pub fn get_latest_update(&self) -> Result<Option<&update_metadata::Update>> {
        let os_info = BottlerocketRelease::new().context(error::ReleaseVersion)?;
        for update in &self.available_updates {
            // If the current running version is greater than the max version ever published,
            // or moves us to a valid version <= the maximum version, update.
            // Updates are listed in descending order (in terms of versions) in the manifest,
            // so the first picked out would be the latest update available.
            if os_info.version_id < update.version || os_info.version_id > update.max_version {
                return Ok(Some(update));
            }
        }
        Ok(None)
    }

    /// Checks the list of updates to for an available update.
    /// If the 'version-lock'ed version is available returns true. Otherwise returns false
    pub fn update_available_updates(
        &mut self,
        socket_path: &str,
        updates: Vec<update_metadata::Update>,
    ) -> Result<bool> {
        self.available_updates = updates;
        // Check if the 'version-lock'ed update is available as the 'chosen' update
        // Retrieve the 'version-lock' setting
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
        let locked_version: FriendlyVersion = serde_json::from_value(
            settings["updates"]["version-lock"].to_owned(),
        )
        .context(error::GetSetting {
            setting: "/settings/updates/version-lock",
        })?;

        if String::from(locked_version.to_owned()) == "latest" {
            // Set chosen_update to the latest version available
            if let Some(latest_update) = self.get_latest_update()? {
                self.chosen_update = Some(UpdateImage {
                    arch: latest_update.arch.clone(),
                    version: latest_update.version.clone(),
                    variant: latest_update.variant.clone(),
                });
                return Ok(true);
            }
        } else {
            let chosen_version =
                FriendlyVersion::try_into(locked_version.to_owned()).context(error::SemVer {
                    version: locked_version,
                })?;
            for update in &self.available_updates {
                if update.version == chosen_version {
                    self.chosen_update = Some(UpdateImage {
                        arch: update.arch.clone(),
                        version: chosen_version,
                        variant: update.variant.clone(),
                    });
                    return Ok(true);
                }
            }
        }
        // 'version-lock'ed update is unavailable.
        self.chosen_update = None;
        Ok(false)
    }
}
