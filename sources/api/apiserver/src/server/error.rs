use crate::datastore::{self, deserialization, serialization};
use nix::unistd::Gid;
use snafu::Snafu;
use std::io;
use std::path::PathBuf;
use std::string::String;

// We want server (router/handler) and controller errors together so it's easy to define response
// error codes for all the high-level types of errors that could happen during a request.
#[derive(Debug, Snafu)]
#[snafu(visibility = "pub(super)")]
pub enum Error {
    // Systemd Notification errors
    #[snafu(display("Systemd notify error: {}", source))]
    SystemdNotify { source: std::io::Error },

    #[snafu(display("Failed to send systemd status notification"))]
    SystemdNotifyStatus,

    // =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

    // Set file metadata errors
    #[snafu(display(
        "Failed to set file permissions on the API socket to {:o}: {}",
        mode,
        source
    ))]
    SetPermissions { source: std::io::Error, mode: u32 },

    #[snafu(display("Failed to set group owner on the API socket to {}: {}", gid, source))]
    SetGroup { source: nix::Error, gid: Gid },

    // =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

    // Server errors
    #[snafu(display("Missing required input '{}'", input))]
    MissingInput { input: String },

    #[snafu(display("Input '{}' cannot be empty", input))]
    EmptyInput { input: String },

    #[snafu(display("Another thread poisoned the data store lock by panicking"))]
    DataStoreLock,

    #[snafu(display("Unable to serialize response: {}", source))]
    ResponseSerialization { source: serde_json::Error },

    #[snafu(display("Unable to bind to {}: {}", path.display(), source))]
    BindSocket { path: PathBuf, source: io::Error },

    #[snafu(display("Unable to start server: {}", source))]
    ServerStart { source: io::Error },

    #[snafu(display("Tried to commit with no pending changes"))]
    CommitWithNoPending,

    #[snafu(display("Unable to get OS release data: {}", source))]
    ReleaseData {
        source: bottlerocket_release::Error,
    },

    // =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=   =^..^=

    // Controller errors
    #[snafu(display("Found no '{}' in datastore", prefix))]
    MissingData { prefix: String },

    #[snafu(display("Found no '{}' in datastore", requested))]
    ListKeys { requested: String },

    #[snafu(display("Listed key '{}' not found on disk", key))]
    ListedKeyNotPresent { key: String },

    #[snafu(display("Data store error during {}: {}", op, source))]
    DataStore {
        op: String,
        source: datastore::Error,
    },

    #[snafu(display("Error deserializing {}: {} ", given, source))]
    Deserialization {
        given: String,
        source: deserialization::Error,
    },

    #[snafu(display("Error serializing {}: {} ", given, source))]
    DataStoreSerialization {
        given: String,
        source: serialization::Error,
    },

    #[snafu(display("Error serializing {}: {} ", given, source))]
    CommandSerialization {
        given: String,
        source: serde_json::Error,
    },

    #[snafu(display("Unable to make {} key '{}': {}", key_type, name, source))]
    NewKey {
        key_type: String,
        name: String,
        source: datastore::Error,
    },

    #[snafu(display("Metadata '{}' is not valid JSON: {}", key, source))]
    InvalidMetadata {
        key: String,
        source: serde_json::Error,
    },

    #[snafu(display("Unable to start config applier: {} ", source))]
    ConfigApplierStart { source: io::Error },

    #[snafu(display("Unable to use config applier, couldn't get stdin"))]
    ConfigApplierStdin {},

    #[snafu(display("Unable to send input to config applier: {}", source))]
    ConfigApplierWrite { source: io::Error },

    #[snafu(display("Unable to start the update dispatcher: {} ", source))]
    UpdateDispatcher { source: io::Error },

    #[snafu(display("Update lock held: {} ", String::from_utf8_lossy(stderr)))]
    UpdateLockHeld { stderr: Vec<u8> },

    #[snafu(display("Update missing: {} ", String::from_utf8_lossy(stderr)))]
    UpdateMissing { stderr: Vec<u8> },

    #[snafu(display(
        "No update image applied to staging partition: {} ",
        String::from_utf8_lossy(stderr)
    ))]
    NoStagedImage { stderr: Vec<u8> },

    #[snafu(display(
        "Update action not allowed according to update state: {} ",
        String::from_utf8_lossy(stderr)
    ))]
    UpdateActionNotAllowed { stderr: Vec<u8> },

    #[snafu(display("Update dispatcher failed: {} ", String::from_utf8_lossy(stderr)))]
    UpdateError { stderr: Vec<u8> },

    #[snafu(display(
        "Failed to parse update status from '{}': {} ",
        String::from_utf8_lossy(stdout),
        source
    ))]
    UpdateStatusParse {
        stdout: Vec<u8>,
        source: serde_json::Error,
    },

    #[snafu(display(
        "Failed to parse update information from '{}': {} ",
        String::from_utf8_lossy(stdout),
        source
    ))]
    UpdateInfoParse {
        stdout: Vec<u8>,
        source: serde_json::Error,
    },

    #[snafu(display("Unable to start shutdown: {}", source))]
    Shutdown { source: io::Error },

    #[snafu(display(
        "Failed to reboot, exit code: {}, stderr: {}",
        exit_code,
        String::from_utf8_lossy(stderr)
    ))]
    Reboot { exit_code: i32, stderr: Vec<u8> },
}

pub type Result<T> = std::result::Result<T, Error>;
