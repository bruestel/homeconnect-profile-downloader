//! The two answers worth remembering between runs: which region the account is
//! in, and where the last save went.
//!
//! Deliberately small. Nothing here is a preference in the sense of something
//! to tune; both are answers the user already gave once, and asking again every
//! start would be the application forgetting what it was told.
//!
//! No dependency for the path. Three platforms, three well-known directories,
//! twenty lines.

use crate::Region;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub region: Region,
    /// Where the last save went. `None` until the first one.
    pub destination: Option<PathBuf>,
}

impl Default for Settings {
    fn default() -> Self {
        Self { region: Region::Europe, destination: None }
    }
}

impl Settings {
    /// Whatever was stored, or the defaults.
    ///
    /// A missing or unreadable file is not an error worth reporting: it means a
    /// first run, or a file someone edited by hand, and in both cases carrying
    /// on with the defaults is what the user wants.
    pub fn load() -> Self {
        std::fs::read_to_string(Self::path())
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    /// Best effort. Failing to remember a choice must never fail a save.
    pub fn store(&self) {
        let path = Self::path();
        if let Some(folder) = path.parent() {
            let _ = std::fs::create_dir_all(folder);
        }
        if let Ok(text) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(path, text);
        }
    }

    /// Where the next save should be offered.
    ///
    /// A remembered folder that is no longer there is not offered. That is not
    /// a rare case: on Windows this file lives in the roaming profile, so it
    /// follows the user to another machine where the path may mean nothing, and
    /// on any system a folder can be renamed between two runs. Without the
    /// check the first save would silently create a directory nobody asked for.
    pub fn destination_or_default(&self) -> PathBuf {
        self.destination
            .clone()
            .filter(|folder| folder.is_dir())
            .unwrap_or_else(crate::naming::default_destination)
    }

    pub fn path() -> PathBuf {
        config_directory().join("settings.json")
    }
}

/// Where each system keeps a small application's configuration.
///
/// | | |
/// | --- | --- |
/// | Linux | `$XDG_CONFIG_HOME/hcpd`, or `~/.config/hcpd` |
/// | macOS | `~/Library/Application Support/hcpd` |
/// | Windows | `%APPDATA%\hcpd`, which is the roaming profile |
///
/// Roaming rather than local on Windows because the region is worth carrying to
/// another machine. The destination is checked before it is offered, for the
/// case where it is not.
fn config_directory() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("hcpd")
    }
    #[cfg(target_os = "macos")]
    {
        home()
            .map(|home| home.join("Library/Application Support/hcpd"))
            .unwrap_or_else(|| std::env::temp_dir().join("hcpd"))
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| home().map(|home| home.join(".config")))
            .unwrap_or_else(std::env::temp_dir)
            .join("hcpd")
    }
}

#[cfg(not(target_os = "windows"))]
fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_survive_a_file_that_is_not_there() {
        // Whatever the machine holds, the type has to have an answer.
        let settings = Settings::default();
        assert_eq!(settings.region, Region::Europe);
        assert!(settings.destination.is_none());
    }

    #[test]
    fn settings_round_trip_through_json() {
        let settings =
            Settings { region: Region::China, destination: Some(PathBuf::from("/tmp/somewhere")) };
        let text = serde_json::to_string(&settings).unwrap();
        let back: Settings = serde_json::from_str(&text).unwrap();
        assert_eq!(back.region, Region::China);
        assert_eq!(back.destination, settings.destination);
    }

    #[test]
    fn a_file_missing_a_field_still_loads() {
        // Written by an older version, or edited by hand.
        let back: Settings = serde_json::from_str("{}").unwrap();
        assert_eq!(back.region, Region::Europe);
    }

    #[test]
    fn the_path_ends_where_a_person_would_look_for_it() {
        let path = Settings::path();
        assert!(path.ends_with("hcpd/settings.json"), "was {}", path.display());

        // The directory above it, pinned per platform. These are conventions
        // rather than anything the compiler checks, so a test is the only thing
        // that would notice a change.
        let folder = path.parent().expect("the file sits in a directory");
        #[cfg(target_os = "windows")]
        assert!(folder.ends_with("hcpd"), "was {}", folder.display());
        #[cfg(target_os = "macos")]
        assert!(folder.ends_with("Library/Application Support/hcpd"), "was {}", folder.display());
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        assert!(folder.ends_with("hcpd"), "was {}", folder.display());
    }

    #[test]
    fn a_destination_that_is_gone_is_not_offered_again() {
        let settings = Settings {
            region: Region::Europe,
            destination: Some(PathBuf::from("/definitely/not/here/any/more")),
        };
        // Falls back rather than offering a path the first save would have to
        // create.
        assert_eq!(settings.destination_or_default(), crate::naming::default_destination());
    }

    #[test]
    fn a_destination_that_is_still_there_is_kept() {
        let somewhere = std::env::temp_dir();
        let settings = Settings { region: Region::Europe, destination: Some(somewhere.clone()) };
        assert_eq!(settings.destination_or_default(), somewhere);
    }
}
