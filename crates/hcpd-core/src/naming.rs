//! The names of the files we write, and the timestamps inside them.
//!
//! Reproduced from the Electron version rather than reinvented: people have
//! downloads from it sitting in a folder, and a rename would make the new ones
//! sort and read differently for no gain. Every shape here is pinned by a test.

use chrono::{DateTime, Local};
use std::path::PathBuf;

/// Where a save is offered first.
///
/// The download folder, which is where a person looks for something they just
/// saved. The Electron version wrote to a folder under the system temp
/// directory (`app.getPath('temp')`, main.js:632), a reasonable place for a
/// program that decides on its own and a poor one to offer someone: on most
/// systems it is swept.
///
/// Only ever a starting point. The chooser is one click away and the answer is
/// remembered, so this is the first save and no other.
pub fn default_destination() -> PathBuf {
    download_folder()
        .or_else(home_directory)
        .unwrap_or_else(|| std::env::temp_dir().join("home-connect-profiles"))
}

/// The download folder, as the system knows it.
///
/// Not simply `~/Downloads`: on Linux the name is the user's own and can be in
/// their language, and it is recorded rather than fixed. So the desktop is
/// asked first, in the two places it keeps the answer, and the English name is
/// only the last guess.
fn download_folder() -> Option<PathBuf> {
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        // Exported into the session by some desktops, by no means all.
        if let Some(folder) = std::env::var_os("XDG_DOWNLOAD_DIR").map(PathBuf::from)
            && folder.is_dir()
        {
            return Some(folder);
        }
        // The file that always holds it, in the form `XDG_DOWNLOAD_DIR="$HOME/..."`.
        if let Some(home) = home_directory()
            && let Ok(text) = std::fs::read_to_string(home.join(".config/user-dirs.dirs"))
        {
            for line in text.lines() {
                let Some(value) = line.trim().strip_prefix("XDG_DOWNLOAD_DIR=") else { continue };
                let value = value.trim().trim_matches('"');
                let folder = match value.strip_prefix("$HOME/") {
                    Some(rest) => home.join(rest),
                    None => PathBuf::from(value),
                };
                if folder.is_dir() {
                    return Some(folder);
                }
            }
        }
    }

    home_directory().map(|home| home.join("Downloads")).filter(|folder| folder.is_dir())
}

/// The home directory, as each system names it.
pub fn home_directory() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    let variable = "USERPROFILE";
    #[cfg(not(target_os = "windows"))]
    let variable = "HOME";

    std::env::var_os(variable).map(PathBuf::from).filter(|path| path.is_dir())
}

/// `2026-09-01_14-32-05`, the stamp inside every file name.
pub fn file_stamp(now: DateTime<Local>) -> String {
    now.format("%Y-%m-%d_%H-%M-%S").to_string()
}

/// The `created` field inside a profile.
///
/// Nanosecond precision with a zero-filled tail and a numeric offset, as in
/// `2026-09-01T14:32:05.123000000+02:00`. The Electron version padded
/// milliseconds with six zeroes to reach nanoseconds (main.js:637), and the
/// readers of this field parse a fixed width, so the padding stays.
pub fn created_stamp(now: DateTime<Local>) -> String {
    let millis = now.format("%3f");
    format!("{}.{millis}000000{}", now.format("%Y-%m-%dT%H:%M:%S"), now.format("%:z"))
}

/// `WasherDryer` becomes `washer-dryer`: a dash at every lower-to-upper
/// boundary, then lowercased.
pub fn kebab(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 4);
    let mut previous_lower = false;
    for character in value.chars() {
        if previous_lower && character.is_uppercase() {
            out.push('-');
        }
        previous_lower = character.is_lowercase();
        out.extend(character.to_lowercase());
    }
    out
}

/// The zip written for one appliance:
/// `homeconnectdirect-washer-bosch-hcs04com1-68a40e2e1c3f_2026-09-01_14-32-05.zip`
pub fn profile_zip_name(
    prefix: &str,
    appliance_type: &str,
    brand: &str,
    vib: &str,
    mac: &str,
    now: DateTime<Local>,
) -> String {
    format!(
        "{prefix}-{}-{}-{}-{}_{}.zip",
        kebab(appliance_type),
        brand.to_lowercase(),
        vib.to_lowercase(),
        // The API writes the MAC with dashes and the file name has its own
        // separators, so they come out.
        mac.replace('-', "").to_lowercase(),
        file_stamp(now)
    )
}

/// The single JSON hcpy gets for the whole account.
pub fn hcpy_config_name(now: DateTime<Local>) -> String {
    format!("hcpy-devices_{}.json", file_stamp(now))
}
