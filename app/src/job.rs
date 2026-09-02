//! One fetch, and one save. They are separate on purpose.
//!
//! A fetch signs in and pulls down everything about every appliance, and writes
//! nothing. What it returns is held in memory, and from it any of the three
//! formats can be produced later. That is the whole reason for the split: the
//! three targets differ only in how the same material is arranged, so asking
//! which one you want before signing in was asking too early, and picking a
//! second one used to cost a second login.
//!
//! Progress comes back as steps rather than lines, because the window shows it
//! that way: a step opens, gathers detail under it, and closes when the next
//! one opens.

use chrono::Local;
use hcpd_core::profile::{Appliance, Encryption};
use hcpd_core::{Region, RegionCheck, Target, naming, profile, xml};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

/// One appliance, with everything needed to write it in any format.
///
/// The archive is Home Connect's own, held as it arrived. It is the expensive
/// part of a fetch and the only part a second format would need again.
#[derive(Clone)]
pub struct Fetched {
    pub appliance: Appliance,
    pub encryption: Encryption,
    pub archive: Arc<Vec<u8>>,
}

impl std::fmt::Debug for Fetched {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The archive is half a megabyte of zip; its length is the useful part.
        write!(f, "Fetched({}, {} bytes)", self.appliance.ha_id, self.archive.len())
    }
}

/// What the window is told while a fetch is going on.
pub enum Progress {
    /// A new step begins, which closes the one before it.
    Step(String),
    /// A line belonging to the step currently open.
    Detail(String),
    /// Something worth reading that is not a failure. The step it belongs to
    /// keeps it on screen rather than folding it away with everything else.
    Warning(String),
    /// The token says the account lives somewhere else. The window offers this
    /// as a correction rather than leaving the user to work it out.
    WrongRegion(Region),
}

pub type Report<'a> = dyn Fn(Progress) + 'a;

fn step(report: &Report<'_>, title: impl Into<String>) {
    report(Progress::Step(title.into()));
}

fn detail(report: &Report<'_>, line: impl Into<String>) {
    report(Progress::Detail(line.into()));
}

fn warn(report: &Report<'_>, line: impl Into<String>) {
    report(Progress::Warning(line.into()));
}

/// Signs in and collects every appliance on the account. Writes nothing.
pub fn fetch(region: Region, report: &Report<'_>) -> Result<Vec<Fetched>, String> {
    step(report, "Sign in");
    let pkce = hcpd_core::Pkce::new();
    let code = login(region, &pkce, report)?;

    let mut suspect = None;

    step(report, "Read the account");
    let client = hcpd_client::Client::connect(region, &code, &pkce.verifier)
        .map_err(|error| error.to_string())?;
    detail(report, format!("Account: {}", client.hc_id));

    // The token names the account's region. That is no help before signing in,
    // because the authorize endpoint is itself regional, but afterwards it can
    // tell a wrong choice from a right one.
    //
    // It never stops the run. Only one spelling has actually been seen, so a
    // value this version does not recognise must not be allowed to block an
    // account that would have worked. If the choice really was wrong, the next
    // request fails on its own, and by then the window already has the answer
    // to offer.
    match region.check(client.region_claim.as_deref()) {
        RegionCheck::Agrees => {
            detail(report, format!("Region: {}, which the token agrees with.", region.label()));
        }
        RegionCheck::Absent => {
            detail(report, format!("Region: {}. The token does not name one.", region.label()));
        }
        RegionCheck::Differs(theirs) => {
            warn(
                report,
                format!(
                    "Region: {}, but the token says {}. Continuing, though this \
                     account probably has no appliances here.",
                    region.label(),
                    theirs.label()
                ),
            );
            report(Progress::WrongRegion(theirs));
            suspect = Some(theirs);
        }
        RegionCheck::Unrecognised(claim) => {
            // Printed so it can be recognised next time. This is how the
            // remaining spelling will be learnt.
            warn(
                report,
                format!(
                    "Region: {}. The token says {claim:?}, which this version does \
                     not know.",
                    region.label()
                ),
            );
        }
    }

    step(report, "List appliances");
    // A wrong region does not answer 401 here; it answers with an empty list.
    // So the message that would otherwise say nothing useful gets the reason
    // appended to it.
    let appliances =
        client.appliances(&|line| detail(report, line)).map_err(|error| match suspect {
            Some(theirs) => format!(
                "{error} The token says this account is registered in {}, so that \
                 is probably where its appliances are.",
                theirs.label()
            ),
            None => error.to_string(),
        })?;
    detail(report, format!("{} appliance(s) on the account.", appliances.len()));

    let mut fetched = Vec::new();
    for appliance in appliances {
        step(report, appliance.label());

        let Some(encryption) = appliance.encryption.clone() else {
            // Not a failure of the fetch: an appliance with no encryption data
            // cannot be reached locally, so there is nothing to write for it.
            detail(report, "No encryption data available, so this one is skipped.");
            continue;
        };
        detail(report, format!("Encryption: {}", encryption.label()));

        let archive = client
            .appliance_archive(&appliance.ha_id)
            .map_err(|error| format!("{}: {error}", appliance.ha_id))?;
        detail(report, format!("Archive: {} bytes", thousands(archive.len())));

        // Parsed here rather than at save time so a broken document is reported
        // now, while the step it belongs to is still on screen.
        let (feature_mapping, device_description) = hcpd_core::archive::documents(&archive)
            .map_err(|error| format!("{}: {error}", appliance.ha_id))?;
        let description = xml::parse(&feature_mapping, &device_description)
            .map_err(|error| format!("{}: {error}", appliance.ha_id))?;
        detail(report, format!("{} features described.", description.features.len()));

        fetched.push(Fetched { appliance, encryption, archive: Arc::new(archive) });
    }

    if fetched.is_empty() {
        return Err("No appliances found for this account!".into());
    }

    step(report, format!("Done: {}", plural(fetched.len(), "appliance", "appliances")));
    Ok(fetched)
}

/// Writes what a fetch collected, in one of the three formats.
///
/// Every format comes out of the same material, so this needs no network and no
/// second sign-in.
pub fn save(fetched: &[Fetched], target: Target, folder: &Path) -> Result<Vec<PathBuf>, String> {
    std::fs::create_dir_all(folder)
        .map_err(|error| format!("Could not create {}: {error}", folder.display()))?;

    let now = Local::now();
    let mut written = Vec::new();

    if target.is_hcpy() {
        let mut devices = Vec::with_capacity(fetched.len());
        for one in fetched {
            let (feature_mapping, device_description) = hcpd_core::archive::documents(&one.archive)
                .map_err(|error| format!("{}: {error}", one.appliance.ha_id))?;
            let description = xml::parse(&feature_mapping, &device_description)
                .map_err(|error| format!("{}: {error}", one.appliance.ha_id))?;
            devices.push(profile::hcpy_device(&one.appliance, &one.encryption, &description));
        }

        let path = folder.join(naming::hcpy_config_name(now));
        let config = profile::hcpy_config(devices).map_err(|error| error.to_string())?;
        std::fs::write(&path, config)
            .map_err(|error| format!("Could not write {}: {error}", path.display()))?;
        written.push(path);
    } else {
        for one in fetched {
            let profile = profile::profile_json(&one.appliance, &one.encryption, now);
            let bytes =
                hcpd_core::archive::with_profile(&one.archive, &one.appliance.ha_id, &profile, now)
                    .map_err(|error| format!("{}: {error}", one.appliance.ha_id))?;
            let path = folder.join(profile::zip_name(&one.appliance, target, now));
            std::fs::write(&path, bytes)
                .map_err(|error| format!("Could not write {}: {error}", path.display()))?;
            written.push(path);
        }
    }

    Ok(written)
}

/// Runs the login helper and waits for the code it prints.
///
/// The helper is a separate process because the webview and this window each
/// want an event loop of their own, and they cannot both have one. Its trace
/// arrives on stderr as it happens; the answer is one line of JSON on stdout.
fn login(region: Region, pkce: &hcpd_core::Pkce, report: &Report<'_>) -> Result<String, String> {
    let helper = helper_path();
    detail(report, "Opening the Home Connect login window.");

    let mut child = Command::new(&helper)
        .arg(hcpd_core::authorize_url(region, pkce))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            format!("Could not start the login window ({}): {error}", helper.display())
        })?;

    // stderr to its end first, stdout afterwards. That order is only safe
    // because the helper writes stdout exactly once, as it exits: a helper that
    // wrote more than a pipe buffer holds before closing stderr would block on
    // stdout while this loop waited on stderr, and neither would move again.
    let stderr = BufReader::new(child.stderr.take().expect("stderr was piped"));
    for line in stderr.lines().map_while(Result::ok) {
        // The trace is for us, not for the user; only the milestone earns a
        // line in the step.
        if line.contains("redirect caught") {
            detail(report, "Signed in.");
        }
        eprintln!("hcpd-login: {line}");
    }

    let output = child.wait_with_output().map_err(|error| error.to_string())?;

    // Nothing at all means the window went away without answering: quit from
    // its own menu, killed, or crashed. That is a cancelled sign-in, and saying
    // so is better than repeating a parser's complaint about an empty input,
    // which is what the user saw before.
    if output.stdout.iter().all(u8::is_ascii_whitespace) {
        return Err("Sign-in cancelled.".to_owned());
    }

    let reply: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("The login window answered with nothing usable: {error}"))?;
    if let Some(error) = reply["error"].as_str() {
        return Err(error.to_owned());
    }
    reply["code"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "The login window returned no code.".to_owned())
}

/// Next to our own binary, which is where cargo and every bundler put it.
fn helper_path() -> PathBuf {
    let name = if cfg!(windows) { "hcpd-login.exe" } else { "hcpd-login" };
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(name)))
        .unwrap_or_else(|| name.into())
}

fn thousands(value: usize) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(digit);
    }
    out
}

pub fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_counts_are_grouped_for_reading() {
        assert_eq!(thousands(190097), "190 097");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1000), "1 000");
    }

    #[test]
    fn one_appliance_is_not_appliances() {
        assert_eq!(plural(1, "appliance", "appliances"), "1 appliance");
        assert_eq!(plural(0, "file", "files"), "0 files");
    }
}
