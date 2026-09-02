//! Home Connect's own archive with our profile added.
//!
//! Bytes in, bytes out, with no file system. That is what lets the parity test run
//! this over real archives and compare the result against what the Electron
//! version produced, without an account and without writing anything.

use crate::Error;
use chrono::{DateTime, Datelike, Local, Timelike};
use serde_json::{Map, Value};
use std::io::{Cursor, Read, Write};

/// The moment, as a zip entry records one.
///
/// Zip cannot hold a date before 1980 or after 2107, and there is no useful
/// answer if the clock is outside that: the entry falls back to the format's
/// own default rather than the write failing over a timestamp.
fn stamp(now: DateTime<Local>) -> zip::DateTime {
    zip::DateTime::from_date_and_time(
        now.year() as u16,
        now.month() as u8,
        now.day() as u8,
        now.hour() as u8,
        now.minute() as u8,
        now.second() as u8,
    )
    .unwrap_or(zip::DateTime::DEFAULT)
}

/// The names the two documents an appliance is described by end in.
const DEVICE_DESCRIPTION: &str = "_DeviceDescription.xml";
const FEATURE_MAPPING: &str = "_FeatureMapping.xml";

fn zip_error(error: impl std::fmt::Display) -> Error {
    Error::msg(format!("the appliance archive: {error}"))
}

/// The two XML documents, pulled out of an archive.
///
/// Matched on the suffix rather than the whole name: the archive prefixes both
/// with the haId, and that prefix has changed shape between accounts.
pub fn documents(archive: &[u8]) -> Result<(String, String), Error> {
    let mut zip = zip::ZipArchive::new(Cursor::new(archive)).map_err(zip_error)?;

    let (mut device_description, mut feature_mapping) = (None, None);
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index).map_err(zip_error)?;
        let name = entry.name().to_owned();
        let slot = if name.ends_with(DEVICE_DESCRIPTION) {
            &mut device_description
        } else if name.ends_with(FEATURE_MAPPING) {
            &mut feature_mapping
        } else {
            continue;
        };
        let mut text = String::new();
        entry.read_to_string(&mut text).map_err(|error| Error::msg(format!("{name}: {error}")))?;
        *slot = Some(text);
    }

    match (feature_mapping, device_description) {
        (Some(mapping), Some(description)) => Ok((mapping, description)),
        _ => Err(Error::msg("the archive holds no appliance description")),
    }
}

/// The archive again, with `<haId>.json` added.
///
/// The existing entries are copied still compressed. Nothing in them is ours to
/// change, and recompressing would cost time and alter bytes that three other
/// projects read.
pub fn with_profile(
    archive: &[u8],
    ha_id: &str,
    profile: &Map<String, Value>,
    now: DateTime<Local>,
) -> Result<Vec<u8>, Error> {
    let mut source = zip::ZipArchive::new(Cursor::new(archive)).map_err(zip_error)?;
    let mut buffer = Cursor::new(Vec::new());
    let mut out = zip::ZipWriter::new(&mut buffer);

    for index in 0..source.len() {
        let entry = source.by_index(index).map_err(zip_error)?;
        // An archive downloaded twice must not grow a second profile.
        if entry.name() == format!("{ha_id}.json") {
            continue;
        }
        out.raw_copy_file(entry).map_err(zip_error)?;
    }

    out.start_file(
        format!("{ha_id}.json"),
        zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            // Without this the entry is dated 1980-01-01, the zip format's zero,
            // which in a file listing looks like something broke. The other
            // entries keep whatever Home Connect gave them, since they are
            // copied untouched.
            .last_modified_time(stamp(now)),
    )
    .map_err(zip_error)?;
    let text = serde_json::to_string_pretty(profile)?;
    out.write_all(text.as_bytes()).map_err(|error| Error::msg(error.to_string()))?;
    out.finish().map_err(zip_error)?;

    Ok(buffer.into_inner())
}

/// Every entry in an archive, by name. For tests and for comparing two of them.
pub fn entries(archive: &[u8]) -> Result<Vec<(String, Vec<u8>)>, Error> {
    let mut zip = zip::ZipArchive::new(Cursor::new(archive)).map_err(zip_error)?;
    let mut out = Vec::with_capacity(zip.len());
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index).map_err(zip_error)?;
        let name = entry.name().to_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).map_err(|error| Error::msg(format!("{name}: {error}")))?;
        out.push((name, bytes));
    }
    Ok(out)
}
