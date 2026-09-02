//! What we write, and for whom.
//!
//! Two shapes come out of the same appliance. The openHAB binding and
//! homeconnect_local_hass each want a zip per appliance: Home Connect's own
//! archive with one JSON added. hcpy wants a single JSON for the whole account,
//! with the two XML documents already merged into it.
//!
//! Both shapes are reproduced from the Electron version field for field. They
//! are read by three projects we do not control, so a renamed key is a broken
//! download, not a tidy-up.

use crate::{Error, Target, naming, xml};
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// How an appliance is reached on the local network. TLS where it has a
/// certificate, AES where it has a shared key and an IV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Encryption {
    Tls { key: String },
    Aes { key: String, iv: String },
}

impl Encryption {
    /// Which of the two the API answered with, if either.
    ///
    /// TLS wins where both are present, as it did in the Electron version
    /// (main.js:282). An appliance with neither is not usable locally and is
    /// skipped by the caller rather than written half-formed.
    pub fn from_parts(tls_key: Option<String>, aes: Option<(String, String)>) -> Option<Self> {
        match (tls_key, aes) {
            (Some(key), _) => Some(Self::Tls { key }),
            (None, Some((key, iv))) => Some(Self::Aes { key, iv }),
            (None, None) => None,
        }
    }

    pub fn key(&self) -> &str {
        match self {
            Self::Tls { key } | Self::Aes { key, .. } => key,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Tls { .. } => "TLS",
            Self::Aes { .. } => "AES",
        }
    }
}

/// One appliance on the account, after the two API calls that describe it.
///
/// More fields than any of the three output formats uses. The extra ones are
/// for the window: an account is a list of things the user named, and
/// `SIEMENS-XY123ABC4-001122334455` is not what they called the dishwasher.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Appliance {
    pub ha_id: String,
    pub ha_type: String,
    pub serial_number: String,
    pub brand: String,
    pub vib: String,
    pub mac: String,
    /// What the user called it, in their own language. Empty if the account has
    /// no name for it.
    pub name: String,
    /// The model number as it is printed on the appliance, index included, such
    /// as `SN658X06TE/38`. `vib` is the same thing without the index.
    pub e_number: String,
    /// Which revision of the device description the account holds. Two
    /// downloads of the same appliance differ only if this does.
    pub ddf_version: Option<u64>,
    #[serde(skip)]
    pub encryption: Option<Encryption>,
}

impl Appliance {
    /// The name a person would recognise in a list: theirs, where they gave
    /// one, and the make and model where they did not.
    pub fn label(&self) -> String {
        if self.name.is_empty() {
            format!("{} {}", self.brand, self.ha_type)
        } else {
            self.name.clone()
        }
    }

    /// The line under the name: what it is, and which one.
    pub fn description(&self) -> String {
        let model = if self.e_number.is_empty() { self.vib.clone() } else { self.e_number.clone() };
        format!("{} {model}", self.ha_type)
    }
}

/// The JSON that goes inside an appliance's zip.
///
/// Built as a map rather than a struct so the key order is the one the Electron
/// version wrote (main.js:299). These files get diffed against older downloads,
/// and a reordered key turns a no-op into a full-file change.
pub fn profile_json(
    appliance: &Appliance,
    encryption: &Encryption,
    now: DateTime<Local>,
) -> Map<String, Value> {
    let mut profile = Map::new();
    let mut put = |key: &str, value: &str| {
        profile.insert(key.to_owned(), Value::String(value.to_owned()));
    };

    put("haId", &appliance.ha_id);
    put("type", &appliance.ha_type);
    put("serialNumber", &appliance.serial_number);
    // Upper case even though the API is inconsistent about it, because the
    // openHAB binding matches on it.
    put("brand", &appliance.brand.to_uppercase());
    put("vib", &appliance.vib);
    put("mac", &appliance.mac);
    put("featureMappingFileName", &format!("{}_FeatureMapping.xml", appliance.ha_id));
    put("deviceDescriptionFileName", &format!("{}_DeviceDescription.xml", appliance.ha_id));
    put("created", &naming::created_stamp(now));
    put("connectionType", encryption.label());
    put("key", encryption.key());
    if let Encryption::Aes { iv, .. } = encryption {
        put("iv", iv);
    }
    profile
}

/// One entry in hcpy's device list: how to reach the appliance, then everything
/// the two XML documents say about it.
pub fn hcpy_device(
    appliance: &Appliance,
    encryption: &Encryption,
    description: &xml::Description,
) -> Map<String, Value> {
    let mut device = Map::new();
    device.insert("name".into(), Value::String(appliance.ha_type.to_lowercase()));
    device.insert("key".into(), Value::String(encryption.key().to_owned()));

    // The host differs with the encryption, and not incidentally: a TLS
    // appliance answers to a name built from its brand and type, an AES one
    // only to its haId.
    match encryption {
        Encryption::Tls { .. } => {
            device.insert(
                "host".into(),
                Value::String(format!(
                    "{}-{}-{}",
                    appliance.brand, appliance.ha_type, appliance.ha_id
                )),
            );
        }
        Encryption::Aes { iv, .. } => {
            device.insert("iv".into(), Value::String(iv.clone()));
            device.insert("host".into(), Value::String(appliance.ha_id.clone()));
        }
    }

    device.insert("description".into(), Value::Object(description.description.clone()));
    device.insert("features".into(), description.features_json());
    device
}

/// The whole hcpy file.
pub fn hcpy_config(devices: Vec<Map<String, Value>>) -> Result<String, Error> {
    let list = Value::Array(devices.into_iter().map(Value::Object).collect());
    Ok(serde_json::to_string_pretty(&list)?)
}

/// The zip an appliance's download is written to.
pub fn zip_name(appliance: &Appliance, target: Target, now: DateTime<Local>) -> String {
    naming::profile_zip_name(
        target.file_prefix(),
        &appliance.ha_type,
        &appliance.brand,
        &appliance.vib,
        &appliance.mac,
        now,
    )
}
