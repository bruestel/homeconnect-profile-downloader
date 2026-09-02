//! Everything here runs without an account, a network or a display.
//!
//! The shapes under test are not ours: three projects read these files, and
//! people have downloads from the Electron version sitting in a folder next to
//! the new ones. So the tests pin the old behaviour rather than a nicer one,
//! including the two places where xml2js did something that is easy to miss and
//! silent to get wrong.

use super::*;
use chrono::{Local, TimeZone};
use profile::{Appliance, Encryption};
use serde_json::{Map, Value};

/// A fixed local moment, so the stamps are assertable.
fn moment() -> chrono::DateTime<Local> {
    Local.with_ymd_and_hms(2026, 9, 1, 14, 32, 5).unwrap()
}

fn washer() -> Appliance {
    Appliance {
        ha_id: "BOSCH-HCS04COM1-68A40E2E1C3F".into(),
        ha_type: "WasherDryer".into(),
        serial_number: "402001234567890123".into(),
        brand: "bosch".into(),
        vib: "HCS04COM1".into(),
        mac: "68-A4-0E-2E-1C-3F".into(),
        name: "Waschtrockner".into(),
        e_number: "HCS04COM1/38".into(),
        ddf_version: Some(3),
        encryption: None,
    }
}

#[test]
fn an_appliance_is_listed_under_the_name_the_user_gave_it() {
    let appliance = washer();
    assert_eq!(appliance.label(), "Waschtrockner");
    assert_eq!(appliance.description(), "WasherDryer HCS04COM1/38");
}

#[test]
fn an_appliance_with_no_name_falls_back_to_its_make() {
    // The account need not hold a name, and "" is a worse label than none.
    let appliance = Appliance { name: String::new(), ..washer() };
    assert_eq!(appliance.label(), "bosch WasherDryer");
}

#[test]
fn the_model_falls_back_to_the_vib_where_there_is_no_e_number() {
    // vib is the same number without the index, so it is the right stand-in.
    let appliance = Appliance { e_number: String::new(), ..washer() };
    assert_eq!(appliance.description(), "WasherDryer HCS04COM1");
}

#[test]
fn regions_use_their_own_hosts() {
    // China is not merely a different subdomain: it is a different top-level
    // domain on both hosts, which is what the 1.0.1 fix was about.
    assert_eq!(Region::China.api_base(), "https://api.home-connect.cn");
    assert_eq!(Region::China.asset_base(), "https://cn.services.home-connect.cn");
    assert!(Region::Europe.asset_base().starts_with("https://eu."));
    assert!(Region::NorthAmerica.api_base().contains("api-rna"));
}

#[test]
fn authorize_url_carries_the_challenge_and_not_the_verifier() {
    let pkce = Pkce::new();
    let url = authorize_url(Region::Europe, &pkce);

    assert!(url.starts_with("https://api.home-connect.com/security/oauth/authorize?"));
    assert!(url.contains("code_challenge_method=S256"));
    assert!(url.contains(&format!("code_challenge={}", pkce.challenge)));
    // The whole point of PKCE: the verifier stays here until the token request.
    assert!(!url.contains(&pkce.verifier));
}

#[test]
fn a_pkce_pair_is_fresh_every_time() {
    assert_ne!(Pkce::new().verifier, Pkce::new().verifier);
}

#[test]
fn kebab_splits_at_the_case_boundary() {
    assert_eq!(naming::kebab("WasherDryer"), "washer-dryer");
    assert_eq!(naming::kebab("Oven"), "oven");
    assert_eq!(naming::kebab("CoffeeMaker"), "coffee-maker");
    // No boundary to find, and nothing invented.
    assert_eq!(naming::kebab("HOB"), "hob");
}

#[test]
fn file_names_match_the_electron_versions() {
    assert_eq!(
        profile::zip_name(&washer(), Target::HomeConnectDirect, moment()),
        "homeconnectdirect-washer-dryer-bosch-hcs04com1-68a40e2e1c3f_2026-09-01_14-32-05.zip"
    );
    assert_eq!(
        profile::zip_name(&washer(), Target::HomeAssistantLocal, moment()),
        "homeconnect-local-hass-washer-dryer-bosch-hcs04com1-68a40e2e1c3f_2026-09-01_14-32-05.zip"
    );
    assert_eq!(naming::hcpy_config_name(moment()), "hcpy-devices_2026-09-01_14-32-05.json");
}

#[test]
fn created_stamp_pads_milliseconds_out_to_nanoseconds() {
    let stamp = naming::created_stamp(moment());
    let (head, offset) = stamp.split_at(stamp.len() - 6);
    assert_eq!(head, "2026-09-01T14:32:05.000000000");
    // A numeric offset, not a zone name, because readers parse a fixed width.
    assert!(offset.starts_with('+') || offset.starts_with('-'), "offset was {offset}");
    assert_eq!(offset.len(), 6);
}

#[test]
fn tls_wins_where_an_appliance_offers_both() {
    let both = Encryption::from_parts(Some("tls".into()), Some(("aes".into(), "iv".into())));
    assert_eq!(both, Some(Encryption::Tls { key: "tls".into() }));

    let aes = Encryption::from_parts(None, Some(("aes".into(), "iv".into())));
    assert_eq!(aes, Some(Encryption::Aes { key: "aes".into(), iv: "iv".into() }));

    // Neither means the appliance cannot be reached locally at all.
    assert_eq!(Encryption::from_parts(None, None), None);
}

#[test]
fn profile_json_keeps_the_order_and_upper_cases_the_brand() {
    let profile = profile::profile_json(
        &washer(),
        &Encryption::Aes { key: "abc".into(), iv: "def".into() },
        moment(),
    );

    let keys: Vec<&str> = profile.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        [
            "haId",
            "type",
            "serialNumber",
            "brand",
            "vib",
            "mac",
            "featureMappingFileName",
            "deviceDescriptionFileName",
            "created",
            "connectionType",
            "key",
            "iv",
        ]
    );
    assert_eq!(profile["brand"], "BOSCH");
    assert_eq!(profile["connectionType"], "AES");
    assert_eq!(
        profile["featureMappingFileName"],
        "BOSCH-HCS04COM1-68A40E2E1C3F_FeatureMapping.xml"
    );
}

#[test]
fn a_tls_profile_has_no_iv() {
    let profile =
        profile::profile_json(&washer(), &Encryption::Tls { key: "abc".into() }, moment());
    assert_eq!(profile["connectionType"], "TLS");
    assert!(!profile.contains_key("iv"));
}

#[test]
fn hcpy_addresses_tls_and_aes_appliances_differently() {
    let description = xml::Description::default();

    let tls = profile::hcpy_device(&washer(), &Encryption::Tls { key: "k".into() }, &description);
    assert_eq!(tls["host"], "bosch-WasherDryer-BOSCH-HCS04COM1-68A40E2E1C3F");
    assert!(!tls.contains_key("iv"));
    assert_eq!(tls["name"], "washerdryer");

    let aes = profile::hcpy_device(
        &washer(),
        &Encryption::Aes { key: "k".into(), iv: "i".into() },
        &description,
    );
    // An AES appliance answers only to its haId.
    assert_eq!(aes["host"], "BOSCH-HCS04COM1-68A40E2E1C3F");
    assert_eq!(aes["iv"], "i");
}

// --- the XML merge -------------------------------------------------------

const FEATURE_MAPPING: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<featureMappingFile>
  <featureDescription>
    <feature refUID="0x0014">BSH.Common.Setting.PowerState</feature>
    <feature refUID="0x0064">Dishcare.Dishwasher.Program.Auto1</feature>
    <feature refUID="0x00FF">BSH.Common.Root.SelectedProgram</feature>
  </featureDescription>
  <enumDescriptionList>
    <enumDescription refENID="0x0003" enumKey="PowerState">
      <enumMember refValue="2">Off</enumMember>
      <enumMember refValue="3">On</enumMember>
    </enumDescription>
  </enumDescriptionList>
</featureMappingFile>"#;

const DEVICE_DESCRIPTION: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<device uid="0x00FF" access="readWrite">
  <description>
    <model>SMV4HCX48E</model>
    <version>3</version>
    <pairableDeviceTypes>a very long list</pairableDeviceTypes>
  </description>
  <statusList>
    <status uid="0x0014" access="readWrite" available="true" enumerationType="0x0003"/>
  </statusList>
  <programGroup>
    <program uid="0x0064" access="readWrite" execution="selectandstart"/>
  </programGroup>
</device>"#;

fn parsed() -> xml::Description {
    xml::parse(FEATURE_MAPPING, DEVICE_DESCRIPTION).expect("the fixture parses")
}

#[test]
fn attributes_are_merged_onto_the_feature_that_shares_the_uid() {
    let parsed = parsed();
    let power = &parsed.features[&0x14];

    assert_eq!(power["name"], "BSH.Common.Setting.PowerState");
    assert_eq!(power["access"], "readWrite");
    assert_eq!(power["available"], "true");
}

#[test]
fn an_enumeration_is_replaced_by_its_members() {
    let parsed = parsed();
    let power = &parsed.features[&0x14];

    assert_eq!(power["values"]["2"], "Off");
    assert_eq!(power["values"]["3"], "On");
    // The id was only ever a key into the enumeration list.
    assert!(!power.contains_key("enumerationType"));
    // And the uid is the map's key already.
    assert!(!power.contains_key("uid"));
}

#[test]
fn the_devices_own_attributes_do_not_leak_onto_a_feature() {
    // `<device uid="0x00FF" access="readWrite">` shares its uid with a real
    // feature. The Electron version skips depth 0 and 1 for exactly this
    // reason, and without that rule this feature would claim the device's
    // access.
    let parsed = parsed();
    let selected = &parsed.features[&0xFF];

    assert_eq!(selected["name"], "BSH.Common.Root.SelectedProgram");
    assert!(!selected.contains_key("access"), "the device's attributes leaked: {selected:?}");
}

#[test]
fn feature_keys_come_out_in_numeric_order() {
    // 20, 100, 255. A string-keyed map would answer 100, 20, 255, and hcpy's
    // users would see every file reordered.
    let json = parsed().features_json();
    let keys: Vec<&str> = json.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, ["20", "100", "255"]);
}

#[test]
fn the_description_drops_the_pairable_list() {
    let parsed = parsed();
    assert_eq!(parsed.description["model"], "SMV4HCX48E");
    assert_eq!(parsed.description["version"], "3");
    assert!(!parsed.description.contains_key("pairableDeviceTypes"));
}

#[test]
fn a_broken_document_is_an_error_that_names_the_file() {
    let error = xml::parse("<featureMappingFile>", DEVICE_DESCRIPTION).unwrap_err();
    assert!(error.to_string().contains("FeatureMapping.xml"), "was: {error}");
}

#[test]
fn the_region_claim_is_read_where_the_spelling_is_known() {
    // "EU" is the one that has actually been seen. The rest are the spellings
    // the hosts suggest, and they are matched exactly rather than by substring.
    assert_eq!(Region::from_claim("EU"), Some(Region::Europe));
    assert_eq!(Region::from_claim(" eu "), Some(Region::Europe));
    assert_eq!(Region::from_claim("Europe"), Some(Region::Europe));
    assert_eq!(Region::from_claim("NA"), Some(Region::NorthAmerica));
    assert_eq!(Region::from_claim("rna"), Some(Region::NorthAmerica));
    assert_eq!(Region::from_claim("CN"), Some(Region::China));
}

#[test]
fn an_unknown_spelling_is_never_guessed_at() {
    // The version before this matched substrings, which turns a value nobody
    // has seen into a confident wrong answer. "eu-west-1" is the example: it
    // looks European and could be anything.
    assert_eq!(Region::from_claim("eu-west-1"), None);
    assert_eq!(Region::from_claim("moon"), None);
    assert_eq!(Region::from_claim(""), None);
}

#[test]
fn checking_a_region_never_blocks_a_sign_in() {
    use crate::RegionCheck;

    assert_eq!(Region::Europe.check(Some("EU")), RegionCheck::Agrees);
    assert_eq!(Region::Europe.check(None), RegionCheck::Absent);
    assert_eq!(Region::Europe.check(Some("NA")), RegionCheck::Differs(Region::NorthAmerica));
    // The case that matters: a spelling we do not know must come back as
    // itself, so it can be reported and later recognised, and must not be
    // turned into a mismatch that stops the run.
    assert_eq!(
        Region::Europe.check(Some("eu-west-1")),
        RegionCheck::Unrecognised("eu-west-1".to_owned())
    );
}

#[test]
fn a_save_is_offered_somewhere_a_person_would_look() {
    let destination = naming::default_destination();
    assert!(destination.is_absolute(), "was {}", destination.display());
    // Whatever the machine holds, there has to be an answer: the chain ends in
    // a fallback that needs no home directory at all.
    assert!(!destination.as_os_str().is_empty());

    // And it must be a folder that exists, or the first save fails on a path
    // that was only ever a guess.
    if destination != std::env::temp_dir().join("home-connect-profiles") {
        assert!(destination.is_dir(), "{} is not a directory", destination.display());
    }
}

#[test]
fn the_home_directory_is_only_reported_when_it_is_one() {
    // A variable pointing at nothing is worse than no variable, because it
    // would be offered as a destination and then fail on the first write.
    if let Some(home) = naming::home_directory() {
        assert!(home.is_dir(), "{} is not a directory", home.display());
    }
}

// ---------------------------------------------------------------------------
// The archive.
//
// Covered until now only by the parity test, which runs against real downloads
// and is deliberately not in the repository. That left the claim in
// `with_profile`, that an archive downloaded twice must not grow a second
// profile, asserted by a comment and by nothing else.

/// An archive shaped like Home Connect's, built in memory.
fn archive_of(entries: &[(&str, &str)]) -> Vec<u8> {
    use std::io::Write;
    let mut buffer = std::io::Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(&mut buffer);
    for (name, body) in entries {
        zip.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
        zip.write_all(body.as_bytes()).unwrap();
    }
    zip.finish().unwrap();
    buffer.into_inner()
}

fn an_appliance_archive() -> Vec<u8> {
    archive_of(&[
        ("BOSCH-HCS04COM1-68A40E2E1C3F_FeatureMapping.xml", "<featureMapping/>"),
        ("BOSCH-HCS04COM1-68A40E2E1C3F_DeviceDescription.xml", "<device/>"),
        ("something-else.txt", "not ours"),
    ])
}

fn a_profile() -> Map<String, Value> {
    let mut profile = Map::new();
    profile.insert("haId".into(), Value::from("BOSCH-HCS04COM1-68A40E2E1C3F"));
    profile
}

#[test]
fn the_two_documents_are_found_by_their_suffix() {
    let (mapping, description) = archive::documents(&an_appliance_archive()).unwrap();
    assert_eq!(mapping, "<featureMapping/>");
    assert_eq!(description, "<device/>");
}

#[test]
fn an_archive_without_the_descriptions_is_an_error() {
    let archive = archive_of(&[("readme.txt", "nothing useful here")]);
    let error = archive::documents(&archive).unwrap_err().to_string();
    assert!(error.contains("no appliance description"), "was {error}");
}

#[test]
fn the_profile_is_added_and_everything_else_is_kept() {
    let original = an_appliance_archive();
    let with =
        archive::with_profile(&original, "BOSCH-HCS04COM1-68A40E2E1C3F", &a_profile(), moment())
            .unwrap();

    let before: Vec<String> =
        archive::entries(&original).unwrap().into_iter().map(|(n, _)| n).collect();
    let after: Vec<String> = archive::entries(&with).unwrap().into_iter().map(|(n, _)| n).collect();

    for name in &before {
        assert!(after.contains(name), "{name} was dropped");
    }
    assert!(after.contains(&"BOSCH-HCS04COM1-68A40E2E1C3F.json".to_owned()));
    assert_eq!(after.len(), before.len() + 1);

    // The documents still read back, so the copy kept them intact.
    let (mapping, _) = archive::documents(&with).unwrap();
    assert_eq!(mapping, "<featureMapping/>");
}

#[test]
fn an_archive_written_twice_holds_one_profile() {
    let ha_id = "BOSCH-HCS04COM1-68A40E2E1C3F";
    let once =
        archive::with_profile(&an_appliance_archive(), ha_id, &a_profile(), moment()).unwrap();
    let twice = archive::with_profile(&once, ha_id, &a_profile(), moment()).unwrap();

    let names: Vec<String> =
        archive::entries(&twice).unwrap().into_iter().map(|(n, _)| n).collect();
    let profiles =
        names.iter().filter(|n| n.as_str() == "BOSCH-HCS04COM1-68A40E2E1C3F.json").count();
    assert_eq!(profiles, 1, "entries were {names:?}");
    assert_eq!(names.len(), 4);
}

#[test]
fn the_added_entry_carries_the_moment_it_was_written() {
    let with = archive::with_profile(
        &an_appliance_archive(),
        "BOSCH-HCS04COM1-68A40E2E1C3F",
        &a_profile(),
        moment(),
    )
    .unwrap();

    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(with)).unwrap();
    let entry = zip.by_name("BOSCH-HCS04COM1-68A40E2E1C3F.json").unwrap();
    let stamp = entry.last_modified().expect("the entry carries a timestamp");
    // 1980-01-01 is the format's zero, which is what an unset stamp looks like
    // in a file listing.
    assert_eq!((stamp.year(), stamp.month(), stamp.day()), (2026, 9, 1));
}
