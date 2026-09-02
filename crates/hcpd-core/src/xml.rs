//! Home Connect describes an appliance in two XML documents, and hcpy wants
//! them merged into one object. This is that merge.
//!
//! It is a reproduction, not a design. The Electron version does it with xml2js
//! (main.js:433), and two of its behaviours are load-bearing in ways the code
//! does not say out loud:
//!
//! * **Direct children of `<device>` are skipped.** The walk only merges
//!   attributes from depth two downwards. Without it the device's own
//!   attributes land on whichever feature shares its uid.
//! * **The key order is numeric, not textual.** A JavaScript object with
//!   integer-like keys iterates in ascending numeric order, so that is the
//!   order `JSON.stringify` wrote and the order hcpy's users have been reading.
//!   `BTreeMap<u64, _>` reproduces it; a string-keyed map would put 1000 before
//!   200.
//!
//! Both are pinned by tests, because both fail quietly.

use crate::Error;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// One appliance, as the two documents together describe it.
#[derive(Debug, Default)]
pub struct Description {
    /// Feature uid to its properties: the name from the feature mapping, the
    /// attributes from the device description, and the enumeration's values
    /// where it has one.
    pub features: BTreeMap<u64, Map<String, Value>>,
    /// The `<description>` block: model, version, and the like.
    pub description: Map<String, Value>,
}

impl Description {
    /// `features` as hcpy reads it: keys are the uids in decimal, ascending.
    pub fn features_json(&self) -> Value {
        Value::Object(
            self.features
                .iter()
                .map(|(uid, feature)| (uid.to_string(), Value::Object(feature.clone())))
                .collect(),
        )
    }
}

/// `0x1001` and `1001` both mean the same thing here, because JavaScript's
/// `parseInt(value, 16)` accepts either, and both appear in these files.
fn hex(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    let digits =
        trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    u64::from_str_radix(digits, 16).ok()
}

/// The whole of an element's text, children included, which is what xml2js
/// hands back for the leaf elements these documents use.
///
/// Text nodes only. `descendants()` yields the element itself as well, and
/// roxmltree's `text()` on an element returns its first child's text, so
/// collecting both returns everything twice.
fn text_of(node: roxmltree::Node<'_, '_>) -> String {
    node.descendants()
        .filter(roxmltree::Node::is_text)
        .filter_map(|n| n.text())
        .collect::<String>()
        .trim()
        .to_owned()
}

pub fn parse(feature_mapping: &str, device_description: &str) -> Result<Description, Error> {
    let mapping = roxmltree::Document::parse(feature_mapping)
        .map_err(|source| Error::Xml { file: "FeatureMapping.xml".into(), source })?;
    let device = roxmltree::Document::parse(device_description)
        .map_err(|source| Error::Xml { file: "DeviceDescription.xml".into(), source })?;

    let enums = parse_enums(&mapping);
    let mut features = parse_features(&mapping);

    // Depth 0 is `<device>` itself, so its own children sit at depth 1 and are
    // skipped. See the note at the top.
    merge_attributes(device.root_element(), 0, &enums, &mut features);

    Ok(Description { features, description: parse_description(&device) })
}

/// Enumeration id to its members, `refValue` to label.
fn parse_enums(mapping: &roxmltree::Document<'_>) -> BTreeMap<u64, BTreeMap<i64, String>> {
    let mut enums = BTreeMap::new();
    for list in mapping.descendants().filter(|n| n.has_tag_name("enumDescriptionList")) {
        for description in list.children().filter(|n| n.has_tag_name("enumDescription")) {
            let Some(id) = description.attribute("refENID").and_then(hex) else { continue };
            let members = description
                .children()
                .filter(|n| n.has_tag_name("enumMember"))
                .filter_map(|member| {
                    let value = member.attribute("refValue")?.trim().parse::<i64>().ok()?;
                    Some((value, text_of(member)))
                })
                .collect();
            enums.insert(id, members);
        }
    }
    enums
}

/// Feature uid to a fresh object holding just its name. Everything else is
/// merged in from the device description.
fn parse_features(mapping: &roxmltree::Document<'_>) -> BTreeMap<u64, Map<String, Value>> {
    let mut features = BTreeMap::new();
    for block in mapping.descendants().filter(|n| n.has_tag_name("featureDescription")) {
        for feature in block.children().filter(|n| n.has_tag_name("feature")) {
            let Some(uid) = feature.attribute("refUID").and_then(hex) else { continue };
            let mut entry = Map::new();
            entry.insert("name".into(), Value::String(text_of(feature)));
            features.insert(uid, entry);
        }
    }
    features
}

/// Walks the device description and folds every element's attributes onto the
/// feature that shares its uid.
fn merge_attributes(
    node: roxmltree::Node<'_, '_>,
    depth: usize,
    enums: &BTreeMap<u64, BTreeMap<i64, String>>,
    features: &mut BTreeMap<u64, Map<String, Value>>,
) {
    if depth > 1
        && let Some(uid) = node.attribute("uid").and_then(hex)
        && let Some(feature) = features.get_mut(&uid)
    {
        for attribute in node.attributes() {
            feature
                .insert(attribute.name().to_owned(), Value::String(attribute.value().to_owned()));
        }

        // An enumeration is replaced by its members: the reader wants the
        // labels, not the id it would have to look up.
        if let Some(enumeration) =
            feature.get("enumerationType").and_then(Value::as_str).and_then(hex)
            && let Some(members) = enums.get(&enumeration)
        {
            let values = members.iter().map(|(k, v)| (k.to_string(), Value::String(v.clone())));
            feature.insert("values".into(), Value::Object(values.collect()));
        }
        feature.shift_remove("enumerationType");
        // The uid is the key already; repeating it inside the value is noise.
        feature.shift_remove("uid");
    }

    for child in node.children().filter(roxmltree::Node::is_element) {
        merge_attributes(child, depth + 1, enums, features);
    }
}

/// The `<description>` block, minus the one element the Electron version drops.
fn parse_description(device: &roxmltree::Document<'_>) -> Map<String, Value> {
    let mut description = Map::new();
    let Some(block) = device.root_element().children().find(|n| n.has_tag_name("description"))
    else {
        return description;
    };
    for child in block.children().filter(roxmltree::Node::is_element) {
        let name = child.tag_name().name();
        // A list of other appliances this one can pair with: long, and of no
        // use to anything reading a profile.
        if name == "pairableDeviceTypes" {
            continue;
        }
        // First occurrence wins, as `desc[key][0]` did.
        description.entry(name.to_owned()).or_insert_with(|| Value::String(text_of(child)));
    }
    description
}
