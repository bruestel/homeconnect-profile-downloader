//! Everything the downloader does that touches neither the network nor a
//! window: which host serves which region, the PKCE pair, the names of the
//! files we write, and the mapping from Home Connect's two XML documents to the
//! profiles three different projects expect.
//!
//! It is a separate crate so all of that can be tested without an account, a
//! network or a display, which is where nearly every test in this repository
//! lives.

pub mod archive;
pub mod naming;
pub mod profile;
pub mod settings;
pub mod xml;

mod pkce;

pub use pkce::{Pkce, nonce};

use serde::{Deserialize, Serialize};

/// Where the account lives. Picks both hosts, which are not the same domain and
/// on CN not even the same top-level domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Region {
    Europe,
    NorthAmerica,
    China,
}

impl Region {
    pub const ALL: [Self; 3] = [Self::Europe, Self::NorthAmerica, Self::China];

    /// Where the OAuth endpoints live.
    pub fn api_base(self) -> &'static str {
        match self {
            Self::Europe => "https://api.home-connect.com",
            Self::NorthAmerica => "https://api-rna.home-connect.com",
            Self::China => "https://api.home-connect.cn",
        }
    }

    /// Where the account, the appliances and their XML live.
    pub fn asset_base(self) -> &'static str {
        match self {
            Self::Europe => "https://eu.services.home-connect.com",
            Self::NorthAmerica => "https://na.services.home-connect.com",
            Self::China => "https://cn.services.home-connect.cn",
        }
    }

    /// The region as the access token names it.
    ///
    /// The token carries a `region` claim, found by printing the claim names
    /// during a real sign-in. It is no help *before* signing in, because the
    /// authorize endpoint is itself regional and has to be chosen first, but it
    /// can tell a wrong choice from a right one afterwards.
    ///
    /// ## How much of this is measured
    ///
    /// | | |
    /// | --- | --- |
    /// | `EU` | seen, in this project's own European account |
    /// | `NA` | seen, as `"x-reg": "NA"` in another user's logs |
    /// | `CN` | **not seen.** Inferred from the host, which is `.cn` |
    ///
    /// So the matching is exact, against the spellings that have been seen plus
    /// a few the hosts suggest, and anything else is **not** guessed at: it
    /// comes back as unrecognised and is reported as it stands. That is what
    /// lets the next person with such an account tell us what their token
    /// actually says.
    ///
    /// The earlier version of this matched on substrings, which is how a value
    /// nobody has ever seen turns into a confident wrong answer.
    pub fn from_claim(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "eu" | "europe" | "region_eu" => Some(Self::Europe),
            "na" | "rna" | "us" | "northamerica" | "north_america" | "region_na" => {
                Some(Self::NorthAmerica)
            }
            "cn" | "china" | "region_cn" => Some(Self::China),
            _ => None,
        }
    }

    /// What the token says about the region that was chosen.
    ///
    /// Never an error, and that is the point. A mismatch here is a *suggestion*
    /// and the fetch carries on regardless, because the alternative is that one
    /// unrecognised spelling blocks an account that would have worked.
    ///
    /// What a wrong region actually does was measured rather than assumed: it
    /// is **not** a 401. Signing in to North America with a European account
    /// succeeds, and the appliance list comes back empty, so the run fails two
    /// steps later with "No appliances found for this account!". Nothing in
    /// that sentence points at the region, which is exactly why this check is
    /// worth having.
    pub fn check(self, claim: Option<&str>) -> RegionCheck {
        match claim {
            None => RegionCheck::Absent,
            Some(claim) => match Self::from_claim(claim) {
                Some(theirs) if theirs == self => RegionCheck::Agrees,
                Some(theirs) => RegionCheck::Differs(theirs),
                None => RegionCheck::Unrecognised(claim.trim().to_owned()),
            },
        }
    }

    /// The short name, for a sentence.
    pub fn label(self) -> &'static str {
        match self {
            Self::Europe => "Europe",
            Self::NorthAmerica => "North America",
            Self::China => "Greater China",
        }
    }

    /// The name in the picker, which says cloud rather than country.
    ///
    /// A region here is which of Home Connect's three clouds holds the account,
    /// and that is not the same as where the appliance stands: the European
    /// cloud serves Australia too. Somebody in Sydney reading "Europe" would
    /// reasonably pick something else and then find no appliances, which is the
    /// failure this wording is here to prevent.
    ///
    /// The countries in brackets are examples, not a documented mapping. There
    /// is no published list, so each ends in an ellipsis rather than pretending
    /// to be complete.
    pub fn cloud_label(self) -> &'static str {
        match self {
            Self::Europe => "Europe cloud (Europe, Australia, ...)",
            Self::NorthAmerica => "North America cloud (USA, Canada, ...)",
            Self::China => "China cloud (China)",
        }
    }
}

impl std::fmt::Display for Region {
    /// The long name, because the only place a region is shown on its own is
    /// the picker. Sentences use `label`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.cloud_label())
    }
}

/// What the token's `region` claim says about the region that was chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegionCheck {
    /// The token carries no such claim.
    Absent,
    Agrees,
    /// The token names a different region, which is almost certainly the right
    /// one. Only ever a suggestion.
    Differs(Region),
    /// A spelling this version does not know. Reported as it stands.
    Unrecognised(String),
}

/// Which project the download is for. They want different files, and for hcpy a
/// different file altogether.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Target {
    /// The openHAB binding.
    HomeConnectDirect,
    /// The Home Assistant integration.
    HomeAssistantLocal,
    /// hcpy.
    Hcpy,
}

impl Target {
    pub const ALL: [Self; 3] = [Self::HomeConnectDirect, Self::HomeAssistantLocal, Self::Hcpy];

    pub fn label(self) -> &'static str {
        match self {
            Self::HomeConnectDirect => "Home Connect Direct Binding (openHAB)",
            Self::HomeAssistantLocal => "Home Connect Local (Home Assistant)",
            Self::Hcpy => "hcpy",
        }
    }

    /// The first part of a written file's name.
    pub fn file_prefix(self) -> &'static str {
        match self {
            Self::HomeConnectDirect => "homeconnectdirect",
            // Everything that is not the openHAB binding took this prefix in
            // the Electron version, hcpy included, though hcpy never reaches
            // it, because it writes one JSON instead of a zip per appliance.
            Self::HomeAssistantLocal | Self::Hcpy => "homeconnect-local-hass",
        }
    }

    /// hcpy gets one JSON for all appliances; the other two get a zip each.
    pub fn is_hcpy(self) -> bool {
        matches!(self, Self::Hcpy)
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// The OAuth client the Electron version registered, and the redirect it was
/// registered with. The redirect is a scheme nothing on the system handles,
/// which is the point: the webview catches the navigation to it and no browser
/// ever follows it.
pub const CLIENT_ID: &str = "9B75AC9EC512F36C84256AC47D813E2C1DD0D6520DF774B020E1E6E2EB29B1F3";
pub const REDIRECT_URI: &str = "hcauth://auth/prod";
pub const SCOPE: &str = "Control DeleteAppliance IdentifyAppliance Images Monitor \
                         ReadAccount ReadOrigApi Settings WriteAppliance WriteOrigApi";

/// Builds the URL the login webview opens.
pub fn authorize_url(region: Region, pkce: &Pkce) -> String {
    let mut url = url::Url::parse(&format!("{}/security/oauth/authorize", region.api_base()))
        .expect("a region's api_base is a valid URL");
    url.query_pairs_mut()
        .append_pair("redirect_url", REDIRECT_URI)
        .append_pair("client_id", CLIENT_ID)
        .append_pair("response_type", "code")
        .append_pair("prompt", "login")
        .append_pair("code_challenge_method", "S256")
        .append_pair("code_challenge", &pkce.challenge)
        // Both are sent because the service expects them, and neither is
        // checked when the redirect comes back. What protects this exchange is
        // PKCE and the fact that the redirect never leaves our own webview, so
        // there is no browser and no third party to confuse it with. Saying so
        // beats leaving a parameter that looks like a check nobody performs.
        .append_pair("state", &nonce(16))
        .append_pair("nonce", &nonce(16))
        .append_pair("scope", SCOPE);
    url.into()
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Message(String),
    #[error("XML in {file}: {source}")]
    Xml {
        file: String,
        #[source]
        source: roxmltree::Error,
    },
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl Error {
    pub fn msg(text: impl Into<String>) -> Self {
        Self::Message(text.into())
    }
}

#[cfg(test)]
mod tests;
