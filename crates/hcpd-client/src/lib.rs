//! The Home Connect API, over blocking reqwest.
//!
//! Blocking on purpose. The whole job is a short sequence of requests that the
//! window runs on a thread of its own and reports progress from; an async
//! runtime would buy nothing here and would have to be threaded through
//! everything.
//!
//! The error messages are deliberately the Electron version's, word for word,
//! where a user might have seen them before. "Wrong region used!" in particular
//! is the one people search for.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hcpd_core::profile::{Appliance, Encryption};
use hcpd_core::{CLIENT_ID, REDIRECT_URI, Region};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Wrong region used! Try a different region.")]
    WrongRegion,
    #[error("No appliances found for this account!")]
    NoAppliances,
    #[error("No real appliances found for this account (only demo appliances)!")]
    OnlyDemoAppliances,
    #[error("Invalid server response code! Received: {0}")]
    Status(reqwest::StatusCode),
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}

type Result<T> = std::result::Result<T, Error>;

pub struct Client {
    http: reqwest::blocking::Client,
    region: Region,
    token: String,
    /// The account id, taken from the token.
    pub hc_id: String,
    /// The names of the claims the token carries, values left out.
    ///
    /// Here to answer one question with evidence rather than a guess: whether
    /// the account's region can be read off the token instead of being asked
    /// for. It cannot be read off it *before* signing in either way, because
    /// the authorize endpoint is regional, but a claim naming the region would
    /// at least let a wrong choice be caught before the first request fails.
    /// Only the names are kept; the values are the account.
    pub claim_names: Vec<String>,
    /// The region claim as the token spells it, if it carries one.
    ///
    /// Read from `region` or from `x-reg`, both of which have been seen. Kept
    /// by name because it is the one claim that is about the service rather
    /// than about the person.
    pub region_claim: Option<String>,
}

impl Client {
    /// Exchanges the authorization code for a token and reads the account id
    /// out of it.
    pub fn connect(region: Region, code: &str, verifier: &str) -> Result<Self> {
        let http = reqwest::blocking::Client::builder()
            .user_agent(concat!("hcpd/", env!("CARGO_PKG_VERSION")))
            // Both spelled out, though only the first changes behaviour.
            // reqwest's blocking client, unlike its async one, already applies
            // a 30 second timeout to connect, read and write; a server that
            // accepts the connection and then says nothing does not hang the
            // fetch thread. Stating it pins the value against a change in that
            // default, and the shorter connect timeout separates a host that
            // cannot be reached from one that is merely slow to answer, which
            // on a network with dead IPv6 is the difference between eight
            // seconds and thirty.
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let response = http
            .post(format!("{}/security/oauth/token", region.api_base()))
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", CLIENT_ID),
                ("code_verifier", verifier),
                ("code", code),
                ("redirect_uri", REDIRECT_URI),
            ])
            .send()?;
        if !response.status().is_success() {
            return Err(Error::Message(format!(
                "Invalid HTTP response received: {}",
                response.status()
            )));
        }

        let body: serde_json::Value = response.json()?;
        let token = body["access_token"]
            .as_str()
            .ok_or_else(|| Error::Message("No access token in the response!".into()))?
            .to_owned();
        let Claims { hc_id, names, region_claim } = read_claims(&token)?;

        Ok(Self { http, region, token, hc_id, claim_names: names, region_claim })
    }

    /// Every real appliance on the account, with its encryption material.
    ///
    /// Demo appliances are dropped: they support neither encryption nor local
    /// communication, so a profile for one is a file that cannot work.
    /// `note` is called for anything worth telling the user about but not worth
    /// stopping for.
    pub fn appliances(&self, note: &dyn Fn(String)) -> Result<Vec<Appliance>> {
        let response = self
            .http
            .get(format!(
                "{}/api/account/v2/accounts/{}/paired-appliances",
                self.region.asset_base(),
                self.hc_id
            ))
            .bearer_auth(&self.token)
            .header("Accept", "application/json")
            .send()?;
        // The one status worth naming: the account exists, but not in the
        // region that was asked.
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Error::WrongRegion);
        }
        if !response.status().is_success() {
            return Err(Error::Status(response.status()));
        }

        let body: serde_json::Value = response.json()?;
        let listed = body["appliances"].as_array().cloned().unwrap_or_default();
        if listed.is_empty() {
            return Err(Error::NoAppliances);
        }

        let real: Vec<&serde_json::Value> =
            listed.iter().filter(|a| a["isDemo"] != serde_json::Value::Bool(true)).collect();
        if real.is_empty() {
            return Err(Error::OnlyDemoAppliances);
        }
        if real.len() < listed.len() {
            note(format!("Filtered out {} demo appliance(s).", listed.len() - real.len()));
        }

        // What the endpoint offers, as against what we read. Names only; the
        // values are the account. Printed once rather than per appliance,
        // because they are the same shape.
        if let Some(names) = field_names(real[0]) {
            note(format!("The appliance list offers: {names}"));
        }

        let mut appliances = Vec::with_capacity(real.len());
        for entry in real {
            let text = |key: &str| entry[key].as_str().unwrap_or_default().to_owned();
            let ha_id = text("haId");
            if ha_id.is_empty() {
                note("Skipping an appliance with no haId.".into());
                continue;
            }

            // An appliance whose encryption cannot be read is still worth
            // listing: the caller decides what to do with one, and stopping the
            // whole download over it would lose the others.
            let encryption = match self.encryption(&ha_id, note) {
                Ok(encryption) => encryption,
                Err(error) => {
                    note(format!("Could not fetch encryption data for {ha_id}: {error}"));
                    None
                }
            };

            appliances.push(Appliance {
                ha_id,
                ha_type: text("haType"),
                serial_number: text("serialNumber"),
                brand: text("brand"),
                vib: text("vib"),
                mac: text("mac"),
                name: text("name"),
                e_number: text("eNumber"),
                ddf_version: entry["ddfVersion"].as_u64(),
                encryption,
            });
        }

        Ok(appliances)
    }

    fn encryption(&self, ha_id: &str, note: &dyn Fn(String)) -> Result<Option<Encryption>> {
        let response = self
            .http
            .get(format!(
                "{}/api/appliance/v2/appliances/{ha_id}/encryption-information",
                self.region.asset_base()
            ))
            .bearer_auth(&self.token)
            .header("Accept", "application/json")
            .send()?;
        if !response.status().is_success() {
            return Err(Error::Status(response.status()));
        }

        let body: serde_json::Value = response.json()?;
        if let Some(names) = field_names(&body) {
            note(format!("The encryption data offers: {names}"));
        }
        let tls = body["tls"]["key"].as_str().map(str::to_owned);
        let aes = match (body["aes"]["key"].as_str(), body["aes"]["iv"].as_str()) {
            (Some(key), Some(iv)) => Some((key.to_owned(), iv.to_owned())),
            _ => None,
        };
        Ok(Encryption::from_parts(tls, aes))
    }

    /// The zip Home Connect keeps for an appliance: the two XML documents, and
    /// whatever else it feels like including.
    pub fn appliance_archive(&self, ha_id: &str) -> Result<Vec<u8>> {
        let response = self
            .http
            .get(format!("{}/api/iddf/v1/iddf/{ha_id}", self.region.asset_base()))
            .bearer_auth(&self.token)
            .send()?;
        if !response.status().is_success() {
            return Err(Error::Status(response.status()));
        }
        Ok(response.bytes()?.to_vec())
    }
}

struct Claims {
    hc_id: String,
    names: Vec<String>,
    region_claim: Option<String>,
}

/// The keys of a JSON object, in one line, so a run can say what an endpoint
/// offered rather than only what we took from it.
///
/// A key holding an object is written as `name{a, b}`, because the useful
/// question is usually one level down: `tls` alone says nothing, `tls{key,
/// certificate}` says what is there.
fn field_names(value: &serde_json::Value) -> Option<String> {
    let object = value.as_object()?;
    let mut names = Vec::with_capacity(object.len());
    for (key, value) in object {
        match value.as_object() {
            Some(inner) if !inner.is_empty() => names
                .push(format!("{key}{{{}}}", inner.keys().cloned().collect::<Vec<_>>().join(", "))),
            _ => names.push(key.clone()),
        }
    }
    Some(names.join(", "))
}

/// The account id is the token's `sub` claim, returned with the names of every
/// other claim and the value of the one that names the region.
///
/// Nothing here verifies the signature, and neither did the Electron version
/// (main.js:206): the token came from the endpoint we just spoke to over TLS,
/// and it is handed straight back to the same service.
fn read_claims(token: &str) -> Result<Claims> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| Error::Message("The access token is not a JWT!".into()))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|error| Error::Message(format!("Could not decode the token payload: {error}")))?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded)
        .map_err(|error| Error::Message(format!("Could not read the token payload: {error}")))?;
    let names =
        claims.as_object().map(|object| object.keys().cloned().collect()).unwrap_or_default();
    let hc_id = claims["sub"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::Message("No account id in the token!".into()))?;
    // Two spellings of the same thing. This account's token calls it `region`;
    // logs from another user's account call it `x-reg`. Whichever is present.
    let region_claim =
        claims["region"].as_str().or_else(|| claims["x-reg"].as_str()).map(str::to_owned);
    Ok(Claims { hc_id, names, region_claim })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    fn token_with(payload: &str) -> String {
        format!("header.{}.signature", URL_SAFE_NO_PAD.encode(payload))
    }

    #[test]
    fn the_account_id_comes_out_of_the_token() {
        let token = token_with(r#"{"sub":"ABCDEF0123","iss":"home-connect"}"#);
        let claims = read_claims(&token).unwrap();
        assert_eq!(claims.hc_id, "ABCDEF0123");
        assert_eq!(claims.names, ["sub", "iss"]);
        assert_eq!(claims.region_claim, None);
    }

    #[test]
    fn the_region_claim_is_kept_when_the_token_carries_one() {
        // The claim list a real European sign-in showed, shortened.
        let token = token_with(r#"{"clty":"a","sub":"X","region":"EU","scope":"b"}"#);
        let claims = read_claims(&token).unwrap();
        assert_eq!(claims.region_claim.as_deref(), Some("EU"));
        assert!(claims.names.contains(&"region".to_owned()));
    }

    #[test]
    fn the_other_spelling_of_the_claim_is_read_too() {
        // Seen in another account's logs, where the region arrives as `x-reg`.
        let token = token_with(r#"{"sub":"X","x-reg":"NA"}"#);
        assert_eq!(read_claims(&token).unwrap().region_claim.as_deref(), Some("NA"));
    }

    #[test]
    fn region_wins_over_x_reg_when_a_token_carries_both() {
        // No token has been seen with both. If one turns up, the claim this
        // account's own token uses is the one to believe.
        let token = token_with(r#"{"sub":"X","region":"EU","x-reg":"NA"}"#);
        assert_eq!(read_claims(&token).unwrap().region_claim.as_deref(), Some("EU"));
    }

    #[test]
    fn a_token_without_a_subject_is_an_error_rather_than_an_empty_id() {
        let token = token_with(r#"{"iss":"home-connect"}"#);
        assert!(read_claims(&token).is_err());
    }

    #[test]
    fn field_names_open_one_level_of_nesting() {
        let value = serde_json::json!({
            "haId": "X",
            "tls": { "key": "k", "certificate": "c" },
            "aes": {},
            "isDemo": false
        });
        // The order is the document's, not the alphabet's: serde_json runs
        // with preserve_order here, so this reports what the endpoint sent in
        // the order it sent it.
        assert_eq!(field_names(&value).unwrap(), "haId, tls{key, certificate}, aes, isDemo");
    }

    #[test]
    fn field_names_of_something_that_is_not_an_object() {
        assert_eq!(field_names(&serde_json::json!([1, 2])), None);
    }

    #[test]
    fn something_that_is_not_a_jwt_is_rejected() {
        assert!(read_claims("not-a-token").is_err());
    }
}
