//! Local ZCode Coding Plan usage, independent of ZCode's running process.
//! Never print credentials, decrypted plaintext or server response bodies.
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::models::{UsageData, UsageSection};
use crate::poller::PollError;

const QUOTA_URL: &str = "https://api.z.ai/api/monitor/usage/quota/limit";
const CREDENTIAL_SUFFIX: &str = ":api-key";
const CREDENTIAL_ACCOUNT: &str = "zai-individual-coding-plan";
const ENCRYPTED_PREFIX: &str = "enc:v1:";

#[derive(Deserialize)]
struct QuotaEnvelope {
    code: Option<i64>,
    success: Option<bool>,
    data: Option<QuotaData>,
}

#[derive(Deserialize)]
struct QuotaData {
    limits: Vec<QuotaLimit>,
}

#[derive(Deserialize)]
struct QuotaLimit {
    #[serde(rename = "type")]
    kind: String,
    unit: i64,
    percentage: f64,
    #[serde(rename = "nextResetTime")]
    next_reset_time: Option<u64>,
}

fn credentials_path() -> Option<PathBuf> {
    Some(
        dirs::home_dir()?
            .join(".zcode")
            .join("v2")
            .join("credentials.json"),
    )
}

pub fn credential_watch_signature() -> String {
    let Some(path) = credentials_path() else {
        return "zai|missing".to_owned();
    };
    match std::fs::metadata(path) {
        Ok(meta) => {
            let modified = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok());
            format!("zai|{}|{:?}", meta.len(), modified)
        }
        Err(_) => "zai|missing".to_owned(),
    }
}

fn read_encrypted_key() -> Result<String, PollError> {
    let path = credentials_path().ok_or(PollError::NoCredentials)?;
    let bytes = std::fs::read(path).map_err(|_| PollError::NoCredentials)?;
    if bytes.len() > 256 * 1024 {
        return Err(PollError::RequestFailed);
    }
    let values: HashMap<String, String> =
        serde_json::from_slice(&bytes).map_err(|_| PollError::RequestFailed)?;
    let mut keys = values
        .iter()
        .filter(|(name, _)| name.contains(CREDENTIAL_ACCOUNT) && name.ends_with(CREDENTIAL_SUFFIX));
    let (_, key) = keys.next().ok_or(PollError::NoCredentials)?;
    if keys.next().is_some() {
        return Err(PollError::RequestFailed);
    }
    if !key.starts_with(ENCRYPTED_PREFIX) {
        return Err(PollError::AuthRequired);
    }
    Ok(key.clone())
}

fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    // Local encrypted envelope only: reject malformed input before decoding.
    if text.len() % 4 == 1 {
        return None;
    }
    let mut result = Vec::with_capacity(text.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for byte in text.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
            buffer &= (1u32 << bits) - 1;
        }
    }
    if bits != 0 && buffer != 0 {
        return None;
    }
    Some(result)
}

fn decode_credential(
    stored: &str,
    home: &str,
    user: &str,
    custom: Option<&str>,
) -> Result<String, PollError> {
    let encoded = stored
        .strip_prefix(ENCRYPTED_PREFIX)
        .ok_or(PollError::AuthRequired)?;
    let mut components = encoded.split('.');
    let iv = b64url_decode(components.next().ok_or(PollError::AuthRequired)?)
        .ok_or(PollError::AuthRequired)?;
    let tag = b64url_decode(components.next().ok_or(PollError::AuthRequired)?)
        .ok_or(PollError::AuthRequired)?;
    let mut encrypted = b64url_decode(components.next().ok_or(PollError::AuthRequired)?)
        .ok_or(PollError::AuthRequired)?;
    if components.next().is_some() || iv.len() != 12 || tag.len() != 16 {
        return Err(PollError::AuthRequired);
    }

    let secret = custom
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|| format!("zcode-credential-fallback:win32:{home}:{user}"));
    let mut key = Sha256::digest(secret.as_bytes());
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| PollError::AuthRequired)?;
    let result = cipher.decrypt_in_place_detached(
        Nonce::from_slice(&iv),
        b"",
        &mut encrypted,
        Tag::from_slice(&tag),
    );
    key.fill(0);
    if result.is_err() {
        encrypted.fill(0);
        return Err(PollError::AuthRequired);
    }
    let text = String::from_utf8(encrypted.clone()).map_err(|_| PollError::AuthRequired)?;
    encrypted.fill(0);
    // ZCode's decrypted account key has two dot-delimited parts.
    if text.split('.').count() != 2 || text.is_empty() {
        return Err(PollError::AuthRequired);
    }
    Ok(text)
}

fn section(limit: QuotaLimit) -> Result<UsageSection, PollError> {
    if !limit.percentage.is_finite() || !(0.0..=100.0).contains(&limit.percentage) {
        return Err(PollError::RequestFailed);
    }
    let resets_at = limit
        .next_reset_time
        .and_then(|ms| UNIX_EPOCH.checked_add(Duration::from_millis(ms)));
    Ok(UsageSection {
        percentage: limit.percentage,
        resets_at,
    })
}

fn parse_quota(body: QuotaEnvelope) -> Result<UsageData, PollError> {
    if body.code == Some(401) {
        return Err(PollError::AuthRequired);
    }
    if body.success != Some(true) || body.code != Some(200) {
        return Err(PollError::RequestFailed);
    }
    let data = body.data.ok_or(PollError::RequestFailed)?;
    let mut five_hour = None;
    let mut weekly = None;
    for limit in data.limits {
        if limit.kind != "CREDIT_LIMIT" && limit.kind != "TOKENS_LIMIT" {
            continue;
        }
        match limit.unit {
            3 if five_hour.is_none() => five_hour = Some(section(limit)?),
            6 if weekly.is_none() => weekly = Some(section(limit)?),
            _ => {}
        }
    }
    Ok(UsageData {
        session: five_hour.ok_or(PollError::RequestFailed)?,
        weekly: weekly.ok_or(PollError::RequestFailed)?,
    })
}

pub fn poll_zai() -> Result<UsageData, PollError> {
    let stored = read_encrypted_key()?;
    let home = dirs::home_dir().ok_or(PollError::NoCredentials)?;
    let home = home.to_str().ok_or(PollError::AuthRequired)?;
    let user = std::env::var("USERNAME").map_err(|_| PollError::AuthRequired)?;
    let custom = std::env::var("ZCODE_CREDENTIAL_SECRET").ok();
    let key = decode_credential(&stored, home, &user, custom.as_deref())?;
    // Match the existing providers: ureq is built without default TLS features,
    // so HTTPS requires the native Windows TLS connector configured in build_agent.
    let agent = crate::poller::build_agent()?;
    let response = agent
        .get(QUOTA_URL)
        .set("Authorization", &format!("Bearer {key}"))
        .call()
        .map_err(|error| match error {
            ureq::Error::Status(401 | 403, _) => PollError::AuthRequired,
            ureq::Error::Status(429, _) => PollError::RateLimited(None),
            ureq::Error::Status(500..=599, _) => PollError::ServerError,
            ureq::Error::Transport(_) => PollError::NetworkUnavailable,
            _ => PollError::RequestFailed,
        })?;
    // Drop the decrypted API key as soon as the request has been made.
    drop(key);
    let payload: QuotaEnvelope = response.into_json().map_err(|_| PollError::RequestFailed)?;
    parse_quota(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_realistic_credit_limits_by_window_unit() {
        let payload: QuotaEnvelope = serde_json::from_str(
            r#"{
            "code": 200, "success": true, "data": { "limits": [
                {"type":"CREDIT_LIMIT", "unit":6, "percentage":73, "remaining":2608,
                 "nextResetTime":1791974062984},
                {"type":"CREDIT_LIMIT", "unit":3, "percentage":28, "remaining":1431,
                 "nextResetTime":1791641989488}
            ]}}"#,
        )
        .unwrap();
        let data = parse_quota(payload).unwrap();
        assert_eq!(data.session.percentage, 28.0);
        assert_eq!(data.weekly.percentage, 73.0);
        assert!(data.session.resets_at.is_some());
    }

    #[test]
    fn rejects_body_auth_failure_even_when_http_is_ok() {
        let payload: QuotaEnvelope =
            serde_json::from_str(r#"{"code":401,"success":false}"#).unwrap();
        assert_eq!(parse_quota(payload).unwrap_err(), PollError::AuthRequired);
    }

    #[test]
    fn rejects_missing_weekly_instead_of_displaying_zero_usage() {
        let payload: QuotaEnvelope = serde_json::from_str(
            r#"{
            "code":200,"success":true,"data":{"limits":[
                {"type":"CREDIT_LIMIT","unit":3,"percentage":25}
            ]}}"#,
        )
        .unwrap();
        assert_eq!(parse_quota(payload).unwrap_err(), PollError::RequestFailed);
    }

    #[test]
    fn base64url_round_trip_parts() {
        assert_eq!(b64url_decode("AQIDBA"), Some(vec![1, 2, 3, 4]));
        assert_eq!(b64url_decode("AQIDBA=="), None);
    }

    #[test]
    fn decrypts_zcode_envelope_in_memory() {
        let secret = "zcode-credential-fallback:win32:C:\\Users\\Demo:Demo";
        let key = Sha256::digest(secret.as_bytes());
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let iv = [7u8; 12];
        let mut contents = b"part1.part2".to_vec();
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&iv), b"", &mut contents)
            .unwrap();
        fn url64(bytes: &[u8]) -> String {
            const CHARS: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            let mut result = String::new();
            let mut value = 0u32;
            let mut bits = 0;
            for &byte in bytes {
                value = (value << 8) | u32::from(byte);
                bits += 8;
                while bits >= 6 {
                    bits -= 6;
                    result.push(CHARS[((value >> bits) & 63) as usize] as char);
                    value &= (1 << bits) - 1;
                }
            }
            if bits > 0 {
                result.push(CHARS[(value << (6 - bits)) as usize] as char);
            }
            result
        }
        let stored = format!("enc:v1:{}.{}.{}", url64(&iv), url64(&tag), url64(&contents));
        assert_eq!(
            decode_credential(&stored, "C:\\Users\\Demo", "Demo", None).unwrap(),
            "part1.part2"
        );
    }
}
