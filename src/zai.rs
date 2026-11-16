//! Local ZCode Coding Plan usage, independent of ZCode's running process.
//! Never print credentials, decrypted plaintext or server response bodies.
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::models::{UsageData, UsageSection};
use crate::poller::PollError;

const QUOTA_URL: &str = "https://api.z.ai/api/monitor/usage/quota/limit";
const CREDENTIAL_SUFFIX: &str = ":api-key";
const CREDENTIAL_ACCOUNT: &str = "zai-individual-coding-plan";
const ENCRYPTED_PREFIX: &str = "enc:v1:";
const SYSTEM_PREFIX: &str = "enc:v2:";
const SYSTEM_SERVICE: &str = "ZCode Credential Encryption";

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

// Shared v1/v2 AES-GCM envelope: base64url(iv12).base64url(tag16).base64url(ciphertext).
fn decrypt_envelope(payload: &str, key: &[u8]) -> Result<Zeroizing<String>, PollError> {
    if key.len() != 32 {
        return Err(PollError::AuthRequired);
    }
    let mut parts = payload.split('.');
    let iv = b64url_decode(parts.next().ok_or(PollError::AuthRequired)?)
        .ok_or(PollError::AuthRequired)?;
    let tag = b64url_decode(parts.next().ok_or(PollError::AuthRequired)?)
        .ok_or(PollError::AuthRequired)?;
    let mut encrypted = b64url_decode(parts.next().ok_or(PollError::AuthRequired)?)
        .ok_or(PollError::AuthRequired)?;
    if parts.next().is_some() || iv.len() != 12 || tag.len() != 16 {
        encrypted.zeroize();
        return Err(PollError::AuthRequired);
    }

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| PollError::AuthRequired)?;
    if cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&iv),
            b"",
            &mut encrypted,
            Tag::from_slice(&tag),
        )
        .is_err()
    {
        encrypted.zeroize();
        return Err(PollError::AuthRequired);
    }
    let text = match String::from_utf8(encrypted) {
        Ok(text) => Zeroizing::new(text),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            return Err(PollError::AuthRequired);
        }
    };
    // Manual Coding Plan API keys are two dot-separated components.
    if text.split('.').count() != 2 || text.is_empty() {
        return Err(PollError::AuthRequired);
    }
    Ok(text)
}

// Legacy ZCode credentials: SHA-256 of the configured or account-specific fallback secret.
fn decode_credential(
    stored: &str,
    home: &str,
    user: &str,
    custom: Option<&str>,
) -> Result<Zeroizing<String>, PollError> {
    let encoded = stored
        .strip_prefix(ENCRYPTED_PREFIX)
        .ok_or(PollError::AuthRequired)?;
    let secret = Zeroizing::new(
        custom
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.trim().to_owned())
            .unwrap_or_else(|| format!("zcode-credential-fallback:win32:{home}:{user}")),
    );
    let mut key = Sha256::digest(secret.as_bytes());
    let result = decrypt_envelope(encoded, &key);
    key.fill(0);
    result
}

// ZCode 3.18+ uses enc:v2:os:<keyId>:<payload>. keyId is the first 24 hex
// characters of SHA-256 of the raw 32-byte key stored in Windows Credential Manager.
fn decode_v2_credential(stored: &str, key: &[u8]) -> Result<Zeroizing<String>, PollError> {
    let encoded = stored
        .strip_prefix(SYSTEM_PREFIX)
        .ok_or(PollError::AuthRequired)?;
    let mut parts = encoded.split(':');
    let source = parts.next().ok_or(PollError::AuthRequired)?;
    let fingerprint = parts.next().ok_or(PollError::AuthRequired)?;
    let payload = parts.next().ok_or(PollError::AuthRequired)?;
    if source != "os"
        || parts.next().is_some()
        || fingerprint.len() != 24
        || !fingerprint.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || key.len() != 32
    {
        return Err(PollError::AuthRequired);
    }
    let digest = Sha256::digest(key);
    if !format!("{digest:x}").starts_with(fingerprint) {
        return Err(PollError::AuthRequired);
    }
    decrypt_envelope(payload, key)
}

// Exact @napi-rs/keyring Windows entry identity used by ZCode:
//   service = "ZCode Credential Encryption"
//   username = hex(SHA-256(Node path.resolve(credentials.json)))
//   Windows generic credential target = "<username>.<service>".
fn system_credential_target(path: &Path) -> Result<String, PollError> {
    let path = path.to_str().ok_or(PollError::AuthRequired)?;
    let digest = Sha256::digest(path.as_bytes());
    Ok(format!("{digest:x}.{SYSTEM_SERVICE}"))
}

fn read_windows_system_key(path: &Path) -> Result<Zeroizing<Vec<u8>>, PollError> {
    use windows::core::PCWSTR;
    use windows::Win32::Security::Credentials::{
        CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC,
    };

    let target = system_credential_target(path)?;
    let target_wide: Vec<u16> = target.encode_utf16().chain(std::iter::once(0)).collect();
    let mut credential: *mut CREDENTIALW = std::ptr::null_mut();
    // Read ONLY the expected generic credential under the current Windows logon.
    unsafe {
        CredReadW(
            PCWSTR(target_wide.as_ptr()),
            CRED_TYPE_GENERIC,
            0,
            &mut credential,
        )
        .map_err(|_| PollError::AuthRequired)?;
        if credential.is_null() {
            return Err(PollError::AuthRequired);
        }

        // Erase the OS-allocated password blob before freeing the CredRead result.
        struct CredentialGuard(*mut CREDENTIALW);
        impl Drop for CredentialGuard {
            fn drop(&mut self) {
                unsafe {
                    let credential = &mut *self.0;
                    if credential.CredentialBlobSize != 0 && !credential.CredentialBlob.is_null() {
                        std::slice::from_raw_parts_mut(
                            credential.CredentialBlob,
                            credential.CredentialBlobSize as usize,
                        )
                        .zeroize();
                    }
                    CredFree(self.0.cast());
                }
            }
        }
        let _guard = CredentialGuard(credential);
        let record = &*credential;
        // @napi-rs/keyring setPassword stores a 43-character base64url string
        // as UTF-16LE (without a NUL terminator), not raw key bytes.
        if record.Type != CRED_TYPE_GENERIC
            || record.CredentialBlobSize != 86
            || record.CredentialBlob.is_null()
        {
            return Err(PollError::AuthRequired);
        }
        let bytes = std::slice::from_raw_parts(record.CredentialBlob, 86);
        let mut encoded = Zeroizing::new(String::with_capacity(43));
        for pair in bytes.chunks_exact(2) {
            let unit = u16::from_le_bytes([pair[0], pair[1]]);
            let byte = u8::try_from(unit).map_err(|_| PollError::AuthRequired)?;
            if !(byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_') {
                return Err(PollError::AuthRequired);
            }
            encoded.push(char::from(byte));
        }
        let key = Zeroizing::new(b64url_decode(&encoded).ok_or(PollError::AuthRequired)?);
        if key.len() != 32 {
            return Err(PollError::AuthRequired);
        }
        Ok(key)
    }
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

fn classify_quota_transport_error(error: ureq::Error) -> PollError {
    match error {
        ureq::Error::Status(401 | 403, _) => PollError::AuthRequired,
        ureq::Error::Status(429, response) => PollError::RateLimited(
            response
                .header("Retry-After")
                .and_then(|hint| crate::retry_after::delay_ms(hint, std::time::SystemTime::now())),
        ),
        ureq::Error::Status(500..=599, _) => PollError::ServerError,
        ureq::Error::Transport(_) => PollError::NetworkUnavailable,
        _ => PollError::RequestFailed,
    }
}

pub fn poll_zai() -> Result<UsageData, PollError> {
    let stored = read_encrypted_key()?;
    let key = if stored.starts_with("enc:v2:os:") {
        let path = credentials_path().ok_or(PollError::NoCredentials)?;
        let system_key = read_windows_system_key(&path)?;
        decode_v2_credential(&stored, &system_key)?
    } else {
        let home = dirs::home_dir().ok_or(PollError::NoCredentials)?;
        let home = home.to_str().ok_or(PollError::AuthRequired)?;
        let user = std::env::var("USERNAME").map_err(|_| PollError::AuthRequired)?;
        let custom = std::env::var("ZCODE_CREDENTIAL_SECRET").ok();
        decode_credential(&stored, home, &user, custom.as_deref())?
    };
    // Match the existing providers: ureq is built without default TLS features,
    // so HTTPS requires the native Windows TLS connector configured in build_agent.
    let agent = crate::poller::build_agent()?;
    // Keep both plaintext key and Authorization header in zeroizing buffers.
    let mut auth = Zeroizing::new(String::from("Bearer "));
    auth.push_str(key.as_str());
    let response = agent
        .get(QUOTA_URL)
        .set("Authorization", auth.as_str())
        .call()
        .map_err(classify_quota_transport_error)?;
    // Drop the decrypted API key as soon as the request has been made.
    drop(auth);
    drop(key);
    let payload: QuotaEnvelope = response.into_json().map_err(|_| PollError::RequestFailed)?;
    parse_quota(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode64(bytes: &[u8]) -> String {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
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

    #[test]
    fn accepts_valid_v2_os_credential_and_rejects_wrong_key_id() {
        let key = [42u8; 32];
        let iv = [7u8; 12];
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let mut plaintext = b"part1.part2".to_vec();
        let tag = cipher
            .encrypt_in_place_detached(Nonce::from_slice(&iv), b"", &mut plaintext)
            .unwrap();
        let fingerprint = format!("{:x}", Sha256::digest(key));
        let payload = format!(
            "{}.{}.{}",
            encode64(&iv),
            encode64(&tag),
            encode64(&plaintext)
        );
        let stored = format!("enc:v2:os:{}:{}", &fingerprint[..24], payload);
        assert_eq!(decode_v2_credential(&stored, &key).unwrap().as_str(), "part1.part2");

        let wrong_key = [43u8; 32];
        assert_eq!(
            decode_v2_credential(&stored, &wrong_key).unwrap_err(),
            PollError::AuthRequired
        );
        assert_eq!(
            decode_v2_credential(&stored.replace(":os:", ":env:"), &key).unwrap_err(),
            PollError::AuthRequired
        );
        assert_eq!(
            decode_v2_credential(&stored.replace(":os:", ":unexpected:"), &key).unwrap_err(),
            PollError::AuthRequired
        );
        assert_eq!(
            decode_v2_credential(&stored.replace(&fingerprint[..24], "not-a-key-id"), &key)
                .unwrap_err(),
            PollError::AuthRequired
        );

        let mut tampered = tag.to_vec();
        tampered[0] ^= 1;
        let bad_payload = format!(
            "{}.{}.{}",
            encode64(&iv),
            encode64(&tampered),
            encode64(&plaintext)
        );
        let bad = format!("enc:v2:os:{}:{}", &fingerprint[..24], bad_payload);
        assert_eq!(
            decode_v2_credential(&bad, &key).unwrap_err(),
            PollError::AuthRequired
        );
    }

    #[test]
    fn system_key_target_uses_zcode_service_and_file_path_hash() {
        let path = Path::new(r"C:\Users\Demo\.zcode\v2\credentials.json");
        let target = system_credential_target(path).unwrap();
        assert!(target.ends_with(".ZCode Credential Encryption"));
        assert_eq!(target.split('.').next().unwrap().len(), 64);
    }

    #[test]
    fn preserves_retry_after_window_from_rate_limit_responses() {
        let response: ureq::Response = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 180\r\n\r\n"
            .parse()
            .unwrap();
        let err = ureq::Error::Status(429, response);
        assert_eq!(classify_quota_transport_error(err), PollError::RateLimited(Some(180_000)));
    }

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
    fn zero_used_with_no_reset_time_is_a_real_zai_quota_value() {
        let payload: QuotaEnvelope = serde_json::from_str(
            r#"{
                "code": 200, "success": true, "data": { "limits": [
                    {"type": "CREDIT_LIMIT", "unit": 3, "percentage": 0},
                    {"type": "CREDIT_LIMIT", "unit": 6, "percentage": 97}
                ]}
            }"#,
        )
        .unwrap();
        let data = parse_quota(payload).unwrap();
        assert_eq!(data.session.percentage, 0.0);
        assert!(data.session.resets_at.is_none());
        assert_eq!(data.weekly.percentage, 97.0);
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
            decode_credential(&stored, "C:\\Users\\Demo", "Demo", None)
                .unwrap()
                .as_str(),
            "part1.part2"
        );
    }
}
