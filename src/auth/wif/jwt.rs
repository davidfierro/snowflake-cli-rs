//! Reading JWT claims without verifying the signature (Snowflake verifies it), as the connector's
//! `extract_iss_and_sub_without_signature_verification` does with PyJWT.

use super::{INVALID_WIF_SETTINGS, WIF_CREDENTIALS_NOT_FOUND, WifError};
use base64::Engine;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::{DecodePaddingMode, general_purpose};

/// URL-safe base64, with or without padding (PyJWT's `base64url_decode`).
const URL_SAFE_ANY_PAD: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

fn invalid(why: &str) -> WifError {
    WifError::new(INVALID_WIF_SETTINGS, format!("Invalid JWT token: {why}"))
}

/// The claims of `token`, with PyJWT's error texts. Messages never include the token.
fn claims(token: &str) -> Result<serde_json::Map<String, serde_json::Value>, WifError> {
    let (signing_input, signature) = token
        .rsplit_once('.')
        .ok_or_else(|| invalid("Not enough segments"))?;
    let (header, payload) = signing_input
        .split_once('.')
        .ok_or_else(|| invalid("Not enough segments"))?;
    let header = URL_SAFE_ANY_PAD
        .decode(header)
        .map_err(|_| invalid("Invalid header padding"))?;
    match serde_json::from_slice::<serde_json::Value>(&header) {
        Ok(serde_json::Value::Object(_)) => {}
        Ok(_) => return Err(invalid("Invalid header string: must be a json object")),
        Err(_) => return Err(invalid("Invalid header string")),
    }
    let payload = URL_SAFE_ANY_PAD
        .decode(payload)
        .map_err(|_| invalid("Invalid payload padding"))?;
    URL_SAFE_ANY_PAD
        .decode(signature)
        .map_err(|_| invalid("Invalid crypto padding"))?;
    match serde_json::from_slice::<serde_json::Value>(&payload) {
        Ok(serde_json::Value::Object(map)) => Ok(map),
        Ok(_) => Err(invalid("Invalid payload string: must be a json object")),
        Err(_) => Err(invalid("Invalid payload string")),
    }
}

/// `iss` and `sub`, or the connector's error.
pub fn issuer_and_subject(token: &str) -> Result<(String, String), WifError> {
    let claims = claims(token)?;
    let text = |name: &str| {
        claims.get(name).map(|v| match v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
    };
    match (text("iss"), text("sub")) {
        (Some(iss), Some(sub)) => Ok((iss, sub)),
        _ => Err(WifError::new(
            WIF_CREDENTIALS_NOT_FOUND,
            "Token is missing 'iss' or 'sub' claims.",
        )),
    }
}

/// snow's `_is_expired_jwt`: a JWT whose numeric `exp` is at or before `deadline` (seconds since
/// the epoch). Anything else is not expired, and is used as given.
pub fn is_expired(token: &str, deadline: u64) -> bool {
    let Some(payload) = token.split('.').nth(1) else {
        return false;
    };
    let Ok(bytes) = general_purpose::URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .or_else(|_| URL_SAFE_ANY_PAD.decode(payload))
    else {
        return false;
    };
    let Ok(serde_json::Value::Object(claims)) = serde_json::from_slice(&bytes) else {
        return false;
    };
    claims
        .get("exp")
        .and_then(serde_json::Value::as_f64)
        .is_some_and(|exp| exp <= deadline as f64)
}

#[cfg(test)]
pub(crate) fn make(claims: &serde_json::Value) -> String {
    let enc = |v: &str| general_purpose::URL_SAFE_NO_PAD.encode(v);
    format!(
        "{}.{}.{}",
        enc(r#"{"alg":"RS256","typ":"JWT"}"#),
        enc(&claims.to_string()),
        enc("signature")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_iss_and_sub() {
        let token = make(&json!({"iss": "https://issuer", "sub": "workload", "exp": 1}));
        assert_eq!(
            issuer_and_subject(&token).unwrap(),
            ("https://issuer".to_string(), "workload".to_string())
        );
        // Padded segments are accepted too; a numeric claim reads as text.
        let padded = format!(
            "{}.{}.c2ln",
            general_purpose::URL_SAFE.encode("{}"),
            general_purpose::URL_SAFE.encode(r#"{"iss":"i","sub":7}"#)
        );
        assert_eq!(issuer_and_subject(&padded).unwrap().1, "7");
    }

    #[test]
    fn errors_are_pyjwt_s_and_never_hold_the_token() {
        let enc = |v: &str| general_purpose::URL_SAFE_NO_PAD.encode(v);
        let cases = [
            ("SECRET".to_string(), "Not enough segments"),
            ("SECRET.x".to_string(), "Not enough segments"),
            ("@@@.e30.c2ln".to_string(), "Invalid header padding"),
            (
                format!("{}.e30.c2ln", enc("SECRET")),
                "Invalid header string",
            ),
            (
                format!("{}.e30.c2ln", enc("[1]")),
                "Invalid header string: must be a json object",
            ),
            (format!("{}.@@@.c2ln", enc("{}")), "Invalid payload padding"),
            (format!("{}.e30.@@@", enc("{}")), "Invalid crypto padding"),
            (
                format!("{}.{}.c2ln", enc("{}"), enc("SECRET")),
                "Invalid payload string",
            ),
            (
                format!("{}.{}.c2ln", enc("{}"), enc("[]")),
                "Invalid payload string: must be a json object",
            ),
        ];
        for (token, why) in cases {
            let err = issuer_and_subject(&token).unwrap_err();
            assert_eq!(err.code, INVALID_WIF_SETTINGS, "{token}");
            assert_eq!(err.message, format!("Invalid JWT token: {why}"), "{token}");
        }
        let err = issuer_and_subject(&make(&json!({"iss": "i"}))).unwrap_err();
        assert_eq!(err.code, WIF_CREDENTIALS_NOT_FOUND);
        assert_eq!(err.message, "Token is missing 'iss' or 'sub' claims.");
    }

    #[test]
    fn expiry_as_snow_reads_it() {
        assert!(is_expired(&make(&json!({"exp": 100})), 100));
        assert!(is_expired(&make(&json!({"exp": 99.5})), 100));
        assert!(!is_expired(&make(&json!({"exp": 101})), 100));
        assert!(!is_expired(&make(&json!({"exp": "100"})), 100));
        assert!(!is_expired(&make(&json!({})), 100));
        assert!(!is_expired("opaque-token", 100));
        assert!(!is_expired("a.@@@.c", 100));
        assert!(!is_expired(
            &format!("a.{}.c", general_purpose::URL_SAFE_NO_PAD.encode("[]")),
            100
        ));
    }
}
