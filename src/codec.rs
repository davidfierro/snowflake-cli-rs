//! Byte and text codecs shared by the signers, the form bodies and the SQL value conversion.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// Percent-encodes `text`: the RFC 3986 unreserved characters (`A-Za-z0-9-_.~`) and the bytes in
/// `safe` are kept, every other byte becomes uppercase `%XX`.
pub(crate) fn percent_encode(text: &str, safe: &[u8]) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || safe.contains(&byte)
        {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `application/x-www-form-urlencoded` value, as Python's `quote_plus`: a space becomes `+`.
pub(crate) fn form_encode_plus(text: &str) -> String {
    percent_encode(text, b" ").replace(' ', "+")
}

/// Lowercase hex of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The bytes of a hex string; `None` for an odd length, non-ASCII or non-hex input.
pub(crate) fn decode_hex(raw: &str) -> Option<Vec<u8>> {
    if !raw.len().is_multiple_of(2) || !raw.is_ascii() {
        return None;
    }
    (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).ok())
        .collect()
}

/// HMAC-SHA256 of `data` under `key`.
pub(crate) fn hmac_sha256(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC takes keys of any size"));
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_encode_keeps_unreserved_and_safe_bytes() {
        assert_eq!(percent_encode("a b/c+d~é", b""), "a%20b%2Fc%2Bd~%C3%A9");
        assert_eq!(percent_encode("a b/c+d~é", b"/"), "a%20b/c%2Bd~%C3%A9");
        assert_eq!(percent_encode("x_y.z-~AZ09", b""), "x_y.z-~AZ09");
    }

    #[test]
    fn form_encode_plus_is_quote_plus() {
        assert_eq!(form_encode_plus("My DB"), "My+DB");
        assert_eq!(form_encode_plus("a+b"), "a%2Bb");
        assert_eq!(form_encode_plus("a/b&c=d é"), "a%2Fb%26c%3Dd+%C3%A9");
    }

    #[test]
    fn hex_round_trips() {
        assert_eq!(hex(&[0x00, 0xab, 0xff]), "00abff");
        assert_eq!(decode_hex("00abFF"), Some(vec![0x00, 0xab, 0xff]));
        assert_eq!(decode_hex(&hex(&[1, 2, 254])), Some(vec![1, 2, 254]));
        assert_eq!(decode_hex(""), Some(vec![]));
    }

    #[test]
    fn decode_hex_rejects_invalid_input() {
        assert_eq!(decode_hex("abc"), None);
        assert_eq!(decode_hex("zz"), None);
        assert_eq!(decode_hex("é"), None);
    }

    #[test]
    fn hmac_sha256_matches_rfc_4231_case_2() {
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", "what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}
