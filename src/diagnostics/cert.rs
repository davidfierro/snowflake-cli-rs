//! The certificate fields the diagnostics report, read from a DER certificate.

use x509_parser::extensions::{DistributionPointName, GeneralName, ParsedExtension};
use x509_parser::oid_registry as oids;
use x509_parser::prelude::{FromDer, X509Certificate, X509Name};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    /// `(short name, value)` pairs in certificate order; a repeated name keeps its first
    /// position and its last value (Python builds a `dict` from the components).
    pub subject: Vec<(String, String)>,
    pub issuer: Vec<(String, String)>,
    pub serial: String,
    /// pyOpenSSL's `get_version()`: 2 for X.509 v3.
    pub version: u32,
    /// Python's `str(datetime)`: `2025-01-01 00:00:00`.
    pub not_before: String,
    pub not_after: String,
    /// OpenSSL's text of the extension: `DNS:a.com, DNS:b.com`.
    pub subject_alt_name: Option<String>,
    /// URLs of `authorityInfoAccess`; `None` when the extension is missing.
    pub authority_info_urls: Option<Vec<String>>,
    /// URLs of `crlDistributionPoints`; `None` when the extension is missing.
    pub crl_urls: Option<Vec<String>>,
}

fn short_name(oid: &x509_parser::der_parser::oid::Oid<'_>) -> String {
    let known = [
        (oids::OID_X509_COMMON_NAME, "CN"),
        (oids::OID_X509_COUNTRY_NAME, "C"),
        (oids::OID_X509_ORGANIZATION_NAME, "O"),
        (oids::OID_X509_ORGANIZATIONAL_UNIT, "OU"),
        (oids::OID_X509_STATE_OR_PROVINCE_NAME, "ST"),
        (oids::OID_X509_LOCALITY_NAME, "L"),
        (oids::OID_X509_SERIALNUMBER, "serialNumber"),
        (oids::OID_PKCS9_EMAIL_ADDRESS, "emailAddress"),
    ];
    known
        .iter()
        .find(|(known_oid, _)| known_oid == oid)
        .map_or_else(|| oid.to_string(), |(_, name)| (*name).to_string())
}

fn components(name: &X509Name<'_>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for attr in name.iter_attributes() {
        let key = short_name(attr.attr_type());
        let value = attr.as_str().unwrap_or_default().to_string();
        match out.iter_mut().find(|(k, _)| *k == key) {
            Some(existing) => existing.1 = value,
            None => out.push((key, value)),
        }
    }
    out
}

/// `strftime` of a Unix time in UTC; `""` for a time out of range.
fn format_time(seconds: i64, pattern: &str) -> String {
    jiff::Timestamp::from_second(seconds)
        .map(|t| t.strftime(pattern).to_string())
        .unwrap_or_default()
}

fn general_name_text(name: &GeneralName<'_>) -> Option<String> {
    match name {
        GeneralName::DNSName(d) => Some(format!("DNS:{d}")),
        GeneralName::RFC822Name(e) => Some(format!("email:{e}")),
        GeneralName::URI(u) => Some(format!("URI:{u}")),
        GeneralName::IPAddress(bytes) => match bytes.len() {
            4 => Some(format!(
                "IP Address:{}",
                std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
            )),
            16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(bytes);
                Some(format!("IP Address:{}", std::net::Ipv6Addr::from(octets)))
            }
            _ => None,
        },
        _ => None,
    }
}

fn http_urls<'a>(names: impl Iterator<Item = &'a GeneralName<'a>>) -> Vec<String> {
    names
        .filter_map(|n| match n {
            GeneralName::URI(u) if u.starts_with("http://") || u.starts_with("https://") => {
                Some(u.to_string())
            }
            _ => None,
        })
        .collect()
}

pub fn parse(der: &[u8]) -> Option<CertInfo> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let mut info = CertInfo {
        subject: components(cert.subject()),
        issuer: components(cert.issuer()),
        serial: String::new(),
        version: cert.version().0,
        not_before: format_time(cert.validity().not_before.timestamp(), "%Y-%m-%d %H:%M:%S"),
        not_after: format_time(cert.validity().not_after.timestamp(), "%Y-%m-%d %H:%M:%S"),
        subject_alt_name: None,
        authority_info_urls: None,
        crl_urls: None,
    };
    info.serial = decimal_serial(cert.raw_serial());
    for ext in cert.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => {
                let parts: Vec<String> = san
                    .general_names
                    .iter()
                    .filter_map(general_name_text)
                    .collect();
                info.subject_alt_name = Some(parts.join(", "));
            }
            ParsedExtension::AuthorityInfoAccess(aia) => {
                info.authority_info_urls = Some(http_urls(
                    aia.accessdescs.iter().map(|d| &d.access_location),
                ));
            }
            ParsedExtension::CRLDistributionPoints(points) => {
                let names = points
                    .points
                    .iter()
                    .filter_map(|p| match &p.distribution_point {
                        Some(DistributionPointName::FullName(names)) => Some(names),
                        _ => None,
                    });
                info.crl_urls = Some(http_urls(names.flatten()));
            }
            _ => {}
        }
    }
    Some(info)
}

/// The big-endian bytes of a serial number as a decimal string.
fn decimal_serial(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = vec![0];
    for byte in bytes {
        let mut carry = u32::from(*byte);
        for d in digits.iter_mut() {
            let v = u32::from(*d) * 256 + carry;
            *d = (v % 10) as u8;
            carry = v / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits.iter().rev().map(|d| char::from(b'0' + d)).collect()
}

/// snow's endpoint check: the issuer's `organizationName` and `notAfter` as Python's
/// `getpeercert()` prints it (`Jun  5 12:00:00 2026 GMT`).
pub fn issuer_org_and_expiry(der: &[u8]) -> (Option<String>, Option<String>) {
    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        return (None, None);
    };
    let org = cert
        .issuer()
        .iter_organization()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(str::to_string);
    let expiry = format_time(
        cert.validity().not_after.timestamp(),
        "%b %e %H:%M:%S %Y GMT",
    );
    (org, Some(expiry).filter(|e| !e.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_serial_converts_big_endian_bytes() {
        assert_eq!(decimal_serial(&[0x01, 0x00]), "256");
        assert_eq!(decimal_serial(&[0x00]), "0");
        assert_eq!(decimal_serial(&[0xff; 9]), "4722366482869645213695");
    }

    #[test]
    fn the_fixture_certificate_is_read_field_by_field() {
        let info = parse(&crate::diagnostics::testing::leaf_der()).unwrap();
        let pairs = |p: &[(String, String)]| -> Vec<(String, String)> { p.to_vec() };
        assert_eq!(
            pairs(&info.subject),
            [
                ("C", "US"),
                ("ST", "California"),
                ("O", "Snowflake Inc."),
                ("CN", "*.snowflakecomputing.com")
            ]
            .map(|(k, v)| (k.to_string(), v.to_string()))
        );
        assert_eq!(info.issuer.len(), 3);
        assert_eq!(info.version, 2);
        assert_eq!(info.not_before, "2026-11-21 14:37:00");
        assert_eq!(info.not_after, "2126-10-28 14:37:00");
        assert_eq!(
            info.serial,
            "220047411758230900080721827967644813597269925001"
        );
        assert_eq!(
            info.subject_alt_name.as_deref(),
            Some("DNS:*.snowflakecomputing.com, DNS:localhost, IP Address:127.0.0.1")
        );
        assert_eq!(
            info.authority_info_urls,
            Some(vec![
                "http://ocsp.test-ca.example/".to_string(),
                "http://crt.test-ca.example/ca.crt".to_string()
            ])
        );
        assert_eq!(
            info.crl_urls,
            Some(vec!["http://crl.test-ca.example/ca.crl".to_string()])
        );
        let (org, expiry) = issuer_org_and_expiry(&crate::diagnostics::testing::leaf_der());
        assert_eq!(org.as_deref(), Some("Amazon"));
        assert_eq!(expiry.as_deref(), Some("Oct 28 14:37:00 2126 GMT"));
    }

    #[test]
    fn general_names_are_written_as_openssl_does() {
        let v6 = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(
            general_name_text(&GeneralName::IPAddress(&v6)).as_deref(),
            Some("IP Address:::1")
        );
        assert_eq!(general_name_text(&GeneralName::IPAddress(&[1, 2])), None);
        assert_eq!(
            general_name_text(&GeneralName::RFC822Name("a@b.c")).as_deref(),
            Some("email:a@b.c")
        );
        assert_eq!(
            general_name_text(&GeneralName::URI("http://x")).as_deref(),
            Some("URI:http://x")
        );
        assert_eq!(
            general_name_text(&GeneralName::DirectoryName(
                x509_parser::prelude::X509Name::from_der(&[0x30, 0x00])
                    .unwrap()
                    .1
            )),
            None
        );
    }

    #[test]
    fn garbage_is_not_a_certificate() {
        assert!(parse(b"nope").is_none());
        assert_eq!(issuer_org_and_expiry(b"nope"), (None, None));
    }
}
