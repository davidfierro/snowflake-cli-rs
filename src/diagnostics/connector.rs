//! The report the Python connector writes when `enable_diag` is on
//! (`snowflake.connector.connection_diagnostic.ConnectionDiagnostic`): proxy hints, the account
//! host's certificate, the OCSP responders and, from the allowlist, the stage and telemetry
//! hosts. snow 3.34.0 relies on it for the first part of `SnowflakeConnectionTestReport.txt`.
//!
//! Not ported, because the SQL API client has no equivalent: tunnelling the probes through
//! `HTTPS_PROXY` (they connect directly), the Windows registry walk, and the HTTP body check of
//! the transparent-proxy test (a DNS lookup stands in for it).

use super::cert::{self, CertInfo};
use super::net::{NetError, Network, TlsFloor};
use super::{Query, py_list_repr};
use crate::env::Env;
use crate::output::result::py_str_repr;
use serde_json::Value;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const REPORT_FILENAME: &str = "SnowflakeConnectionTestReport.txt";
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const ALLOWLIST_SQL: &str =
    "select /* snowflake-connector-python:connection_diagnostics */ system$allowlist();";
const ALLOWLIST_PRIVATELINK_SQL: &str = "select system$allowlist_privatelink();";
const CERT_AUTHORITIES: [&str; 3] = [
    "C=US; O=Google Trust Services LLC",
    "C=US; O=Amazon",
    "C=US; O=DigiCert Inc",
];
const INVALID_HOST: &str = "nonexistentdomain.invalid";
const PROXY_TEST_HOST: &str = "www.google.com";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Initial,
    Proxy,
    SnowflakeUrl,
    Stage,
    Ocsp,
    Telemetry,
    Ignore,
}

#[derive(Debug, PartialEq, Eq)]
enum Probe {
    Cert(Vec<u8>),
    Success,
    Failed,
}

pub struct ConnectorDiag<'a> {
    net: &'a dyn Network,
    env: &'a Env,
    host: String,
    results: HashMap<usize, Vec<String>>,
    ocsp_urls: Vec<String>,
    crl_urls: Vec<String>,
    cert_info: HashMap<String, CertInfo>,
    report_file: PathBuf,
    allowlist_file: Option<PathBuf>,
    allowlist_sql: &'static str,
    allowlist_ok: bool,
}

/// The last label of `host` when it is letters only, else `com` (the connector's rule).
fn top_level_domain(host: &str) -> String {
    host.rsplit_once('.')
        .map(|(_, tld)| tld)
        .filter(|t| (1..=63).contains(&t.len()) && t.chars().all(|c| c.is_ascii_alphabetic()))
        .unwrap_or("com")
        .to_lowercase()
}

/// Python's `ipaddress.ip_address(ip).is_private` for IPv4.
fn is_private(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
        }
        _ => false,
    }
}

/// The proxy variables Python's `urllib.request.getproxies()` reads from the environment,
/// `{scheme: url}`; a lowercase variable wins over an uppercase one. Passwords in a proxy URL
/// are masked: the report is a file people attach to support tickets.
fn env_proxies(env: &Env) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let set = |out: &mut Vec<(String, String)>, key: String, value: Option<String>| {
        out.retain(|(k, _)| *k != key);
        if let Some(v) = value {
            out.push((key, v));
        }
    };
    for (name, value) in env.iter() {
        if let Some(scheme) = proxy_scheme(name)
            && !value.is_empty()
        {
            set(
                &mut out,
                scheme.to_lowercase(),
                Some(mask_proxy_password(value)),
            );
        }
    }
    for (name, value) in env.iter() {
        if let Some(scheme) = name.strip_suffix("_proxy") {
            let v = (!value.is_empty()).then(|| mask_proxy_password(value));
            set(&mut out, scheme.to_string(), v);
        }
    }
    out
}

/// `https` for `HTTPS_PROXY` or `https_proxy`, matching the suffix in any case.
fn proxy_scheme(name: &str) -> Option<&str> {
    let split = name.len().checked_sub("_proxy".len())?;
    let (scheme, suffix) = name.split_at_checked(split)?;
    suffix.eq_ignore_ascii_case("_proxy").then_some(scheme)
}

/// `http://user:secret@host:80` becomes `http://***@host:80`.
fn mask_proxy_password(url: &str) -> String {
    // The scheme is optional: `user:pw@proxy:3128` is a proxy URL to Python's urllib too.
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (format!("{scheme}://"), rest),
        None => (String::new(), url),
    };
    let Some((_, host)) = rest.rsplit_once('@') else {
        return url.to_string();
    };
    // The whole userinfo goes: a lone token (`http://<token>@proxy`) is a credential too.
    format!("{scheme}***@{host}")
}

fn dict_repr(pairs: &[(String, String)]) -> String {
    let items: Vec<String> = pairs
        .iter()
        .map(|(k, v)| format!("{}: {}", py_str_repr(k), py_str_repr(v)))
        .collect();
    format!("{{{}}}", items.join(", "))
}

/// The certificate's DN as `str()` shows pyOpenSSL's `dict(get_components())`: bytes keys and
/// values.
fn bytes_dict_repr(pairs: &[(String, String)]) -> String {
    let items: Vec<String> = pairs
        .iter()
        .map(|(k, v)| format!("b{}: b{}", py_str_repr(k), py_str_repr(v)))
        .collect();
    format!("{{{}}}", items.join(", "))
}

/// `__get_issuer_string`: `json.dumps` of the issuer without braces and quotes, `: ` → `=`,
/// `,` → `;`.
fn issuer_string(issuer: &[(String, String)]) -> String {
    let joined: Vec<String> = issuer.iter().map(|(k, v)| format!("{k}: {v}")).collect();
    joined
        .join(", ")
        .replace(['{', '}', '"'], "")
        .replace(": ", "=")
        .replace(',', ";")
}

fn authority_of(url: &str) -> Option<String> {
    url.split('/').nth(2).map(str::to_string)
}

impl<'a> ConnectorDiag<'a> {
    /// Creates the diagnostic and, as the connector does, probes `host` at once.
    pub fn new(
        net: &'a dyn Network,
        env: &'a Env,
        account: &str,
        host: &str,
        log_dir: &Path,
        allowlist_file: Option<PathBuf>,
    ) -> Self {
        let tld = top_level_domain(host);
        let mut diag = Self {
            net,
            env,
            host: host.to_string(),
            results: HashMap::new(),
            ocsp_urls: Vec::new(),
            crl_urls: Vec::new(),
            cert_info: HashMap::new(),
            report_file: log_dir.join(REPORT_FILENAME),
            allowlist_file,
            allowlist_sql: ALLOWLIST_SQL,
            allowlist_ok: false,
        };
        diag.add(
            Section::Initial,
            format!("Specified snowflake account: {account}"),
        );
        diag.add(
            Section::Initial,
            format!("Host based on specified account: {host}"),
        );
        if host.contains(&format!(".{tld}.snowflakecomputing.{tld}")) {
            let fixed = format!(
                "{}.{tld}",
                host.split_once(&format!(".{tld}.snow"))
                    .map_or(host, |s| s.0)
            );
            log::debug!(
                "Account should not have snowflakecomputing.{tld} in it. You provided {host}.  \
                 Continuing with fixed host."
            );
            diag.add(
                Section::Initial,
                format!(
                    "We removed extra .snowflakecomputing.{tld} and will continue with host: {fixed}"
                ),
            );
            diag.host = fixed;
        }
        let host = diag.host.clone();
        diag.https_host_report(&host, 443, Section::SnowflakeUrl);
        log::info!("Reporting to file {}", diag.report_file.display());
        if diag.is_privatelink() {
            diag.ocsp_urls.push(format!("ocsp.{}", diag.host));
            diag.allowlist_sql = ALLOWLIST_PRIVATELINK_SQL;
        } else {
            diag.ocsp_urls
                .push(format!("ocsp.snowflakecomputing.{tld}"));
        }
        diag
    }

    fn key(section: Section) -> usize {
        section as usize
    }

    fn label(section: Section) -> &'static str {
        match section {
            Section::Initial => "INITIAL",
            Section::Proxy => "PROXY",
            Section::SnowflakeUrl => "SNOWFLAKE_URL",
            Section::Stage => "STAGE",
            Section::Ocsp => "OCSP_RESPONDER",
            Section::Telemetry => "OUT_OF_BAND_TELEMETRY",
            Section::Ignore => "IGNORE",
        }
    }

    fn add(&mut self, section: Section, message: String) {
        let line = format!("{}: {message}", Self::label(section));
        self.results
            .entry(Self::key(section))
            .or_default()
            .push(line);
    }

    fn lines(&self, section: Section) -> String {
        self.results
            .get(&Self::key(section))
            .map(|l| l.join("\n"))
            .unwrap_or_default()
    }

    fn is_privatelink(&self) -> bool {
        self.host.contains("privatelink")
    }

    fn list_ips(&mut self, host: &str, section: Section) {
        let ips = match self.net.lookup(host) {
            Ok(ips) => ips,
            Err(e) => {
                log::debug!("Connectivity Test Exception in list_ips: {}", e.message());
                return;
            }
        };
        let base = format!("{host}: nslookup results");
        if !host.contains("snowflakecomputing") {
            self.add(section, format!("{base}: {}", py_list_repr(&ips)));
            return;
        }
        for ip in ips {
            if is_private(&ip) {
                if !self.is_privatelink() {
                    self.add(
                        section,
                        format!(
                            "{base}: private ip: {ip}: WARNING: this is not typical for a \
                             non-privatelink account"
                        ),
                    );
                }
            } else if self.is_privatelink() {
                self.add(
                    section,
                    format!(
                        "{base}: public ip: {ip}: WARNING: privatelink accounts must have a \
                         private ip."
                    ),
                );
            } else {
                self.add(section, format!("{base}: public ip: {ip}"));
            }
        }
    }

    /// `__test_socket_get_cert`.
    fn test_socket_get_cert(&mut self, host: &str, port: u16, section: Section) -> Probe {
        self.list_ips(host, section);
        if port == 443 {
            return match self
                .net
                .peer_cert(host, port, PROBE_TIMEOUT, TlsFloor::Tls12)
            {
                Ok(der) => Probe::Cert(der),
                Err(NetError::Tls(e)) => {
                    if e.contains("WRONG_VERSION_NUMBER") {
                        self.add(
                            section,
                            format!("{host}:{port}: URL Check: Failed: Proxy Auth Error: {e}"),
                        );
                    }
                    Probe::Failed
                }
                Err(NetError::Other(e)) => {
                    self.add(
                        section,
                        format!("{host}:{port}: URL Check: Failed: Unknown Exception: {e}"),
                    );
                    Probe::Failed
                }
            };
        }
        match self.net.http_get(host, port, PROBE_TIMEOUT) {
            Ok(response) => {
                let good = ["200", "301", "cloudfront"]
                    .iter()
                    .any(|needle| response.contains(needle));
                if good {
                    self.add(
                        section,
                        format!("{host}:{port}: URL Check: Connected Successfully"),
                    );
                    Probe::Success
                } else {
                    self.add(
                        section,
                        format!(
                            "{host}:{port}: URL Check: Failed: {}",
                            crate::render::sanitize::sanitize_for_terminal(&response)
                        ),
                    );
                    Probe::Failed
                }
            }
            Err(e) => {
                self.add(
                    section,
                    format!(
                        "{host}:{port}: URL Check: Failed: Unknown Exception: {}",
                        e.message()
                    ),
                );
                Probe::Failed
            }
        }
    }

    /// `__https_host_report`.
    fn https_host_report(&mut self, host: &str, port: u16, section: Section) {
        let Probe::Cert(der) = self.test_socket_get_cert(host, port, section) else {
            return;
        };
        let Some(info) = cert::parse(&der) else {
            log::debug!("Connectivity Test Exception in https_host_report: unreadable certificate");
            return;
        };
        let subject_repr = bytes_dict_repr(&info.subject);
        let host_suffix = host.split_once('.').map_or("", |(_, s)| s);
        if subject_repr.contains(host_suffix) {
            self.add(
                section,
                format!("{host}:{port}: URL Check: Connected Successfully"),
            );
        } else if let Some(san) = &info.subject_alt_name {
            if san.contains(host_suffix) {
                self.add(
                    section,
                    format!("{host}:{port}: URL Check: Connected Successfully"),
                );
            } else {
                self.add(
                    section,
                    format!(
                        "{host}:{port}: URL Check: Failed: Certificate mismatch: Host not in \
                         subject or alt names"
                    ),
                );
            }
        }
        self.add(section, format!("{host}: Cert info:"));
        self.add(
            section,
            format!("{host}: subject: {}", dict_repr(&info.subject)),
        );
        self.add(
            section,
            format!("{host}: issuer: {}", dict_repr(&info.issuer)),
        );
        self.add(section, format!("{host}: serialNumber: {}", info.serial));
        self.add(section, format!("{host}: version: {}", info.version));
        self.add(section, format!("{host}: notBefore: {}", info.not_before));
        self.add(section, format!("{host}: notAfter: {}", info.not_after));
        if section == Section::SnowflakeUrl {
            match &info.authority_info_urls {
                Some(urls) => self
                    .ocsp_urls
                    .extend(urls.iter().filter_map(|u| authority_of(u))),
                None => self.add(
                    Section::Initial,
                    "Unable to find ocsp URLs in certificate.".into(),
                ),
            }
            match &info.crl_urls {
                Some(urls) => self
                    .crl_urls
                    .extend(urls.iter().filter_map(|u| authority_of(u))),
                None => self.add(
                    Section::Ignore,
                    "Unable to find crl URLs in certificate.".into(),
                ),
            }
        }
        if let Some(san) = &info.subject_alt_name {
            self.add(section, format!("{host}: subjectAltName: {san}"));
        }
        self.add(
            section,
            format!("{host}: crlUrls: {}", py_list_repr(&self.crl_urls)),
        );
        self.add(
            section,
            format!("{host}: ocspURLs: {}", py_list_repr(&self.ocsp_urls)),
        );
        self.cert_info.insert(host.to_string(), info);
    }

    fn issuer_check(&mut self, host: &str) {
        let Some(info) = self.cert_info.get(host) else {
            return;
        };
        let issuer = issuer_string(&info.issuer);
        if !CERT_AUTHORITIES.iter().any(|ca| issuer.starts_with(ca)) {
            let expected =
                py_list_repr(&CERT_AUTHORITIES.map(String::from)).replace(['[', ']'], "");
            self.add(
                Section::Proxy,
                format!(
                    "There is likely a proxy because the issuer for {host} is not correct. \
                     Got {issuer} and expected one of ({expected})"
                ),
            );
        }
    }

    /// `__check_for_proxies`.
    fn check_for_proxies(&mut self) {
        // Linux has no system proxy settings: with the variables removed there is nothing left.
        self.add(
            Section::Proxy,
            "Proxies with Env vars removed(SYSTEM PROXIES): {}".into(),
        );
        let env_proxies = env_proxies(self.env);
        self.add(
            Section::Proxy,
            format!(
                "Proxies with Env vars restored(ENV PROXIES): {}",
                dict_repr(&env_proxies)
            ),
        );
        let host = self.host.clone();
        self.issuer_check(&host);
        self.https_host_report(PROXY_TEST_HOST, 443, Section::Ignore);
        self.issuer_check(PROXY_TEST_HOST);
        match self.net.lookup(INVALID_HOST) {
            Err(e) => self.add(
                Section::Proxy,
                format!(
                    "Could not determine if a proxy does or does not exist based on Exception: \
                     HTTPSConnectionPool(host='{INVALID_HOST}', port=443): Max retries exceeded \
                     with url: / (Caused by NameResolutionError(\"HTTPSConnection(\
                     host='{INVALID_HOST}', port=443): Failed to resolve '{INVALID_HOST}' ({})\"))",
                    e.message()
                ),
            ),
            Ok(_) => self.add(
                Section::Proxy,
                "It is likely there is a proxy based on HTTP response.".into(),
            ),
        }
    }

    /// `run_test`: the checks that need no session.
    pub fn run_test(&mut self) {
        self.check_for_proxies();
        let mut urls = self.ocsp_urls.clone();
        urls.sort();
        urls.dedup();
        self.ocsp_urls = urls.clone();
        for url in urls {
            self.test_socket_get_cert(&url, 80, Section::Ocsp);
        }
    }

    /// `run_post_test`: the allowlist, from the file or from `queries`, then its hosts.
    pub fn run_post_test(&mut self, queries: Option<&dyn Query>) {
        let mut allowlist: Option<Value> = None;
        match &self.allowlist_file {
            None => {
                if let Some(queries) = queries {
                    match self.query_allowlist(queries) {
                        Ok(v) => {
                            allowlist = Some(v);
                            self.allowlist_ok = true;
                        }
                        Err(e) => log::debug!("Unable to do allowlist checks: exception: {e}"),
                    }
                }
            }
            Some(path) => {
                match std::fs::read_to_string(path)
                    .map_err(|e| e.to_string())
                    .and_then(|t| serde_json::from_str::<Value>(&t).map_err(|e| e.to_string()))
                {
                    Ok(v) => {
                        allowlist = Some(v);
                        self.allowlist_ok = true;
                    }
                    Err(e) => self.add(
                        Section::Initial,
                        format!(
                            "Allowlist was not valid json: '{e}'.  Please run 'select \
                             system$allowlist();' and validate the file {} is correct.",
                            path.display()
                        ),
                    ),
                }
            }
        }
        let entries = allowlist.as_ref().and_then(|v| match v {
            Value::Array(items) if items.iter().all(Value::is_object) => Some(items),
            _ => None,
        });
        let Some(entries) = entries else {
            self.add(
                Section::Initial,
                "Allowlist is not a valid list of json objects. Please run 'select \
                 system$allowlist();' and provide as a json file using the \
                 connection_diag_allowlist_path option."
                    .into(),
            );
            return;
        };
        for entry in entries {
            let (Some(kind), Some(host), Some(port)) = (
                entry.get("type").and_then(Value::as_str),
                entry.get("host").and_then(Value::as_str),
                entry.get("port").and_then(|p| {
                    p.as_u64()
                        .or_else(|| p.as_str().and_then(|s| s.parse().ok()))
                        .and_then(|p| u16::try_from(p).ok())
                }),
            ) else {
                log::debug!("Skipping a malformed allowlist entry");
                continue;
            };
            match kind {
                "OCSP_RESPONDER" => {
                    if !self.ocsp_urls.iter().any(|u| u == host) {
                        self.test_socket_get_cert(host, port, Section::Ocsp);
                    }
                }
                "STAGE" => self.https_host_report(host, port, Section::Stage),
                "OUT_OF_BAND_TELEMETRY" => self.https_host_report(host, port, Section::Telemetry),
                _ => {}
            }
        }
    }

    fn query_allowlist(&self, queries: &dyn Query) -> Result<Value, String> {
        let rows = queries.rows(self.allowlist_sql)?;
        let text = rows
            .first()
            .and_then(|r| r.first())
            .and_then(|(_, v)| v.clone())
            .ok_or_else(|| "the allowlist query returned no rows".to_string())?;
        serde_json::from_str(&text).map_err(|e| e.to_string())
    }

    /// The text `generate_report` writes.
    pub fn report_text(&self) -> String {
        let mut message =
            "=========Connectivity diagnostic report================================".to_string();
        message = format!("{message}\n{}\n", self.lines(Section::Initial));
        message = format!(
            "{message}\n=========Proxy information - These are best guesses, not guarantees====\n{}\n",
            self.lines(Section::Proxy)
        );
        message = format!(
            "{message}\n=========Snowflake URL information=====================================\n{}\n",
            self.lines(Section::SnowflakeUrl)
        );
        if self.allowlist_ok {
            message = format!(
                "{message}\n=========Snowflake Stage information===================================\nWe retrieved stage info from the allowlist\n{}\n",
                self.lines(Section::Stage)
            );
        } else {
            message = format!(
                "{message}\n=========Snowflake Stage information - Unavailable=====================\nWe could not connect to Snowflake to get allowlist, so we do not have stage\ndiagnostic info\n"
            );
        }
        message = format!(
            "{message}\n=========Snowflake OCSP information===================================="
        );
        if self.allowlist_ok {
            message.push_str(
                "\nWe were able to retrieve system allowlist.\nThese OCSP hosts came from the certificate and the allowlist.",
            );
        } else {
            message.push_str(
                "\nWe were unable to retrieve system allowlist.\nThese OCSP hosts only came from the certificate.",
            );
        }
        message = format!("{message}\n{}\n", self.lines(Section::Ocsp));
        if self.allowlist_ok {
            message = format!(
                "{message}\n=========Snowflake Out of bound telemetry check========================\n{}\n",
                self.lines(Section::Telemetry)
            );
        }
        message
    }

    /// `generate_report`: overwrites the report file.
    pub fn generate_report(&self) -> std::io::Result<PathBuf> {
        let text = self.report_text();
        log::debug!("{text}");
        use std::io::Write;
        super::open_report(&self.report_file, false)?.write_all(text.as_bytes())?;
        Ok(self.report_file.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::{FakeNetwork, FakeQuery, fixture, leaf_der};
    use super::*;

    const HOST: &str = "acct.snowflakecomputing.com";

    fn ok_get() -> Result<&'static str, NetError> {
        Ok("HTTP/1.1 200 OK\r\n\r\n")
    }

    /// A network where everything works for the leaf certificate.
    fn healthy() -> FakeNetwork {
        FakeNetwork::default()
            .lookup(HOST, &["54.1.2.3"])
            .cert(HOST, 443, Ok(leaf_der()))
            .cert(PROXY_TEST_HOST, 443, Ok(leaf_der()))
            .get("ocsp.snowflakecomputing.com", 80, ok_get())
            .get("ocsp.test-ca.example", 80, ok_get())
            .get("crt.test-ca.example", 80, ok_get())
    }

    fn run(net: &FakeNetwork, allowlist: Option<PathBuf>, queries: Option<&dyn Query>) -> String {
        let env = Env::from_pairs([
            ("HTTPS_PROXY", "http://proxyuser:s3cret@proxy.corp:3128"),
            ("no_proxy", "localhost"),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let mut diag = ConnectorDiag::new(net, &env, "ACCT", HOST, dir.path(), allowlist);
        diag.run_test();
        diag.run_post_test(queries);
        let path = diag.generate_report().unwrap();
        assert_eq!(path, dir.path().join(REPORT_FILENAME));
        std::fs::read_to_string(path).unwrap()
    }

    fn write_allowlist(dir: &Path) -> PathBuf {
        let path = dir.join("allowlist.json");
        std::fs::write(
            &path,
            r#"[
              {"type":"SNOWFLAKE_DEPLOYMENT","host":"acct.snowflakecomputing.com","port":443},
              {"type":"OCSP_RESPONDER","host":"ocsp.snowflakecomputing.com","port":80},
              {"type":"OCSP_RESPONDER","host":"ocsp.other.example","port":80},
              {"type":"STAGE","host":"stage.snowflakecomputing.com","port":"443"},
              {"type":"OUT_OF_BAND_TELEMETRY","host":"telemetry.snowflakecomputing.com","port":443},
              {"type":"STAGE","port":443}
            ]"#,
        )
        .unwrap();
        path
    }

    #[test]
    fn report_with_an_allowlist_file_matches_the_connector_format() {
        let dir = tempfile::tempdir().unwrap();
        let net = healthy()
            .lookup("stage.snowflakecomputing.com", &["52.1.1.1", "52.2.2.2"])
            .cert("stage.snowflakecomputing.com", 443, Ok(leaf_der()))
            .cert("telemetry.snowflakecomputing.com", 443, Ok(leaf_der()))
            .get("ocsp.other.example", 80, Ok("HTTP/1.1 403 Forbidden"));
        let report = run(&net, Some(write_allowlist(dir.path())), None);
        let golden =
            std::fs::read_to_string(fixture("../../golden/diagnostics/connector_report.txt"))
                .unwrap();
        assert_eq!(report, golden);
    }

    #[test]
    fn report_without_an_allowlist_says_so() {
        let net = healthy();
        let report = run(&net, None, None);
        let golden = std::fs::read_to_string(fixture(
            "../../golden/diagnostics/connector_report_no_allowlist.txt",
        ))
        .unwrap();
        assert_eq!(report, golden);
    }

    #[test]
    fn the_allowlist_comes_from_system_allowlist_when_no_file_is_given() {
        let net = healthy()
            .cert("stage.snowflakecomputing.com", 443, Ok(leaf_der()))
            .cert("telemetry.snowflakecomputing.com", 443, Ok(leaf_der()));
        let queries = FakeQuery::default().answer(
            "select /* snowflake-connector-python:connection_diagnostics */ system$allowlist();",
            &[&[(
                "SYSTEM$ALLOWLIST()",
                Some(
                    r#"[{"type":"STAGE","host":"stage.snowflakecomputing.com","port":443},
                        {"type":"OUT_OF_BAND_TELEMETRY","host":"telemetry.snowflakecomputing.com","port":443}]"#,
                ),
            )]],
        );
        let report = run(&net, None, Some(&queries));
        assert!(
            report.contains("=========Snowflake Stage information===="),
            "{report}"
        );
        assert!(report.contains(
            "STAGE: stage.snowflakecomputing.com:443: URL Check: Connected Successfully"
        ));
        assert!(
            report.contains("OUT_OF_BAND_TELEMETRY: telemetry.snowflakecomputing.com: Cert info:")
        );
        assert_eq!(queries.asked().len(), 1);
    }

    #[test]
    fn a_failing_allowlist_query_leaves_the_stage_section_unavailable() {
        let queries = FakeQuery::default();
        let report = run(&healthy(), None, Some(&queries));
        assert!(report.contains("Snowflake Stage information - Unavailable"));
        assert!(report.contains("INITIAL: Allowlist is not a valid list of json objects."));
    }

    #[test]
    fn privatelink_accounts_use_the_privatelink_allowlist_and_responder() {
        let host = "acct.privatelink.snowflakecomputing.com";
        let net = FakeNetwork::default().lookup(host, &["10.0.0.5", "54.1.2.3"]);
        let env = Env::default();
        let dir = tempfile::tempdir().unwrap();
        let mut diag = ConnectorDiag::new(&net, &env, "ACCT", host, dir.path(), None);
        assert_eq!(diag.allowlist_sql, "select system$allowlist_privatelink();");
        assert_eq!(diag.ocsp_urls, vec![format!("ocsp.{host}")]);
        let text = diag.report_text();
        assert!(
            text.contains("nslookup results: public ip: 54.1.2.3: WARNING: privatelink accounts must have a private ip."),
            "{text}"
        );
        assert!(
            !text.contains("10.0.0.5"),
            "a private ip is expected for privatelink"
        );
        diag.run_post_test(None);
    }

    #[test]
    fn a_private_ip_is_a_warning_for_a_public_account() {
        let net = FakeNetwork::default().lookup(HOST, &["10.1.2.3"]);
        let env = Env::default();
        let diag = ConnectorDiag::new(&net, &env, "ACCT", HOST, Path::new("/nonexistent"), None);
        assert!(diag.report_text().contains(
            "acct.snowflakecomputing.com: nslookup results: private ip: 10.1.2.3: WARNING: this is not typical for a non-privatelink account"
        ));
    }

    #[test]
    fn a_repeated_domain_in_the_host_is_fixed() {
        let net = FakeNetwork::default();
        let env = Env::default();
        let diag = ConnectorDiag::new(
            &net,
            &env,
            "ACCT",
            "acct.com.snowflakecomputing.com",
            Path::new("/x"),
            None,
        );
        assert_eq!(diag.host, "acct.com");
        assert!(diag.report_text().contains(
            "INITIAL: We removed extra .snowflakecomputing.com and will continue with host: acct.com"
        ));
    }

    #[test]
    fn connection_failures_are_reported_not_raised() {
        let net = FakeNetwork::default()
            .cert(HOST, 443, Err(NetError::Tls("WRONG_VERSION_NUMBER".into())))
            .cert(
                PROXY_TEST_HOST,
                443,
                Err(NetError::Tls("certificate verify failed".into())),
            );
        let report = run(&net, None, None);
        assert!(report.contains(
            "SNOWFLAKE_URL: acct.snowflakecomputing.com:443: URL Check: Failed: Proxy Auth Error: WRONG_VERSION_NUMBER"
        ));
        // A TLS failure other than a wrong version leaves no trace in the report.
        assert!(!report.contains("certificate verify failed"));
        assert!(report.contains(
            "OCSP_RESPONDER: ocsp.snowflakecomputing.com:80: URL Check: Failed: Unknown Exception: [Errno 111] Connection refused"
        ));
    }

    #[test]
    fn an_issuer_outside_the_known_authorities_hints_at_a_proxy() {
        // The fixture's issuer is `C=US; O=Amazon`; a different DN must trigger the hint.
        let mut info = cert::parse(&leaf_der()).unwrap();
        info.issuer = vec![("C".into(), "XX".into()), ("O".into(), "Corp Proxy".into())];
        let net = FakeNetwork::default();
        let env = Env::default();
        let mut diag = ConnectorDiag::new(&net, &env, "ACCT", HOST, Path::new("/x"), None);
        diag.cert_info.insert(HOST.into(), info);
        diag.issuer_check(HOST);
        assert!(diag.report_text().contains(
            "PROXY: There is likely a proxy because the issuer for acct.snowflakecomputing.com is not correct. Got C=XX; O=Corp Proxy and expected one of ('C=US; O=Google Trust Services LLC', 'C=US; O=Amazon', 'C=US; O=DigiCert Inc')"
        ));
    }

    #[test]
    fn a_resolvable_invalid_domain_means_a_proxy() {
        let net = healthy().lookup(INVALID_HOST, &["1.2.3.4"]);
        let report = run(&net, None, None);
        assert!(report.contains("PROXY: It is likely there is a proxy based on HTTP response."));
    }

    #[test]
    fn proxy_passwords_never_reach_the_report() {
        let report = run(&healthy(), None, None);
        assert!(
            report.contains("{'https': 'http://***@proxy.corp:3128', 'no': 'localhost'}"),
            "{report}"
        );
        assert!(!report.contains("s3cret"));
    }

    #[test]
    fn an_invalid_allowlist_file_is_reported_in_the_initial_section() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "{not json").unwrap();
        let report = run(&healthy(), Some(path.clone()), None);
        assert!(report.contains("INITIAL: Allowlist was not valid json: '"));
        assert!(report.contains(&format!("validate the file {} is correct.", path.display())));
        assert!(report.contains("INITIAL: Allowlist is not a valid list of json objects."));
        // A file that is not a list is the same.
        std::fs::write(&path, r#"{"a": 1}"#).unwrap();
        let report = run(&healthy(), Some(path), None);
        assert!(report.contains("INITIAL: Allowlist is not a valid list of json objects."));
    }

    #[test]
    fn a_redirect_or_cdn_answer_counts_as_reachable() {
        let net = healthy()
            .get("ocsp.snowflakecomputing.com", 80, Ok("HTTP/1.1 301 Moved"))
            .get("ocsp.test-ca.example", 80, Ok("Server: cloudfront"));
        let report = run(&net, None, None);
        assert!(
            report.contains("ocsp.snowflakecomputing.com:80: URL Check: Connected Successfully")
        );
        assert!(report.contains("ocsp.test-ca.example:80: URL Check: Connected Successfully"));
    }

    #[test]
    fn a_certificate_for_another_domain_is_a_mismatch() {
        let mut info = cert::parse(&leaf_der()).unwrap();
        info.subject = vec![("CN".into(), "other.test".into())];
        info.subject_alt_name = Some("DNS:other.test".into());
        // Rebuild the report lines through the public path: patch the cert cache, then re-run.
        let net = FakeNetwork::default();
        let env = Env::default();
        let mut diag = ConnectorDiag::new(&net, &env, "ACCT", HOST, Path::new("/x"), None);
        let der = leaf_der();
        let net2 = FakeNetwork::default().cert("host.other.test", 443, Ok(der));
        diag.net = &net2;
        // The fixture is for *.snowflakecomputing.com, so `other.test` is not in it.
        diag.https_host_report("host.other.test", 443, Section::SnowflakeUrl);
        assert!(diag.report_text().contains(
            "host.other.test:443: URL Check: Failed: Certificate mismatch: Host not in subject or alt names"
        ));
    }

    #[test]
    fn helpers_follow_the_connector() {
        assert_eq!(top_level_domain("a.snowflakecomputing.cn"), "cn");
        assert_eq!(top_level_domain("localhost"), "com");
        assert_eq!(top_level_domain("1.2.3.4"), "com");
        assert!(is_private("192.168.0.1") && is_private("127.0.0.1"));
        assert!(!is_private("8.8.8.8") && !is_private("not an ip"));
        assert_eq!(mask_proxy_password("http://u:p@h:1"), "http://***@h:1");
        assert_eq!(mask_proxy_password("http://token@h"), "http://***@h");
        assert_eq!(mask_proxy_password("socks5h://u:p@h"), "socks5h://***@h");
        assert_eq!(mask_proxy_password("h:1"), "h:1");
        assert_eq!(mask_proxy_password("u:p@h:1"), "***@h:1");
        assert_eq!(
            issuer_string(&[("C".into(), "US".into()), ("O".into(), "A, \"B\"".into())]),
            "C=US; O=A; B"
        );
    }

    #[test]
    fn proxy_variables_follow_python_getproxies() {
        let env = Env::from_pairs([
            ("HTTPS_PROXY", "http://upper"),
            ("https_proxy", "http://lower"),
            ("FTP_PROXY", ""),
            ("http_proxy", ""),
            ("HTTP_PROXY", "http://gone"),
            ("PATH", "/bin"),
        ]);
        assert_eq!(
            env_proxies(&env),
            vec![("https".to_string(), "http://lower".to_string())]
        );
    }
}
