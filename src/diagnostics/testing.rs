//! Fakes for the diagnostics tests.
#![allow(clippy::unwrap_used, clippy::expect_used)] // test code

use super::net::{NetError, Network, Probed, TlsFloor};
use super::{Query, Row};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use std::collections::HashMap;
use std::time::Duration;

pub fn fixture(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/certs")
        .join(name)
}

/// The DER of `tests/fixtures/certs/leaf.pem`: subject `C=US, ST=California, O=Snowflake Inc.,
/// CN=*.snowflakecomputing.com`, issuer `C=US, O=Amazon, CN=Test Amazon CA`.
pub fn leaf_der() -> Vec<u8> {
    CertificateDer::from_pem_file(fixture("leaf.pem"))
        .unwrap()
        .as_ref()
        .to_vec()
}

#[derive(Default)]
pub struct FakeNetwork {
    pub lookups: HashMap<String, Vec<String>>,
    pub certs: HashMap<(String, u16), Result<Vec<u8>, NetError>>,
    pub gets: HashMap<(String, u16), Result<String, NetError>>,
    pub probes: HashMap<(String, u16), Result<Probed, String>>,
}

impl FakeNetwork {
    pub fn lookup(mut self, host: &str, ips: &[&str]) -> Self {
        self.lookups
            .insert(host.into(), ips.iter().map(|s| s.to_string()).collect());
        self
    }

    pub fn cert(mut self, host: &str, port: u16, cert: Result<Vec<u8>, NetError>) -> Self {
        self.certs.insert((host.into(), port), cert);
        self
    }

    pub fn get(mut self, host: &str, port: u16, answer: Result<&str, NetError>) -> Self {
        self.gets
            .insert((host.into(), port), answer.map(str::to_string));
        self
    }

    pub fn probe(mut self, host: &str, port: u16, result: Result<Probed, &str>) -> Self {
        self.probes
            .insert((host.into(), port), result.map_err(str::to_string));
        self
    }
}

impl Network for FakeNetwork {
    fn lookup(&self, host: &str) -> Result<Vec<String>, NetError> {
        self.lookups
            .get(host)
            .cloned()
            .ok_or_else(|| NetError::Other("[Errno -2] Name or service not known".into()))
    }

    fn peer_cert(
        &self,
        host: &str,
        port: u16,
        _timeout: Duration,
        _floor: TlsFloor,
    ) -> Result<Vec<u8>, NetError> {
        self.certs
            .get(&(host.to_string(), port))
            .cloned()
            .unwrap_or_else(|| Err(NetError::Other("[Errno 111] Connection refused".into())))
    }

    fn http_get(&self, host: &str, port: u16, _timeout: Duration) -> Result<String, NetError> {
        self.gets
            .get(&(host.to_string(), port))
            .cloned()
            .unwrap_or_else(|| Err(NetError::Other("[Errno 111] Connection refused".into())))
    }

    fn probe(&self, host: &str, port: u16, _timeout: Duration) -> Result<Probed, String> {
        self.probes
            .get(&(host.to_string(), port))
            .cloned()
            .unwrap_or_else(|| Err("[Errno 111] Connection refused".into()))
    }
}

/// Answers by the start of the SQL text; anything else fails.
#[derive(Default)]
pub struct FakeQuery {
    pub answers: Vec<(String, Result<Vec<Row>, String>)>,
    pub asked: std::sync::Mutex<Vec<String>>,
}

impl FakeQuery {
    pub fn answer(mut self, sql_prefix: &str, rows: &[&[(&str, Option<&str>)]]) -> Self {
        let rows = rows
            .iter()
            .map(|r| {
                r.iter()
                    .map(|(k, v)| (k.to_string(), v.map(str::to_string)))
                    .collect()
            })
            .collect();
        self.answers.push((sql_prefix.into(), Ok(rows)));
        self
    }

    pub fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().clone()
    }
}

impl Query for FakeQuery {
    fn rows(&self, sql: &str) -> Result<Vec<Row>, String> {
        self.asked.lock().unwrap().push(sql.to_string());
        self.answers
            .iter()
            .find(|(prefix, _)| sql.starts_with(prefix.as_str()))
            .map(|(_, r)| r.clone())
            .unwrap_or_else(|| Err("SQL access control error".into()))
    }
}
