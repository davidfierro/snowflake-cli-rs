//! The network seam of the connectivity diagnostics: DNS, TCP and TLS probes behind a trait,
//! so the report logic is tested with canned answers and the CLI tests use local sockets.

use crate::env::Env;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// How a network call failed. The connector tells TLS failures apart from the rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetError {
    Tls(String),
    Other(String),
}

impl NetError {
    pub fn message(&self) -> &str {
        match self {
            NetError::Tls(m) | NetError::Other(m) => m,
        }
    }
}

/// Minimum TLS version a probe accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsFloor {
    /// The connector's diagnostic (`get_min_tls_version()` defaults to TLS 1.2).
    Tls12,
    /// snow's endpoint checks.
    Tls13,
}

/// What a successful endpoint probe learned (snow's `check_endpoint`).
#[derive(Debug, Clone, PartialEq)]
pub struct Probed {
    pub latency_ms: f64,
    pub issuer_org: Option<String>,
    /// `notAfter` in OpenSSL's text form, e.g. `Jun  5 12:00:00 2026 GMT`.
    pub not_after: Option<String>,
}

pub trait Network: Sync {
    /// IPv4 addresses of `host` (Python's `gethostbyname_ex`).
    fn lookup(&self, host: &str) -> Result<Vec<String>, NetError>;
    /// Leaf certificate (DER) of `host:port`, after a verified TLS handshake.
    fn peer_cert(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
        floor: TlsFloor,
    ) -> Result<Vec<u8>, NetError>;
    /// Sends `GET /` over plain TCP and returns the first 4096 bytes of the answer.
    fn http_get(&self, host: &str, port: u16, timeout: Duration) -> Result<String, NetError>;
    /// TCP connect (plus a TLS 1.3 handshake on 443); `Err` holds the failure text.
    fn probe(&self, host: &str, port: u16, timeout: Duration) -> Result<Probed, String>;
}

/// The real network.
pub struct SystemNetwork {
    /// `REQUESTS_CA_BUNDLE`, then `SSL_CERT_FILE`, as the connector and snow honour them.
    ca_file: Option<String>,
    /// The client configuration of each [`TlsFloor`], built on first use and shared by every
    /// probed host.
    configs: [OnceLock<Arc<rustls::ClientConfig>>; 2],
    /// Test hook: how many configurations were built.
    #[cfg(test)]
    builds: std::sync::atomic::AtomicUsize,
}

impl SystemNetwork {
    pub fn new(env: &Env) -> Self {
        let ca_file = ["REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"]
            .iter()
            .filter_map(|var| env.get(var))
            .find(|path| std::path::Path::new(path).is_file())
            .map(str::to_string);
        Self::with_ca_file(ca_file)
    }

    fn with_ca_file(ca_file: Option<String>) -> Self {
        Self {
            ca_file,
            configs: [OnceLock::new(), OnceLock::new()],
            #[cfg(test)]
            builds: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// The shared configuration for `floor`. A failure (an unreadable CA bundle) is not cached.
    fn tls_config(&self, floor: TlsFloor) -> Result<Arc<rustls::ClientConfig>, NetError> {
        let cell = &self.configs[floor as usize];
        if let Some(config) = cell.get() {
            return Ok(Arc::clone(config));
        }
        let config = self.build_tls_config(floor)?;
        Ok(Arc::clone(cell.get_or_init(|| config)))
    }

    fn build_tls_config(&self, floor: TlsFloor) -> Result<Arc<rustls::ClientConfig>, NetError> {
        #[cfg(test)]
        self.builds
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        let mut roots = rustls::RootCertStore::empty();
        match &self.ca_file {
            Some(path) => {
                for cert in CertificateDer::pem_file_iter(path)
                    .map_err(|e| NetError::Other(e.to_string()))?
                    .flatten()
                {
                    // A malformed certificate in the bundle is skipped, like OpenSSL does.
                    let _ = roots.add(cert);
                }
            }
            None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let versions: &[&rustls::SupportedProtocolVersion] = match floor {
            TlsFloor::Tls12 => rustls::ALL_VERSIONS,
            TlsFloor::Tls13 => &[&rustls::version::TLS13],
        };
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .map_err(|e| NetError::Other(e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Arc::new(config))
    }

    fn connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, std::io::Error> {
        let mut last = None;
        for addr in (host, port).to_socket_addrs()? {
            match TcpStream::connect_timeout(&addr, timeout) {
                Ok(stream) => {
                    stream.set_read_timeout(Some(timeout))?;
                    stream.set_write_timeout(Some(timeout))?;
                    return Ok(stream);
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| std::io::Error::other("no address found")))
    }

    /// Handshakes on `stream`; returns the leaf certificate.
    fn handshake(
        &self,
        stream: TcpStream,
        host: &str,
        floor: TlsFloor,
    ) -> Result<Vec<u8>, NetError> {
        let name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| NetError::Other(e.to_string()))?;
        let mut conn = rustls::ClientConnection::new(self.tls_config(floor)?, name)
            .map_err(|e| NetError::Tls(e.to_string()))?;
        let mut stream = stream;
        while conn.is_handshaking() {
            conn.complete_io(&mut stream).map_err(|e| {
                if e.kind() == std::io::ErrorKind::InvalidData {
                    NetError::Tls(e.to_string())
                } else {
                    NetError::Other(python_io_error(&e))
                }
            })?;
        }
        conn.peer_certificates()
            .and_then(|certs| certs.first())
            .map(|c| c.as_ref().to_vec())
            .ok_or_else(|| NetError::Tls("the server sent no certificate".into()))
    }
}

/// A server that only speaks TLS 1.2 closes the handshake on Python's TLS 1.3 floor; its
/// error reads like this.
fn python_tls_text(message: &str) -> &str {
    if message.contains("ServerTlsVersionIsDisabledByOurConfig")
        || message.contains("ProtocolVersion")
    {
        "TLS/SSL connection has been closed (EOF) (_ssl.c:1035)"
    } else {
        message
    }
}

/// An I/O error as Python prints an `OSError`: `[Errno 111] Connection refused`.
pub fn python_io_error(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(code) => {
            let text = e.to_string();
            let text = text
                .strip_suffix(&format!(" (os error {code})"))
                .unwrap_or(&text);
            format!("[Errno {code}] {text}")
        }
        // getaddrinfo failures carry no errno in Rust; Python prints them as `gaierror`s.
        None => {
            let text = e.to_string();
            match text.strip_prefix("failed to lookup address information: ") {
                Some(rest @ "Name or service not known") => format!("[Errno -2] {rest}"),
                Some(rest @ "Temporary failure in name resolution") => {
                    format!("[Errno -3] {rest}")
                }
                _ => text,
            }
        }
    }
}

impl Network for SystemNetwork {
    fn lookup(&self, host: &str) -> Result<Vec<String>, NetError> {
        let addrs = (host, 0)
            .to_socket_addrs()
            .map_err(|e| NetError::Other(python_io_error(&e)))?;
        let mut ips: Vec<String> = Vec::new();
        for addr in addrs.filter(|a| a.is_ipv4()) {
            let ip = addr.ip().to_string();
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
        Ok(ips)
    }

    fn peer_cert(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
        floor: TlsFloor,
    ) -> Result<Vec<u8>, NetError> {
        let stream =
            Self::connect(host, port, timeout).map_err(|e| NetError::Other(python_io_error(&e)))?;
        self.handshake(stream, host, floor)
    }

    fn http_get(&self, host: &str, port: u16, timeout: Duration) -> Result<String, NetError> {
        let io = |e: std::io::Error| NetError::Other(python_io_error(&e));
        let mut stream = Self::connect(host, port, timeout).map_err(io)?;
        let mut request = String::new();
        let _ = write!(
            request,
            "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).map_err(io)?;
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).map_err(io)?;
        Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
    }

    fn probe(&self, host: &str, port: u16, timeout: Duration) -> Result<Probed, String> {
        self.probe_with(host, port, timeout, port == 443)
    }
}

impl SystemNetwork {
    /// [`Network::probe`], with the TLS handshake decided by the caller (it is port 443 only).
    fn probe_with(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
        tls: bool,
    ) -> Result<Probed, String> {
        let start = Instant::now();
        let stream = Self::connect(host, port, timeout).map_err(|e| python_io_error(&e))?;
        let latency_ms = (start.elapsed().as_secs_f64() * 10_000.0).round() / 10.0;
        if !tls {
            return Ok(Probed {
                latency_ms,
                issuer_org: None,
                not_after: None,
            });
        }
        let der = self
            .handshake(stream, host, TlsFloor::Tls13)
            .map_err(|e| format!("TLS handshake failed: {}", python_tls_text(e.message())))?;
        let (issuer_org, not_after) = super::cert::issuer_org_and_expiry(&der);
        Ok(Probed {
            latency_ms,
            issuer_org,
            not_after,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::{fixture, leaf_der};
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    use std::net::TcpListener;

    const T: Duration = Duration::from_secs(5);

    fn trusting_fixture_ca() -> SystemNetwork {
        let ca = fixture("ca.pem");
        SystemNetwork::new(&Env::from_pairs([(
            "REQUESTS_CA_BUNDLE",
            ca.to_str().unwrap().to_string(),
        )]))
    }

    /// A TLS server for the fixture leaf on a free port, serving `connections` handshakes.
    fn tls_server(versions: &[&'static rustls::SupportedProtocolVersion]) -> u16 {
        let certs = vec![CertificateDer::from_pem_file(fixture("leaf.pem")).unwrap()];
        let key = PrivateKeyDer::from_pem_file(fixture("leaf.key")).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        let config = Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut stream = stream;
                let mut conn = rustls::ServerConnection::new(config.clone()).unwrap();
                // A failed handshake is the client's business; keep serving.
                let _ = conn.complete_io(&mut stream);
            }
        });
        port
    }

    /// A plain server that sends `answer` to the first request of each connection.
    fn plain_server(answer: &'static [u8]) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut stream = stream;
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(answer);
            }
        });
        port
    }

    fn closed_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    #[test]
    fn io_errors_read_like_pythons_oserror() {
        let refused = std::io::Error::from_raw_os_error(111);
        assert_eq!(python_io_error(&refused), "[Errno 111] Connection refused");
        let other = std::io::Error::other("boom");
        assert_eq!(python_io_error(&other), "boom");
        let gai = |m: &str| {
            python_io_error(&std::io::Error::other(format!(
                "failed to lookup address information: {m}"
            )))
        };
        assert_eq!(
            gai("Name or service not known"),
            "[Errno -2] Name or service not known"
        );
        assert_eq!(
            gai("Temporary failure in name resolution"),
            "[Errno -3] Temporary failure in name resolution"
        );
        assert_eq!(
            gai("something else"),
            "failed to lookup address information: something else"
        );
        assert_eq!(NetError::Tls("t".into()).message(), "t");
        assert_eq!(NetError::Other("o".into()).message(), "o");
    }

    #[test]
    fn lookup_returns_ipv4_addresses_once() {
        let net = SystemNetwork::new(&Env::default());
        assert_eq!(net.lookup("127.0.0.1").unwrap(), ["127.0.0.1"]);
        assert!(net.lookup("nonexistentdomain.invalid").is_err());
    }

    #[test]
    fn http_get_returns_the_first_answer() {
        let net = SystemNetwork::new(&Env::default());
        let port = plain_server(b"HTTP/1.1 200 OK\r\n\r\n");
        assert_eq!(
            net.http_get("127.0.0.1", port, T).unwrap(),
            "HTTP/1.1 200 OK\r\n\r\n"
        );
        let err = net.http_get("127.0.0.1", closed_port(), T).unwrap_err();
        assert!(err.message().starts_with("[Errno 111]"), "{err:?}");
    }

    #[test]
    fn probe_measures_a_plain_connection() {
        let net = SystemNetwork::new(&Env::default());
        let port = plain_server(b"");
        let probed = net.probe("127.0.0.1", port, T).unwrap();
        assert!(probed.latency_ms >= 0.0);
        assert_eq!((probed.issuer_org, probed.not_after), (None, None));
        let err = net.probe("127.0.0.1", closed_port(), T).unwrap_err();
        assert!(err.starts_with("[Errno 111]"), "{err}");
    }

    #[test]
    fn one_tls_config_is_built_per_floor_for_all_hosts() {
        let net = trusting_fixture_ca();
        for _ in 0..3 {
            let port = tls_server(rustls::ALL_VERSIONS);
            net.peer_cert("localhost", port, T, TlsFloor::Tls12)
                .unwrap();
        }
        let port = tls_server(rustls::ALL_VERSIONS);
        net.peer_cert("localhost", port, T, TlsFloor::Tls13)
            .unwrap();
        let port = tls_server(rustls::ALL_VERSIONS);
        net.peer_cert("localhost", port, T, TlsFloor::Tls13)
            .unwrap();
        // Four probes of two floors: two configurations.
        assert_eq!(net.builds.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn peer_cert_returns_the_verified_leaf() {
        let port = tls_server(rustls::ALL_VERSIONS);
        let der = trusting_fixture_ca()
            .peer_cert("localhost", port, T, TlsFloor::Tls12)
            .unwrap();
        assert_eq!(der, leaf_der());
    }

    #[test]
    fn peer_cert_rejects_an_untrusted_certificate_as_a_tls_error() {
        let port = tls_server(rustls::ALL_VERSIONS);
        // Without the fixture CA, the public roots do not know the issuer.
        let err = SystemNetwork::new(&Env::default())
            .peer_cert("localhost", port, T, TlsFloor::Tls12)
            .unwrap_err();
        assert!(matches!(err, NetError::Tls(_)), "{err:?}");
    }

    #[test]
    fn peer_cert_fails_on_a_server_that_is_not_tls() {
        let port = plain_server(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        let err = SystemNetwork::new(&Env::default())
            .peer_cert("localhost", port, T, TlsFloor::Tls12)
            .unwrap_err();
        assert!(matches!(err, NetError::Tls(_)), "{err:?}");
        let closed = SystemNetwork::new(&Env::default())
            .peer_cert("localhost", closed_port(), T, TlsFloor::Tls12)
            .unwrap_err();
        assert!(closed.message().starts_with("[Errno 111]"));
    }

    #[test]
    fn a_name_that_is_not_a_server_name_fails_before_connecting() {
        let port = plain_server(b"");
        let err = trusting_fixture_ca().peer_cert("not a host name", port, T, TlsFloor::Tls12);
        // The connect fails first for a name that does not resolve.
        assert!(err.is_err());
    }

    #[test]
    fn a_tls_probe_reads_the_issuer_and_the_expiry() {
        let port = tls_server(rustls::ALL_VERSIONS);
        let probed = trusting_fixture_ca()
            .probe_with("localhost", port, T, true)
            .unwrap();
        assert_eq!(probed.issuer_org.as_deref(), Some("Amazon"));
        assert_eq!(
            probed.not_after.as_deref(),
            Some("Oct 28 14:37:00 2126 GMT")
        );
    }

    #[test]
    fn a_tls_probe_requires_tls_13() {
        let port = tls_server(&[&rustls::version::TLS12]);
        let err = trusting_fixture_ca()
            .probe_with("localhost", port, T, true)
            .unwrap_err();
        assert_eq!(
            err,
            "TLS handshake failed: TLS/SSL connection has been closed (EOF) (_ssl.c:1035)"
        );
        // The connector's diagnostic accepts TLS 1.2.
        assert!(
            trusting_fixture_ca()
                .peer_cert("localhost", port, T, TlsFloor::Tls12)
                .is_ok()
        );
    }

    #[test]
    fn the_ca_bundle_variables_are_honoured_in_order_and_skip_missing_files() {
        let ca = fixture("ca.pem");
        let env = Env::from_pairs([
            ("REQUESTS_CA_BUNDLE", "/nonexistent/bundle.pem".to_string()),
            ("SSL_CERT_FILE", ca.to_str().unwrap().to_string()),
        ]);
        assert_eq!(SystemNetwork::new(&env).ca_file.as_deref(), ca.to_str());
        assert_eq!(SystemNetwork::new(&Env::default()).ca_file, None);
    }

    #[test]
    fn an_unreadable_bundle_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let garbage = dir.path().join("garbage.pem");
        std::fs::write(&garbage, "not pem at all").unwrap();
        let net = SystemNetwork::with_ca_file(Some(garbage.to_str().unwrap().to_string()));
        let port = tls_server(rustls::ALL_VERSIONS);
        // No usable root: the handshake cannot verify the server.
        assert!(
            net.peer_cert("localhost", port, T, TlsFloor::Tls12)
                .is_err()
        );
        let gone = SystemNetwork::with_ca_file(Some(
            dir.path().join("gone.pem").to_str().unwrap().to_string(),
        ));
        assert!(
            gone.peer_cert("localhost", port, T, TlsFloor::Tls12)
                .is_err()
        );
    }
}
