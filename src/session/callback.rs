//! The localhost HTTP callback server of the browser and OAuth authorization-code flows
//! (ADR 0005, Decisions 2 and 4): it binds `127.0.0.1` only, reads one request at a time until
//! the flow has what it waits for or the timeout passes, then closes.

use crate::error::{Error, ErrorKind, Result};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

/// Largest request read (the connector's buffer is 16 KiB).
const MAX_REQUEST: usize = 16 * 1024;
const ACCEPT_POLL: Duration = Duration::from_millis(20);
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// One request the browser sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    /// The request target, e.g. `/?token=…`.
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Request {
    /// The first header named `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn parse(raw: &str) -> Option<Self> {
        let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw, ""));
        let mut lines = head.split("\r\n");
        let mut first = lines.next()?.split_whitespace();
        let method = first.next()?.to_ascii_uppercase();
        let target = first.next()?.to_string();
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
            .collect();
        Some(Self {
            method,
            target,
            headers,
            body: body.to_string(),
        })
    }
}

/// A listening socket on `127.0.0.1`.
pub struct CallbackServer {
    listener: TcpListener,
    port: u16,
}

impl CallbackServer {
    /// Binds `127.0.0.1:<port>` (`0`: any free port).
    pub fn bind(port: u16) -> Result<Self> {
        let listener =
            TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).map_err(|e| {
                Error::new(
                    ErrorKind::Connection,
                    format!("Failed to start the sign-in callback server on port {port}."),
                )
                .with_source(e)
            })?;
        let port = listener.local_addr().map(|a| a.port()).unwrap_or(port);
        listener.set_nonblocking(true).map_err(|e| {
            Error::new(
                ErrorKind::Connection,
                "Failed to start the sign-in callback server.",
            )
            .with_source(e)
        })?;
        Ok(Self { listener, port })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Waits for the next request until `deadline`; `None` when it passed. A connection that
    /// sends nothing parseable is closed and skipped.
    pub fn next(&self, deadline: Instant) -> Option<(Request, Responder)> {
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    if let Some(request) = read_request(&stream) {
                        return Some((request, Responder { stream }));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => {}
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(ACCEPT_POLL);
        }
    }
}

/// Answers one request, then closes its connection.
pub struct Responder {
    stream: TcpStream,
}

impl Responder {
    /// `HTTP/1.1 200 OK` with `headers` and `body`.
    pub fn ok(mut self, headers: &[(&str, &str)], body: &str) {
        let mut text = String::from("HTTP/1.1 200 OK\r\n");
        for (name, value) in headers {
            text.push_str(&format!("{name}: {value}\r\n"));
        }
        text.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
        // The browser may already be gone; the flow has what it needs either way.
        let _ = self.stream.write_all(text.as_bytes());
        let _ = self.stream.flush();
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }

    /// Closes the connection without an answer.
    pub fn close(self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

fn read_request(stream: &TcpStream) -> Option<Request> {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    let mut reader = stream;
    loop {
        let n = reader.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);
        if raw.len() >= MAX_REQUEST || complete(&raw) {
            break;
        }
    }
    raw.truncate(MAX_REQUEST);
    Request::parse(&String::from_utf8_lossy(&raw))
}

/// The headers are in, and as much body as `Content-Length` announces.
fn complete(raw: &[u8]) -> bool {
    let text = String::from_utf8_lossy(raw);
    let Some((head, body)) = text.split_once("\r\n\r\n") else {
        return false;
    };
    let length = head
        .split("\r\n")
        .filter_map(|l| l.split_once(':'))
        .find(|(n, _)| n.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    body.len() >= length
}

/// The decoded value of query parameter `name` in a URL or request target.
pub fn query_param(url: &str, name: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    let query = query.split('#').next().unwrap_or(query);
    form_param(query, name)
}

/// The decoded value of `name` in an `application/x-www-form-urlencoded` string.
pub fn form_param(form: &str, name: &str) -> Option<String> {
    form.split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(k) == name).then(|| percent_decode(v))
        })
        .next()
}

/// `+` is a space and `%XX` a byte, as Python's `parse_qs`.
pub fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = |b: u8| (b as char).to_digit(16);
                match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push((hi * 16 + lo) as u8);
                        i += 2;
                    }
                    _ => out.push(b'%'),
                }
            }
            other => out.push(other),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send(port: u16, raw: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.write_all(raw.as_bytes()).unwrap();
        let mut answer = String::new();
        let _ = stream.read_to_string(&mut answer);
        answer
    }

    #[test]
    fn it_reads_a_request_and_answers_it() {
        let server = CallbackServer::bind(0).unwrap();
        let port = server.port();
        assert_ne!(port, 0);
        let client = std::thread::spawn(move || {
            send(
                port,
                "POST /cb?x=1 HTTP/1.1\r\nHost: a\r\nContent-Length: 11\r\n\r\ntoken=a%2Bb",
            )
        });
        let (request, responder) = server
            .next(Instant::now() + Duration::from_secs(5))
            .unwrap();
        assert_eq!(request.method, "POST");
        assert_eq!(request.target, "/cb?x=1");
        assert_eq!(request.header("host"), Some("a"));
        assert_eq!(request.header("origin"), None);
        assert_eq!(form_param(&request.body, "token").as_deref(), Some("a+b"));
        responder.ok(&[("Content-Type", "text/html")], "done");
        let answer = client.join().unwrap();
        assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(answer.contains("Content-Type: text/html\r\n"));
        assert!(answer.ends_with("Content-Length: 4\r\n\r\ndone"));
    }

    #[test]
    fn junk_is_skipped_and_the_deadline_ends_the_wait() {
        let server = CallbackServer::bind(0).unwrap();
        let port = server.port();
        std::thread::spawn(move || {
            // An empty connection, then a real request.
            drop(TcpStream::connect(("127.0.0.1", port)).unwrap());
            send(port, "GET /?token=t HTTP/1.1\r\n\r\n")
        });
        let (request, responder) = server
            .next(Instant::now() + Duration::from_secs(5))
            .unwrap();
        assert_eq!(query_param(&request.target, "token").as_deref(), Some("t"));
        responder.close();
        assert!(server.next(Instant::now()).is_none());
    }

    #[test]
    fn a_port_in_use_is_an_error() {
        let server = CallbackServer::bind(0).unwrap();
        let err = CallbackServer::bind(server.port()).err().unwrap();
        assert_eq!(err.kind(), ErrorKind::Connection);
    }

    #[test]
    fn parsing_and_decoding() {
        assert_eq!(Request::parse(""), None);
        assert_eq!(Request::parse("GET"), None);
        assert_eq!(
            query_param("http://h/p?a=1&code=x%20y+z&state=s#frag", "code").as_deref(),
            Some("x y z")
        );
        assert_eq!(
            query_param("http://h/p?state=s#frag", "state").as_deref(),
            Some("s")
        );
        assert_eq!(query_param("http://h/p", "code"), None);
        assert_eq!(form_param("flag&b=2", "flag").as_deref(), Some(""));
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz%41"), "%zzA");
        assert_eq!(percent_decode("%C3%A9"), "é");
        assert!(complete(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(!complete(b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nab"));
        assert!(!complete(b"GET / HTTP/1.1\r\n"));
    }
}
