//! A string that must never reach any output or log.

use std::fmt;
use zeroize::Zeroizing;

/// Private key PEM, passphrase, JWT or any other credential.
///
/// It has no `Display`, `Debug` prints a fixed mask, and the memory is wiped
/// on drop. Code reads the value only through [`Secret::expose`], right where
/// it is used (signing, the HTTP header).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Wraps a credential.
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// The raw value. Never pass it to a formatter, logger or error.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Secret::new(value)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(****)")
    }
}
