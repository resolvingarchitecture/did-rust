//! One error type for the whole crate.

use std::fmt;

/// Anything that can go wrong building or reading a DID record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A key, id or signature was not the hex shape it must be.
    Format(String),
    /// A value was structurally valid hex but not a usable curve point / scalar.
    Crypto(String),
    /// A builder was called with arguments that cannot produce a valid record.
    Input(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Format(m) => write!(f, "format error: {m}"),
            Error::Crypto(m) => write!(f, "crypto error: {m}"),
            Error::Input(m) => write!(f, "invalid input: {m}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
