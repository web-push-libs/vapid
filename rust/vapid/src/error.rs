// Error handling based on the failure crate

use std::error::Error;
use std::fmt;
use std::result;

use backtrace::Backtrace;
use thiserror::Error;

pub type VapidResult<T> = result::Result<T, VapidError>;

#[derive(Debug)]
pub struct VapidError {
    kind: VapidErrorKind,
    pub backtrace: Backtrace,
}

#[derive(Debug, Error)]
pub enum VapidErrorKind {
    /// General IO instance. Can be returned for bad files or key data.
    #[error("IO error: {:?}", .0)]
    File(#[from] std::io::Error),
    /// OpenSSL errors. These tend not to be very specific (or helpful).
    #[error("OpenSSL error: {:?}", .0)]
    OpenSSL(#[from] openssl::error::ErrorStack),
    /// JSON parsing error.
    #[error("JSON error:{:?}", .0)]
    Json(#[from] serde_json::Error),

    /// An invalid public key was specified. Is it EC Prime256v1?
    #[error("Invalid public key")]
    PublicKey,
    /// A vapid error occurred.
    #[error("VAPID error: {}", .0)]
    Protocol(String),
    /// A random internal error
    #[error("Internal Error {:?}", .0)]
    Internal(String),
}

/// VapidErrors are the general error wrapper that we use. These include
/// a public `backtrace` which can be combined with your own because they're
/// stupidly useful.
impl VapidError {
    pub fn kind(&self) -> &VapidErrorKind {
        &self.kind
    }

    pub fn internal(msg: &str) -> Self {
        VapidErrorKind::Internal(msg.to_owned()).into()
    }
}

impl<T> From<T> for VapidError
where
    VapidErrorKind: From<T>,
{
    fn from(item: T) -> Self {
        VapidError {
            kind: VapidErrorKind::from(item),
            backtrace: Backtrace::new(),
        }
    }
}

impl Error for VapidError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.kind.source()
    }
}

impl fmt::Display for VapidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(f)
    }
}
