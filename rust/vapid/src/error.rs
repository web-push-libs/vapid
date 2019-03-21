// Error handling based on the failure crate

use std::fmt;
use std::result;

use failure::{Backtrace, Context, Error, Fail};

pub type VapidResult<T> = result::Result<T, Error>;

#[derive(Debug)]
pub struct VapidError {
    inner: Context<VapidErrorKind>,
}

#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum VapidErrorKind {
    #[fail(display = "Invalid public key")]
    PublicKeyError,
    #[fail(display = "VAPID error: {}", _0)]
    VapidError(String),
    #[fail(display = "Internal Error {:?}", _0)]
    InternalError(String),
}

impl Fail for VapidError {
    fn cause(&self) -> Option<&Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl fmt::Display for VapidError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl From<VapidErrorKind> for VapidError {
    fn from(kind: VapidErrorKind) -> VapidError {
        Context::new(kind).into()
    }
}

impl From<Context<VapidErrorKind>> for VapidError {
    fn from(inner: Context<VapidErrorKind>) -> VapidError {
        VapidError { inner }
    }
}

impl From<Error> for VapidError {
    fn from(err: Error) -> VapidError {
        VapidErrorKind::InternalError(format!("Error: {:?}", err)).into()
    }
}
