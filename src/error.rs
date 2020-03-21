use crate::error::ACLError::{IoError, ValidationError};
use acl_sys::{ACL_TYPE_ACCESS, ACL_TYPE_DEFAULT};
use std::error::Error;
use std::io::ErrorKind;
use std::{fmt, io};

/// Use a bit flag to track whether error was caused by read or write
pub(crate) const FLAG_WRITE: u32 = 0x4000_0000;

/// Error type from ACL operations.
// Perhaps an overkill, I could just use io::Error instead.
// But now that I wrote this, might as well keep it. :)
#[derive(Debug)]
pub enum ACLError {
    /// Error reading or writing ACL
    IoError { err: io::Error, flags: u32 },
    /// ACL is not valid and cannot be written.
    /// Unfortunately it is not possible to provide detailed reasons.
    ValidationError,
}

impl Error for ACLError {}

impl fmt::Display for ACLError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IoError { flags, err } => write!(
                f,
                "Error {} {}: {}",
                op_display(*flags),
                type_display(*flags),
                err
            ),
            ValidationError => write!(f, "ACL failed validation"),
        }
    }
}

impl ACLError {
    /// Get a general category of error. `ValidationError` gets returned as `InvalidData`.
    ///
    /// ```
    /// use posix_acl::PosixACL;
    /// use std::io::ErrorKind;
    /// let err = PosixACL::read_acl("/tmp/this-file-does-not-exist").unwrap_err();
    /// assert_eq!(err.kind(), ErrorKind::NotFound);
    /// ```
    pub fn kind(&self) -> ErrorKind {
        match self {
            ValidationError => ErrorKind::InvalidData,
            IoError { ref err, .. } => err.kind(),
        }
    }
}

/// `acl_type_t` string representation for error messages
pub(crate) fn op_display(flags: u32) -> &'static str {
    if flags & FLAG_WRITE != 0 {
        "writing"
    } else {
        "reading"
    }
}

/// `acl_type_t` string representation for error messages
pub(crate) fn type_display(flags: u32) -> &'static str {
    let flags = flags & !FLAG_WRITE;
    match flags {
        ACL_TYPE_ACCESS => "ACL",
        ACL_TYPE_DEFAULT => "default ACL",
        _ => panic!("Invalid flags"),
    }
}
