use crate::error::ACLError::{IoError, ValidationError};
use acl_sys::{ACL_TYPE_ACCESS, ACL_TYPE_DEFAULT};
use std::error::Error;
use std::io::ErrorKind;
use std::{fmt, io};

/// Use a bit flag to track whether error was caused by read or write
pub(crate) const FLAG_WRITE: u32 = 0x4000_0000;

/// Error type from ACL operations. To distinguish different causes, use the [`kind()`](Self::kind)
/// method.
//
// Perhaps an overkill, I could have used io::Error instead.
// But now that I wrote this, might as well keep it. :)
#[derive(Debug)]
#[allow(clippy::upper_case_acronyms)]
#[allow(clippy::module_name_repetitions)]
pub enum ACLError {
    /// Filesystem error while reading or writing ACL (file not found, permission denied, etc).
    IoError(IoErrorDetail),
    /// ACL is not valid and cannot be written.
    ///
    /// Unfortunately it is not possible to provide detailed reasons, but mainly it can mean:
    /// * Required entries are missing (`UserObj`, `GroupObj`, `Mask` and `Other`).
    /// * ACL contains entries that are not unique.
    ValidationError(ValidationErrorDetail),
}

// Stores private fields for ACLError::IoError
#[derive(Debug)]
pub struct IoErrorDetail {
    err: io::Error,
    flags: u32,
}

// Currently an empty struct, created for future extensibility
#[derive(Debug)]
pub struct ValidationErrorDetail {
    _private: (),
}

impl Error for ACLError {
    /// Get underlying [`std::io::Error`] value.
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ValidationError(..) => None,
            IoError(IoErrorDetail { ref err, .. }) => Some(err),
        }
    }
}

impl fmt::Display for ACLError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IoError(IoErrorDetail { flags, err }) => write!(
                f,
                "Error {} {}: {}",
                op_display(*flags),
                type_display(*flags),
                err
            ),
            ValidationError(_) => write!(f, "ACL failed validation"),
        }
    }
}

impl ACLError {
    /// Get a general category of error, as [`std::io::ErrorKind`].
    /// Validation errors get returned as `InvalidData`.
    ///
    /// ```
    /// use posix_acl::PosixACL;
    /// use std::io::ErrorKind;
    /// let err = PosixACL::read_acl("/tmp/this-file-does-not-exist").unwrap_err();
    /// assert_eq!(err.kind(), ErrorKind::NotFound);
    /// ```
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        match self {
            ValidationError(_) => ErrorKind::InvalidData,
            IoError(IoErrorDetail { ref err, .. }) => err.kind(),
        }
    }

    /// Get reference to underlying `std::io::Error` that occurred, if any.
    ///
    /// ```
    /// use posix_acl::PosixACL;
    /// use std::io::ErrorKind;
    /// let err = PosixACL::read_acl("/tmp/this-file-does-not-exist").unwrap_err();
    /// assert_eq!(err.as_io_error().unwrap().raw_os_error().unwrap(), libc::ENOENT);
    /// ```
    #[must_use]
    pub fn as_io_error(&self) -> Option<&io::Error> {
        match self {
            ValidationError(_) => None,
            IoError(IoErrorDetail { ref err, .. }) => Some(err),
        }
    }

    pub(crate) fn last_os_error(flags: u32) -> ACLError {
        IoError(IoErrorDetail {
            err: io::Error::last_os_error(),
            flags,
        })
    }

    pub(crate) fn validation_error() -> ACLError {
        ValidationError(ValidationErrorDetail { _private: () })
    }
}

/// `acl_type_t` string representation for error messages
pub(crate) fn op_display(flags: u32) -> &'static str {
    if flags & FLAG_WRITE == FLAG_WRITE {
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
