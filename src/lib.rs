//! **posix-acl** is a Rust library to interact with POSIX file system Access Control Lists (ACL).
//! It wraps the operating system's C interface with a safe Rust API. The API is deliberately
//! different from the POSIX C API to make it easier to use.
//!
//! NB! Currently only tested on Linux.
//!
//! While officially called a "list", The main struct [`PosixACL`] implements a "mapping-like"
//! interface where key is the [`Qualifier`] enum and value is `u32` containing permission bits.
//! This is without any loss of functionality, as duplicate entries with the same Qualifier are
//! disallowed by POSIX anyway.
//!
//! For background information about ACL behavior, read [POSIX Access Control Lists on Linux](
//! https://www.usenix.org/legacy/publications/library/proceedings/usenix03/tech/freenix03/full_papers/gruenbacher/gruenbacher_html/main.html).
//!
//! ## Usage example
//! ```
//! use posix_acl::{PosixACL, Qualifier, ACL_READ, ACL_WRITE};
//!
//! # std::fs::File::create("/tmp/posix-acl-testfile").unwrap();
//! // Read ACL from file (if there is no ACL yet, the OS will synthesize one)
//! let mut acl = PosixACL::read_acl("/tmp/posix-acl-testfile").unwrap();
//!
//! // Get permissions of owning user of the file
//! let perm = acl.get(Qualifier::UserObj).unwrap();
//! assert_eq!(perm, ACL_READ | ACL_WRITE);
//!
//! // Get permissions for user UID 1234
//! let perm = acl.get(Qualifier::User(1234));
//! assert!(perm.is_none());
//!
//! // Grant read access to group GID 1234 (adds new entry or overwrites an existing entry)
//! acl.set(Qualifier::Group(1234), ACL_READ);
//!
//! // Remove ACL entry of group GID 1234
//! acl.remove(Qualifier::Group(1234));
//!
//! // Write ACL back to the file
//! acl.write_acl("/tmp/posix-acl-testfile").unwrap();
//! ```

#![warn(missing_docs)]
#![warn(clippy::cargo)]
#![warn(clippy::pedantic)]
#![warn(clippy::impl_trait_in_params)]
#![warn(clippy::print_stdout)]
#![allow(clippy::module_name_repetitions)]

mod acl;
mod entry;
mod error;
mod iter;
mod util;

/// Read permission
pub const ACL_READ: u32 = acl_sys::ACL_READ;
/// Write permission
pub const ACL_WRITE: u32 = acl_sys::ACL_WRITE;
/// Execute permission
pub const ACL_EXECUTE: u32 = acl_sys::ACL_EXECUTE;
/// All possible permissions combined: `ACL_READ | ACL_WRITE | ACL_EXECUTE`
pub const ACL_RWX: u32 = ACL_READ | ACL_WRITE | ACL_EXECUTE;

// Re-export public structs
pub use acl::PosixACL;
pub use entry::ACLEntry;
pub use entry::Qualifier;
pub use error::ACLError;
