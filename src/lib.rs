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
//! # std::fs::File::create("/tmp/posix-acl-testfile");
//! // Read ACL from file (if there is no ACL yet, the OS will synthesize one)
//! let mut acl = PosixACL::read_acl("/tmp/posix-acl-testfile".as_ref()).unwrap();
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
//! acl.write_acl("/tmp/posix-acl-testfile".as_ref()).unwrap();
//! ```

#[macro_use]
extern crate simple_error;

use std::ffi::CString;
use std::io::Error;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::slice::from_raw_parts;
use std::str::from_utf8;

use libc::ssize_t;
use simple_error::SimpleError;

use crate::Qualifier::*;
use acl_sys::{
    acl_add_perm, acl_calc_mask, acl_clear_perms, acl_create_entry, acl_delete_entry, acl_entry_t,
    acl_free, acl_get_entry, acl_get_file, acl_get_permset, acl_get_qualifier, acl_get_tag_type,
    acl_init, acl_permset_t, acl_set_file, acl_set_permset, acl_set_qualifier, acl_set_tag_type,
    acl_size, acl_t, acl_to_text, acl_type_t, acl_valid, ACL_GROUP, ACL_GROUP_OBJ, ACL_MASK,
    ACL_OTHER, ACL_TYPE_ACCESS, ACL_TYPE_DEFAULT, ACL_UNDEFINED_TAG, ACL_USER, ACL_USER_OBJ,
};
use std::os::raw::c_void;
use std::ptr::null_mut;
use std::{fmt, mem};

#[cfg(test)]
mod tests;

/// Read permission
pub const ACL_READ: u32 = acl_sys::ACL_READ;
/// Write permission
pub const ACL_WRITE: u32 = acl_sys::ACL_WRITE;
/// Execute permission
pub const ACL_EXECUTE: u32 = acl_sys::ACL_EXECUTE;
/// All possible permissions combined: `ACL_READ | ACL_WRITE | ACL_EXECUTE`
pub const ACL_RWX: u32 = ACL_READ | ACL_WRITE | ACL_EXECUTE;

/// The ACL of a file.
pub struct PosixACL {
    acl: acl_t,
}

/// Custom debug formatting, since output `PosixACL { acl: 0x7fd74c000ca8 }` is not very helpful.
impl fmt::Debug for PosixACL {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Not really a tuple, but tuple formatting is compact.
        fmt.debug_tuple("PosixACL")
            .field(&self.compact_text())
            .finish()
    }
}

/// NB! Unix-only
fn path_to_cstring(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).unwrap()
}

/// `acl_type_t` string representation for error messages
fn type_description(flags: acl_type_t) -> &'static str {
    match flags {
        ACL_TYPE_ACCESS => "ACL",
        ACL_TYPE_DEFAULT => "default ACL",
        _ => panic!("Invalid flags"),
    }
}

/// Safe wrapper around C pointers to automatically free when going out of scope.
struct AutoPtr<T>(*mut T);

impl<T> Drop for AutoPtr<T> {
    fn drop(&mut self) {
        let ret = unsafe { acl_free(self.0 as *mut c_void) };
        check_return(ret, "acl_free");
    }
}

/// The subject of a permission grant.
#[derive(Debug, PartialEq)]
pub enum Qualifier {
    /// Unrecognized/corrupt entries
    Undefined,
    /// Permissions for owner of the file
    UserObj,
    /// Permissions for owning group of the file
    GroupObj,
    /// Permissions for everyone else not covered by the ACL
    Other,
    /// Permissions for user with UID `u32` value
    User(u32),
    /// Permissions for group with GID `u32` value
    Group(u32),
    /// Auto-generated entry
    Mask,
}

impl Qualifier {
    fn tag_type(&self) -> i32 {
        match self {
            Undefined => ACL_UNDEFINED_TAG,
            UserObj => ACL_USER_OBJ,
            GroupObj => ACL_GROUP_OBJ,
            User(_) => ACL_USER,
            Group(_) => ACL_GROUP,
            Mask => ACL_MASK,
            Other => ACL_OTHER,
        }
    }
    fn uid(&self) -> Option<u32> {
        match self {
            User(uid) | Group(uid) => Some(*uid),
            _ => None,
        }
    }
    /// Convert C type acl_entry_t to Rust Qualifier
    fn from_entry(entry: acl_entry_t) -> Qualifier {
        let tag_type = 0;
        let ret = unsafe { acl_get_tag_type(entry, &tag_type) };
        check_return(ret, "acl_get_tag_type");
        match tag_type {
            ACL_UNDEFINED_TAG => Undefined,
            ACL_USER_OBJ => UserObj,
            ACL_GROUP_OBJ => GroupObj,
            ACL_USER => User(Qualifier::get_entry_uid(entry)),
            ACL_GROUP => Group(Qualifier::get_entry_uid(entry)),
            ACL_MASK => Mask,
            ACL_OTHER => Other,
            _ => {
                panic!("Unexpected tag type {}", tag_type);
            }
        }
    }
    /// Helper function for from_entry()
    fn get_entry_uid(entry: acl_entry_t) -> u32 {
        unsafe {
            let uid = AutoPtr(acl_get_qualifier(entry) as *mut u32);
            check_pointer(uid.0, "acl_get_qualifier");
            *uid.0
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct ACLEntry {
    pub qual: Qualifier,
    pub perm: u32,
}

impl ACLEntry {
    /// Convert C type acl_entry_t to Rust ACLEntry
    fn from_entry(entry: acl_entry_t) -> ACLEntry {
        let perm;
        let mut permset: acl_permset_t = null_mut();
        unsafe {
            let ret = acl_get_permset(entry, &mut permset);
            check_return(ret, "acl_get_permset");
            perm = *(permset as *const u32);
        }
        ACLEntry {
            qual: Qualifier::from_entry(entry),
            perm,
        }
    }
}

fn check_return(ret: i32, func: &str) {
    if ret != 0 {
        panic!("Error in {}: {}", func, Error::last_os_error());
    }
}

fn check_pointer<T: ?Sized>(ret: *const T, func: &str) {
    if ret.is_null() {
        panic!("Error in {}: {}", func, Error::last_os_error());
    }
}

impl PosixACL {
    /// Convert a file mode ("chmod" number) into an ACL. This is the primary constructor.
    /// Note that modes are usually expressed in Octal, e.g. `PosixACL::new(0o644)`
    ///
    /// This creates the minimal required entries. By the POSIX ACL spec, every valid ACL must
    /// contain at least four entries: UserObj, GroupObj, Mask and Other.
    ///
    /// Bits higher than 9 (e.g. SUID flag, etc) are ignored.
    ///
    /// ```
    /// use posix_acl::PosixACL;
    /// assert_eq!(
    ///     PosixACL::new(0o751).as_text(),
    ///     "user::rwx\ngroup::r-x\nmask::r-x\nother::--x\n"
    /// );
    /// ```
    pub fn new(file_mode: u32) -> PosixACL {
        let mut acl = PosixACL::empty();
        acl.set(UserObj, (file_mode >> 6) & ACL_RWX);
        acl.set(GroupObj, (file_mode >> 3) & ACL_RWX);
        acl.set(Mask, (file_mode >> 3) & ACL_RWX);
        acl.set(Other, file_mode & ACL_RWX);
        acl
    }

    /// Create an empty ACL. NB! Empty ACLs are NOT considered valid.
    pub fn empty() -> PosixACL {
        PosixACL::with_capacity(6)
    }

    /// Create an empty ACL with capacity. NB! Empty ACLs are NOT considered valid.
    pub fn with_capacity(capacity: usize) -> PosixACL {
        let acl = unsafe { acl_init(capacity as i32) };
        check_pointer(acl, "acl_init");
        PosixACL { acl }
    }

    pub fn len(&self) -> usize {
        unsafe { acl_size(self.acl) }
    }

    /// Read a path's access ACL and return as `PosixACL` object.
    pub fn read_acl(path: &Path) -> Result<PosixACL, SimpleError> {
        Self::read_acl_flags(path, ACL_TYPE_ACCESS)
    }

    /// Read a directory's default ACL and return as `PosixACL` object.
    /// This will fail if `path` is not a directory.
    ///
    /// Default ACL determines permissions for new files and subdirectories created in the
    /// directory.
    pub fn read_default_acl(path: &Path) -> Result<PosixACL, SimpleError> {
        Self::read_acl_flags(path, ACL_TYPE_DEFAULT)
    }

    fn read_acl_flags(path: &Path, flags: acl_type_t) -> Result<PosixACL, SimpleError> {
        let c_path = path_to_cstring(path);
        let acl: acl_t = unsafe { acl_get_file(c_path.as_ptr(), flags) };
        if acl.is_null() {
            bail!(
                "Error reading {} {}: {}",
                path.display(),
                type_description(flags),
                Error::last_os_error()
            );
        }
        Ok(PosixACL { acl })
    }

    /// Write this ACL to a path's access ACL. Overwrites any existing access ACL.
    ///
    /// Automatically re-calculates the magic `Mask` entry and calls validation.
    pub fn write_acl(&mut self, path: &Path) -> Result<(), SimpleError> {
        self.write_acl_flags(path, ACL_TYPE_ACCESS)
    }

    /// Write this ACL to a directory's default ACL. Overwrites any existing default ACL.
    /// This will fail if `path` is not a directory.
    ///
    /// Default ACL determines permissions for new files and subdirectories created in the
    /// directory.
    ///
    /// Automatically re-calculates the magic `Mask` entry and calls validation.
    pub fn write_default_acl(&mut self, path: &Path) -> Result<(), SimpleError> {
        self.write_acl_flags(path, ACL_TYPE_DEFAULT)
    }

    fn write_acl_flags(&mut self, path: &Path, flags: acl_type_t) -> Result<(), SimpleError> {
        let c_path = path_to_cstring(path);
        self.fix_mask();
        self.validate()?;
        let ret = unsafe { acl_set_file(c_path.as_ptr(), flags, self.acl) };
        if ret != 0 {
            bail!(
                "Error writing {} {}: {}",
                path.display(),
                type_description(flags),
                Error::last_os_error()
            );
        }
        Ok(())
    }

    /// Iterator of `acl_entry_t`, unsafe
    unsafe fn raw_iter(&self) -> RawACLIterator {
        RawACLIterator::new(&self)
    }

    /// Get all ACLEntry items. The POSIX ACL C API does not allow multiple parallel iterators so we
    /// return a materialized vector just to be safe.
    pub fn entries(&self) -> Vec<ACLEntry> {
        unsafe { self.raw_iter() }
            .map(ACLEntry::from_entry)
            .collect()
    }

    /// Set the permission of `qual` to `perm`. If this `qual` already exists, it is updated,
    /// otherwise a new one is added.
    ///
    /// `perm` must be a combination of the `ACL_` constants, combined by binary OR.
    pub fn set(&mut self, qual: Qualifier, perm: u32) {
        let entry = match self.raw_get_entry(&qual) {
            Some(v) => v,
            None => self.raw_add_entry(&qual),
        };

        Self::raw_set_permset(entry, perm);
    }

    /// Get the current `perm` value of `qual`, if any.
    pub fn get(&self, qual: Qualifier) -> Option<u32> {
        let entry = self.raw_get_entry(&qual)?;

        // XXX inefficient, no need to construct ACLEntry.
        Some(ACLEntry::from_entry(entry).perm)
    }

    /// Remove entry with matching `qual`. If found, returns the matching `perm`, otherwise `None`
    pub fn remove(&self, qual: Qualifier) -> Option<u32> {
        let entry = self.raw_get_entry(&qual)?;
        let wrapped = ACLEntry::from_entry(entry);

        unsafe {
            acl_delete_entry(self.acl, entry);
        }

        // XXX inefficient, no need to construct ACLEntry.
        Some(wrapped.perm)
    }

    fn raw_set_permset(entry: acl_entry_t, perm: u32) {
        unsafe {
            let mut permset: acl_permset_t = null_mut();
            check_return(acl_get_permset(entry, &mut permset), "acl_get_permset");
            check_return(acl_clear_perms(permset), "acl_clear_perms");
            check_return(acl_add_perm(permset, perm), "acl_add_perm");
            check_return(acl_set_permset(entry, permset), "acl_set_permset");
        }
    }

    fn raw_get_entry(&self, qual: &Qualifier) -> Option<acl_entry_t> {
        for entry in unsafe { self.raw_iter() } {
            // XXX this is slightly inefficient, calls to get_entry_uid() could be short-circuited.
            if Qualifier::from_entry(entry) == *qual {
                // Found it!
                return Some(entry);
            }
        }
        None
    }

    fn raw_add_entry(&mut self, qual: &Qualifier) -> acl_entry_t {
        let mut entry: acl_entry_t = null_mut();
        unsafe {
            check_return(
                acl_create_entry(&mut self.acl, &mut entry),
                "acl_create_entry",
            );
            check_return(acl_set_tag_type(entry, qual.tag_type()), "acl_set_tag_type");
            if let Some(uid) = qual.uid() {
                check_return(
                    acl_set_qualifier(entry, &uid as *const u32 as *const c_void),
                    "acl_set_qualifier",
                );
            }
        }
        entry
    }

    /// Re-calculate the `Qualifier::Mask` entry.
    ///
    /// Usually there is no need to call this directly, as this is done during
    /// `write_acl/write_default_acl()` automatically.
    pub fn fix_mask(&mut self) {
        unsafe {
            check_return(acl_calc_mask(&mut self.acl), "acl_calc_mask");
        }
    }

    /// Return the textual representation of the ACL. Individual entries are separated by newline
    /// (`'\n'`).
    ///
    /// UID/GID are automatically resolved to names by the platform.
    pub fn as_text(&self) -> String {
        let mut len: ssize_t = 0;
        let txt = AutoPtr(unsafe { acl_to_text(self.acl, &mut len) });
        check_pointer(txt.0, "acl_to_text");
        let chars = unsafe { from_raw_parts(txt.0 as *const u8, len as usize) };

        from_utf8(chars).unwrap().to_string()
    }

    fn compact_text(&self) -> String {
        self.as_text().trim_end().replace('\n', ",")
    }

    /// Call the platform's validation function. Unfortunately it is not possible to provide
    /// detailed error messages.
    pub fn validate(&self) -> Result<(), SimpleError> {
        let ret = unsafe { acl_valid(self.acl) };
        if ret != 0 {
            bail!("Invalid ACL: {}", self.compact_text());
        }
        Ok(())
    }

    /// Consumes the `PosixACL`, returning the wrapped `acl_t`.
    /// This can then be used directly in FFI calls to the acl library.
    ///
    /// To avoid a memory leak, the `acl_t` must either:
    ///
    /// - Be converted back to a PosixACL using `PosixACL::from_raw`
    /// - Have `acl_free` called on it
    // Note: it's typically considered safe for Rust functions to leak resources (in this specific
    // case, the function is analogous to the safe `Rc::into_raw` function in the standard library).
    // For more discussion on this, see [the nomicon](https://doc.rust-lang.org/nomicon/leaking.html).
    pub fn into_raw(self) -> acl_t {
        let acl = self.acl;
        mem::forget(self);
        acl
    }

    /// Constructs a `PosixACL` from a raw `acl_t`. You should treat the `acl_t`
    /// as being 'consumed' by this function.
    ///
    /// # Safety
    ///
    /// The `acl_t` must be a valid acl (not `(acl_t)NULL`) acl returned
    /// either `PosixACL::into_raw` or another acl library function.
    ///
    /// Improper usage of this function may lead to memory problems (e.g.
    /// calling it twice on the same acl may lead to a double free).
    pub unsafe fn from_raw(acl: acl_t) -> Self {
        Self { acl }
    }
}

impl Drop for PosixACL {
    fn drop(&mut self) {
        AutoPtr(self.acl);
    }
}

impl PartialEq for PosixACL {
    fn eq(&self, other: &Self) -> bool {
        self.entries() == other.entries()
    }
}

/* Whaat, these constants aren't declared in acl-sys */
const ACL_FIRST_ENTRY: i32 = 0;
const ACL_NEXT_ENTRY: i32 = 1;

struct RawACLIterator<'a> {
    acl: &'a PosixACL,
    next: i32,
}

impl<'a> RawACLIterator<'a> {
    fn new(acl: &'a PosixACL) -> RawACLIterator {
        RawACLIterator {
            acl,
            next: ACL_FIRST_ENTRY,
        }
    }
}

impl<'a> Iterator for RawACLIterator<'a> {
    type Item = acl_entry_t;

    fn next(&mut self) -> Option<Self::Item> {
        let mut entry: acl_entry_t = null_mut();
        // The returned entry is owned by the ACL itself, no need to free it.
        let ret = unsafe { acl_get_entry(self.acl.acl, self.next, &mut entry) };
        if ret == 0 {
            return None;
        } else if ret != 1 {
            check_return(ret, "acl_get_entry");
        }
        // OK, ret == 1
        self.next = ACL_NEXT_ENTRY;
        Some(entry)
    }
}
