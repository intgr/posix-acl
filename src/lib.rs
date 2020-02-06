#[macro_use]
extern crate simple_error;

use core::mem;
use std::ffi::CString;
use std::io::Error;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::slice::from_raw_parts;
use std::str::from_utf8;

use acl_sys::*;
use libc::ssize_t;
use libc::types::common::c95::c_void;
use simple_error::{SimpleError, SimpleResult};

use crate::Qualifier::*;

/// All possible permissions
pub const ACL_RWX: u32 = ACL_READ | ACL_WRITE | ACL_EXECUTE;

pub struct PosixACL {
    acl: acl_t,
}

/** NB! Unix-only */
fn path_to_cstring(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).unwrap()
}

/// Safe wrapper around C pointers to automatically free when going out of scope.
struct AutoPtr<T>(*mut T);

impl<T> Drop for AutoPtr<T> {
    fn drop(&mut self) {
        let ret = unsafe { acl_free(self.0 as *mut c_void) };
        check_return(ret, "acl_free");
    }
}

#[derive(Debug, PartialEq)]
pub enum Qualifier {
    Undefined,
    UserObj,
    GroupObj,
    Other,
    User(u32),
    Group(u32),
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
        let tag_type;
        unsafe {
            tag_type = mem::zeroed();
            let ret = acl_get_tag_type(entry, &tag_type);
            check_return(ret, "acl_get_tag_type");
        }
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
    qual: Qualifier,
    perm: u32,
}

impl ACLEntry {
    /// Convert C type acl_entry_t to Rust ACLEntry
    fn from_entry(entry: acl_entry_t) -> ACLEntry {
        let perm;
        unsafe {
            let mut permset: acl_permset_t = mem::zeroed();
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
    ///
    /// This creates the minimal required entries. By the POSIX ACL spec, every valid ACL must
    /// contain at least four entries: UserObj, GroupObj, Mask and Other.
    ///
    /// Bits higher than 9 (e.g. SUID flag, etc) are ignored.
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

    pub fn read_acl(path: &Path) -> Result<PosixACL, SimpleError> {
        let c_path = path_to_cstring(path);
        let acl: acl_t = unsafe { acl_get_file(c_path.as_ptr(), ACL_TYPE_ACCESS) };
        if acl.is_null() {
            bail!(
                "Error reading {} ACL: {}",
                path.display(),
                Error::last_os_error()
            );
        }
        Ok(PosixACL { acl })
    }

    pub fn write_acl(&mut self, path: &Path) -> SimpleResult<()> {
        let c_path = path_to_cstring(path);
        self.fix_mask();
        self.validate()?;
        let ret = unsafe { acl_set_file(c_path.as_ptr(), ACL_TYPE_ACCESS, self.acl) };
        if ret != 0 {
            bail!(
                "Error writing {} ACL: {}",
                path.display(),
                Error::last_os_error()
            );
        }
        Ok(())
    }

    /// Iterator of acl_entry_t, unsafe
    unsafe fn raw_iter(&self) -> RawACLIterator {
        RawACLIterator::new(&self)
    }

    /// Get all ACLEntry items. The POSIX ACL API does not allow multiple parallel iterators so we
    /// return a materialized vector just to be safe.
    pub fn entries(&self) -> Vec<ACLEntry> {
        unsafe { self.raw_iter() }
            .map(ACLEntry::from_entry)
            .collect()
    }

    /// Set the permission of `qual` to `perm`. If this `qual` already exists, it is updated,
    /// otherwise a new one is added.
    pub fn set(&mut self, qual: Qualifier, perm: u32) {
        let entry = match self.raw_get_entry(&qual) {
            Some(v) => v,
            None => self.raw_add_entry(&qual),
        };

        Self::raw_set_permset(entry, perm);
    }

    fn raw_set_permset(entry: acl_entry_t, perm: u32) {
        unsafe {
            let mut permset: acl_permset_t = mem::zeroed();
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
        unsafe {
            let mut entry: acl_entry_t = mem::zeroed();
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
            entry
        }
    }

    pub fn fix_mask(&mut self) {
        unsafe {
            check_return(acl_calc_mask(&mut self.acl), "acl_calc_mask");
        }
    }

    pub fn as_text(&self) -> String {
        let mut len: ssize_t = 0;
        let txt = AutoPtr(unsafe { acl_to_text(self.acl, &mut len) });
        check_pointer(txt.0, "acl_to_text");
        let chars = unsafe { from_raw_parts(txt.0 as *const u8, len as usize) };

        from_utf8(chars).unwrap().to_string()
    }

    pub fn compact_text(&self) -> String {
        self.as_text().replace('\n', ",")
    }

    pub fn validate(&self) -> SimpleResult<()> {
        let ret = unsafe { acl_valid(self.acl) };
        if ret != 0 {
            bail!("Invalid ACL: {}", self.compact_text());
        }
        Ok(())
    }
}

impl Drop for PosixACL {
    fn drop(&mut self) {
        AutoPtr(self.acl);
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
        let mut entry: acl_entry_t;
        unsafe {
            entry = mem::zeroed();
            // The returned entry is owned by the ACL itself, no need to free it.
            let ret = acl_get_entry(self.acl.acl, self.next, &mut entry);
            if ret == 0 {
                return None;
            } else if ret != 1 {
                check_return(ret, "acl_get_entry");
            }
            // OK, ret == 1
            self.next = ACL_NEXT_ENTRY;
        }
        Some(entry)
    }
}

#[cfg(test)]
mod tests;
