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

pub struct PosixACL {
    acl: acl_t,
}

/** NB! Unix-only */
fn path_to_cstring(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).unwrap()
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
            let uid: *const u32 = acl_get_qualifier(entry) as *const u32;
            *uid
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
    pub fn new() -> PosixACL {
        PosixACL::with_capacity(6)
    }

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

    pub fn set(&mut self, qual: Qualifier, perm: u32) {
        unsafe {
            let mut entry: acl_entry_t = mem::zeroed();
            check_return(
                acl_create_entry(&mut self.acl, &mut entry),
                "acl_create_entry",
            );
            let mut permset: acl_permset_t = mem::zeroed();
            check_return(acl_get_permset(entry, &mut permset), "acl_get_permset");
            check_return(acl_add_perm(permset, perm), "acl_add_perm");
            check_return(acl_set_permset(entry, permset), "acl_set_permset");
            check_return(acl_set_tag_type(entry, qual.tag_type()), "acl_set_tag_type");
            if let Some(uid) = qual.uid() {
                check_return(
                    acl_set_qualifier(entry, &uid as *const u32 as *const c_void),
                    "acl_set_qualifier",
                );
            }
        }
    }

    pub fn fix_mask(&mut self) {
        unsafe {
            check_return(acl_calc_mask(&mut self.acl), "acl_calc_mask");
        }
    }

    pub fn as_text(&self) -> String {
        let chars = unsafe {
            let mut len: ssize_t = 0;
            let txt = acl_to_text(self.acl, &mut len);
            check_pointer(txt, "acl_to_text");
            from_raw_parts(txt as *const u8, len as usize)
        };
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
mod tests {
    use crate::Qualifier::*;
    use crate::{ACLEntry, PosixACL};
    use acl_sys::{ACL_EXECUTE, ACL_READ, ACL_WRITE};

    fn full_fixture() -> PosixACL {
        let mut acl = PosixACL::new();
        acl.set(UserObj, ACL_READ | ACL_WRITE);
        acl.set(User(0), ACL_READ | ACL_WRITE);
        acl.set(User(99), 0); // nobody
        acl.set(GroupObj, ACL_READ);
        acl.set(Group(0), ACL_READ);
        acl.set(Group(99), 0); // nobody
        acl.set(Other, 0);
        acl.fix_mask();
        acl
    }

    #[test]
    fn new() {
        let acl = PosixACL::new();
        assert_eq!(acl.as_text(), "");
    }
    #[test]
    fn empty_mask() {
        let mut acl = PosixACL::new();
        // UserObj and Other qualifiers do not affect mask.
        acl.set(UserObj, ACL_READ | ACL_WRITE);
        acl.set(Other, ACL_READ);
        acl.fix_mask();
        assert_eq!(acl.as_text(), "user::rw-\nmask::---\nother::r--\n");
    }
    #[test]
    fn other_mask() {
        let mut acl = PosixACL::new();
        // GroupObj, User, Group qualifiers affect mask.
        acl.set(GroupObj, ACL_READ);
        acl.set(User(0), ACL_WRITE);
        acl.set(Group(0), ACL_EXECUTE);
        acl.fix_mask();
        assert_eq!(
            acl.as_text(),
            "user:root:-w-\ngroup::r--\ngroup:root:--x\nmask::rwx\n"
        );
    }
    #[test]
    fn validate_empty() {
        let mut acl = PosixACL::new();
        assert_eq!(acl.validate().unwrap_err().as_str(), "Invalid ACL: ");
        acl.fix_mask();
        assert_eq!(
            acl.validate().unwrap_err().as_str(),
            "Invalid ACL: mask::---,"
        );
    }
    #[test]
    fn validate_ok() {
        let mut acl = PosixACL::new();
        acl.set(UserObj, ACL_READ | ACL_WRITE);
        acl.set(GroupObj, ACL_READ | ACL_WRITE);
        acl.set(Other, 0);
        assert_eq!(acl.validate(), Ok(()));

        acl.set(User(0), ACL_READ);
        acl.set(Group(0), ACL_READ);
        assert_eq!(
            acl.validate().unwrap_err().as_str(),
            "Invalid ACL: user::rw-,user:root:r--,group::rw-,group:root:r--,other::---,"
        );

        acl.fix_mask();
        assert!(acl.validate().is_ok());
    }
    #[test]
    fn iterate() {
        let acl = full_fixture();
        // XXX is this ordering Linux-specific?
        assert_eq!(
            acl.entries(),
            [
                ACLEntry {
                    qual: UserObj,
                    perm: 6
                },
                ACLEntry {
                    qual: User(0),
                    perm: 6
                },
                ACLEntry {
                    qual: User(99),
                    perm: 0
                },
                ACLEntry {
                    qual: GroupObj,
                    perm: 4
                },
                ACLEntry {
                    qual: Group(0),
                    perm: 4
                },
                ACLEntry {
                    qual: Group(99),
                    perm: 0
                },
                ACLEntry {
                    qual: Mask,
                    perm: 6
                },
                ACLEntry {
                    qual: Other,
                    perm: 0
                }
            ]
        );
    }
    /** Demonstrate that multiple iterators cannot exist in parallel :( */
    #[test]
    #[should_panic(expected = "assertion failed: ")]
    fn multi_iterator() {
        let acl = full_fixture();
        unsafe { acl.raw_iter() }
            .zip(unsafe { acl.raw_iter() })
            .for_each(|(a, b)| assert_eq!(a, b))
    }
}
