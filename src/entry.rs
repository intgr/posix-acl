use crate::util::{check_pointer, check_return, AutoPtr};
use crate::Qualifier::*;
use acl_sys::{
    acl_entry_t, acl_get_permset, acl_get_qualifier, acl_get_tag_type, acl_permset_t, ACL_GROUP,
    ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER, ACL_UNDEFINED_TAG, ACL_USER, ACL_USER_OBJ,
};
use std::ptr::null_mut;

/// The subject of a permission grant.
#[derive(Debug, PartialEq, Eq)]
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
    pub(crate) fn tag_type(&self) -> i32 {
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
    pub(crate) fn uid(&self) -> Option<u32> {
        match self {
            User(uid) | Group(uid) => Some(*uid),
            _ => None,
        }
    }
    /// Convert C type acl_entry_t to Rust Qualifier
    pub(crate) fn from_entry(entry: acl_entry_t) -> Qualifier {
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

/// Returned from [`PosixACL::entries()`](crate::PosixACL::entries).
#[derive(Debug, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
pub struct ACLEntry {
    pub qual: Qualifier,
    pub perm: u32,
}

impl ACLEntry {
    /// Convert C type acl_entry_t to Rust ACLEntry
    pub(crate) fn from_entry(entry: acl_entry_t) -> ACLEntry {
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
