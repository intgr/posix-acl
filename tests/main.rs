//! Integration tests for public API.
//!
//! For internal unit tests, use top-level `src/tests.rs` instead.

use acl_sys::{ACL_EXECUTE, ACL_READ, ACL_WRITE};
use posix_acl::Qualifier::*;
use posix_acl::{ACLEntry, PosixACL, ACL_RWX};

fn full_fixture() -> PosixACL {
    let mut acl = PosixACL::new(0o640);
    acl.set(User(0), ACL_READ | ACL_WRITE);
    acl.set(User(99), 0);
    acl.set(Group(0), ACL_READ);
    acl.set(Group(99), 0);
    acl.fix_mask();
    acl
}

#[test]
fn new() {
    let acl = PosixACL::new(0o751);
    assert_eq!(
        acl.as_text(),
        "user::rwx\ngroup::r-x\nmask::r-x\nother::--x\n"
    );
    assert_eq!(acl.validate(), Ok(()));
}
#[test]
fn empty() {
    let acl = PosixACL::empty();
    assert_eq!(acl.as_text(), "");
}
#[test]
fn empty_mask() {
    let mut acl = PosixACL::empty();
    // UserObj and Other qualifiers do not affect mask.
    acl.set(UserObj, ACL_READ | ACL_WRITE);
    acl.set(Other, ACL_READ);
    acl.fix_mask();
    assert_eq!(acl.as_text(), "user::rw-\nmask::---\nother::r--\n");
}
#[test]
fn other_mask() {
    let mut acl = PosixACL::empty();
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
    let mut acl = PosixACL::empty();
    assert_eq!(acl.validate().unwrap_err().as_str(), "Invalid ACL: ");
    acl.fix_mask();
    assert_eq!(
        acl.validate().unwrap_err().as_str(),
        "Invalid ACL: mask::---"
    );
}
#[test]
fn validate_ok() {
    let mut acl = PosixACL::empty();
    acl.set(UserObj, ACL_READ | ACL_WRITE);
    acl.set(GroupObj, ACL_READ | ACL_WRITE);
    acl.set(Other, 0);
    assert_eq!(acl.validate(), Ok(()));

    acl.set(User(0), ACL_READ);
    acl.set(Group(0), ACL_READ);
    assert_eq!(
        acl.validate().unwrap_err().as_str(),
        "Invalid ACL: user::rw-,user:root:r--,group::rw-,group:root:r--,other::---"
    );

    acl.fix_mask();
    assert!(acl.validate().is_ok());
}
/// .set() method overwrites previous entry if one exists.
#[test]
fn set_overwrite() {
    let mut acl = PosixACL::empty();
    acl.set(UserObj, ACL_RWX);
    assert_eq!(acl.as_text(), "user::rwx\n");
    acl.set(UserObj, 0);
    assert_eq!(acl.as_text(), "user::---\n");
    acl.set(UserObj, ACL_READ);
    assert_eq!(acl.as_text(), "user::r--\n");
}
/// Test .get() method
#[test]
fn get() {
    let acl = full_fixture();
    assert_eq!(acl.get(UserObj), Some(ACL_READ | ACL_WRITE));
    assert_eq!(acl.get(GroupObj), Some(ACL_READ));
    assert_eq!(acl.get(Group(99)), Some(0));
    assert_eq!(acl.get(User(1234)), None);
    assert_eq!(acl.get(Mask), Some(ACL_READ | ACL_WRITE));
}
/// Test .remove() method
#[test]
fn remove() {
    let acl = PosixACL::new(0o750);
    assert_eq!(acl.remove(UserObj), Some(ACL_RWX));
    assert_eq!(acl.remove(UserObj), None);

    assert_eq!(acl.remove(GroupObj), Some(ACL_READ | ACL_EXECUTE));
    assert_eq!(acl.remove(Other), Some(0));
    assert_eq!(acl.remove(Mask), Some(ACL_READ | ACL_EXECUTE));

    assert_eq!(acl.entries(), [])
}
#[test]
fn equality() {
    let acl = PosixACL::new(0o751);

    // Not using assert_eq! because the debug trait is not implemented by PosixACL.
    assert_eq!(acl, acl);
    assert_eq!(acl, PosixACL::new(0o751));
    assert_ne!(acl, PosixACL::new(0o741));

    acl.remove(Mask);
    assert_ne!(acl, PosixACL::new(0o751));
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
// Test debug formatting
#[test]
fn debug() {
    // Cannot use `full_fixture()` because UID 99 is not portable
    let mut acl = PosixACL::new(0o640);
    acl.set(User(0), ACL_READ | ACL_WRITE);
    acl.set(Group(0), ACL_READ);
    acl.fix_mask();

    assert_eq!(
        format!("{:?}", acl),
        "PosixACL(\"user::rw-,user:root:rw-,group::r--,group:root:r--,mask::rw-,other::---\")"
    );
}
