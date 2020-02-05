use crate::Qualifier::*;
use crate::{ACLEntry, PosixACL};
use acl_sys::{ACL_EXECUTE, ACL_READ, ACL_WRITE};

fn full_fixture() -> PosixACL {
    let mut acl = PosixACL::new(0o640);
    acl.set(User(0), ACL_READ | ACL_WRITE);
    acl.set(User(99), 0); // nobody
    acl.set(Group(0), ACL_READ);
    acl.set(Group(99), 0); // nobody
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
        "Invalid ACL: mask::---,"
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
