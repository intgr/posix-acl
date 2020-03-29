//! Integration tests for public API.
//!
//! For internal unit tests, write directly into `src/` modules.

use acl_sys::{acl_free, ACL_EXECUTE, ACL_READ, ACL_WRITE};
use posix_acl::Qualifier::*;
use posix_acl::{ACLEntry, ACLError, PosixACL, ACL_RWX};
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use tempfile::{tempdir, TempDir};

fn full_fixture() -> PosixACL {
    let mut acl = PosixACL::new(0o640);
    acl.set(User(0), ACL_READ | ACL_WRITE);
    acl.set(Group(0), ACL_READ);
    // Using UID/GID 55555 that is likely undefined on Linux systems
    acl.set(User(55555), 0);
    acl.set(Group(55555), 0);
    acl.fix_mask();
    acl
}

/// Helper to create empty test files
fn test_file(dir: &TempDir, name: &str, mode: u32) -> PathBuf {
    let path = dir.path().join(name);
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .open(&path)
        .unwrap();
    path
}

#[test]
fn new() {
    let acl = PosixACL::new(0o751);
    assert_eq!(acl.as_text(), "user::rwx\ngroup::r-x\nother::--x\n");
    assert!(acl.validate().is_ok());
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
    let err = acl.validate().unwrap_err();
    assert!(matches!(err, ACLError::ValidationError(_)));
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert_eq!(err.to_string(), "ACL failed validation");
    acl.fix_mask();
    assert_eq!(acl.validate().unwrap_err().kind(), ErrorKind::InvalidData);
}
#[test]
fn validate_ok() {
    let mut acl = PosixACL::empty();
    acl.set(UserObj, ACL_READ | ACL_WRITE);
    acl.set(GroupObj, ACL_READ | ACL_WRITE);
    acl.set(Other, 0);
    assert!(acl.validate().is_ok());

    acl.set(User(0), ACL_READ);
    acl.set(Group(0), ACL_READ);
    assert!(matches!(
        acl.validate().unwrap_err(),
        ACLError::ValidationError(_)
    ));

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
    assert_eq!(acl.get(Group(55555)), Some(0));
    assert_eq!(acl.get(User(1234)), None);
    assert_eq!(acl.get(Mask), Some(ACL_READ | ACL_WRITE));
}
/// Test .remove() method
#[test]
fn remove() {
    let mut acl = PosixACL::new(0o750);
    assert_eq!(acl.remove(UserObj), Some(ACL_RWX));
    assert_eq!(acl.remove(UserObj), None);

    assert_eq!(acl.remove(GroupObj), Some(ACL_READ | ACL_EXECUTE));
    assert_eq!(acl.remove(Other), Some(0));

    assert_eq!(acl.remove(User(1234)), None);
    acl.set(User(1234), ACL_RWX);
    assert_eq!(acl.remove(User(1234)), Some(ACL_RWX));

    assert_eq!(acl.entries(), [])
}
#[test]
fn equality() {
    let acl = PosixACL::new(0o751);

    // Not using assert_eq! because the debug trait is not implemented by PosixACL.
    assert_eq!(acl, acl);
    assert_eq!(acl, PosixACL::new(0o751));
    assert_ne!(acl, PosixACL::new(0o741));

    acl.remove(Other);
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
                qual: User(55555),
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
                qual: Group(55555),
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
    let acl = full_fixture();

    assert_eq!(
        format!("{:?}", acl),
        "PosixACL(\"\
        user::rw-,user:root:rw-,user:55555:---,\
        group::r--,group:root:r--,group:55555:---,\
        mask::rw-,other::---\
        \")"
    );
}
/// Make sure that ACL survives the write+read round-trip
#[test]
fn writeread() {
    let mut acl1 = full_fixture();
    let dir = tempdir().unwrap();
    let path = test_file(&dir, "test.file", 0o777);

    let ret = acl1.write_acl(&path);
    assert!(ret.is_ok());
    let acl2 = PosixACL::read_acl(&path).unwrap();
    assert_eq!(acl1, acl2);
}
/// Make sure that *default* ACL survives the write+read round-trip
#[test]
fn writeread_default() {
    let mut acl1 = full_fixture();
    let dir = tempdir().unwrap();

    let ret = acl1.write_default_acl(dir.path());
    assert!(ret.is_ok());
    let acl2 = PosixACL::read_default_acl(dir.path()).unwrap();
    assert_eq!(acl1, acl2);
}
#[test]
fn read_file_with_no_acl() {
    let dir = tempdir().unwrap();
    let path = test_file(&dir, "test.file", 0o640);

    let acl = PosixACL::read_acl(&path).unwrap();
    assert_eq!(
        format!("{:?}", acl),
        "PosixACL(\"user::rw-,group::r--,other::---\")"
    );
    assert_eq!(acl, PosixACL::new(0o640));
}
#[test]
fn read_acl_not_found() {
    let err = PosixACL::read_acl("file_not_found").unwrap_err();
    assert!(matches!(err, ACLError::IoError(_)));
    assert_eq!(err.kind(), ErrorKind::NotFound);
    assert_eq!(
        err.to_string(),
        "Error reading ACL: No such file or directory (os error 2)"
    );
}
#[test]
fn write_acl_not_found() {
    let mut acl = PosixACL::new(0o644);
    let err = acl.write_acl("file_not_found").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::NotFound);
    assert_eq!(
        err.to_string(),
        "Error writing ACL: No such file or directory (os error 2)"
    );
}
#[test]
fn read_default_acl() {
    let dir = tempdir().unwrap();
    let acl = PosixACL::read_default_acl(dir.path()).unwrap();
    assert_eq!(format!("{:?}", acl), "PosixACL(\"\")");
}
/// Test different types accepted by AsRef<Path>
#[test]
fn path_types() {
    PosixACL::read_acl("/tmp").unwrap();
    PosixACL::read_acl(&"/tmp").unwrap();
    PosixACL::read_acl(String::from("/tmp")).unwrap();
    PosixACL::read_acl(&String::from("/tmp")).unwrap();
    PosixACL::read_acl(Path::new("/tmp")).unwrap();
    PosixACL::read_acl(&Path::new("/tmp")).unwrap();
    PosixACL::read_acl(PathBuf::from("/tmp")).unwrap();
    PosixACL::read_acl(&PathBuf::from("/tmp")).unwrap();
}
/// read_default_acl() fails when called with non-directory
#[test]
fn read_default_acl_file() {
    let dir = tempdir().unwrap();
    let path = test_file(&dir, "test.file", 0o777);

    let err = PosixACL::read_default_acl(&path).unwrap_err();
    // That's a confusing error message, but whatever...
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    assert_eq!(
        err.to_string(),
        "Error reading default ACL: Permission denied (os error 13)"
    );
}
/// write_default_acl() fails when called with non-directory
#[test]
fn write_default_acl_file() {
    let dir = tempdir().unwrap();
    let path = test_file(&dir, "test.file", 0o644);
    let mut acl = full_fixture();

    let err = acl.write_default_acl(&path).unwrap_err();
    // That's a confusing error message, but whatever...
    assert_eq!(
        err.to_string(),
        "Error writing default ACL: Permission denied (os error 13)"
    );
}

#[test]
fn acl_into_from_raw() {
    let acl1 = full_fixture();
    let ptr = acl1.into_raw();
    let acl2 = unsafe { PosixACL::from_raw(ptr) };
    assert_eq!(full_fixture(), acl2);
}

#[test]
fn acl_into_raw_free() {
    let acl1 = full_fixture();
    let ptr = acl1.into_raw();
    assert_eq!(unsafe { acl_free(ptr) }, 0);
}
