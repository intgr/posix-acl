posix-acl
=========

[![Crates.io version](https://img.shields.io/crates/v/posix-acl.svg)](https://crates.io/crates/posix-acl)
[![Documentation](https://docs.rs/posix-acl/badge.svg)](https://docs.rs/posix-acl/)
[![Tests status](https://github.com/intgr/posix-acl/workflows/Tests/badge.svg?branch=master)](https://github.com/intgr/posix-acl/actions?query=workflow:Tests)

**posix-acl** is a Rust library to interact with POSIX file system Access Control Lists (ACL).
It wraps the operating system's C interface with a safe Rust API. The API is deliberately different
from the POSIX C API to make it easier to use.

NB! Currently only tested on Linux.

Resources:
* [Library API documentation on Docs.rs](https://docs.rs/posix-acl/)
* [Background information about ACL behavior](
https://www.usenix.org/legacy/publications/library/proceedings/usenix03/tech/freenix03/full_papers/gruenbacher/gruenbacher_html/main.html)

### Usage example
```rust
use posix_acl::{PosixACL, Qualifier, ACL_READ, ACL_WRITE};

fn main() {
    // Read ACL from file (if there is no ACL yet, the OS will synthesize one)
    let mut acl = PosixACL::read_acl("/tmp/posix-acl-testfile").unwrap();

    // Get permissions of owning user of the file
    let perm = acl.get(Qualifier::UserObj).unwrap();
    assert_eq!(perm, ACL_READ | ACL_WRITE);

    // Get permissions for user UID 1234
    let perm = acl.get(Qualifier::User(1234));
    assert!(perm.is_none());

    // Grant read access to group GID 1234 (adds new entry or overwrites an existing entry)
    acl.set(Qualifier::Group(1234), ACL_READ);

    // Remove ACL entry of group GID 1234
    acl.remove(Qualifier::Group(1234));

    // Write ACL back to the file
    acl.write_acl("/tmp/posix-acl-testfile").unwrap();
}
```

Release history
---------------
##### 0.5.0 (2020-03-17)

* **API change:** Now using `AsRef<Path>` in methods that accept paths (`read_acl` etc.) (#33)

  This means `.as_ref()` is no longer needed or allowed when passing paths to these methods.
* Added methods `into_raw`, `from_raw` for converting to/from raw `acl_t` pointer (#21).
  Thanks to @aidanhs!
* Documentation tweaks & code cleanups.

##### 0.4.0 (2020-03-10)
This release is fully API-compatible with 0.3.0.
* Documentation expanded substantially (#27)
* Added `read_default_acl()` and `write_default_acl()` to interact with default ACLs of directories
  (#18, #30). Thanks to @aidanhs!
* PosixACL struct now implements the `Debug` trait (#24)
* Improved test coverage and CI workflow

##### 0.3.0 (2020-02-20)
* Update 'acl-sys' and 'libc' dependencies (#14)

##### 0.2.0 (2020-02-08)
* Add equality trait for PosixACL (#7)
* Use GitHub Actions & Docker for CI (#6)
* Add ACL remove() method
* Make ACLEntry fields public as intended

##### 0.1.0 (2020-02-06)
* Initial release
