posix-acl
=========

[![Crates.io version](https://img.shields.io/crates/v/posix-acl.svg)](https://crates.io/crates/posix-acl)
[![Documentation](https://docs.rs/posix-acl/badge.svg)](https://docs.rs/posix-acl/)
[![Tests status](https://github.com/intgr/posix-acl/workflows/Tests/badge.svg?branch=master)](https://github.com/intgr/posix-acl/actions?query=workflow:Tests)

posix-acl is a simple Rust library to interact with POSIX filesystem ACLs. It uses the operating
system's C API internally.

Turns out that the C POSIX ACL library is actually quite annoying to work with and this library
significantly improves on that.

NB! Currently only tested on Linux.

Read [Documentation on Docs.rs](https://docs.rs/posix-acl/) for more details.

Release history
---------------

##### 0.2.0 (2020-02-08)
* Add badges to README & docs.rs link (#8)
* Add equality trait for PosixACL (#7)
* Use GitHub Actions & Docker for CI (#6)
* Add ACL remove() method
* Make ACLEntry fields public as intended

##### 0.1.0 (2020-02-06)
* Initial release
