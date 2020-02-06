posix-acl
=========

posix-acl is a simple Rust library to interact with POSIX filesystem ACLs. It uses the operating
system's C API internally.

Turns out that the C POSIX ACL library is actually quite annoying to work with and this library
significantly improves on that.

NB! Currently only tested on Linux.
