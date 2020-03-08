//! Unit tests using internal API.
//!
//! For testing public API (e.g. integration tests), use `tests/main.rs` instead.

use crate::PosixACL;

/** Demonstrate that multiple iterators cannot exist in parallel :( */
#[test]
#[should_panic(expected = "assertion failed: ")]
fn multi_iterator() {
    let acl = PosixACL::new(0o640);
    unsafe { acl.raw_iter() }
        .zip(unsafe { acl.raw_iter() })
        .for_each(|(a, b)| assert_eq!(a, b))
}
