use crate::util::check_return;
use crate::PosixACL;
use acl_sys::{acl_entry_t, acl_get_entry, ACL_FIRST_ENTRY, ACL_NEXT_ENTRY};
use std::ptr::null_mut;

pub(crate) struct RawACLIterator<'a> {
    acl: &'a PosixACL,
    next: i32,
}

impl<'a> RawACLIterator<'a> {
    pub(crate) fn new(acl: &'a PosixACL) -> RawACLIterator {
        RawACLIterator {
            acl,
            next: ACL_FIRST_ENTRY,
        }
    }
}

impl<'a> Iterator for RawACLIterator<'a> {
    type Item = acl_entry_t;

    fn next(&mut self) -> Option<Self::Item> {
        let mut entry: acl_entry_t = null_mut();
        // The returned entry is owned by the ACL itself, no need to free it.
        let ret = unsafe { acl_get_entry(self.acl.acl, self.next, &mut entry) };
        if ret == 0 {
            return None;
        } else if ret != 1 {
            check_return(ret, "acl_get_entry");
        }
        // OK, ret == 1
        self.next = ACL_NEXT_ENTRY;
        Some(entry)
    }
}

/** Demonstrate that multiple iterators cannot exist in parallel :( */
#[test]
#[should_panic(expected = "assertion failed: ")]
fn multi_iterator() {
    let acl = PosixACL::new(0o640);
    let iter1 = unsafe { acl.raw_iter() };
    let iter2 = unsafe { acl.raw_iter() };

    iter1.zip(iter2).for_each(|(a, b)| assert_eq!(a, b))
}
