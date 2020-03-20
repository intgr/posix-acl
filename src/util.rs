//! This file is for small helpers & utilities that aren't exported by the library.
use std::ffi::CString;
use std::io;
use std::os::raw::c_void;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use acl_sys::{acl_free, acl_type_t, ACL_TYPE_ACCESS, ACL_TYPE_DEFAULT};

/// NB! Unix-only
pub(crate) fn path_to_cstring(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).unwrap()
}

/// `acl_type_t` string representation for error messages
pub(crate) fn type_description(flags: acl_type_t) -> &'static str {
    match flags {
        ACL_TYPE_ACCESS => "ACL",
        ACL_TYPE_DEFAULT => "default ACL",
        _ => panic!("Invalid flags"),
    }
}

/// Safe wrapper around C pointers to automatically free when going out of scope.
pub(crate) struct AutoPtr<T>(pub(crate) *mut T);

impl<T> Drop for AutoPtr<T> {
    fn drop(&mut self) {
        let ret = unsafe { acl_free(self.0 as *mut c_void) };
        check_return(ret, "acl_free");
    }
}

pub(crate) fn check_return(ret: i32, func: &str) {
    if ret != 0 {
        panic!("Error in {}: {}", func, io::Error::last_os_error());
    }
}

pub(crate) fn check_pointer<T: ?Sized>(ret: *const T, func: &str) {
    if ret.is_null() {
        panic!("Error in {}: {}", func, io::Error::last_os_error());
    }
}
