use crate::error::{ACLError, FLAG_WRITE};
use crate::iter::RawACLIterator;
use crate::util::{check_pointer, check_return, path_to_cstring, AutoPtr};
use crate::Qualifier::*;
use crate::{ACLEntry, Qualifier, ACL_RWX};
use acl_sys::{
    acl_add_perm, acl_calc_mask, acl_clear_perms, acl_create_entry, acl_delete_entry, acl_entry_t,
    acl_get_file, acl_get_permset, acl_init, acl_permset_t, acl_set_file, acl_set_permset,
    acl_set_qualifier, acl_set_tag_type, acl_t, acl_to_text, acl_type_t, acl_valid,
    ACL_TYPE_ACCESS, ACL_TYPE_DEFAULT,
};
use libc::ssize_t;
use std::os::raw::c_void;
use std::path::Path;
use std::ptr::null_mut;
use std::slice::from_raw_parts;
use std::str::from_utf8;
use std::{fmt, mem};

/// The ACL of a file.
///
/// Implements a "mapping-like" interface where key is the `Qualifier` enum and value is `u32`
/// containing permission bits.
/// Using methods `get(qual) -> perms`, `set(qual, perms)`, `remove(qual)`.
#[allow(clippy::upper_case_acronyms)]
pub struct PosixACL {
    pub(crate) acl: acl_t,
}

/// Custom debug formatting, since output `PosixACL { acl: 0x7fd74c000ca8 }` is not very helpful.
impl fmt::Debug for PosixACL {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Not really a tuple, but tuple formatting is compact.
        fmt.debug_tuple("PosixACL")
            .field(&self.compact_text())
            .finish()
    }
}

impl Drop for PosixACL {
    fn drop(&mut self) {
        AutoPtr(self.acl);
    }
}

impl PartialEq for PosixACL {
    fn eq(&self, other: &Self) -> bool {
        self.entries() == other.entries()
    }
}

impl PosixACL {
    /// Convert a file mode ("chmod" number) into a "minimal" ACL. This is the primary constructor.
    /// Note that modes are usually expressed in octal, e.g. `PosixACL::new(0o644)`
    ///
    /// This creates the minimal required entries. By the POSIX ACL spec, every valid ACL must
    /// contain at least three entries: `UserObj`, `GroupObj` and `Other`, corresponding to file
    /// mode bits.
    ///
    /// Input bits higher than 9 (e.g. SUID flag, etc) are ignored.
    ///
    /// ```
    /// use posix_acl::PosixACL;
    /// assert_eq!(
    ///     PosixACL::new(0o751).as_text(),
    ///     "user::rwx\ngroup::r-x\nother::--x\n"
    /// );
    /// ```
    #[must_use]
    pub fn new(file_mode: u32) -> PosixACL {
        let mut acl = PosixACL::empty();
        acl.set(UserObj, (file_mode >> 6) & ACL_RWX);
        acl.set(GroupObj, (file_mode >> 3) & ACL_RWX);
        acl.set(Other, file_mode & ACL_RWX);
        acl
    }

    /// Create an empty ACL. NB! Empty ACLs are NOT considered valid.
    #[must_use]
    pub fn empty() -> PosixACL {
        PosixACL::with_capacity(6)
    }

    /// Create an empty ACL with capacity. NB! Empty ACLs are NOT considered valid.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> PosixACL {
        let acl = unsafe { acl_init(capacity as i32) };
        check_pointer(acl, "acl_init");
        PosixACL { acl }
    }

    /// Read a path's access ACL and return as `PosixACL` object.
    /// ```
    /// use posix_acl::PosixACL;
    /// let acl = PosixACL::read_acl("/etc/shells").unwrap();
    /// ```
    ///
    /// # Errors
    /// * `ACLError::IoError`: Filesystem errors (file not found, permission denied, etc).
    ///
    /// <div class="warning">
    /// It is NOT an error if the provided path has no ACL; a minimal ACL will be returned.
    /// </div>
    pub fn read_acl<P: AsRef<Path>>(path: P) -> Result<PosixACL, ACLError> {
        Self::read_acl_flags(path.as_ref(), ACL_TYPE_ACCESS)
    }

    /// Read a directory's default ACL and return as `PosixACL` object.
    /// This will fail if `path` is not a directory.
    ///
    /// Default ACL determines permissions for new files and subdirectories created in the
    /// directory.
    /// ```
    /// use posix_acl::PosixACL;
    /// let acl = PosixACL::read_default_acl("/tmp").unwrap();
    /// ```
    ///
    /// # Errors
    /// * `ACLError::IoError`: Filesystem errors (file not found, permission denied, etc).
    /// * Passing a non-directory path will fail with 'permission denied' error on Linux.
    ///
    /// <div class="warning">
    /// It is NOT an error if the provided path has no ACL; an empty ACL will be returned.
    /// </div>
    pub fn read_default_acl<P: AsRef<Path>>(path: P) -> Result<PosixACL, ACLError> {
        Self::read_acl_flags(path.as_ref(), ACL_TYPE_DEFAULT)
    }

    fn read_acl_flags(path: &Path, flags: acl_type_t) -> Result<PosixACL, ACLError> {
        let c_path = path_to_cstring(path);
        let acl: acl_t = unsafe { acl_get_file(c_path.as_ptr(), flags) };
        if acl.is_null() {
            Err(ACLError::last_os_error(flags))
        } else {
            Ok(PosixACL { acl })
        }
    }

    /// Validate and write this ACL to a path's access ACL. Overwrites any existing access ACL.
    ///
    /// Note: this function takes mutable `self` because it automatically re-calculates the magic
    /// `Mask` entry.
    ///
    /// # Errors
    /// * `ACLError::IoError`: Filesystem errors (file not found, permission denied, etc).
    /// * `ACLError::ValidationError`: The ACL failed validation. See [`PosixACL::validate()`] for
    ///    more information.
    pub fn write_acl<P: AsRef<Path>>(&mut self, path: P) -> Result<(), ACLError> {
        self.write_acl_flags(path.as_ref(), ACL_TYPE_ACCESS)
    }

    /// Validate and write this ACL to a directory's default ACL. Overwrites existing default ACL.
    /// This will fail if `path` is not a directory.
    ///
    /// Default ACL determines permissions for new files and subdirectories created in the
    /// directory.
    ///
    /// Note: this function takes mutable `self` because it automatically re-calculates the magic
    /// `Mask` entry.
    ///
    /// # Errors
    /// * `ACLError::IoError`: Filesystem errors (file not found, permission denied, etc).
    /// * `ACLError::ValidationError`: The ACL failed validation. See [`PosixACL::validate()`] for
    ///    more information.
    pub fn write_default_acl<P: AsRef<Path>>(&mut self, path: P) -> Result<(), ACLError> {
        self.write_acl_flags(path.as_ref(), ACL_TYPE_DEFAULT)
    }

    fn write_acl_flags(&mut self, path: &Path, flags: acl_type_t) -> Result<(), ACLError> {
        let c_path = path_to_cstring(path);
        self.fix_mask();
        self.validate()?;
        let ret = unsafe { acl_set_file(c_path.as_ptr(), flags, self.acl) };
        if ret == 0 {
            Ok(())
        } else {
            Err(ACLError::last_os_error(FLAG_WRITE | flags))
        }
    }

    /// Iterator of `acl_entry_t`, unsafe
    pub(crate) unsafe fn raw_iter(&self) -> RawACLIterator {
        RawACLIterator::new(self)
    }

    /// Get all `ACLEntry` items. The POSIX ACL C API does not allow multiple parallel iterators so we
    /// return a materialized vector just to be safe.
    pub fn entries(&self) -> Vec<ACLEntry> {
        unsafe { self.raw_iter() }
            .map(ACLEntry::from_entry)
            .collect()
    }

    /// Get the current `perm` value of `qual`, if any.
    #[must_use]
    pub fn get(&self, qual: Qualifier) -> Option<u32> {
        let entry = self.raw_get_entry(&qual)?;

        // XXX inefficient, no need to construct ACLEntry.
        Some(ACLEntry::from_entry(entry).perm)
    }

    /// Set the permission of `qual` to `perm`. If this `qual` already exists, it is updated,
    /// otherwise a new one is added.
    ///
    /// `perm` must be a combination of the `ACL_` constants, combined by binary OR.
    pub fn set(&mut self, qual: Qualifier, perm: u32) {
        let entry = match self.raw_get_entry(&qual) {
            Some(v) => v,
            None => self.raw_add_entry(&qual),
        };

        Self::raw_set_permset(entry, perm);
    }

    /// Remove entry with matching `qual`. If found, returns the matching `perm`, otherwise `None`
    #[allow(clippy::must_use_candidate)]
    pub fn remove(&self, qual: Qualifier) -> Option<u32> {
        let entry = self.raw_get_entry(&qual)?;
        let wrapped = ACLEntry::from_entry(entry);

        unsafe {
            acl_delete_entry(self.acl, entry);
        }

        // XXX inefficient, no need to construct ACLEntry.
        Some(wrapped.perm)
    }

    fn raw_set_permset(entry: acl_entry_t, perm: u32) {
        unsafe {
            let mut permset: acl_permset_t = null_mut();
            check_return(acl_get_permset(entry, &mut permset), "acl_get_permset");
            check_return(acl_clear_perms(permset), "acl_clear_perms");
            check_return(acl_add_perm(permset, perm), "acl_add_perm");
            check_return(acl_set_permset(entry, permset), "acl_set_permset");
        }
    }

    fn raw_get_entry(&self, qual: &Qualifier) -> Option<acl_entry_t> {
        unsafe { self.raw_iter() }.find(
            // XXX this is slightly inefficient, calls to get_entry_uid() could be short-circuited.
            |&entry| Qualifier::from_entry(entry) == *qual,
        )
    }

    fn raw_add_entry(&mut self, qual: &Qualifier) -> acl_entry_t {
        let mut entry: acl_entry_t = null_mut();
        unsafe {
            check_return(
                acl_create_entry(&mut self.acl, &mut entry),
                "acl_create_entry",
            );
            check_return(acl_set_tag_type(entry, qual.tag_type()), "acl_set_tag_type");
            if let Some(uid) = qual.uid() {
                check_return(
                    acl_set_qualifier(entry, &uid as *const u32 as *const c_void),
                    "acl_set_qualifier",
                );
            }
        }
        entry
    }

    /// Re-calculate the `Qualifier::Mask` entry.
    ///
    /// Usually there is no need to call this directly, as this is done during
    /// `write_acl/write_default_acl()` automatically.
    pub fn fix_mask(&mut self) {
        unsafe {
            check_return(acl_calc_mask(&mut self.acl), "acl_calc_mask");
        }
    }

    /// Return the textual representation of the ACL. Individual entries are separated by newline
    /// (`'\n'`).
    ///
    /// UID/GID are automatically resolved to names by the platform.
    ///
    /// # Panics
    ///
    /// When platform returns a string that is not valid UTF-8.
    #[must_use]
    pub fn as_text(&self) -> String {
        let mut len: ssize_t = 0;
        let txt = AutoPtr(unsafe { acl_to_text(self.acl, &mut len) });
        check_pointer(txt.0, "acl_to_text");
        let chars = unsafe { from_raw_parts(txt.0 as *const u8, len as usize) };

        from_utf8(chars).unwrap().to_string()
    }

    fn compact_text(&self) -> String {
        self.as_text().trim_end().replace('\n', ",")
    }

    /// Call the platform's validation function.
    ///
    /// Usually there is no need to explicitly call this method, the `write_acl()` method validates
    /// ACL prior to writing.
    /// If you didn't take special care of the `Mask` entry, it may be necessary to call
    /// `fix_mask()` prior to `validate()`.
    ///
    /// # Errors
    /// * `ACLError::ValidationError`: The ACL failed validation.
    ///
    /// Unfortunately it is not possible to provide detailed error reasons, but mainly it can be:
    /// * Required entries are missing (`UserObj`, `GroupObj`, `Mask` and `Other`).
    /// * ACL contains entries that are not unique.
    pub fn validate(&self) -> Result<(), ACLError> {
        let ret = unsafe { acl_valid(self.acl) };
        if ret == 0 {
            Ok(())
        } else {
            Err(ACLError::validation_error())
        }
    }

    /// Consumes the `PosixACL`, returning the wrapped `acl_t`.
    /// This can then be used directly in FFI calls to the acl library.
    ///
    /// To avoid a memory leak, the `acl_t` must either:
    ///
    /// - Be converted back to a `PosixACL` using [`PosixACL::from_raw()`]
    /// - Have `acl_free()` called on it
    //
    // Note: it's typically considered safe for Rust functions to leak resources (in this specific
    // case, the function is analogous to the safe `Rc::into_raw` function in the standard library).
    // For more discussion on this, see [the nomicon](https://doc.rust-lang.org/nomicon/leaking.html).
    #[must_use]
    pub fn into_raw(self) -> acl_t {
        let acl = self.acl;
        mem::forget(self);
        acl
    }

    /// Constructs a `PosixACL` from a raw `acl_t`. You should treat the `acl_t`
    /// as being 'consumed' by this function.
    ///
    /// # Safety
    ///
    /// The `acl_t` must be a valid ACL (not `(acl_t)NULL`) acl returned
    /// either [`PosixACL::into_raw()`] or another ACL library function.
    ///
    /// Improper usage of this function may lead to memory unsafety (e.g.
    /// calling it twice on the same acl may lead to a double free).
    pub unsafe fn from_raw(acl: acl_t) -> Self {
        Self { acl }
    }
}
