//! Example CLI app to read and print ACL of a file.
//!
//! Run with command: `cargo run --example printacl /some/path`

use posix_acl::Qualifier::*;
use posix_acl::{ACLEntry, ACLError, PosixACL, ACL_EXECUTE, ACL_READ, ACL_WRITE};
use std::env::args_os;
use std::path::Path;
use std::process::exit;

fn print_acl(acl: PosixACL) {
    let entries = acl.entries();
    if entries.is_empty() {
        // If no "default" ACL has been set on directories, they have 0 entries.
        println!("    (no entries)")
    }
    for entry in entries {
        let ACLEntry { qual, perm } = entry;
        println!(
            "    {}:{}{}{}",
            match qual {
                Undefined => "invalid:".into(),
                UserObj => "user:".into(),
                GroupObj => "group:".into(),
                Other => "other:".into(),
                User(uid) => format!("user:{}", uid),
                Group(gid) => format!("group:{}", gid),
                Mask => "mask:".into(),
            },
            if perm & ACL_READ != 0 { "r" } else { "-" },
            if perm & ACL_WRITE != 0 { "w" } else { "-" },
            if perm & ACL_EXECUTE != 0 { "x" } else { "-" },
        )
    }
}

/// Returns 1 for error, 0 for success
fn handle_acl_result(result: Result<PosixACL, ACLError>, path: &Path, type_hint: &str) -> u32 {
    match result {
        Ok(acl) => {
            println!("{} {}:", path.display(), type_hint);
            print_acl(acl);
            0
        }
        Err(e) => {
            eprintln!("{}: {}", path.display(), e);
            1
        }
    }
}

fn main() {
    let args = args_os();
    if args.len() <= 1 {
        println!("Usage: printacl [FILE ...]");
        exit(1);
    }
    let mut errs = 0;

    for filename in args.skip(1) {
        let path = Path::new(&filename);
        errs += handle_acl_result(PosixACL::read_acl(path), path, "ACL");

        // Only directories have "default" ACLs
        if path.is_dir() {
            errs += handle_acl_result(PosixACL::read_default_acl(path), path, "DEFAULT");
        }
    }

    if errs > 0 {
        exit(2);
    }
}
