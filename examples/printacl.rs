//! Example CLI app to read and print ACL of a file.
//!
//! Run with command: `cargo run --example printacl /some/path`

use posix_acl::Qualifier::*;
use posix_acl::{ACLEntry, PosixACL, ACL_EXECUTE, ACL_READ, ACL_WRITE};
use std::env::args_os;
use std::path::Path;
use std::process::exit;

fn print_acl(acl: PosixACL) {
    let entries = acl.entries();
    if entries.is_empty() {
        // Happens
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

fn main() {
    let args = args_os();
    if args.len() <= 1 {
        println!("Usage: printacl [FILE ...]");
        exit(1);
    }

    for filename in args.skip(1) {
        let path = Path::new(&filename);
        match PosixACL::read_acl(path) {
            Ok(acl) => {
                println!("{} ACL:", path.display());
                print_acl(acl)
            }
            Err(e) => eprintln!("{}: {}", path.display(), e),
        }
        if path.is_dir() {
            match PosixACL::read_default_acl(path) {
                Ok(acl) => {
                    println!("{} DEFAULT:", path.display());
                    print_acl(acl)
                }
                Err(e) => eprintln!("{}: {}", path.display(), e),
            }
        }
        println!();
    }
}
