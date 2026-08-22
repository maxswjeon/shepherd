//! Phase 0c / §6 — the registration side, deliberately a SEPARATE IMAGE from
//! `cfserve.exe`.
//!
//! Subcommands:
//!   query <path>       CfGetSyncRootInfoByPath      — does a registration made
//!                                                     by an already-exited
//!                                                     process still exist?
//!   register <path>    CfRegisterSyncRoot, FLAG_NONE
//!   unregister <path>  CfUnregisterSyncRoot
//!
//! `register` exits immediately afterwards. That exit is the experiment: if
//! `cfserve.exe` can then connect and hydrate, registration and connection are
//! decoupled, which is what §6 asks.

use std::path::PathBuf;

use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Storage::CloudFilters::*;

include!("common.rs");

fn query(root: &str) -> i32 {
    let path = HSTRING::from(root);
    let mut rc = 0;
    for (name, class) in [
        ("BASIC", CF_SYNC_ROOT_INFO_BASIC),
        ("STANDARD", CF_SYNC_ROOT_INFO_STANDARD),
        ("PROVIDER", CF_SYNC_ROOT_INFO_PROVIDER),
    ] {
        let mut buf = vec![0u8; 4096];
        let mut used = 0u32;
        let r = unsafe {
            CfGetSyncRootInfoByPath(
                &path,
                class,
                buf.as_mut_ptr() as *mut _,
                buf.len() as u32,
                Some(&mut used),
            )
        };
        match r {
            Ok(()) => logline("", &format!("[query:{name}] OK — {used} bytes returned")),
            Err(e) => {
                rc = 1;
                logline(
                    "",
                    &format!(
                        "[query:{name}] FAILED 0x{:08X} {}",
                        e.code().0 as u32,
                        e.message()
                    ),
                );
            }
        }
    }
    rc
}

fn register(root: &str) -> i32 {
    let dir = PathBuf::from(root);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        logline("", &format!("[register] mkdir failed: {e}"));
        return 2;
    }
    let path = HSTRING::from(dir.as_os_str());

    let name = HSTRING::from("ShepherdDecoupleProbe");
    let ver = HSTRING::from("1.0");
    let mut info = CF_SYNC_REGISTRATION::default();
    info.StructSize = std::mem::size_of::<CF_SYNC_REGISTRATION>() as u32;
    info.ProviderName = PCWSTR(name.as_ptr());
    info.ProviderVersion = PCWSTR(ver.as_ptr());

    let mut pol = CF_SYNC_POLICIES::default();
    pol.StructSize = std::mem::size_of::<CF_SYNC_POLICIES>() as u32;
    pol.Hydration.Primary = CF_HYDRATION_POLICY_PRIMARY(CF_HYDRATION_POLICY_FULL.0);
    pol.Population.Primary = CF_POPULATION_POLICY_PRIMARY(CF_POPULATION_POLICY_FULL.0);
    pol.InSync = CF_INSYNC_POLICY_TRACK_ALL;
    pol.HardLink = CF_HARDLINK_POLICY_NONE;

    match unsafe { CfRegisterSyncRoot(&path, &info, &pol, CF_REGISTER_FLAG_NONE) } {
        Ok(()) => {
            logline(
                "",
                &format!(
                    "[register] OK — pid {} registered {root} with CF_REGISTER_FLAG_NONE",
                    std::process::id()
                ),
            );
            logline("", "[register] this process now EXITS. Anything that works after this line is decoupled from it.");
            0
        }
        Err(e) => {
            logline(
                "",
                &format!(
                    "[register] REFUSED 0x{:08X} {}",
                    e.code().0 as u32,
                    e.message()
                ),
            );
            1
        }
    }
}

fn unregister(root: &str) -> i32 {
    let path = HSTRING::from(root);
    match unsafe { CfUnregisterSyncRoot(&path) } {
        Ok(()) => {
            logline("", &format!("[unregister] OK — {root}"));
            0
        }
        Err(e) => {
            logline(
                "",
                &format!(
                    "[unregister] failed 0x{:08X} {}",
                    e.code().0 as u32,
                    e.message()
                ),
            );
            1
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: cfreg <query|register|unregister> <path>");
        std::process::exit(64);
    }
    logline("", &format!("[cfreg] pid={} image={}", std::process::id(), args[0]));
    let code = match args[1].as_str() {
        "query" => query(&args[2]),
        "register" => register(&args[2]),
        "unregister" => unregister(&args[2]),
        other => {
            eprintln!("unknown subcommand {other}");
            64
        }
    };
    std::process::exit(code);
}
