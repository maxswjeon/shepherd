//! Phase 0c / §6 — the hydration side, a SEPARATE IMAGE and a separate process
//! from `cfreg.exe`, which registered the sync root and then exited.
//!
//!   cfserve <syncroot> <relative-name> <size-bytes> <log-file> <seconds>
//!
//! 1. `CfConnectSyncRoot` with a `CF_CALLBACK_TYPE_FETCH_DATA` handler.
//! 2. `CfCreatePlaceholders` — the file exists, has a size, holds no data.
//! 3. Waits. A read from a THIRD process faults the placeholder, the callback
//!    fires here, and `CfExecute(TRANSFER_DATA)` supplies the bytes.
//!
//! `CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO` is requested so the callback can log
//! the pid and image path of whoever triggered it. Without that, "served from a
//! separate process" would rest on my say-so rather than on the kernel's.

use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;

use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::Storage::CloudFilters::*;
use windows::Win32::Storage::FileSystem::FILE_BASIC_INFO;
use windows::Win32::System::SystemInformation::GetSystemTimeAsFileTime;

include!("common.rs");

static DATA: OnceLock<Vec<u8>> = OnceLock::new();
static LOG: OnceLock<String> = OnceLock::new();
static SERVED: AtomicU32 = AtomicU32::new(0);

fn log(s: &str) {
    logline(LOG.get().map(String::as_str).unwrap_or(""), s);
}

/// `STATUS_SUCCESS`. Written out because `NTSTATUS(0)` on its own reads as a
/// placeholder rather than as a deliberate completion status.
const STATUS_SUCCESS: NTSTATUS = NTSTATUS(0);

unsafe extern "system" fn on_fetch_data(
    info: *const CF_CALLBACK_INFO,
    params: *const CF_CALLBACK_PARAMETERS,
) {
    let info = &*info;
    let fetch = &(*params).Anonymous.FetchData;

    // Who asked? This is the whole point of the experiment.
    let requester = if info.ProcessInfo.is_null() {
        "<no process info>".to_string()
    } else {
        let p = &*info.ProcessInfo;
        format!(
            "pid={} session={} image={:?} cmdline={:?}",
            p.ProcessId,
            p.SessionId,
            p.ImagePath.to_string().unwrap_or_default(),
            p.CommandLine.to_string().unwrap_or_default()
        )
    };
    log(&format!(
        "[serve] FETCH_DATA fired in pid {} — required offset={} len={} | requester {}",
        std::process::id(),
        fetch.RequiredFileOffset,
        fetch.RequiredLength,
        requester
    ));

    let data = DATA.get().expect("data set before connect");
    let start = fetch.RequiredFileOffset.max(0) as usize;
    let want = fetch.RequiredLength.max(0) as usize;
    let end = start.saturating_add(want).min(data.len());
    if start >= end {
        log("[serve] nothing to transfer for that range");
        return;
    }
    let slice = &data[start..end];

    let mut opinfo = CF_OPERATION_INFO::default();
    opinfo.StructSize = std::mem::size_of::<CF_OPERATION_INFO>() as u32;
    opinfo.Type = CF_OPERATION_TYPE_TRANSFER_DATA;
    opinfo.ConnectionKey = info.ConnectionKey;
    opinfo.TransferKey = info.TransferKey;
    opinfo.RequestKey = info.RequestKey;
    opinfo.CorrelationVector = info.CorrelationVector as *const _;

    let mut opparams = CF_OPERATION_PARAMETERS::default();
    // CF_SIZE_OF_OP_PARAM(TransferData): the offset of the union plus the size
    // of the arm actually used. A whole-struct size_of would be wrong.
    opparams.ParamSize = (std::mem::offset_of!(CF_OPERATION_PARAMETERS, Anonymous)
        + std::mem::size_of::<CF_OPERATION_PARAMETERS_0_6>()) as u32;
    opparams.Anonymous.TransferData = CF_OPERATION_PARAMETERS_0_6 {
        Flags: CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
        CompletionStatus: STATUS_SUCCESS,
        Buffer: slice.as_ptr() as *const c_void,
        Offset: start as i64,
        Length: (end - start) as i64,
    };

    match CfExecute(&opinfo, &mut opparams) {
        Ok(()) => {
            SERVED.fetch_add(1, Ordering::SeqCst);
            log(&format!(
                "[serve] CfExecute(TRANSFER_DATA) OK — {} bytes at offset {}",
                end - start,
                start
            ));
        }
        Err(e) => log(&format!(
            "[serve] CfExecute FAILED 0x{:08X} {}",
            e.code().0 as u32,
            e.message()
        )),
    }
}

unsafe extern "system" fn on_fetch_placeholders(
    info: *const CF_CALLBACK_INFO,
    params: *const CF_CALLBACK_PARAMETERS,
) {
    let info = &*info;
    let fp = &(*params).Anonymous.FetchPlaceholders;
    log(&format!(
        "[serve] FETCH_PLACEHOLDERS fired in pid {} — pattern={:?}",
        std::process::id(),
        fp.Pattern.to_string().unwrap_or_default()
    ));

    // The namespace is already fully populated by CfCreatePlaceholders, so the
    // honest answer is "nothing more, stop asking". Answering at all is the
    // point: the previous run registered only FETCH_DATA, and an unanswered
    // FETCH_PLACEHOLDERS is what an outside `dir` was timing out on.
    let mut opinfo = CF_OPERATION_INFO::default();
    opinfo.StructSize = std::mem::size_of::<CF_OPERATION_INFO>() as u32;
    opinfo.Type = CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS;
    opinfo.ConnectionKey = info.ConnectionKey;
    opinfo.TransferKey = info.TransferKey;
    opinfo.RequestKey = info.RequestKey;
    opinfo.CorrelationVector = info.CorrelationVector as *const _;

    let mut opparams = CF_OPERATION_PARAMETERS::default();
    opparams.ParamSize = (std::mem::offset_of!(CF_OPERATION_PARAMETERS, Anonymous)
        + std::mem::size_of::<CF_OPERATION_PARAMETERS_0_7>()) as u32;
    opparams.Anonymous.TransferPlaceholders = CF_OPERATION_PARAMETERS_0_7 {
        Flags: CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_DISABLE_ON_DEMAND_POPULATION,
        CompletionStatus: STATUS_SUCCESS,
        PlaceholderTotalCount: 0,
        PlaceholderArray: std::ptr::null_mut(),
        PlaceholderCount: 0,
        EntriesProcessed: 0,
    };
    match CfExecute(&opinfo, &mut opparams) {
        Ok(()) => log("[serve] CfExecute(TRANSFER_PLACEHOLDERS) OK — namespace declared complete"),
        Err(e) => log(&format!(
            "[serve] CfExecute(TRANSFER_PLACEHOLDERS) FAILED 0x{:08X} {}",
            e.code().0 as u32,
            e.message()
        )),
    }
}

unsafe extern "system" fn on_cancel_fetch_data(
    _info: *const CF_CALLBACK_INFO,
    _params: *const CF_CALLBACK_PARAMETERS,
) {
    log("[serve] CANCEL_FETCH_DATA fired — the platform gave up on a hydration");
}

fn now_filetime() -> i64 {
    let ft = unsafe { GetSystemTimeAsFileTime() };
    ((ft.dwHighDateTime as i64) << 32) | (ft.dwLowDateTime as i64 & 0xFFFF_FFFF)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 6 {
        eprintln!("usage: cfserve <syncroot> <relname> <size> <logfile> <seconds>");
        std::process::exit(64);
    }
    let root = args[1].clone();
    let relname = args[2].clone();
    let size: usize = args[3].parse().expect("size");
    LOG.set(args[4].clone()).ok();
    let seconds: u64 = args[5].parse().expect("seconds");

    // Deterministic content so the reader can verify it got the real bytes and
    // not zeroes — a placeholder that hydrates to zeroes would look identical
    // to a successful transfer from the reader's side.
    let content: Vec<u8> = (0..size).map(|i| b'A' + (i % 26) as u8).collect();
    DATA.set(content.clone()).ok();

    log(&format!(
        "[serve] pid={} image={} — connecting to {root}",
        std::process::id(),
        args[0]
    ));

    let table = [
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_FETCH_DATA,
            Callback: Some(on_fetch_data),
        },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS,
            Callback: Some(on_fetch_placeholders),
        },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_CANCEL_FETCH_DATA,
            Callback: Some(on_cancel_fetch_data),
        },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_NONE,
            Callback: None,
        },
    ];

    let rootw = HSTRING::from(root.as_str());
    let key = match unsafe {
        CfConnectSyncRoot(
            &rootw,
            table.as_ptr(),
            None,
            CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO | CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH,
        )
    } {
        Ok(k) => {
            log(&format!("[serve] CfConnectSyncRoot OK — connection key {}", k.0));
            k
        }
        Err(e) => {
            log(&format!(
                "[serve] CfConnectSyncRoot FAILED 0x{:08X} {}",
                e.code().0 as u32,
                e.message()
            ));
            std::process::exit(1);
        }
    };

    // --- create the placeholder -------------------------------------------
    let relw = HSTRING::from(relname.as_str());
    let identity: [u8; 8] = *b"shepherd";
    let t = now_filetime();
    let mut create = [CF_PLACEHOLDER_CREATE_INFO {
        RelativeFileName: PCWSTR(relw.as_ptr()),
        FsMetadata: CF_FS_METADATA {
            BasicInfo: FILE_BASIC_INFO {
                CreationTime: t,
                LastAccessTime: t,
                LastWriteTime: t,
                ChangeTime: t,
                FileAttributes: 0x80, // FILE_ATTRIBUTE_NORMAL
            },
            FileSize: size as i64,
        },
        FileIdentity: identity.as_ptr() as *const c_void,
        FileIdentityLength: identity.len() as u32,
        Flags: CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC,
        Result: windows::core::HRESULT(0),
        CreateUsn: 0,
    }];
    let mut processed = 0u32;
    match unsafe {
        CfCreatePlaceholders(
            &rootw,
            &mut create,
            CF_CREATE_FLAG_NONE,
            Some(&mut processed),
        )
    } {
        Ok(()) => log(&format!(
            "[serve] CfCreatePlaceholders OK — {processed} entry, per-entry hr=0x{:08X}, {relname} is a {size}-byte placeholder",
            create[0].Result.0 as u32
        )),
        Err(e) => log(&format!(
            "[serve] CfCreatePlaceholders FAILED 0x{:08X} {} (per-entry hr=0x{:08X})",
            e.code().0 as u32,
            e.message(),
            create[0].Result.0 as u32
        )),
    }

    // --- what does the PROVIDER ITSELF see? ------------------------------
    // The external `dir` showed nothing. Before concluding the placeholder was
    // never created, ask the one process that is connected to the sync root.
    let full = std::path::Path::new(&root).join(&relname);
    match std::fs::metadata(&full) {
        Ok(m) => log(&format!(
            "[selfcheck] provider stat OK — len={} readonly={}",
            m.len(),
            m.permissions().readonly()
        )),
        Err(e) => log(&format!("[selfcheck] provider stat FAILED — {e} (raw={:?})", e.raw_os_error())),
    }
    match std::fs::read_dir(&root) {
        Ok(rd) => {
            let names: Vec<String> = rd
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            log(&format!("[selfcheck] provider read_dir OK — {:?}", names));
        }
        Err(e) => log(&format!(
            "[selfcheck] provider read_dir FAILED — {e} (raw={:?})",
            e.raw_os_error()
        )),
    }
    let plain = std::path::Path::new(&root).join("plain-from-provider.txt");
    match std::fs::write(&plain, b"provider") {
        Ok(()) => log("[selfcheck] provider wrote an ORDINARY file into the sync root — OK"),
        Err(e) => log(&format!(
            "[selfcheck] provider ORDINARY write FAILED — {e} (raw={:?})",
            e.raw_os_error()
        )),
    }

    log("[serve] READY — waiting for a read from another process");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    while std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    log(&format!(
        "[serve] done — served {} FETCH_DATA callback(s)",
        SERVED.load(Ordering::SeqCst)
    ));
    let _ = unsafe { CfDisconnectSyncRoot(key) };
    log("[serve] disconnected");
}
