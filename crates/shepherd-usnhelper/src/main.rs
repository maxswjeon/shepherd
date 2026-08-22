//! Windows-only minimal privileged USN journal reader.
//!
//! Reads the USN change journal and streams records over a pipe. It has no
//! other capability by design (§4.2). It is built on every platform so the
//! workspace stays buildable in the Linux and macOS CI legs, but it refuses to
//! run anywhere but Windows.

#[cfg(windows)]
fn main() {
    eprintln!("shepherd-usnhelper: not implemented (Phase 4)");
    std::process::exit(1);
}

#[cfg(not(windows))]
fn main() {
    eprintln!("shepherd-usnhelper is Windows-only; this platform is unsupported.");
    std::process::exit(1);
}
