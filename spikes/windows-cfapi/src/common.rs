// Shared helpers, `include!`d rather than made a lib so each probe binary is an
// independent image on disk — the §6 question is about separate processes, and
// a sceptic can point at two different .exe paths.

use std::io::Write;

#[allow(dead_code)]
pub fn logline(log: &str, s: &str) {
    let line = format!("{s}\n");
    print!("{line}");
    let _ = std::io::stdout().flush();
    if !log.is_empty() {
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(log) {
            let _ = f.write_all(line.as_bytes());
            let _ = f.flush();
        }
    }
}
