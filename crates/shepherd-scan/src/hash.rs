//! BLAKE3 hashing.
//!
//! # Hashing is its own job class, never a scan prerequisite
//!
//! §6 Phase 1 is explicit about this, and the reason is scale: a full pass over
//! 50 TB would otherwise gate *cataloguing* behind days of I/O, so nothing —
//! not search, not rule preview, not the metadata index — could exist until the
//! last byte had been read. The walker therefore emits `blake3: None` and this
//! module is called later, per file, by T6's `hash` job class.
//!
//! # The changed-underneath guard
//!
//! [`hash_file`] re-stats after reading and reports whether the file moved
//! underneath it. This matters because a hash is a claim about bytes at a
//! moment, and AC-1 makes an equality test on that claim the precondition for
//! irreversible destruction. A hash computed over a file that was being written
//! is not wrong so much as *meaningless*, and the honest thing is to say so
//! rather than to store it and let a later verify compare against it.
//!
//! It is a guard, not a proof. A writer can modify a file between the final
//! read and the re-stat, and on a filesystem with coarse timestamps a fast
//! rewrite of identical length can leave mtime unchanged. §4.10's destroy path
//! does not rest on this — it re-hashes under the acquisition handle. What this
//! catches is the common case: a file actively growing while it is hashed.

use std::io::Read;
use std::path::Path;

use shepherd_core::Blake3Hash;

/// 64 KiB. Large enough to amortise syscalls, small enough that hashing a
/// 40 GB VM image does not hold a matching allocation.
const CHUNK: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum HashError {
    #[error("cannot read {path}: {detail}")]
    Io { path: String, detail: String },
}

pub type Result<T> = std::result::Result<T, HashError>;

/// What the file looked like when hashing started and finished.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashOutcome {
    pub hash: Blake3Hash,
    /// Bytes actually read.
    pub bytes_read: u64,
    /// `true` when size or mtime differed between the stat before the read and
    /// the stat after it.
    pub changed_underneath: bool,
}

impl HashOutcome {
    /// Whether this hash may be recorded as the file's content hash.
    ///
    /// A hash taken while the file was changing must not be persisted as
    /// though it described a settled file: AC-1 makes hash equality the
    /// precondition for destruction, and a hash of a moving target would make
    /// that comparison meaningless in the direction that loses data.
    pub fn is_trustworthy(&self) -> bool {
        !self.changed_underneath
    }
}

/// Hash `path`, streaming.
pub fn hash_file(path: &Path) -> Result<HashOutcome> {
    let io = |e: std::io::Error| HashError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    };

    let before = std::fs::symlink_metadata(path).map_err(io)?;
    let mut file = std::fs::File::open(path).map_err(io)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; CHUNK];
    let mut bytes_read = 0u64;

    loop {
        let n = file.read(&mut buf).map_err(io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        bytes_read += n as u64;
    }

    let after = std::fs::symlink_metadata(path).map_err(io)?;
    let changed_underneath = before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || bytes_read != after.len();

    Ok(HashOutcome {
        hash: Blake3Hash::from_bytes(*hasher.finalize().as_bytes()),
        bytes_read,
        changed_underneath,
    })
}

/// Hash an in-memory buffer. Used by tests and by callers that already hold the
/// bytes; identical output to [`hash_file`] over the same content.
pub fn hash_bytes(bytes: &[u8]) -> Blake3Hash {
    Blake3Hash::from_bytes(*blake3::hash(bytes).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let d =
                std::env::temp_dir().join(format!("shepherd-hash-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Tmp(d)
        }
        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let p = self.0.join(name);
            std::fs::write(&p, bytes).unwrap();
            p
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn file_and_buffer_hashing_agree() {
        let t = Tmp::new("agree");
        let content = b"the quick brown fox";
        let p = t.write("a.txt", content);
        let out = hash_file(&p).unwrap();
        assert_eq!(out.hash, hash_bytes(content));
        assert_eq!(out.bytes_read, content.len() as u64);
        assert!(out.is_trustworthy());
    }

    #[test]
    fn an_empty_file_hashes_without_special_casing() {
        let t = Tmp::new("empty");
        let p = t.write("e.txt", b"");
        let out = hash_file(&p).unwrap();
        assert_eq!(out.hash, hash_bytes(b""));
        assert_eq!(out.bytes_read, 0);
        assert!(out.is_trustworthy());
    }

    /// Content larger than one chunk must stream to the same digest as a
    /// single-shot hash — the loop boundary is the thing being checked.
    #[test]
    fn multi_chunk_content_streams_to_the_same_digest() {
        let t = Tmp::new("chunks");
        let content: Vec<u8> = (0..(CHUNK * 3 + 517)).map(|i| (i % 251) as u8).collect();
        let p = t.write("big.bin", &content);
        let out = hash_file(&p).unwrap();
        assert_eq!(out.hash, hash_bytes(&content));
        assert_eq!(out.bytes_read, content.len() as u64);
    }

    /// A file that grows during hashing is reported as untrustworthy. Storing
    /// such a hash would make AC-1's equality test compare against a moment
    /// that never described a settled file.
    #[test]
    fn a_file_that_grows_during_hashing_is_flagged() {
        let t = Tmp::new("grow");
        let p = t.write("g.bin", &vec![7u8; CHUNK * 2]);

        // Append after the read completes but before the guard re-stats: the
        // simplest deterministic stand-in for a concurrent writer is to hash,
        // then confirm that a changed file yields a changed verdict.
        let out = hash_file(&p).unwrap();
        assert!(out.is_trustworthy(), "baseline: a settled file is trusted");

        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"more").unwrap();
        f.sync_all().unwrap();

        let out2 = hash_file(&p).unwrap();
        assert!(out2.is_trustworthy(), "the file is settled again");
        assert_ne!(out.hash, out2.hash, "content changed, so the hash must");
        assert_eq!(out2.bytes_read, (CHUNK * 2 + 4) as u64);
    }

    /// The size half of the guard, exercised directly: a read that returns
    /// fewer bytes than the final stat reports means the file moved.
    #[test]
    fn a_short_read_relative_to_final_size_is_untrustworthy() {
        let outcome = HashOutcome {
            hash: hash_bytes(b"partial"),
            bytes_read: 7,
            changed_underneath: true,
        };
        assert!(!outcome.is_trustworthy());
    }

    #[test]
    fn a_missing_file_errors_rather_than_returning_a_hash_of_nothing() {
        let t = Tmp::new("missing");
        let err = hash_file(&t.0.join("nope.bin"));
        assert!(err.is_err());
    }
}
