//! `gen-files` — materialise a corpus of **real files on a real filesystem**.
//!
//! # Why this exists when `gen-catalog` already does
//!
//! §9 splits M1 into two legs on purpose, and they need two different fixtures.
//!
//! * The **scale** leg is `gen-catalog`: ten million *rows* injected straight
//!   into SQLite, so that the < 50 ms p95 bar measures the index and nothing
//!   else. No filesystem is involved, deliberately — a disk that stats slowly
//!   would otherwise contaminate a number that is about search.
//! * The **functional** leg is this file: `shepctl root add && scan start &&
//!   search` has to walk a real tree, so the tree has to exist. Its bar is
//!   *correctness at a million files*, not throughput.
//!
//! Conflating the two is the mistake this module is shaped to prevent. Nothing
//! here measures latency, and nothing here should ever be reported against the
//! scale bar.
//!
//! # The corpus has to make a wrong answer look wrong
//!
//! A corpus of a million near-identical files proves almost nothing. A `search`
//! that matched on the wrong field, ignored path scope, folded case when it
//! should not, or silently returned a truncated page would all still come back
//! with a plausible-looking count. So the ground truth here is built from
//! **reserved tokens** — every one begins `zz`, which no word, directory name or
//! extension in [`crate::generate`]'s vocabulary can produce, in any case — each
//! planted at a distinct deterministic residue, giving each needle class its own
//! non-round count:
//!
//! | class | where the token lands | what a wrong answer looks like |
//! |---|---|---|
//! | `zzprefix` | start of the filename | 0 if the index is empty |
//! | `zzinfix` | middle of the filename | 0 if only prefixes are matched |
//! | `zzpathfrag` | a **directory** name, never a filename | a name query returning the path count instead of 0 means scope is ignored |
//! | `zzcasemix` | filenames in two different cases | a case-*sensitive* match returns one of the two halves, not their sum |
//! | `.zzx` | a rare extension | the `ext` filter's own count |
//! | `zzdeep` | 24 levels down | 0 if the walker has a depth limit nobody declared |
//!
//! and three traps whose correct answer is **zero**:
//!
//! * `zzdenied` — files inside `.git/` and `node_modules/`. AC-7 says the walker
//!   never descends there. If it did, `files_seen` would be larger by exactly
//!   the recorded count and these would be searchable.
//! * `zzoutside` — files that live *outside* the root and are reachable only
//!   through a symlinked directory. This is the symlink guard's real test: a
//!   symlink pointing *inside* the root proves nothing, because the cycle guard
//!   would deduplicate it by `(dev, ino)` and the count would come out right for
//!   the wrong reason. Pointing outward is what makes following the link
//!   *visible*.
//! * `zzcycle` — `cyc/self -> ..`, the loop the walker must not enter.
//!
//! Every count in `manifest.json` is what the writer **actually wrote**, not
//! what a formula predicts. The walker is a completely independent
//! implementation, so `files_seen == expected_seen` is two unrelated counts
//! agreeing rather than one of them checking itself.
//!
//! # The manifest lives outside the root
//!
//! `<dest>/root/` is scanned; `<dest>/manifest.json` is not. A manifest written
//! inside the tree it describes would be walked, catalogued, counted, and — since
//! it contains every needle token — matched by every query in it.

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rayon::prelude::*;

use crate::Args;
use crate::generate::{dir_for, row};

// ---------------------------------------------------------------------------
// Shape constants
// ---------------------------------------------------------------------------

/// Files per directory in the organic body. Matches [`crate::generate`]'s own
/// ratio so the on-disk corpus and the injected-row corpus have the same tree
/// shape and their numbers stay comparable.
const FILES_PER_DIR: u64 = 50;

/// Residues that plant each needle class, tested in this order so that no file
/// carries two tokens and the classes partition cleanly.
///
/// Coprime-ish moduli chosen so every class lands on a different, non-round
/// count. Equal counts would let two classes be confused for one another
/// without the numbers changing.
const M_PREFIX: u64 = 727;
const M_INFIX: u64 = 471;
const M_PATHFRAG: u64 = 313;
const M_CASE_LOWER: u64 = 941;
const M_CASE_UPPER: u64 = 1327;
const M_EXT: u64 = 1181;

/// Below this the rarest class lands fewer than a handful of times and a count
/// assertion stops discriminating. Refused rather than silently degraded.
const MIN_ORGANIC: u64 = 5_000;

/// Files in the two deliberately over-full directories. NFS `readdir` on a
/// directory this size is a different code path from `readdir` on fifty
/// entries, and it is one of the things that plausibly breaks between nine
/// files and a million.
const FAT_DIRS: u64 = 2;

/// Depth of the deep chain, and how many files sit at the bottom of it.
const DEEP_DEPTH: usize = 24;
const DEEP_FILES: u64 = 17;

/// Files planted inside deny-listed directories (AC-7). Two different reasons —
/// `VersionControl` and `PackageCache` — so a deny-list that lost one rule
/// still fails.
const GIT_FILES: u64 = 211;
const NODE_MODULES_FILES: u64 = 353;

/// Files outside the root, reachable only across a symlinked directory.
const OUTSIDE_FILES: u64 = 137;

/// The three entries the symlink corner contributes to `files_seen`: a real
/// file, a symlink *to* that file (emitted, never followed), and a dangling
/// symlink (emitted too — `symlink_metadata` describes the link, and the link
/// exists).
const SYMLINK_ENTRIES: u64 = 3;

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/// One needle class: the token, the query that should find it, and the count
/// the writer actually produced.
#[derive(Debug, serde::Serialize)]
pub struct Needle {
    pub token: &'static str,
    /// The query string a client sends. Distinct from `token` for the
    /// path-fragment class, whose query carries the separator that selects
    /// `Scope::Path`.
    pub query: String,
    pub expect: u64,
    pub note: &'static str,
}

#[derive(Debug, serde::Serialize)]
pub struct Manifest {
    pub generator: &'static str,
    pub manifest_version: u32,
    pub seed: u64,
    /// Absolute path of the directory to hand to `root.add`.
    pub root: String,
    /// Files the walker must catalogue: exact, not approximate.
    pub expected_seen: u64,
    /// Sum of `symlink_metadata().len()` over exactly those files.
    pub expected_bytes: u64,
    pub dirs_created: u64,
    /// How many organic names needed a disambiguating suffix. Recorded because
    /// the number being non-zero is the interesting fact — it is the count of
    /// files a plain `File::create` would have silently overwritten.
    pub name_collisions: u64,
    pub organic_files: u64,
    pub fat_dir_files: u64,
    pub deep_files: u64,
    pub symlink_entries: u64,
    /// The two halves of the case-variant class, recorded separately so a test
    /// can assert the case-insensitive total is strictly larger than either —
    /// which is the only form of the assertion a case-*sensitive* match fails.
    pub case_lower_files: u64,
    pub case_upper_files: u64,
    pub needles: Vec<Needle>,
    /// Queries whose correct answer is zero.
    pub absent: Vec<AbsentCase>,
    /// Files that exist on disk but must never be catalogued, with the count
    /// `files_seen` would gain if the corresponding guard failed.
    pub traps: Vec<Trap>,
    /// A few real rows, for asserting that a hit carries the catalog's view of
    /// the file rather than just its name.
    pub samples: Vec<Sample>,
}

#[derive(Debug, serde::Serialize)]
pub struct AbsentCase {
    pub query: String,
    pub why: &'static str,
}

#[derive(Debug, serde::Serialize)]
pub struct Trap {
    pub name: &'static str,
    pub files: u64,
    pub token: &'static str,
    pub why: &'static str,
}

#[derive(Debug, serde::Serialize)]
pub struct Sample {
    pub rel_path: String,
    pub size: u64,
}

// ---------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------

/// Body length for file `i`: small, varied, and a pure function of the index so
/// `expected_bytes` is exact without stat-ing a million files back.
///
/// Varied rather than constant because a constant would make `bytes_seen` a
/// restatement of `files_seen` — one number checking itself.
#[inline]
fn body_len(i: u64) -> usize {
    1 + (crate::stream(0x00B0_D1E5, i) % 199) as usize
}

fn write_body(path: &Path, i: u64) -> std::io::Result<u64> {
    let n = body_len(i);
    // `create_new`, not `create`. A plain `create` truncates whatever is there
    // and reports success, which is exactly how thirty files went missing from
    // a corpus whose manifest said they were present. With O_EXCL a duplicate
    // path is an error the generator has to answer for.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    // A repeating pattern rather than zeroes: a sparse-file optimisation
    // somewhere in the stack would otherwise make the on-disk footprint
    // unrepresentative of a real corpus.
    let byte = b'a' + (i % 26) as u8;
    f.write_all(&vec![byte; n])?;
    Ok(n as u64)
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

/// Where an organic file's parent directory sits, relative to the root.
///
/// Reuses [`crate::generate::dir_for`] verbatim and re-roots its absolute path
/// as a relative one. Reuse rather than a second tree generator: the plan's
/// whole reproducibility story is that one corpus generator serves every phase,
/// and a filesystem tree that did not share the row fixture's shape would make
/// the functional and scale legs describe different corpora.
fn rel_dir(seed: u64, dir_id: u64) -> String {
    dir_for(seed, dir_id).trim_start_matches('/').to_string()
}

/// FNV-1a over a path, for collision detection only.
///
/// Not cryptographic and does not need to be: a false positive costs one
/// unnecessary disambiguating suffix, and at 64 bits over ten million paths the
/// chance of even one is about three in a hundred million.
#[inline]
fn path_hash(p: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in p.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

/// Which needle class, if any, file `i` carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Organic,
    Prefix,
    Infix,
    PathFrag,
    CaseLower,
    CaseUpper,
    Ext,
}

/// Deterministic, mutually exclusive, and evaluated in a fixed order so a file
/// never carries two tokens.
#[inline]
fn class_of(i: u64) -> Class {
    if i % M_PREFIX == 11 {
        Class::Prefix
    } else if i % M_INFIX == 5 {
        Class::Infix
    } else if i % M_PATHFRAG == 7 {
        Class::PathFrag
    } else if i % M_CASE_LOWER == 3 {
        Class::CaseLower
    } else if i % M_CASE_UPPER == 9 {
        Class::CaseUpper
    } else if i % M_EXT == 13 {
        Class::Ext
    } else {
        Class::Organic
    }
}

/// The path of organic file `i`, relative to the root, and its class.
fn organic_path(seed: u64, i: u64, dir_space: u64) -> (String, Class) {
    organic_path_at(seed, i, dir_space, false)
}

/// As [`organic_path`], but with the deterministic disambiguator applied.
///
/// # Why any of this is needed
///
/// The name generator draws from a deliberately small vocabulary, so at a
/// million files a handful of independent indices land on the same directory
/// *and* the same filename — about thirty in a million, measured. Every one of
/// them was a `File::create` that silently truncated a file another index had
/// already written, so the corpus held thirty fewer files than the manifest
/// claimed and every count in it was quietly a little wrong.
///
/// That is not a hypothetical: it is what the first 1M run found, and it found
/// it because `files_seen` is asserted to the unit. The manifest is ground
/// truth for every other assertion, so a manifest that disagrees with the disk
/// is the one defect that would make all of them meaningless.
///
/// The suffix is applied to **both** colliding indices, not to a "loser" chosen
/// at write time. Choosing at write time would make the corpus depend on thread
/// scheduling; deciding it from the pre-computed hash set keeps the tree a pure
/// function of `(seed, files)`.
fn organic_path_at(seed: u64, i: u64, dir_space: u64, disambiguate: bool) -> (String, Class) {
    let r = row(seed, i, dir_space);
    // `row`'s own directory, re-rooted. Taken from the row rather than
    // re-derived from the stream: two ways of computing the same directory is
    // two things to keep in step, and a corpus whose planner and writer
    // disagree puts files in directories the planner never created.
    let dir = r.parent.trim_start_matches('/');
    let class = class_of(i);
    let stem = r
        .name
        .strip_suffix(&format!(".{}", r.ext))
        .unwrap_or(&r.name);
    // Threaded through every shape rather than appended to the finished path,
    // so the disambiguator lands in the *stem* and never after the extension —
    // an `.zzx` file must keep its extension or the `filters.ext` leg would be
    // testing a different set from the `.zzx` query.
    let d = if disambiguate {
        format!("-{i}")
    } else {
        String::new()
    };
    let path = match class {
        Class::Organic => format!("{dir}/{stem}{d}.{}", r.ext),
        Class::Prefix => format!("{dir}/zzprefix-{stem}{d}.{}", r.ext),
        Class::Infix => format!("{dir}/{stem}-zzinfix-{i}.{}", r.ext),
        // The token is a directory component and appears nowhere in the
        // filename. That asymmetry is the whole point of the class.
        Class::PathFrag => format!("{dir}/zzpathfrag/{stem}{d}.{}", r.ext),
        Class::CaseLower => format!("{dir}/zzcasemix-{stem}{d}.{}", r.ext),
        Class::CaseUpper => format!("{dir}/ZZCASEMIX-{stem}{d}.{}", r.ext),
        Class::Ext => format!("{dir}/{stem}{d}.zzx"),
    };
    (path, class)
}

/// Indices whose plain path is shared with another index.
///
/// One pass, parallel, storing eight bytes per file rather than the path
/// itself: at ten million files that is 80 MB instead of a gigabyte of strings.
fn colliding_indices(seed: u64, organic: u64, dir_space: u64) -> std::collections::HashSet<u64> {
    let mut hashes: Vec<u64> = (0..organic)
        .into_par_iter()
        .map(|i| path_hash(&organic_path(seed, i, dir_space).0))
        .collect();
    let mut sorted = hashes.clone();
    sorted.par_sort_unstable();
    let mut dup: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for w in sorted.windows(2) {
        if w[0] == w[1] {
            dup.insert(w[0]);
        }
    }
    hashes.clear();
    if dup.is_empty() {
        return std::collections::HashSet::new();
    }
    (0..organic)
        .into_par_iter()
        .filter(|i| dup.contains(&path_hash(&organic_path(seed, *i, dir_space).0)))
        .collect()
}

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

pub struct GenFilesOpts {
    pub dest: PathBuf,
    pub files: u64,
    pub seed: u64,
    pub threads: usize,
}

pub fn gen_files(a: &Args) -> Result<(), String> {
    let o = opts_from(a)?;
    let root = o.dest.join("root");
    let outside = o.dest.join("outside");

    if root.exists() {
        return Err(format!(
            "{} already exists. Refusing to write into a corpus that may be \
             half-generated: a partial tree produces a manifest whose counts are \
             right and whose files are not. Remove it first.",
            root.display()
        ));
    }

    // Budget: `deep`, the symlink corner and the fat directories come out of the
    // requested total, so `--files N` means "the scan must catalogue exactly N"
    // rather than "N plus whatever the fixtures add".
    let fat_per_dir = (o.files / 25).min(40_000);
    let fat = fat_per_dir * FAT_DIRS;
    let fixed = DEEP_FILES + SYMLINK_ENTRIES + fat;
    if o.files <= fixed + MIN_ORGANIC {
        return Err(format!(
            "--files {} leaves only {} organic files after the fixed structures \
             ({fixed}); below {MIN_ORGANIC} the rarest needle class lands too few \
             times for its count to discriminate. Raise --files.",
            o.files,
            o.files.saturating_sub(fixed)
        ));
    }
    let organic = o.files - fixed;
    let dir_space = (organic / FILES_PER_DIR).max(1);

    eprintln!(
        "[gen-files] dest={} files={} organic={organic} fat={fat} ({fat_per_dir}/dir) \
         deep={DEEP_FILES} symlinks={SYMLINK_ENTRIES} dir_space={dir_space} threads={} seed={}",
        o.dest.display(),
        o.files,
        o.threads,
        o.seed
    );

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(o.threads)
        .build()
        .map_err(|e| format!("building the writer pool: {e}"))?;

    let t0 = std::time::Instant::now();

    // --- pass 1: directories --------------------------------------------
    //
    // Every directory first, then every file. One `create_dir_all` per file
    // would be a million extra round trips on a network filesystem, where a
    // metadata operation is a packet rather than a page-cache hit.
    let dirs = plan_dirs(&o, organic, dir_space, fat_per_dir);
    let n_dirs = dirs.len() as u64;
    std::fs::create_dir_all(&root).map_err(|e| format!("creating {}: {e}", root.display()))?;
    pool.install(|| {
        dirs.par_iter().try_for_each(|d| {
            std::fs::create_dir_all(root.join(d)).map_err(|e| format!("mkdir {d}: {e}"))
        })
    })?;
    let t_dirs = t0.elapsed();
    eprintln!(
        "[gen-files] {n_dirs} directories in {:.1}s ({:.0}/s)",
        t_dirs.as_secs_f64(),
        n_dirs as f64 / t_dirs.as_secs_f64().max(1e-9)
    );

    // --- pass 2: the organic body, with the needles planted in it --------
    let t_coll = std::time::Instant::now();
    let collisions = pool.install(|| colliding_indices(o.seed, organic, dir_space));
    eprintln!(
        "[gen-files] {} name collisions resolved in {:.1}s",
        collisions.len(),
        t_coll.elapsed().as_secs_f64()
    );

    let counts: [AtomicU64; 7] = std::array::from_fn(|_| AtomicU64::new(0));
    let bytes = AtomicU64::new(0);
    let written = AtomicU64::new(0);
    let mut samples: Vec<Sample> = Vec::new();
    let t1 = std::time::Instant::now();

    pool.install(|| -> Result<(), String> {
        (0..organic).into_par_iter().try_for_each(|i| {
            let (rel, class) = organic_path_at(o.seed, i, dir_space, collisions.contains(&i));
            let n = write_body(&root.join(&rel), i).map_err(|e| format!("writing {rel}: {e}"))?;
            bytes.fetch_add(n, Ordering::Relaxed);
            counts[class as usize].fetch_add(1, Ordering::Relaxed);
            let done = written.fetch_add(1, Ordering::Relaxed) + 1;
            if done.is_multiple_of(100_000) {
                eprintln!(
                    "[gen-files] {done}/{organic} organic files ({:.0}/s)",
                    done as f64 / t1.elapsed().as_secs_f64().max(1e-9)
                );
            }
            Ok(())
        })
    })?;
    let t_files = t1.elapsed();
    eprintln!(
        "[gen-files] {organic} organic files in {:.1}s ({:.0}/s)",
        t_files.as_secs_f64(),
        organic as f64 / t_files.as_secs_f64().max(1e-9)
    );

    // --- pass 3: the fat directories -------------------------------------
    let t2 = std::time::Instant::now();
    pool.install(|| -> Result<(), String> {
        (0..fat).into_par_iter().try_for_each(|k| {
            let which = if k < fat_per_dir { "bulk-a" } else { "bulk-b" };
            let i = organic + k;
            let r = row(o.seed, i, dir_space);
            let rel = format!("fat/{which}/{k:07}-{}", r.name);
            let n = write_body(&root.join(&rel), i).map_err(|e| format!("writing {rel}: {e}"))?;
            bytes.fetch_add(n, Ordering::Relaxed);
            Ok(())
        })
    })?;
    eprintln!(
        "[gen-files] {fat} files across {FAT_DIRS} fat directories in {:.1}s",
        t2.elapsed().as_secs_f64()
    );

    // --- pass 4: the deep chain ------------------------------------------
    let deep_dir = deep_rel();
    for k in 0..DEEP_FILES {
        let rel = format!("{deep_dir}/zzdeep-{k:03}.txt");
        let n = write_body(&root.join(&rel), 900_000_000 + k)
            .map_err(|e| format!("writing {rel}: {e}"))?;
        bytes.fetch_add(n, Ordering::Relaxed);
        // Deep-chain names are unique, so a client can search for exactly one
        // of them and check the *hydrated* row — path and size — rather than
        // only that a count came back. An organic filename would not do: the
        // vocabulary repeats, so a name query can legitimately return many.
        if k < 3 {
            samples.push(Sample {
                rel_path: rel.clone(),
                size: n,
            });
        }
    }

    // --- pass 5: the traps ------------------------------------------------
    //
    // Written last so that a failure here cannot be mistaken for a short body.
    for k in 0..GIT_FILES {
        let rel = format!("proj/.git/objects/zzdenied-git-{k:04}.pack");
        write_body(&root.join(&rel), 800_000_000 + k).map_err(|e| format!("writing {rel}: {e}"))?;
    }
    for k in 0..NODE_MODULES_FILES {
        let rel = format!("proj/node_modules/leftpad/zzdenied-npm-{k:04}.js");
        write_body(&root.join(&rel), 810_000_000 + k).map_err(|e| format!("writing {rel}: {e}"))?;
    }
    std::fs::create_dir_all(outside.join("payload"))
        .map_err(|e| format!("creating {}: {e}", outside.display()))?;
    for k in 0..OUTSIDE_FILES {
        let rel = format!("payload/zzoutside-{k:04}.dat");
        write_body(&outside.join(&rel), 820_000_000 + k)
            .map_err(|e| format!("writing outside/{rel}: {e}"))?;
    }

    samples.extend(write_symlink_corner(&root, &bytes)?);

    // --- the manifest -----------------------------------------------------
    let get = |c: Class| counts[c as usize].load(Ordering::Relaxed);
    let expected_seen = organic + fat + DEEP_FILES + SYMLINK_ENTRIES;
    let accounted: u64 = (0..7).map(|k| counts[k].load(Ordering::Relaxed)).sum();
    if accounted != organic {
        return Err(format!(
            "the writer classified {accounted} files but wrote {organic}; the \
             manifest would describe a corpus that does not exist"
        ));
    }

    let needles = vec![
        Needle {
            token: "zzprefix",
            query: "zzprefix".into(),
            expect: get(Class::Prefix),
            note: "the token opens the filename",
        },
        Needle {
            token: "zzinfix",
            query: "zzinfix".into(),
            expect: get(Class::Infix),
            note: "the token is interior to the filename",
        },
        Needle {
            token: "zzpathfrag",
            // The separator is what selects `Scope::Path`. Without it the same
            // text is a name query, and the name query's answer is zero.
            query: "zzpathfrag/".into(),
            expect: get(Class::PathFrag),
            note: "a directory component; the same token WITHOUT the separator must return 0",
        },
        Needle {
            token: "zzcasemix",
            query: "zzcasemix".into(),
            expect: get(Class::CaseLower) + get(Class::CaseUpper),
            note: "sum of both cases; a case-sensitive match returns one half",
        },
        Needle {
            token: "ZZCASEMIX",
            query: "ZZCASEMIX".into(),
            expect: get(Class::CaseLower) + get(Class::CaseUpper),
            note: "the same sum, queried in the other case",
        },
        Needle {
            token: "zzx",
            query: ".zzx".into(),
            expect: get(Class::Ext),
            note: "a rare extension, also reachable through filters.ext",
        },
        Needle {
            token: "zzdeep",
            query: "zzdeep".into(),
            expect: DEEP_FILES,
            note: "at the bottom of a 24-level chain",
        },
        Needle {
            token: "zzsymlinked",
            query: "zzsymlinked".into(),
            expect: 2,
            note: "a real file and the symlink pointing at it; both are entries",
        },
        Needle {
            token: "zzdangling",
            query: "zzdangling".into(),
            expect: 1,
            note: "a symlink whose target does not exist is still an entry",
        },
    ];

    // The floor applies to the residue-planted classes only. The symlink
    // needles are two and one *by construction* — that is their exact expected
    // answer, not a sample too small to trust.
    let case_lower = get(Class::CaseLower);
    let case_upper = get(Class::CaseUpper);
    for (name, n) in [
        ("zzprefix", get(Class::Prefix)),
        ("zzinfix", get(Class::Infix)),
        ("zzpathfrag", get(Class::PathFrag)),
        ("zzcasemix(lower)", case_lower),
        ("zzcasemix(upper)", case_upper),
        (".zzx", get(Class::Ext)),
    ] {
        if n < 3 {
            return Err(format!(
                "needle `{name}` landed {n} time(s); a count that small cannot \
                 discriminate a wrong answer from a right one. Raise --files."
            ));
        }
    }
    if case_lower == case_upper || case_lower == 0 || case_upper == 0 {
        return Err(format!(
            "the case-variant halves are {case_lower} and {case_upper}; they must \
             both be non-zero and unequal, or a case-sensitive match would be \
             indistinguishable from a case-insensitive one"
        ));
    }

    let manifest = Manifest {
        generator: "shepherd-bench gen-files",
        manifest_version: 1,
        seed: o.seed,
        root: root
            .canonicalize()
            .map_err(|e| format!("canonicalising {}: {e}", root.display()))?
            .display()
            .to_string(),
        expected_seen,
        expected_bytes: bytes.load(Ordering::Relaxed),
        dirs_created: n_dirs,
        name_collisions: collisions.len() as u64,
        organic_files: organic,
        fat_dir_files: fat,
        deep_files: DEEP_FILES,
        symlink_entries: SYMLINK_ENTRIES,
        case_lower_files: case_lower,
        case_upper_files: case_upper,
        needles,
        absent: vec![
            AbsentCase {
                query: "zzpathfrag".into(),
                why: "a name-scoped query for a token that appears only in directory names",
            },
            AbsentCase {
                query: "zzdenied".into(),
                why: "every file carrying it is inside .git/ or node_modules/ (AC-7)",
            },
            AbsentCase {
                query: "zzoutside".into(),
                why: "every file carrying it is outside the root, behind a symlinked directory",
            },
            AbsentCase {
                query: "zzprefixq".into(),
                why: "a superstring of a present token",
            },
            AbsentCase {
                query: "qzzinfix".into(),
                why: "a present token with a prefix that is not in any name",
            },
            AbsentCase {
                query: "zznothinghere".into(),
                why: "in no name and no path",
            },
        ],
        traps: vec![
            Trap {
                name: "deny-list: .git",
                files: GIT_FILES,
                token: "zzdenied",
                why: "AC-7 prunes at the directory; following it would add these to files_seen",
            },
            Trap {
                name: "deny-list: node_modules",
                files: NODE_MODULES_FILES,
                token: "zzdenied",
                why: "a second deny reason, so losing one rule still fails",
            },
            Trap {
                name: "symlinked directory leaving the root",
                files: OUTSIDE_FILES,
                token: "zzoutside",
                why: "the only way these are reachable is by following link-outside",
            },
            Trap {
                name: "symlink cycle",
                files: 0,
                token: "zzcycle",
                why: "cyc/self -> .. ; entering it does not terminate",
            },
        ],
        samples,
    };

    let text = serde_json::to_string_pretty(&manifest)
        .map_err(|e| format!("serialising manifest: {e}"))?;
    let mpath = o.dest.join("manifest.json");
    std::fs::write(&mpath, text).map_err(|e| format!("{}: {e}", mpath.display()))?;

    eprintln!(
        "[gen-files] done in {:.1}s — expected_seen={expected_seen} \
         expected_bytes={} manifest={}",
        t0.elapsed().as_secs_f64(),
        manifest.expected_bytes,
        mpath.display()
    );
    Ok(())
}

/// The symlink corner: a real file, a symlink to it, a dangling symlink, a
/// symlinked directory that leaves the root, and a loop.
///
/// The two directory links contribute **nothing** to `files_seen` — a symlinked
/// directory is reported and not descended — and that is exactly what the
/// `zzoutside` trap checks. The two file links do contribute, because
/// `symlink_metadata` describes a link that exists.
fn write_symlink_corner(root: &Path, bytes: &AtomicU64) -> Result<Vec<Sample>, String> {
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    std::fs::create_dir_all(root.join("links")).map_err(|e| format!("links/: {e}"))?;
    std::fs::create_dir_all(root.join("cyc")).map_err(|e| format!("cyc/: {e}"))?;

    let target = root.join("links/zzsymlinked-target.txt");
    let n = write_body(&target, 830_000_000).map_err(|e| format!("symlink target: {e}"))?;
    bytes.fetch_add(n, Ordering::Relaxed);
    let mut samples = vec![Sample {
        rel_path: "links/zzsymlinked-target.txt".into(),
        size: n,
    }];

    // The corpus deliberately carries a symlink, a dangling link and an
    // outward link, because they are what the walker's cycle guard and its
    // `(dev, ino)` bookkeeping are for. Creating them is POSIX: Windows needs
    // either developer mode or SeCreateSymbolicLinkPrivilege, so a generator
    // that silently skipped them would hand the scanner a corpus missing the
    // exact shapes it is meant to be tested against — a fixture that looks
    // complete and is not. It refuses instead.
    #[cfg(not(unix))]
    return Err(format!(
        "the M1 corpus generator needs POSIX symlinks and is not implemented on \
         {} yet: the corpus's symlink, dangling-link and outward-link cases are \
         what the walker's cycle guard is tested against, and generating a \
         corpus without them would silently weaken every assertion made over it",
        std::env::consts::OS
    ));
    #[cfg(unix)]
    let link = |from: &str, to: &str| -> Result<(), String> {
        let p = root.join(from);
        symlink(to, &p).map_err(|e| format!("symlink {from} -> {to}: {e}"))?;
        Ok(())
    };
    link("links/zzsymlinked-link.txt", "zzsymlinked-target.txt")?;
    link("links/zzdangling-link.txt", "no-such-target-zzq")?;
    // Outward, not inward: a link pointing back inside the root would be
    // absorbed by the `(dev, ino)` cycle guard and the file count would come
    // out right whether or not the link was followed.
    link("link-outside", "../outside")?;
    link("cyc/self", "..")?;

    // The two *file* links are entries, and their size is the length of the
    // target string. Measured rather than computed from the literal, because
    // that is what the walker's `symlink_metadata` will report.
    for f in ["links/zzsymlinked-link.txt", "links/zzdangling-link.txt"] {
        let md = std::fs::symlink_metadata(root.join(f)).map_err(|e| format!("stat {f}: {e}"))?;
        bytes.fetch_add(md.len(), Ordering::Relaxed);
        // A symlink's own size is the length of its target string. Recorded so
        // the test asserts that value rather than the target file's size, which
        // is what a walker using `metadata` instead of `symlink_metadata` would
        // report.
        samples.push(Sample {
            rel_path: f.into(),
            size: md.len(),
        });
    }
    Ok(samples)
}

fn deep_rel() -> String {
    let mut p = String::from("deep");
    for k in 1..=DEEP_DEPTH {
        p.push_str(&format!("/level{k:02}"));
    }
    p
}

/// Every directory the corpus needs, deduplicated.
///
/// Enumerated from the same pure functions the writers use, so a directory that
/// is planned and a directory that is written cannot disagree.
fn plan_dirs(o: &GenFilesOpts, organic: u64, dir_space: u64, fat_per_dir: u64) -> Vec<String> {
    let mut set: BTreeSet<String> = (0..dir_space)
        .into_par_iter()
        .map(|k| rel_dir(o.seed, k))
        .collect::<Vec<_>>()
        .into_iter()
        .collect();

    // `zzpathfrag` subdirectories exist only under the parents that actually
    // receive one, so the token does not appear in directories holding nothing.
    let frag: Vec<String> = (0..organic)
        .into_par_iter()
        .filter(|i| class_of(*i) == Class::PathFrag)
        .map(|i| {
            format!(
                "{}/zzpathfrag",
                row(o.seed, i, dir_space).parent.trim_start_matches('/')
            )
        })
        .collect();
    set.extend(frag);

    if fat_per_dir > 0 {
        set.insert("fat/bulk-a".into());
        set.insert("fat/bulk-b".into());
    }
    set.insert(deep_rel());
    set.insert("proj/.git/objects".into());
    set.insert("proj/node_modules/leftpad".into());
    set.insert("links".into());
    set.insert("cyc".into());
    set.into_iter().collect()
}

fn opts_from(a: &Args) -> Result<GenFilesOpts, String> {
    let dest = a
        .dest
        .clone()
        .ok_or("gen-files needs --dest <dir>: the corpus does not belong in the repo")?;
    let files = a
        .files
        .ok_or("gen-files needs --files <n>: the corpus size is never implicit")?;
    Ok(GenFilesOpts {
        dest,
        files,
        seed: a.seed.unwrap_or(20260816),
        threads: a.threads.unwrap_or(8),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The classes must partition: a file carrying two tokens would be counted
    /// twice and every count would be a little wrong in a way no single
    /// assertion catches.
    #[test]
    fn every_index_lands_in_exactly_one_class() {
        let mut seen = [0u64; 7];
        for i in 0..200_000u64 {
            seen[class_of(i) as usize] += 1;
        }
        assert_eq!(seen.iter().sum::<u64>(), 200_000);
        for (k, n) in seen.iter().enumerate() {
            assert!(*n > 0, "class {k} never occurs");
        }
    }

    /// Every needle token has to be unproducible by the organic generator, in
    /// any case. This is the property the whole ground truth rests on: if
    /// `report` were the needle, an organic file would carry it by accident and
    /// no count would mean anything.
    #[test]
    fn no_organic_name_or_directory_can_contain_a_reserved_token() {
        let space = 4_000u64;
        for i in 0..120_000u64 {
            let (rel, class) = organic_path(20260816, i, space);
            if class != Class::Organic {
                continue;
            }
            let lower = rel.to_ascii_lowercase();
            for token in [
                "zz",
                "zzprefix",
                "zzinfix",
                "zzpathfrag",
                "zzcasemix",
                "zzx",
                "zzdeep",
                "zzdenied",
                "zzoutside",
                "zzsymlinked",
                "zzdangling",
            ] {
                assert!(
                    !lower.contains(token),
                    "organic path `{rel}` contains the reserved token `{token}`"
                );
            }
        }
    }

    /// The path-fragment class must put its token in a directory component and
    /// nowhere else, or the name-query-returns-zero assertion is vacuous.
    #[test]
    fn the_path_fragment_token_never_reaches_a_filename() {
        let space = 4_000u64;
        let mut n = 0;
        for i in 0..120_000u64 {
            let (rel, class) = organic_path(20260816, i, space);
            if class != Class::PathFrag {
                continue;
            }
            n += 1;
            let file = rel.rsplit('/').next().unwrap();
            assert!(
                !file.to_ascii_lowercase().contains("zzpathfrag"),
                "`{rel}`'s filename carries the path token"
            );
            assert!(rel.contains("/zzpathfrag/"), "`{rel}` is not under the dir");
        }
        assert!(n > 100, "only {n} path-fragment files in the sample");
    }

    /// The corpus must contain no duplicate path, or the manifest describes
    /// more files than the disk holds and every count derived from it is wrong.
    ///
    /// This test is the regression for a real defect: the first 1M run wrote
    /// 999,969 files while claiming 1,000,000, because ~30 independent indices
    /// drew the same directory and the same filename and `File::create`
    /// truncated the earlier one without complaint.
    #[test]
    fn disambiguation_leaves_no_duplicate_path() {
        // A deliberately cramped directory space, so collisions are dense
        // enough to hit in a fast test rather than needing a million files.
        let (seed, n, space) = (20260816u64, 200_000u64, 400u64);
        let dups = colliding_indices(seed, n, space);
        assert!(
            !dups.is_empty(),
            "no collisions at all in a {space}-directory space — this test is \
             not exercising the resolver"
        );
        let mut all: BTreeSet<String> = BTreeSet::new();
        for i in 0..n {
            let (p, _) = organic_path_at(seed, i, space, dups.contains(&i));
            assert!(
                all.insert(p.clone()),
                "duplicate path after resolution: {p}"
            );
        }
        assert_eq!(all.len() as u64, n);
    }

    /// Without the resolver the same corpus DOES collide — otherwise the test
    /// above would pass for the wrong reason.
    #[test]
    fn without_disambiguation_the_same_corpus_collides() {
        let (seed, n, space) = (20260816u64, 200_000u64, 400u64);
        let mut all: BTreeSet<String> = BTreeSet::new();
        let mut clashes = 0;
        for i in 0..n {
            if !all.insert(organic_path(seed, i, space).0) {
                clashes += 1;
            }
        }
        assert!(
            clashes > 0,
            "the unresolved corpus had no duplicates, so the resolver is \
             protecting against nothing"
        );
    }

    /// The disambiguator must not move the extension: `filters.ext` matches on
    /// the catalog's derived `ext`, so a suffix landing after the dot would
    /// silently change which set the extension leg tests.
    #[test]
    fn disambiguation_keeps_the_extension_last() {
        let (seed, space) = (20260816u64, 400u64);
        let mut checked = 0;
        for i in 0..200_000u64 {
            if class_of(i) != Class::Ext {
                continue;
            }
            let (p, _) = organic_path_at(seed, i, space, true);
            assert!(p.ends_with(".zzx"), "{p}");
            checked += 1;
        }
        assert!(checked > 20, "only {checked} extension-class files sampled");
    }

    /// Body lengths must vary, or `bytes_seen` is `files_seen` in disguise.
    #[test]
    fn body_lengths_vary() {
        let lens: BTreeSet<usize> = (0..5_000u64).map(body_len).collect();
        assert!(lens.len() > 150, "only {} distinct lengths", lens.len());
        assert!(*lens.iter().next().unwrap() >= 1);
    }
}
