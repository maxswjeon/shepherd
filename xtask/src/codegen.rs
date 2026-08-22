//! `cargo xtask codegen` — emit the committed IPC artifacts, or fail on drift.
//!
//! # What this generates
//!
//! Everything under `schemas/`, derived from `shepherd_proto::MethodKind::ALL`:
//!
//! | artifact | consumer |
//! |---|---|
//! | `schemas/ipc-inventory.json` | the AC-54 inventory test (Phase 8); humans reviewing the surface |
//! | `schemas/method/<name>.request.json` | `--json` input validation; the Phase 8 TS client |
//! | `schemas/method/<name>.result.json` | AC-56: what `shepctl --json` puts in `data` |
//! | `schemas/cli-envelope.json` | AC-56: the stable envelope around it |
//! | `schemas/error-codes.json` | the transport taxonomy and its stable slugs |
//! | `schemas/event/*.json` | the event stream contract |
//! | `schemas/handshake/*.json` | `hello` / `helloResult`, which are not table methods |
//!
//! # Why the output is committed rather than built
//!
//! A schema generated into `target/` at build time proves nothing: it always
//! matches, because it was just derived from the code it is meant to constrain.
//! Committing it turns a wire-format change into a **reviewable diff** — the
//! only mechanism that makes AC-56's "stable machine-readable output" checkable
//! by a person. `codegen --check` then fails CI when the tree and the code
//! disagree, so the diff cannot be skipped.
//!
//! `--check` also reports **stale** files: an artifact on disk that the current
//! table no longer produces. Without that, deleting a method would leave its
//! schema behind and the committed surface would over-state what exists.
//!
//! # Not generated here
//!
//! The TypeScript client. §6 Phase 8 owns `ui/*` and "the generated TS client",
//! and there is no TypeScript toolchain in this workspace to compile or check
//! one against — emitting it now would add an artifact no CI step can verify,
//! which is the "tooling credited with running that did not exist" defect §9
//! rule 6 records. `ipc-inventory.json` plus the per-method schemas are the
//! machine-readable substrate that emission will consume.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use shepherd_proto::{
    CLI_SCHEMA_VERSION, COMPATIBILITY_POLICY, CliEnvelope, ErrorCode, EventFrame, Hello,
    HelloResult, MethodKind, PROTO_VERSION, RpcRequest, RpcResponse, SubscribeResult,
    method::schema_of, registry_canonical_form, registry_fingerprint,
};

/// Bumped whenever this generator changes what it emits for an unchanged method
/// table — a new metadata key, a different layout, a schemars upgrade that moves
/// output. It is embedded in every artifact, so a wholesale rewrite of
/// `schemas/` is attributable to the generator rather than mistaken for a
/// protocol change.
pub const GENERATOR_VERSION: u32 = 1;

/// The directory, relative to the workspace root, that this command owns
/// **entirely**. Every file under it is generated; anything else found there is
/// reported as stale.
pub const SCHEMA_DIR: &str = "schemas";

/// One file this command is responsible for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    /// Path relative to the workspace root, with `/` separators.
    pub rel_path: String,
    pub contents: String,
}

/// The per-file verdict of a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// On disk and identical.
    Matches,
    /// On disk and different.
    Differs,
    /// Not on disk.
    Missing,
    /// On disk but no longer generated.
    Stale,
    /// Written by this run (`codegen` without `--check`).
    Wrote,
}

#[derive(Debug, Clone)]
pub struct FileReport {
    pub rel_path: String,
    pub verdict: Verdict,
    /// For `Differs`, the first line number and both renderings.
    pub first_difference: Option<(usize, String, String)>,
}

#[derive(Debug)]
pub struct Report {
    pub files: Vec<FileReport>,
    pub checked: bool,
    pub fingerprint: String,
    pub method_count: usize,
}

impl Report {
    pub fn failed(&self) -> bool {
        self.checked
            && self.files.iter().any(|f| {
                matches!(
                    f.verdict,
                    Verdict::Differs | Verdict::Missing | Verdict::Stale
                )
            })
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        let mode = if self.checked {
            "--check (drift gate)"
        } else {
            "write"
        };
        s.push_str(&format!(
            "cargo xtask codegen {mode} — §4.3 IPC artifacts\n\
             {sep}\n\
             generator v{gen}  ·  proto {proto}  ·  registry {fp}  ·  {n} methods\n\
             {sep}\n",
            sep = "=".repeat(72),
            gen = GENERATOR_VERSION,
            proto = PROTO_VERSION,
            fp = self.fingerprint,
            n = self.method_count,
        ));

        for f in &self.files {
            let tag = match f.verdict {
                Verdict::Matches => "  ok    ",
                Verdict::Wrote => "  wrote ",
                Verdict::Differs => "  DRIFT ",
                Verdict::Missing => "  ABSENT",
                Verdict::Stale => "  STALE ",
            };
            s.push_str(&format!("{tag} {}\n", f.rel_path));
            if let Some((line, on_disk, generated)) = &f.first_difference {
                s.push_str(&format!("          first difference at line {line}\n"));
                s.push_str(&format!("            on disk:   {on_disk}\n"));
                s.push_str(&format!("            generated: {generated}\n"));
            }
        }

        s.push_str(&format!("{}\n", "=".repeat(72)));
        if !self.checked {
            let wrote = self
                .files
                .iter()
                .filter(|f| f.verdict == Verdict::Wrote)
                .count();
            s.push_str(&format!(
                "RESULT: wrote {wrote} file(s) under `{SCHEMA_DIR}/`. \
                 Commit them; `codegen --check` compares against the tree.\n"
            ));
        } else if self.failed() {
            let drift = self
                .files
                .iter()
                .filter(|f| f.verdict != Verdict::Matches)
                .count();
            s.push_str(&format!(
                "RESULT: FAIL — {drift} file(s) disagree with the method table. \
                 Run `cargo xtask codegen` and commit the diff. A schema that no \
                 longer describes the wire format is worse than no schema: AC-56 \
                 promises stable machine-readable output, and the committed \
                 artifact is what that promise is checked against.\n"
            ));
        } else {
            s.push_str(&format!(
                "RESULT: PASS — {} artifact(s) match the method table.\n",
                self.files.len()
            ));
        }
        s
    }

    pub fn to_json(&self) -> String {
        let files: Vec<serde_json::Value> = self
            .files
            .iter()
            .map(|f| {
                serde_json::json!({
                    "path": f.rel_path,
                    "verdict": format!("{:?}", f.verdict).to_lowercase(),
                })
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "generator_version": GENERATOR_VERSION,
            "proto_version": PROTO_VERSION.to_string(),
            "registry_fingerprint": self.fingerprint,
            "method_count": self.method_count,
            "checked": self.checked,
            "failed": self.failed(),
            "files": files,
        }))
        .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// Metadata stamped into every emitted document.
///
/// JSON has no comments, so provenance goes in an `x-` member. JSON Schema
/// ignores unknown keywords, so this is legal in a schema document and inert to
/// a validator.
fn provenance() -> serde_json::Value {
    serde_json::json!({
        "generator": "cargo xtask codegen",
        "generator_version": GENERATOR_VERSION,
        "proto_version": PROTO_VERSION.to_string(),
        "registry_fingerprint": registry_fingerprint(),
        "warning": "GENERATED FILE — edit crates/shepherd-proto and re-run `cargo xtask codegen`.",
    })
}

/// Attach provenance to a schema document and render it.
fn document(mut schema: serde_json::Value, title: &str) -> String {
    if let Some(obj) = schema.as_object_mut() {
        obj.insert("title".into(), serde_json::Value::String(title.into()));
        obj.insert("x-shepherd".into(), provenance());
    }
    render(&schema)
}

/// The single rendering path, so every artifact is byte-identical in style.
///
/// Pretty-printed with a trailing newline: `--check` compares bytes, and a
/// missing trailing newline is the classic way a generated file appears to drift
/// after any editor touches it.
fn render(v: &serde_json::Value) -> String {
    let mut s = serde_json::to_string_pretty(v).expect("generated JSON is representable");
    s.push('\n');
    s
}

/// Everything this command owns, in deterministic order.
pub fn generate() -> Vec<Artifact> {
    let mut out = Vec::new();

    out.push(Artifact {
        rel_path: format!("{SCHEMA_DIR}/ipc-inventory.json"),
        contents: render(&inventory()),
    });

    for k in MethodKind::ALL {
        let name = k.name();
        out.push(Artifact {
            rel_path: format!("{SCHEMA_DIR}/method/{name}.request.json"),
            contents: document(k.request_schema(), &format!("{name} request")),
        });
        out.push(Artifact {
            rel_path: format!("{SCHEMA_DIR}/method/{name}.result.json"),
            contents: document(k.result_schema(), &format!("{name} result")),
        });
    }

    // The stable CLI contract. Emitted alongside — but never inside — the
    // per-method schemas, because they version independently (§4.3).
    out.push(Artifact {
        rel_path: format!("{SCHEMA_DIR}/cli-envelope.json"),
        contents: document(
            schema_of::<CliEnvelope>(),
            &format!("shepctl --json envelope (schema_version {CLI_SCHEMA_VERSION})"),
        ),
    });

    out.push(Artifact {
        rel_path: format!("{SCHEMA_DIR}/error-codes.json"),
        contents: render(&error_codes()),
    });

    // JSON-RPC framing. Separate from the envelope above, which is the point.
    out.push(Artifact {
        rel_path: format!("{SCHEMA_DIR}/transport/rpc-request.json"),
        contents: document(schema_of::<RpcRequest>(), "JSON-RPC request frame"),
    });
    out.push(Artifact {
        rel_path: format!("{SCHEMA_DIR}/transport/rpc-response.json"),
        contents: document(schema_of::<RpcResponse>(), "JSON-RPC response frame"),
    });

    out.push(Artifact {
        rel_path: format!("{SCHEMA_DIR}/event/event-frame.json"),
        contents: document(schema_of::<EventFrame>(), "event notification payload"),
    });
    out.push(Artifact {
        rel_path: format!("{SCHEMA_DIR}/event/subscribe-result.json"),
        contents: document(schema_of::<SubscribeResult>(), "events.subscribe result"),
    });

    // The handshake is deliberately not a table method (see
    // `shepherd_proto::version`), so its schemas are emitted explicitly rather
    // than falling out of the method loop.
    out.push(Artifact {
        rel_path: format!("{SCHEMA_DIR}/handshake/hello.json"),
        contents: document(schema_of::<Hello>(), "hello (connection preamble)"),
    });
    out.push(Artifact {
        rel_path: format!("{SCHEMA_DIR}/handshake/hello-result.json"),
        contents: document(schema_of::<HelloResult>(), "hello result"),
    });

    out.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    out
}

/// `ipc-inventory.json` — the machine-readable description of the whole surface.
fn inventory() -> serde_json::Value {
    let methods: Vec<serde_json::Value> = MethodKind::ALL
        .iter()
        .map(|k| {
            let d = k.descriptor();
            serde_json::json!({
                "id": d.id.0,
                "name": d.name,
                "cli": d.cli_path,
                "cli_command": format!("shepctl {}", d.cli_command()),
                "summary": d.summary,
                "since_minor": d.since_minor,
                "deprecated": d.deprecated.map(|x| serde_json::json!({
                    "since_minor": x.since_minor,
                    "replacement": x.replacement,
                    "note": x.note,
                })),
                "mutates": d.mutates,
                "request_type": d.request_type,
                "result_type": d.result_type,
                "request_schema": format!("{SCHEMA_DIR}/method/{}.request.json", d.name),
                "result_schema": format!("{SCHEMA_DIR}/method/{}.result.json", d.name),
            })
        })
        .collect();

    serde_json::json!({
        "x-shepherd": provenance(),
        "proto_version": {"major": PROTO_VERSION.major, "minor": PROTO_VERSION.minor},
        "cli_envelope_schema_version": CLI_SCHEMA_VERSION,
        "registry_fingerprint": registry_fingerprint(),
        "compatibility_policy": COMPATIBILITY_POLICY,
        // The exact bytes the fingerprint is taken over. A reviewer comparing
        // two inventories can see what changed without recomputing anything.
        "registry_canonical_form": registry_canonical_form(),
        "method_count": MethodKind::ALL.len(),
        "methods": methods,
        "not_generated": {
            "typescript_client": "Phase 8 (§6). No TS toolchain exists in this \
    workspace, so an emitted client could not be compiled or checked here.",
            "ui_subset_of_cli": "Phase 8. `CLI == registered_methods` is structural \
    from Phase 1 — shepctl builds its command tree from the registry — but `UI ⊆ CLI` \
    needs static extraction of TypeScript invoke() sites, which a Rust trait cannot \
    type-check.",
        },
    })
}

/// `error-codes.json` — the transport taxonomy and its one-way bridge to the
/// stable CLI slugs.
fn error_codes() -> serde_json::Value {
    let codes: Vec<serde_json::Value> = ErrorCode::ALL
        .iter()
        .map(|c| {
            serde_json::json!({
                "code": c.as_i32(),
                "name": format!("{c:?}"),
                "stable_slug": c.stable_slug(),
                "summary": c.summary(),
            })
        })
        .collect();
    serde_json::json!({
        "x-shepherd": provenance(),
        "note": "`code` is transport-level and may be added to or subdivided. \
    `stable_slug` is the AC-56 contract: it is what `shepctl --json` puts in \
    `error.code`, and it never changes meaning. Several codes may share one slug. \
    A client that receives an unrecognised code reports the slug `unknown_error` \
    rather than failing to parse.",
        "unknown_code_slug": shepherd_proto::UNKNOWN_ERROR_SLUG,
        "codes": codes,
    })
}

// ---------------------------------------------------------------------------
// Write / check
// ---------------------------------------------------------------------------

/// Write every artifact, creating directories as needed.
pub fn write(root: &Path) -> Result<Report, String> {
    let artifacts = generate();
    let mut files = Vec::new();
    for a in &artifacts {
        let path = root.join(&a.rel_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        std::fs::write(&path, &a.contents)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        files.push(FileReport {
            rel_path: a.rel_path.clone(),
            verdict: Verdict::Wrote,
            first_difference: None,
        });
    }
    // Remove anything the table no longer produces, so a `write` leaves the
    // tree in exactly the state `--check` will pass on.
    for stale in stale_files(root, &artifacts)? {
        std::fs::remove_file(root.join(&stale))
            .map_err(|e| format!("cannot remove stale {stale}: {e}"))?;
        files.push(FileReport {
            rel_path: stale,
            verdict: Verdict::Stale,
            first_difference: None,
        });
    }
    files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    Ok(Report {
        files,
        checked: false,
        fingerprint: registry_fingerprint(),
        method_count: MethodKind::ALL.len(),
    })
}

/// Compare the tree against what the table produces. Never writes.
pub fn check(root: &Path) -> Result<Report, String> {
    let artifacts = generate();
    let mut files = Vec::new();
    for a in &artifacts {
        let path = root.join(&a.rel_path);
        let verdict_and_diff = match std::fs::read_to_string(&path) {
            Err(_) => (Verdict::Missing, None),
            Ok(on_disk) if on_disk == a.contents => (Verdict::Matches, None),
            Ok(on_disk) => (
                Verdict::Differs,
                Some(first_difference(&on_disk, &a.contents)),
            ),
        };
        files.push(FileReport {
            rel_path: a.rel_path.clone(),
            verdict: verdict_and_diff.0,
            first_difference: verdict_and_diff.1,
        });
    }
    for stale in stale_files(root, &artifacts)? {
        files.push(FileReport {
            rel_path: stale,
            verdict: Verdict::Stale,
            first_difference: None,
        });
    }
    files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    Ok(Report {
        files,
        checked: true,
        fingerprint: registry_fingerprint(),
        method_count: MethodKind::ALL.len(),
    })
}

/// Files under `SCHEMA_DIR` that `generate()` does not produce.
fn stale_files(root: &Path, artifacts: &[Artifact]) -> Result<Vec<String>, String> {
    let generated: BTreeSet<&str> = artifacts.iter().map(|a| a.rel_path.as_str()).collect();
    let dir = root.join(SCHEMA_DIR);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut found = Vec::new();
    walk(&dir, &mut found)?;
    let mut stale: Vec<String> = found
        .into_iter()
        .filter_map(|p| {
            let rel = p
                .strip_prefix(root)
                .ok()?
                .to_string_lossy()
                .replace('\\', "/");
            (!generated.contains(rel.as_str())).then_some(rel)
        })
        .collect();
    stale.sort();
    Ok(stale)
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read an entry in {}: {e}", dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}

/// The first line at which two renderings diverge, for a reviewable failure.
///
/// A bare "these files differ" on a 200-line schema sends the reader to a diff
/// tool; naming the line makes the CI log itself sufficient in the common case
/// of a single changed field.
pub(crate) fn first_difference(on_disk: &str, generated: &str) -> (usize, String, String) {
    let mut a = on_disk.lines();
    let mut b = generated.lines();
    let mut n = 0usize;
    loop {
        n += 1;
        match (a.next(), b.next()) {
            (None, None) => return (n, "<end of file>".into(), "<end of file>".into()),
            (x, y) if x != y => {
                return (
                    n,
                    x.unwrap_or("<end of file>").trim().to_string(),
                    y.unwrap_or("<end of file>").trim().to_string(),
                );
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        // `--check` compares bytes, so nondeterminism here would fail CI on a
        // clean tree and the gate would be trained away rather than trusted.
        assert_eq!(generate(), generate());
    }

    #[test]
    fn every_method_gets_a_request_and_a_result_schema() {
        let paths: BTreeSet<String> = generate().into_iter().map(|a| a.rel_path).collect();
        for k in MethodKind::ALL {
            for suffix in ["request", "result"] {
                let want = format!("{SCHEMA_DIR}/method/{}.{suffix}.json", k.name());
                assert!(paths.contains(&want), "missing {want}");
            }
        }
    }

    #[test]
    fn the_envelope_and_the_transport_frame_are_separate_artifacts() {
        // The §4.3 correction, asserted structurally: a reviewer can see the two
        // contracts as two files, and a change to one cannot silently be a
        // change to the other.
        let paths: BTreeSet<String> = generate().into_iter().map(|a| a.rel_path).collect();
        assert!(paths.contains(&format!("{SCHEMA_DIR}/cli-envelope.json")));
        assert!(paths.contains(&format!("{SCHEMA_DIR}/transport/rpc-response.json")));
    }

    #[test]
    fn every_artifact_carries_provenance_and_ends_with_a_newline() {
        for a in generate() {
            assert!(
                a.contents.ends_with('\n'),
                "{} has no trailing newline",
                a.rel_path
            );
            assert!(
                a.contents.contains("registry_fingerprint"),
                "{} carries no fingerprint",
                a.rel_path
            );
            assert!(
                a.contents.contains("GENERATED FILE"),
                "{} does not announce that it is generated",
                a.rel_path
            );
            let parsed: serde_json::Value = serde_json::from_str(&a.contents)
                .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", a.rel_path));
            assert!(parsed.is_object(), "{}", a.rel_path);
        }
    }

    #[test]
    fn the_inventory_lists_every_method_with_its_cli_path() {
        let inv = inventory();
        assert_eq!(
            inv["method_count"].as_u64().unwrap() as usize,
            MethodKind::ALL.len()
        );
        let methods = inv["methods"].as_array().unwrap();
        for (k, m) in MethodKind::ALL.iter().zip(methods) {
            assert_eq!(m["name"], serde_json::json!(k.name()));
            assert_eq!(m["id"], serde_json::json!(k.id().0));
            assert_eq!(
                m["cli"].as_array().unwrap().len(),
                k.cli_path().len(),
                "{}",
                k.name()
            );
        }
        assert!(
            inv["compatibility_policy"]
                .as_str()
                .unwrap()
                .contains("Additive-only")
        );
        assert!(inv["not_generated"]["typescript_client"].is_string());
    }

    #[test]
    fn the_error_code_artifact_covers_the_whole_taxonomy() {
        let doc = error_codes();
        let codes = doc["codes"].as_array().unwrap();
        assert_eq!(codes.len(), ErrorCode::ALL.len());
        for (c, j) in ErrorCode::ALL.iter().zip(codes) {
            assert_eq!(j["code"], serde_json::json!(c.as_i32()));
            assert_eq!(j["stable_slug"], serde_json::json!(c.stable_slug()));
        }
    }

    #[test]
    fn check_reports_missing_differing_and_stale_files() {
        let tmp = std::env::temp_dir().join(format!(
            "shepherd-codegen-test-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        // Empty tree: everything is missing, and that fails.
        let r = check(&tmp).unwrap();
        assert!(r.failed());
        assert!(r.files.iter().all(|f| f.verdict == Verdict::Missing));

        // After a write, everything matches.
        write(&tmp).unwrap();
        let r = check(&tmp).unwrap();
        assert!(!r.failed(), "{}", r.render());
        assert!(r.files.iter().all(|f| f.verdict == Verdict::Matches));

        // A hand-edited artifact drifts, and the report names the line.
        let victim = tmp.join(SCHEMA_DIR).join("ipc-inventory.json");
        let text = std::fs::read_to_string(&victim).unwrap();
        std::fs::write(&victim, text.replace("\"method_count\"", "\"methodCount\"")).unwrap();
        let r = check(&tmp).unwrap();
        assert!(r.failed());
        let f = r
            .files
            .iter()
            .find(|f| f.rel_path.ends_with("ipc-inventory.json"))
            .unwrap();
        assert_eq!(f.verdict, Verdict::Differs);
        assert!(f.first_difference.is_some());

        // A file the table no longer produces is stale, not ignored.
        write(&tmp).unwrap();
        let orphan = tmp
            .join(SCHEMA_DIR)
            .join("method")
            .join("root.gone.request.json");
        std::fs::write(&orphan, "{}\n").unwrap();
        let r = check(&tmp).unwrap();
        assert!(r.failed());
        assert!(
            r.files
                .iter()
                .any(|f| f.verdict == Verdict::Stale
                    && f.rel_path.ends_with("root.gone.request.json")),
            "{}",
            r.render()
        );

        // `write` cleans it up, so write-then-check is always green.
        write(&tmp).unwrap();
        assert!(!check(&tmp).unwrap().failed());

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn first_difference_points_at_the_changed_line() {
        let (n, a, b) = first_difference("one\ntwo\nthree\n", "one\nTWO\nthree\n");
        assert_eq!((n, a.as_str(), b.as_str()), (2, "two", "TWO"));
    }
}
