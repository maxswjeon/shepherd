//! Proof that the §4.1 rule 4 scanner detects a forbidden call site.
//!
//! These fixtures contain the destructive symbol names as literals, so this
//! file MUST stay outside `rule4.scan_roots` in `xtask/deps-policy.toml`
//! (which lists `crates` and `xtask/src`). If someone adds `xtask/tests` to
//! that list, these fixtures will be reported as violations — which is the
//! scanner working, not a bug.

use std::fs;
use std::path::{Path, PathBuf};

use xtask::check_deps::{Rule4, contains_ident, contains_ident_phrase, scan_rule4, strip_comment};

const POLICY: &str = r#"
scan_roots = ["crates"]
escape_hatch = "allow(clippy::disallowed_methods)"
escape_hatch_allowed_in = ["crates/shepherd-tier/src/destroy.rs"]
not_tracked = ["delete_system_object"]

[[symbols]]
name = "delete_object"
owner = "StorageAdapter"
implemented_in = ["crates/shepherd-storage/src/"]
sole_caller = "crates/shepherd-tier/src/destroy.rs"

[[symbols]]
name = "destroy_local"
owner = "PlaceholderProvider"
implemented_in = ["crates/shepherd-placeholder/src/"]
sole_caller = "crates/shepherd-tier/src/destroy.rs"
"#;

struct TempTree(PathBuf);

impl TempTree {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("shepherd-rule4-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp tree");
        TempTree(dir)
    }

    fn write(&self, rel: &str, body: &str) {
        let p = self.0.join(rel);
        fs::create_dir_all(p.parent().unwrap()).expect("mkdir");
        fs::write(p, body).expect("write fixture");
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn policy() -> Rule4 {
    toml::from_str(POLICY).expect("policy fixture parses")
}

/// The legal shape: implementations in their owning crates, calls only from
/// `destroy.rs`, and `delete_system_object` used freely elsewhere.
fn write_compliant(t: &TempTree) {
    t.write(
        "crates/shepherd-storage/src/adapter.rs",
        "pub trait StorageAdapter {\n    fn delete_object(&self, k: &str);\n    fn delete_system_object(&self, k: &str);\n}\n",
    );
    t.write(
        "crates/shepherd-placeholder/src/delete_mode.rs",
        "impl PlaceholderProvider for DeleteMode {\n    fn destroy_local(&self, p: &Path) {}\n}\n",
    );
    t.write(
        "crates/shepherd-tier/src/destroy.rs",
        "#![allow(clippy::disallowed_methods)]\nfn go(a: &A, p: &P) {\n    p.destroy_local(path);\n    a.delete_object(key);\n}\n",
    );
    // Replica maintenance may call the system-object variant. §4.1 rule 4
    // scopes it to the `_shepherd/` prefix and excludes it from the breaker.
    t.write(
        "crates/shepherd-storage/src/replica.rs",
        "fn prune(a: &A) {\n    a.delete_system_object(\"_shepherd/seg-1\");\n}\n",
    );
    t.write("crates/shepherd-tier/src/plan.rs", "fn plan() {}\n");
}

#[test]
fn compliant_tree_passes() {
    let t = TempTree::new("ok");
    write_compliant(&t);
    let (violations, files) = scan_rule4(t.path(), &policy()).expect("scan");
    assert_eq!(files, 5, "expected 5 .rs files scanned");
    assert!(
        violations.is_empty(),
        "compliant tree should pass, got: {violations:#?}"
    );
}

#[test]
fn call_outside_destroy_rs_is_a_violation() {
    let t = TempTree::new("call");
    write_compliant(&t);
    // A second module inside shepherd-tier reaching the destructive method.
    t.write(
        "crates/shepherd-tier/src/plan.rs",
        "fn plan(a: &A) {\n    a.delete_object(key);\n}\n",
    );
    let (violations, _) = scan_rule4(t.path(), &policy()).expect("scan");
    assert_eq!(violations.len(), 1, "got: {violations:#?}");
    assert!(violations[0].contains("shepherd-tier/src/plan.rs:2"));
    assert!(violations[0].contains("StorageAdapter::delete_object"));
}

#[test]
fn call_from_another_crate_is_a_violation() {
    let t = TempTree::new("crate");
    write_compliant(&t);
    t.write(
        "crates/shepherd-rules/src/engine.rs",
        "fn apply(p: &P) {\n    p.destroy_local(path);\n}\n",
    );
    let (violations, _) = scan_rule4(t.path(), &policy()).expect("scan");
    assert_eq!(violations.len(), 1, "got: {violations:#?}");
    assert!(violations[0].contains("shepherd-rules/src/engine.rs"));
    assert!(violations[0].contains("PlaceholderProvider::destroy_local"));
}

#[test]
fn escape_hatch_outside_destroy_rs_is_a_violation() {
    let t = TempTree::new("hatch");
    write_compliant(&t);
    t.write(
        "crates/shepherd-rules/src/preview.rs",
        "#![allow(clippy::disallowed_methods)]\nfn preview() {}\n",
    );
    let (violations, _) = scan_rule4(t.path(), &policy()).expect("scan");
    assert_eq!(violations.len(), 1, "got: {violations:#?}");
    assert!(violations[0].contains("shepherd-rules/src/preview.rs:1"));
    assert!(violations[0].contains("single escape hatch"));
}

#[test]
fn delete_system_object_is_not_tracked() {
    let t = TempTree::new("sysobj");
    write_compliant(&t);
    t.write(
        "crates/shepherd-jobs/src/scrub.rs",
        "fn reap(a: &A) {\n    a.delete_system_object(\"_shepherd/x\");\n}\n",
    );
    let (violations, _) = scan_rule4(t.path(), &policy()).expect("scan");
    assert!(
        violations.is_empty(),
        "delete_system_object is scoped to `_shepherd/` and callable by replica \
         maintenance (§4.1 rule 4); got: {violations:#?}"
    );
}

#[test]
fn a_comment_naming_the_method_is_not_a_call() {
    let t = TempTree::new("comment");
    write_compliant(&t);
    t.write(
        "crates/shepherd-rules/src/delete_policy.rs",
        "/// The discard branch eventually reaches delete_object via shepherd-tier.\nfn branch() {}\n",
    );
    let (violations, _) = scan_rule4(t.path(), &policy()).expect("scan");
    assert!(violations.is_empty(), "got: {violations:#?}");
}

// --- unit-level helpers ----------------------------------------------------

#[test]
fn ident_boundaries() {
    assert!(contains_ident(
        "self.adapter.delete_object(&k)?;",
        "delete_object"
    ));
    assert!(contains_ident("fn delete_object(&self)", "delete_object"));
    assert!(!contains_ident(
        "self.adapter.delete_system_object(&k)?;",
        "delete_object"
    ));
    assert!(!contains_ident("soft_delete_objects()", "delete_object"));
    assert!(!contains_ident("predelete_object()", "delete_object"));
}

#[test]
fn comments_are_stripped() {
    assert_eq!(
        strip_comment("    // calls the destructive method").trim(),
        ""
    );
    assert_eq!(strip_comment("let x = 1; // note").trim(), "let x = 1;");
    assert_eq!(strip_comment("let x = 1;"), "let x = 1;");
}

#[test]
fn escape_hatch_phrase_forms() {
    let p = "allow(clippy::disallowed_methods)";
    assert!(contains_ident_phrase(
        "#![allow(clippy::disallowed_methods)]",
        p
    ));
    assert!(contains_ident_phrase(
        "#![allow( clippy::disallowed_methods )]",
        p
    ));
    assert!(contains_ident_phrase(
        "#[allow(clippy::disallowed_methods, dead_code)]",
        p
    ));
    assert!(!contains_ident_phrase(
        "#![deny(clippy::disallowed_methods)]",
        p
    ));
}
