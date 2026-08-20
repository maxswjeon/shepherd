//! `cargo xtask check-deps` — the compile-time safety invariant of §4.1.
//!
//! Rules 1, 2, 3 and 5 are evaluated against the workspace dependency **graph**
//! (`cargo metadata --no-deps`). §4.1 is explicit that this is the point:
//! "Cargo cannot forbid a syscall; it can forbid an edge." Grepping source
//! would be a different, weaker check.
//!
//! Rule 4 is a call-site constraint, so it is evaluated as a source scan paired
//! with the workspace-wide `clippy::disallowed_methods` deny.
//!
//! Any violation exits non-zero. This command is a required CI step.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

// ---------------------------------------------------------------------------
// Policy (xtask/deps-policy.toml)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Policy {
    pub expected_crates: Vec<String>,
    pub rule1: Rule1,
    pub rule2: Rule2,
    pub rule3: Rule3,
    pub rule4: Rule4,
    pub rule5: Rule5,
}

#[derive(Debug, Deserialize)]
pub struct Rule1 {
    pub crates: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Rule2 {
    pub protected: String,
    pub sole_dependent: String,
    #[serde(default)]
    pub dev_exemptions: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Rule3 {
    pub crate_name: String,
    pub allowed_internal_deps: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Rule4 {
    pub scan_roots: Vec<String>,
    pub escape_hatch: String,
    pub escape_hatch_allowed_in: Vec<String>,
    #[serde(default)]
    pub not_tracked: Vec<String>,
    #[serde(default)]
    pub symbols: Vec<Symbol>,
}

#[derive(Debug, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub owner: String,
    pub implemented_in: Vec<String>,
    pub sole_caller: String,
}

#[derive(Debug, Deserialize)]
pub struct Rule5 {
    pub external_crate: String,
    pub sole_dependent: String,
}

pub fn load_policy(path: &Path) -> Result<Policy, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read policy {}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("cannot parse policy {}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// cargo metadata
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Metadata {
    packages: Vec<Package>,
    workspace_members: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Package {
    name: String,
    id: String,
    manifest_path: String,
    dependencies: Vec<Dep>,
}

#[derive(Debug, Deserialize)]
struct Dep {
    name: String,
    /// `null` for a normal dependency, `"dev"` or `"build"` otherwise.
    kind: Option<String>,
}

impl Dep {
    fn kind_label(&self) -> &str {
        match self.kind.as_deref() {
            None => "dependencies",
            Some("dev") => "dev-dependencies",
            Some("build") => "build-dependencies",
            Some(other) => other,
        }
    }

    fn is_dev(&self) -> bool {
        self.kind.as_deref() == Some("dev")
    }
}

fn cargo_metadata(root: &Path) -> Result<Metadata, String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let out = Command::new(cargo)
        .current_dir(root)
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .map_err(|e| format!("failed to run `cargo metadata`: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "`cargo metadata` failed ({}):\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| format!("cannot parse cargo metadata: {e}"))
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

pub struct RuleResult {
    pub id: &'static str,
    pub title: String,
    pub violations: Vec<String>,
    /// How many concrete things this rule actually looked at. A rule that
    /// inspected nothing is reported as such rather than as a pass.
    pub inspected: usize,
}

pub struct Report {
    pub rules: Vec<RuleResult>,
}

impl Report {
    pub fn failed(&self) -> bool {
        self.rules.iter().any(|r| !r.violations.is_empty())
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "cargo xtask check-deps — §4.1 dependency rules");
        let _ = writeln!(s, "{}", "=".repeat(72));
        for r in &self.rules {
            let status = if r.violations.is_empty() {
                "PASS"
            } else {
                "FAIL"
            };
            let _ = writeln!(
                s,
                "[{status}] {}: {} ({} checked)",
                r.id, r.title, r.inspected
            );
            for v in &r.violations {
                let _ = writeln!(s, "         ✗ {v}");
            }
        }
        let _ = writeln!(s, "{}", "=".repeat(72));
        let failed: Vec<_> = self
            .rules
            .iter()
            .filter(|r| !r.violations.is_empty())
            .collect();
        if failed.is_empty() {
            let _ = writeln!(s, "RESULT: PASS — {} rules, 0 violations", self.rules.len());
        } else {
            let n: usize = failed.iter().map(|r| r.violations.len()).sum();
            let _ = writeln!(
                s,
                "RESULT: FAIL — {n} violation(s) across {} rule(s): {}",
                failed.len(),
                failed.iter().map(|r| r.id).collect::<Vec<_>>().join(", ")
            );
        }
        s
    }

    pub fn to_json(&self) -> String {
        let rules: Vec<_> = self
            .rules
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id,
                    "title": r.title,
                    "inspected": r.inspected,
                    "pass": r.violations.is_empty(),
                    "violations": r.violations,
                })
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "command": "check-deps",
            "pass": !self.failed(),
            "rules": rules,
        }))
        .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn run(root: &Path, policy: &Policy) -> Result<Report, String> {
    let md = cargo_metadata(root)?;
    let members: BTreeSet<&str> = md
        .workspace_members
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let workspace: Vec<&Package> = md
        .packages
        .iter()
        .filter(|p| members.contains(p.id.as_str()))
        .collect();
    let internal: BTreeSet<&str> = workspace.iter().map(|p| p.name.as_str()).collect();

    let rules = vec![
        rule0(root, &workspace, &internal, policy),
        rule1(&workspace, &internal, policy),
        rule2(&workspace, policy),
        rule3(&workspace, &internal, policy),
        rule4(root, policy)?,
        rule5(&workspace, policy),
    ];
    Ok(Report { rules })
}

// --- rule 0: workspace completeness ----------------------------------------

fn rule0(
    root: &Path,
    workspace: &[&Package],
    internal: &BTreeSet<&str>,
    policy: &Policy,
) -> RuleResult {
    let mut violations = Vec::new();

    for want in &policy.expected_crates {
        if !internal.contains(want.as_str()) {
            violations.push(format!(
                "expected crate `{want}` is not a workspace member (deps-policy.toml \
                 expected_crates); a non-member is invisible to rules 1-3 and 5"
            ));
        }
    }

    // Every directory under crates/ must be a member.
    let crates_dir = root.join("crates");
    let mut on_disk = 0usize;
    if let Ok(entries) = std::fs::read_dir(&crates_dir) {
        for e in entries.flatten() {
            if !e.path().is_dir() || !e.path().join("Cargo.toml").is_file() {
                continue;
            }
            on_disk += 1;
            let name = e.file_name().to_string_lossy().to_string();
            let is_member = workspace.iter().any(|p| {
                Path::new(&p.manifest_path)
                    .parent()
                    .map(|d| d == e.path())
                    .unwrap_or(false)
            });
            if !is_member {
                violations.push(format!(
                    "crates/{name} has a Cargo.toml but is not a workspace member"
                ));
            }
        }
    } else {
        violations.push(format!("cannot read {}", crates_dir.display()));
    }

    RuleResult {
        id: "rule0",
        title: format!(
            "workspace completeness — all {} expected crates present and members",
            policy.expected_crates.len()
        ),
        violations,
        inspected: policy.expected_crates.len() + on_disk,
    }
}

// --- rule 1 -----------------------------------------------------------------

fn rule1(workspace: &[&Package], internal: &BTreeSet<&str>, policy: &Policy) -> RuleResult {
    let mut violations = Vec::new();
    for name in &policy.rule1.crates {
        let Some(pkg) = workspace.iter().find(|p| &p.name == name) else {
            violations.push(format!("`{name}` is not a workspace member"));
            continue;
        };
        for dep in &pkg.dependencies {
            if internal.contains(dep.name.as_str()) {
                violations.push(format!(
                    "`{name}` [{}] depends on internal crate `{}` — rule 1 says it depends on \
                     nothing internal",
                    dep.kind_label(),
                    dep.name
                ));
            }
        }
    }
    RuleResult {
        id: "rule1",
        title: format!(
            "{} depend on nothing internal",
            policy.rule1.crates.join(" and ")
        ),
        violations,
        inspected: policy.rule1.crates.len(),
    }
}

// --- rule 2 -----------------------------------------------------------------

fn rule2(workspace: &[&Package], policy: &Policy) -> RuleResult {
    let protected = policy.rule2.protected.as_str();
    let sole = policy.rule2.sole_dependent.as_str();
    let mut violations = Vec::new();
    for pkg in workspace {
        if pkg.name == protected || pkg.name == sole {
            continue;
        }
        for dep in &pkg.dependencies {
            if dep.name != protected {
                continue;
            }
            if dep.is_dev() && policy.rule2.dev_exemptions.contains(&pkg.name) {
                continue;
            }
            violations.push(format!(
                "`{}` [{}] depends on `{protected}` — only `{sole}` may. This edge is what makes \
                 `{sole}::destroy` the only path to a destructive syscall (§4.1 rule 2)",
                pkg.name,
                dep.kind_label()
            ));
        }
    }
    RuleResult {
        id: "rule2",
        title: format!("no crate except `{sole}` depends on `{protected}`"),
        violations,
        // Crates examined, not hits found: "0 checked" on a rule with no hits
        // would be indistinguishable from a rule that never ran.
        inspected: workspace.len(),
    }
}

// --- rule 3 -----------------------------------------------------------------

fn rule3(workspace: &[&Package], internal: &BTreeSet<&str>, policy: &Policy) -> RuleResult {
    let name = policy.rule3.crate_name.as_str();
    let mut violations = Vec::new();
    let mut inspected = 0usize;
    match workspace.iter().find(|p| p.name == name) {
        None => violations.push(format!("`{name}` is not a workspace member")),
        Some(pkg) => {
            for dep in &pkg.dependencies {
                if !internal.contains(dep.name.as_str()) {
                    continue; // external crates are unconstrained by rule 3
                }
                inspected += 1;
                if policy.rule3.allowed_internal_deps.contains(&dep.name) {
                    continue;
                }
                violations.push(format!(
                    "`{name}` [{}] depends on internal crate `{}`, which is not in \
                     rule3.allowed_internal_deps ({}). AC-38's \"plugins cannot trigger a \
                     destructive placeholder operation\" is a compile-time property; widening \
                     this list is a deliberate, reviewed change to deps-policy.toml",
                    dep.kind_label(),
                    dep.name,
                    policy.rule3.allowed_internal_deps.join(", ")
                ));
            }
        }
    }
    RuleResult {
        id: "rule3",
        title: format!(
            "`{name}` depends only on [{}] — not on `shepherd-tier`, `shepherd-placeholder`, \
             or any filesystem-mutating crate",
            policy.rule3.allowed_internal_deps.join(", ")
        ),
        violations,
        inspected,
    }
}

// --- rule 5 -----------------------------------------------------------------

fn rule5(workspace: &[&Package], policy: &Policy) -> RuleResult {
    let ext = policy.rule5.external_crate.as_str();
    let sole = policy.rule5.sole_dependent.as_str();
    let mut violations = Vec::new();
    for pkg in workspace {
        if pkg.name == sole {
            continue;
        }
        for dep in &pkg.dependencies {
            if dep.name == ext {
                violations.push(format!(
                    "`{}` [{}] depends on `{ext}` — only `{sole}` may, and only for `_shepherd/` \
                     control objects. `{ext}` parts cannot be resumed after disconnection and \
                     spec:89 requires every transfer to be resumable (§4.5)",
                    pkg.name,
                    dep.kind_label()
                ));
            }
        }
    }
    RuleResult {
        id: "rule5",
        title: format!("only `{sole}` depends on `{ext}` (§4.5 control-object boundary)"),
        violations,
        inspected: workspace.len(),
    }
}

// ---------------------------------------------------------------------------
// rule 4 — source scan
// ---------------------------------------------------------------------------

/// Collect every `.rs` file under the configured scan roots.
fn rust_files(root: &Path, scan_roots: &[String]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for r in scan_roots {
        collect_rs(&root.join(r), &mut out);
    }
    out.sort();
    out
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            let name = e.file_name();
            if name == "target" || name == ".git" {
                continue;
            }
            collect_rs(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// `true` if `hay` contains `needle` bounded by non-identifier characters.
///
/// Identifier characters are `[A-Za-z0-9_]`, so `delete_object` does **not**
/// match inside `delete_system_object` (which contains no such substring) and
/// does not match inside `soft_delete_objects` either.
pub fn contains_ident(hay: &str, needle: &str) -> bool {
    let hb = hay.as_bytes();
    let nb = needle.as_bytes();
    if nb.is_empty() || nb.len() > hb.len() {
        return false;
    }
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut i = 0usize;
    while i + nb.len() <= hb.len() {
        if &hb[i..i + nb.len()] == nb {
            let before_ok = i == 0 || !is_ident(hb[i - 1]);
            let after_ok = i + nb.len() == hb.len() || !is_ident(hb[i + nb.len()]);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Strip a trailing `//` line comment. Whole-comment lines become empty.
///
/// This is deliberately simple: it means a doc comment naming a destructive
/// method does not trip the scan, while actual code cannot hide behind it
/// (there is no executable Rust after `//` on a line).
pub fn strip_comment(line: &str) -> &str {
    match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    }
}

/// Blank string-literal contents and strip comments, carrying literal state
/// ACROSS lines.
///
/// Rule 4 matches identifiers to find CALLS. Without this it also matches
/// MENTIONS, and those are different claims. The case that forced it:
/// `ac2_resume_50gb.rs` prints a cleanup hint whose text explains that the test
/// deliberately does NOT call `delete_object`, and rule 4 reported it — so a
/// message about respecting the fence read as a breach of it. A check that
/// fires on prose describing the thing matches the name rather than the use,
/// which is what this rule exists to catch everywhere else.
///
/// STATE CROSSES LINES because the literal did. A first attempt blanked each
/// line independently and still reported the violation: the match sits on a
/// `\n\` continuation line that contains no quote of its own, so a per-line
/// scanner cannot know it is inside a string. That is the same shape of error
/// as the defect being fixed — a check looking at the wrong unit.
///
/// Conservative toward REPORTING. Raw and byte strings set `raw_guard`, after
/// which the line is passed through untouched rather than half-parsed, and an
/// unterminated quote simply leaves `in_str` set for the next line. Anything
/// this cannot read confidently still reaches the matcher: a false positive
/// costs a conversation, a false negative costs the fence.
fn clean_line(line: &str, in_str: &mut bool) -> String {
    if line.contains("r\"") || line.contains("r#\"") || line.contains("b\"") {
        return line.to_string();
    }
    let mut out = String::with_capacity(line.len());
    let mut escaped = false;
    let bytes: Vec<char> = line.chars().collect();
    let mut k = 0;
    while k < bytes.len() {
        let c = bytes[k];
        if *in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                *in_str = false;
                out.push(c);
                k += 1;
                continue;
            }
            out.push(' ');
        } else {
            // A `//` outside a literal starts a comment: nothing after it is code.
            if c == '/' && k + 1 < bytes.len() && bytes[k + 1] == '/' {
                break;
            }
            if c == '"' {
                *in_str = true;
            }
            out.push(c);
        }
        k += 1;
    }
    out
}

fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Rule 4a — destructive symbols are declared only in their owning crate and
/// called only from `destroy.rs`. Rule 4b — the clippy escape hatch appears
/// only in `destroy.rs`.
pub fn scan_rule4(root: &Path, policy: &Rule4) -> Result<(Vec<String>, usize), String> {
    let files = rust_files(root, &policy.scan_roots);
    let mut violations = Vec::new();

    for path in &files {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let relp = rel(root, path);

        // Literal state is per FILE, not per line — see `clean_line`.
        let mut in_str = false;
        for (lineno, raw) in text.lines().enumerate() {
            let stripped = clean_line(raw, &mut in_str);
            let line = stripped.as_str();
            if line.trim().is_empty() {
                continue;
            }

            // 4b — escape hatch.
            if contains_ident_phrase(line, &policy.escape_hatch)
                && !policy.escape_hatch_allowed_in.contains(&relp)
            {
                violations.push(format!(
                    "{relp}:{}: `{}` may appear only in {} — it is the single escape hatch from \
                     the workspace-wide `clippy::disallowed_methods` deny (§4.1 rule 4)",
                    lineno + 1,
                    policy.escape_hatch,
                    policy.escape_hatch_allowed_in.join(", ")
                ));
            }

            // 4a — destructive symbols.
            for sym in &policy.symbols {
                if !contains_ident(line, &sym.name) {
                    continue;
                }
                let implemented = sym.implemented_in.iter().any(|p| relp.starts_with(p));
                let is_sole_caller = relp == sym.sole_caller;
                if implemented || is_sole_caller {
                    continue;
                }
                violations.push(format!(
                    "{relp}:{}: references `{}::{}` — only {} may call it, and only {} may \
                     implement it (§4.1 rule 4). {}",
                    lineno + 1,
                    sym.owner,
                    sym.name,
                    sym.sole_caller,
                    sym.implemented_in.join(", "),
                    if policy.not_tracked.is_empty() {
                        String::new()
                    } else {
                        format!(
                            "Not tracked by this rule: {}",
                            policy.not_tracked.join(", ")
                        )
                    }
                ));
            }
        }
    }

    Ok((violations, files.len()))
}

/// Match an attribute phrase like `allow(clippy::disallowed_methods)` allowing
/// arbitrary internal whitespace, so `allow( clippy::disallowed_methods )` and
/// `allow(clippy::disallowed_methods, dead_code)` are both caught.
pub fn contains_ident_phrase(line: &str, phrase: &str) -> bool {
    let squash = |s: &str| s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
    let l = squash(line);
    let p = squash(phrase);
    // Tolerate the multi-lint form `allow(clippy::disallowed_methods, x)`.
    let p_open = p.strip_suffix(')').unwrap_or(&p).to_string();
    l.contains(&p) || l.contains(&format!("{p_open},"))
}

fn rule4(root: &Path, policy: &Policy) -> Result<RuleResult, String> {
    let (violations, files) = scan_rule4(root, &policy.rule4)?;
    Ok(RuleResult {
        id: "rule4",
        title: format!(
            "`{}` is the sole caller of [{}]; escape hatch confined to it",
            policy
                .rule4
                .symbols
                .first()
                .map(|s| s.sole_caller.as_str())
                .unwrap_or("<no symbols configured>"),
            policy
                .rule4
                .symbols
                .iter()
                .map(|s| format!("{}::{}", s.owner, s.name))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        violations,
        inspected: files,
    })
}
