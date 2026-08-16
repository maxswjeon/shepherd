//! User ignore patterns, `.gitignore` semantics (AC-9).
//!
//! A thin wrapper over `ignore::gitignore`, BurntSushi's matcher — the one
//! ripgrep ships. §8.1 specifies the full semantics ("negation, `**`, trailing
//! `/`, anchoring, precedence"), and those are each a way to be *quietly*
//! wrong: a negation cannot re-include a file whose parent directory was
//! excluded; `**` means different things leading, trailing and embedded;
//! trailing `/` restricts to directories; last-match-wins across layered files.
//!
//! The direction of failure decides the trade. An ignore rule that fails to
//! match makes a file the user explicitly excluded eligible for tiering and,
//! under a `discard` policy, destruction. That is a safety path.
//!
//! # Two consumers, one answer
//!
//! §9's Phase 2 gate requires ignore patterns honoured on **both scan and
//! tier** — AC-9's test row is "Ignore patterns honored on *both* scan and
//! tier". A file skipped at scan time but re-considered at tier time would
//! satisfy neither. Both call [`IgnoreSet::is_ignored`]; there is no second
//! implementation to disagree.
//!
//! # The matcher alone is not the whole semantics — the walker's pruning is
//!
//! Established empirically, not assumed: with patterns `["secret/",
//! "!secret/keep.txt"]`, `matched_path_or_any_parents` reports
//! `secret/keep.txt` as **whitelisted**. Git behaves the opposite way, because
//! git never descends into an excluded directory and so never reconsiders the
//! file.
//!
//! That rule lives in the *traversal*, not the matcher, in git and here alike.
//! [`crate::walk`] prunes an ignored directory and never asks about its
//! contents, which is what makes the composed behaviour match git's. A caller
//! that consults [`IgnoreSet::is_ignored`] on an arbitrary path **without**
//! having pruned its parents does not get git semantics — see
//! [`IgnoreSet::is_ignored_with_parents`] for the standalone form.

use std::path::Path;

use ignore::gitignore::{Gitignore, GitignoreBuilder};

#[derive(Debug, thiserror::Error)]
pub enum IgnoreError {
    #[error("invalid ignore pattern `{pattern}`: {detail}")]
    Pattern { pattern: String, detail: String },
    #[error("cannot build ignore set: {0}")]
    Build(String),
}

pub type Result<T> = std::result::Result<T, IgnoreError>;

/// The compiled ignore set for one scan root.
#[derive(Debug)]
pub struct IgnoreSet {
    inner: Gitignore,
}

impl IgnoreSet {
    /// Compile `patterns`, in order. Later patterns win, as in `.gitignore`.
    ///
    /// `root` anchors the set: a leading `/` in a pattern means "relative to
    /// the scan root", not to the filesystem root.
    pub fn new(root: &Path, patterns: &[String]) -> Result<Self> {
        let mut b = GitignoreBuilder::new(root);
        for p in patterns {
            b.add_line(None, p).map_err(|e| IgnoreError::Pattern {
                pattern: p.clone(),
                detail: e.to_string(),
            })?;
        }
        Ok(Self {
            inner: b.build().map_err(|e| IgnoreError::Build(e.to_string()))?,
        })
    }

    /// An ignore set that matches nothing.
    pub fn empty(root: &Path) -> Result<Self> {
        Self::new(root, &[])
    }

    /// Whether `path` is excluded.
    ///
    /// `is_dir` matters: a trailing-slash pattern (`build/`) matches only
    /// directories, and answering it wrong either misses the exclusion or
    /// applies it to a file the user did not name.
    pub fn is_ignored(&self, path: &Path, is_dir: bool) -> bool {
        self.inner
            .matched_path_or_any_parents(path, is_dir)
            .is_ignore()
    }

    /// [`IgnoreSet::is_ignored`], plus git's parent-exclusion rule applied
    /// explicitly.
    ///
    /// For a caller that did **not** arrive here by walking — the tier path
    /// re-checking a catalog row, for instance — this is the correct entry
    /// point. It walks the ancestors between `root` and `path` and treats the
    /// file as ignored if any ancestor directory is, because a negation cannot
    /// re-include a file whose parent directory was excluded.
    ///
    /// AC-9 requires ignores honoured on **both** scan and tier. The scan side
    /// gets this from pruning; the tier side has no walk to prune, so it gets
    /// it from here.
    pub fn is_ignored_with_parents(&self, root: &Path, path: &Path, is_dir: bool) -> bool {
        let Ok(rel) = path.strip_prefix(root) else {
            return self.is_ignored(path, is_dir);
        };
        let mut prefix = root.to_path_buf();
        let components: Vec<_> = rel.components().collect();
        for (i, c) in components.iter().enumerate() {
            prefix.push(c);
            let last = i + 1 == components.len();
            let as_dir = if last { is_dir } else { true };
            if self.inner.matched(&prefix, as_dir).is_ignore() {
                return true;
            }
        }
        false
    }

    /// `true` when no pattern was compiled.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// These are contract tests over the wrapper, not tests of BurntSushi's
    /// matcher. What they establish is that the wiring — anchoring at the scan
    /// root, the `is_dir` flag, parent-directory propagation — is correct, so a
    /// pattern the user writes means what `.gitignore` says it means. §8.1
    /// names exactly these five behaviours.
    fn set(patterns: &[&str]) -> IgnoreSet {
        let pats: Vec<String> = patterns.iter().map(|s| s.to_string()).collect();
        IgnoreSet::new(Path::new("/root"), &pats).unwrap()
    }

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn a_plain_pattern_matches_at_any_depth() {
        let s = set(&["*.log"]);
        assert!(s.is_ignored(&p("/root/a.log"), false));
        assert!(s.is_ignored(&p("/root/deep/nested/b.log"), false));
        assert!(!s.is_ignored(&p("/root/a.txt"), false));
    }

    /// §8.1: anchoring. A leading `/` anchors to the scan root, not the
    /// filesystem root — which is what `GitignoreBuilder::new(root)` buys.
    #[test]
    fn a_leading_slash_anchors_to_the_scan_root() {
        let s = set(&["/build"]);
        assert!(s.is_ignored(&p("/root/build"), true));
        assert!(
            !s.is_ignored(&p("/root/sub/build"), true),
            "an anchored pattern must not match at depth"
        );
    }

    /// §8.1: trailing `/` restricts to directories.
    #[test]
    fn a_trailing_slash_matches_directories_only() {
        let s = set(&["cache/"]);
        assert!(s.is_ignored(&p("/root/cache"), true));
        assert!(
            !s.is_ignored(&p("/root/cache"), false),
            "a FILE named `cache` is not matched by `cache/`"
        );
    }

    /// §8.1: `**`.
    #[test]
    fn double_star_spans_directories() {
        let s = set(&["logs/**/*.txt"]);
        assert!(s.is_ignored(&p("/root/logs/a.txt"), false));
        assert!(s.is_ignored(&p("/root/logs/x/y/b.txt"), false));
        assert!(!s.is_ignored(&p("/root/other/a.txt"), false));
    }

    /// §8.1: negation and precedence together. Last match wins.
    #[test]
    fn negation_re_includes_and_the_last_pattern_wins() {
        let s = set(&["*.log", "!keep.log"]);
        assert!(s.is_ignored(&p("/root/a.log"), false));
        assert!(!s.is_ignored(&p("/root/keep.log"), false));

        // Order matters: reversing them means the exclusion is applied last.
        let s = set(&["!keep.log", "*.log"]);
        assert!(s.is_ignored(&p("/root/keep.log"), false));
    }

    /// The subtle rule: a negation cannot re-include a file whose PARENT
    /// DIRECTORY was excluded, because git never descends into an excluded
    /// directory and so never reconsiders the file.
    ///
    /// **The bare matcher does not implement this**, which was established by
    /// running it rather than assumed. `matched_path_or_any_parents` finds the
    /// negation on the path itself and reports whitelisted. The rule lives in
    /// the traversal — in git and here alike — so the scan side gets it from
    /// [`crate::walk`]'s pruning and any non-walking caller must use
    /// [`IgnoreSet::is_ignored_with_parents`].
    #[test]
    fn the_bare_matcher_does_not_apply_the_parent_exclusion_rule() {
        let s = set(&["secret/", "!secret/keep.txt"]);
        assert!(s.is_ignored(&p("/root/secret"), true));
        assert!(
            !s.is_ignored(&p("/root/secret/keep.txt"), false),
            "documenting the matcher's actual behaviour, so nobody relies on \
             the opposite"
        );
    }

    /// …and the parent-aware form, which the tier path uses, does apply it.
    #[test]
    fn the_parent_aware_form_refuses_a_file_under_an_excluded_directory() {
        let s = set(&["secret/", "!secret/keep.txt"]);
        let root = Path::new("/root");
        assert!(
            s.is_ignored_with_parents(root, &p("/root/secret/keep.txt"), false),
            "the parent directory is excluded, so the negation does not apply"
        );
        // A negation that is NOT shadowed by an excluded parent still works.
        let s = set(&["*.log", "!keep.log"]);
        assert!(!s.is_ignored_with_parents(root, &p("/root/keep.log"), false));
        assert!(s.is_ignored_with_parents(root, &p("/root/other.log"), false));
    }

    /// Parent propagation: a file under an ignored directory is ignored even
    /// when nothing names the file itself. `matched_path_or_any_parents` is
    /// what supplies this, and it is the reason the walker's pruning and this
    /// predicate agree.
    #[test]
    fn files_inherit_an_ignored_parent() {
        let s = set(&["node_modules"]);
        assert!(s.is_ignored(&p("/root/node_modules/pkg/index.js"), false));
    }

    #[test]
    fn an_empty_set_ignores_nothing() {
        let s = IgnoreSet::empty(Path::new("/root")).unwrap();
        assert!(s.is_empty());
        assert!(!s.is_ignored(&p("/root/anything.log"), false));
    }

    /// **The matcher is permissive**, established by running it: an unmatched
    /// `[` compiles rather than erroring.
    ///
    /// Recorded as a test because it is a real limitation with a user-visible
    /// consequence — a typo'd pattern becomes one that matches nothing, and the
    /// user believes an exclusion is in force that is not. The error path
    /// exists and is wired, so a pattern the builder *does* reject surfaces;
    /// there is simply less in that category than one would expect. Surfacing
    /// "this pattern matched nothing across the whole scan" belongs with the
    /// scan summary, where the counts are, not here.
    #[test]
    fn the_matcher_accepts_more_than_it_rejects() {
        let s = IgnoreSet::new(Path::new("/root"), &["[".to_string()]);
        assert!(
            s.is_ok(),
            "documenting permissiveness: a lone `[` is accepted, not rejected"
        );
    }
}
