//! Assertions over the **committed evidence artifacts** that §9's gates name.
//!
//! # Why this module exists
//!
//! §9's Phase 0a/0b gate asks for "`bench-baseline.json` with metadata p95,
//! vector p95 and index RSS at 10M **within bars**". Both halves of that were
//! present in the repository and neither was checked: `bench-baseline.json`
//! records the numbers, `bench-contract.toml` records the bars, and **no test
//! anywhere in the workspace read either file**. The comparison between them —
//! the entire content of the gate — lived only in a human reading two documents
//! and an ADR asserting the conclusion.
//!
//! That is the shape §9 rule 6 refuses: "a name attached to a self-report". The
//! numbers do not become evidence by being written down; they become evidence
//! when something fails if they change.
//!
//! # What these checks are, and what they are not
//!
//! They are checks that the **recorded** measurement satisfies the
//! **precommitted** contract — the artifact against the bar, and the run
//! parameters against the contract that was fixed before the run. A regression
//! that re-emitted `bench-baseline.json` with a worse p95, an edit that moved a
//! bar to fit a number, or a re-run at the wrong concurrency now fails a test.
//!
//! They are **not** a re-measurement. Nothing here runs the bench; the machine
//! that produced those numbers is described in `[reference_machine]` and is not
//! this one. A gate citing these tests is entitled to say "the recorded result
//! clears the precommitted bar", and is not entitled to say "the bar holds
//! today" — which is why §9 has Phase 5 re-run the bench on the real corpus.

use std::path::{Path, PathBuf};

/// Repository root, from this crate's manifest directory.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask/ has a parent")
        .to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline() -> serde_json::Value {
        let p = repo_root().join("bench-baseline.json");
        let text = std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("§9's Phase 0a/0b gate names {}: {e}", p.display()));
        serde_json::from_str(&text).expect("bench-baseline.json is JSON")
    }

    fn contract() -> toml::Value {
        let p = repo_root().join("bench-contract.toml");
        let text = std::fs::read_to_string(&p)
            .unwrap_or_else(|e| panic!("§9's Phase 0a/0b gate names {}: {e}", p.display()));
        toml::from_str(&text).expect("bench-contract.toml is TOML")
    }

    fn f64_at(v: &serde_json::Value, path: &[&str]) -> f64 {
        let mut cur = v;
        for k in path {
            cur = cur
                .get(k)
                .unwrap_or_else(|| panic!("bench-baseline.json has no `{}`", path.join(".")));
        }
        cur.as_f64()
            .unwrap_or_else(|| panic!("`{}` is not a number", path.join(".")))
    }

    fn bar(name: &str) -> f64 {
        contract()["bars"][name]
            .as_float()
            .unwrap_or_else(|| panic!("bench-contract.toml [bars] has no float `{name}`"))
    }

    /// **The metadata bar, checked rather than asserted.** §9's Phase 0a/0b row
    /// wants metadata p95 within its bar; §9's Phase 1 row repeats it as M1's
    /// scale leg. The bar is read from the contract and the measurement from
    /// the baseline, so moving either one to make them agree fails here.
    ///
    /// Cold and warm are checked separately because `[execution]` measures them
    /// separately and a warm-only pass would be the easier half reported as the
    /// result.
    #[test]
    fn the_recorded_metadata_p95_clears_the_precommitted_bar_in_both_cache_states() {
        let b = baseline();
        let limit = bar("metadata_p95_ms");
        for cache in ["cold", "warm"] {
            let key = format!("meta_bench_arena_{cache}");
            let p95 = f64_at(&b, &[&key, "stats", "accepted_p95_ms"]);
            let recorded_bar = f64_at(&b, &[&key, "bar_ms"]);
            assert_eq!(
                recorded_bar, limit,
                "{key} was measured against a {recorded_bar} ms bar while bench-contract.toml \
                 fixes {limit} ms. The bar moved after the run, which is the one edit that can \
                 make any measurement pass"
            );
            assert!(
                p95 < limit,
                "{key} p95 is {p95:.2} ms against the precommitted {limit} ms bar"
            );
            assert_eq!(
                b[&key]["pass"].as_bool(),
                Some(true),
                "{key} records pass=false; a gate citing this artifact would be citing a failure"
            );
            assert_eq!(
                b[&key]["rows"].as_u64(),
                contract()["fixture"]["rows"].as_integer().map(|i| i as u64),
                "{key} was measured over a different row count than the contract fixes — the \
                 10M in \"< 50 ms p95 at 10M\" is half the claim"
            );
        }
    }

    /// The winner is **derived from the artifact, not read from the ADR.**
    ///
    /// `bench-baseline.json` carries no `winner` key: the decision lives in
    /// `docs/adr/0b-index-decision.md` as prose. So the check that the ADR is
    /// backed is that exactly one candidate passes the bar in both cache
    /// states, and that it is the one the ADR names. If a future re-measure
    /// promotes another candidate, or demotes this one, the ADR stops matching
    /// its own evidence here rather than in someone's memory.
    #[test]
    fn the_adr_names_the_only_candidate_that_actually_passed() {
        let b = baseline();
        let winners: Vec<&str> = ["arena", "fts5", "tantivy"]
            .into_iter()
            .filter(|c| {
                ["cold", "warm"].iter().all(|cache| {
                    b[format!("meta_bench_{c}_{cache}")]["pass"]
                        .as_bool()
                        .unwrap_or(false)
                })
            })
            .collect();
        assert_eq!(
            winners,
            ["arena"],
            "the §4.6 tiebreak rule was applied at step 1 with 'no tie to break'; that is only \
             true while exactly one candidate clears the bar in both cache states"
        );

        let adr = std::fs::read_to_string(repo_root().join("docs/adr/0b-index-decision.md"))
            .expect("§9's Phase 0a/0b gate names a written index decision");
        assert!(
            adr.contains("in-RAM name arena"),
            "the ADR must name the candidate its own evidence selects"
        );
    }

    /// **The run parameters, against the contract that was fixed before the
    /// run.** §9 spends most of its Phase 0a/0b row on these — seed,
    /// concurrency, the statistical rule — because a p95 measured with one
    /// client and no background load is a different number wearing the same
    /// name.
    #[test]
    fn the_recorded_run_matches_the_precommitted_workload_contract() {
        let b = baseline();
        let c = contract();
        let cell = &b["meta_bench_arena_cold"];

        assert_eq!(
            cell["query_clients"].as_i64(),
            c["execution"]["query_clients"].as_integer(),
            "concurrency differs from the contract's fixed 4 concurrent clients"
        );
        assert!(
            cell["background_rows_ingested"].as_u64().unwrap_or(0) > 0,
            "the contract fixes a background ingest load; a run without one is an idle-daemon \
             measurement"
        );
        let runs = cell["stats"]["runs"]
            .as_array()
            .expect("stats.runs is an array");
        assert_eq!(
            runs.len() as i64,
            c["statistics"]["runs"].as_integer().unwrap(),
            "the contract fixes the number of runs; accept-on-median-of-runs is meaningless \
             with a different count"
        );
        for r in runs {
            assert_eq!(
                r["n"].as_i64(),
                c["statistics"]["queries_per_run"].as_integer(),
                "a run used a different query count than the contract's `queries_per_run`"
            );
        }
    }

    /// AC-46's ceiling is a **range with a floor**, and §9 states the floor is
    /// a rejection: "< 4 GB rejected as unachievable at 10M × 384-dim". A
    /// ceiling recorded as satisfied by a measurement that was never taken at
    /// 10M is the failure mode here, so the scaled f32 cell is excluded by
    /// name rather than by hoping nobody looks.
    #[test]
    fn every_ann_cell_that_ran_at_full_scale_fits_the_ac46_band() {
        let b = baseline();
        let c = contract();
        let min = c["bars"]["ac46_ceiling_min_gib"].as_float().unwrap();
        let max = c["bars"]["ac46_ceiling_max_gib"].as_float().unwrap();
        let vectors = c["fixture"]["vectors"].as_integer().unwrap() as u64;

        let mut checked = 0;
        for (key, cell) in b.as_object().unwrap() {
            if !key.starts_with("ann_bench_") {
                continue;
            }
            if cell["vectors"].as_u64() != Some(vectors) {
                // A scaled run. It must say so rather than pass quietly.
                assert!(
                    cell["scaled_run_reason"].is_string(),
                    "{key} ran at a reduced scale with no recorded reason"
                );
                continue;
            }
            let rss_gib = cell["peak_vm_hwm_bytes"].as_f64().unwrap() / 1024.0_f64.powi(3);
            assert!(
                rss_gib >= min && rss_gib <= max,
                "{key} peak RSS is {rss_gib:.2} GiB, outside AC-46's {min}–{max} GiB band"
            );
            let p95 = f64_at(&b, &[key.as_str(), "stats", "accepted_p95_ms"]);
            assert!(
                p95 < bar("vector_p95_ms"),
                "{key} vector p95 is {p95:.2} ms against a {} ms bar",
                bar("vector_p95_ms")
            );
            checked += 1;
        }
        // The assertion that makes the loop mean something: a filter matching
        // nothing would have passed every line above.
        assert!(
            checked >= 4,
            "only {checked} full-scale ANN cells were checked; f16 and i8 were each measured \
             cold and warm, so a count below four means the loop filtered out the evidence"
        );
    }

    /// **`shepctl`'s command surface against the method registry, asserted to
    /// be in CI.** §9's Phase 1 row requires that AC-54's check "runs in CI
    /// **from this phase**" while AC-54 itself is owned at Phase 8. Running the
    /// test locally proves the test passes; it does not prove CI runs it, and
    /// the clause is specifically about CI. This reads the workflow.
    #[test]
    fn ci_runs_the_ac54_cli_equals_registry_check_with_a_count_guard() {
        let ci = std::fs::read_to_string(repo_root().join(".github/workflows/ci.yml"))
            .expect("Phase 0a creates .github/workflows/ci.yml");
        assert!(
            ci.contains("ac54_cli_equals_registered_methods"),
            "§9 requires AC-54's CLI == registered_methods check to run in CI from Phase 1, and \
             the workflow does not name it"
        );
        assert!(
            ci.contains("1 passed"),
            "the CI step must assert the test COUNT, not its exit status: `cargo test --exact` \
             on a name that no longer exists exits 0 and runs nothing"
        );
    }

    /// The three-platform matrix §9's Phase 0a/0b row demands, read from the
    /// workflow rather than from the artifact's prose.
    #[test]
    fn ci_declares_all_three_platforms() {
        let ci = std::fs::read_to_string(repo_root().join(".github/workflows/ci.yml"))
            .expect("Phase 0a creates .github/workflows/ci.yml");
        for os in ["ubuntu-latest", "windows-latest", "macos-latest"] {
            assert!(ci.contains(os), "the CI matrix does not declare {os}");
        }
    }

    /// The tiebreak rule §4.6 fixes has five scored axes, three of which
    /// (persistence, crash-consistency, cold-start rebuild) were added because
    /// latency-and-RSS alone would have picked a different candidate. A
    /// contract that quietly lost them would let the decision be re-derived on
    /// the two axes it was corrected away from.
    #[test]
    fn the_contract_still_scores_every_axis_the_tiebreak_rule_names() {
        let c = contract();
        let axes: Vec<String> = c["tiebreak"]["scored_axes"]
            .as_array()
            .expect("[tiebreak].scored_axes")
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        for axis in [
            "latency_p95",
            "index_rss",
            "persistence_model",
            "crash_consistency_with_catalog",
            "cold_start_rebuild_cost",
        ] {
            assert!(axes.contains(&axis.to_string()), "missing axis {axis}");
        }
    }
}
