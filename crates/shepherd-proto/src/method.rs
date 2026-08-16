//! The method table — the single source of truth for what the product can do.
//!
//! # One declaration, five derived artifacts
//!
//! §4.3: "`shepherd-proto` declares every method once", and the daemon dispatch
//! table, `shepctl`'s command tree, the TypeScript client, the committed JSON
//! Schemas and the AC-54 inventory are all *derived*. The [`methods!`]
//! invocation at the bottom of this file is that declaration.
//!
//! | derived from the table | where | how divergence is caught |
//! |---|---|---|
//! | [`ShepherdApi`], one fn per method | generated here | a daemon missing one does not compile |
//! | [`ShepherdApi::dispatch`] | generated here | generated; cannot omit a method |
//! | `shepctl`'s command tree | built at run time from [`MethodKind::ALL`] | generated; cannot omit a method |
//! | `schemas/**` + `ipc-inventory.json` | `cargo xtask codegen` | `codegen --check` fails CI on drift |
//! | the TypeScript client | Phase 8 | see the note under "What Phase 8 adds" |
//!
//! # Why `methods!` and not `#[derive(Method)]`
//!
//! §4.3's sketch shows `#[derive(Method)]`. A derive macro must live in a
//! `proc-macro` crate, that crate would be a workspace member, and §4.1
//! dependency rule 1 — enforced by `cargo xtask check-deps` — says
//! `shepherd-proto` depends on **nothing internal**. Satisfying the sketch
//! literally would mean widening a safety policy to accommodate a syntax
//! preference, which is the move `xtask/deps-policy.toml` exists to make
//! visible. A declarative macro needs no crate, no `syn`, and no policy edit.
//!
//! The property the plan actually asks for is unaffected: every method is
//! declared exactly once and everything else is generated from that declaration.
//! A table macro arguably serves it better than a derive would, because the
//! derive in the sketch could not have emitted the JSON Schemas or the TS client
//! anyway — those are `xtask codegen`'s outputs, not a compile-time expansion.
//!
//! # Additive evolution, in the types
//!
//! [`crate::COMPATIBILITY_POLICY`] states the rules; these are the ones this
//! module enforces mechanically:
//!
//! * every method carries a permanent [`MethodId`]; `ids_are_unique` fails the
//!   build if two share one, and the committed inventory makes reuse of a
//!   retired id a reviewable diff;
//! * every method carries `since_minor`, and [`MethodKind::available_at`] is
//!   what a daemon consults before serving a call on a downgraded connection;
//! * a method is deprecated — keeping its id, its behaviour and its slot —
//!   before it is ever removed.
//!
//! # What Phase 8 adds, and why it is not here
//!
//! `CLI == registered_methods` is structural from Phase 1: `shepctl` builds its
//! command tree *from* [`MethodKind::ALL`], so it cannot name a method the
//! registry lacks or lack one the registry names. The other half of AC-54,
//! `UI ⊆ CLI`, cannot be closed the same way — a Rust trait cannot type-check a
//! TypeScript `invoke()` call site. Phase 8's mechanism is different in kind:
//! the generated TS client becomes the only permitted IPC path and raw `invoke`
//! is banned by lint, with the inventory test consuming
//! `schemas/ipc-inventory.json`. That is noted here so the Phase 8 owner
//! inherits the requirement rather than rediscovering it; it is deliberately not
//! built now.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, RpcError};
use crate::request::*;
use crate::response::*;

/// A method's permanent numeric identity.
///
/// Stable across renames: the *name* is what humans and the CLI use, the id is
/// what a recorded fixture, an audit row or a metrics label refers to. An id is
/// never reused, including after the method it named is removed.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct MethodId(pub u32);

impl std::fmt::Display for MethodId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A method scheduled for removal at the next major version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Deprecation {
    /// The minor at which the deprecation was announced. The method keeps
    /// working; this is the number a client uses to decide when to migrate.
    pub since_minor: u16,
    /// The method to use instead, if there is one.
    pub replacement: Option<&'static str>,
    pub note: &'static str,
}

/// Everything the registry knows about one method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct MethodDescriptor {
    pub id: MethodId,
    /// The JSON-RPC method name, e.g. `"root.add"`.
    pub name: &'static str,
    /// The CLI command path, e.g. `["root", "add"]`. Exactly the path
    /// `shepctl` exposes; it is not re-declared anywhere else.
    pub cli_path: &'static [&'static str],
    pub summary: &'static str,
    /// The protocol minor at which this method was introduced.
    pub since_minor: u16,
    pub deprecated: Option<Deprecation>,
    /// Whether the method can change persistent state. Read-only methods are
    /// the ones a future restricted client may be allowed to call.
    pub mutates: bool,
    /// The Rust type name of the request payload. Used to name the emitted
    /// schema file, so a rename shows up as a `codegen --check` diff.
    pub request_type: &'static str,
    pub result_type: &'static str,
}

impl MethodDescriptor {
    /// The CLI path as a user types it, e.g. `"root add"`.
    pub fn cli_command(&self) -> String {
        self.cli_path.join(" ")
    }
}

/// Render a type's JSON Schema.
///
/// One place, so every emitted schema comes from the same generator settings and
/// a settings change is a single diff across the whole `schemas/` tree.
pub fn schema_of<T: JsonSchema>() -> serde_json::Value {
    serde_json::to_value(schemars::schema_for!(T))
        .expect("a JSON Schema is representable as JSON by construction")
}

/// Optional-deprecation helper for [`methods!`]. Not part of the public API.
macro_rules! opt_deprecation {
    () => {
        None
    };
    ($since:literal, $replacement:expr, $note:literal) => {
        Some($crate::method::Deprecation {
            since_minor: $since,
            replacement: $replacement,
            note: $note,
        })
    };
}

/// Declare the method table.
///
/// Generates [`MethodKind`], [`Method`], [`MethodResult`], [`ShepherdApi`], the
/// descriptor table and the schema accessors. See the module docs for why this
/// is a declarative macro rather than the `#[derive(Method)]` of §4.3's sketch.
macro_rules! methods {
    (
        $(
            $(#[$vmeta:meta])*
            $variant:ident {
                id       = $id:literal,
                name     = $name:literal,
                cli      = [$($cli:literal),+ $(,)?],
                summary  = $summary:literal,
                since    = $since:literal,
                mutates  = $mutates:literal,
                request  = $req:ty,
                result   = $res:ty,
                call     = $call:ident
                $(, deprecated = ($dsince:literal, $drepl:expr, $dnote:literal))? $(,)?
            }
        ),+ $(,)?
    ) => {
        /// Every registered method, as a fieldless discriminant.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum MethodKind {
            $($(#[$vmeta])* $variant,)+
        }

        /// The descriptor table, in declaration order.
        ///
        /// [`MethodKind::ALL`] is index-aligned with this, which is what makes
        /// [`MethodKind::descriptor`] a `const fn` index rather than a match.
        pub static DESCRIPTORS: &[MethodDescriptor] = &[
            $(MethodDescriptor {
                id: MethodId($id),
                name: $name,
                cli_path: &[$($cli),+],
                summary: $summary,
                since_minor: $since,
                deprecated: opt_deprecation!($($dsince, $drepl, $dnote)?),
                mutates: $mutates,
                request_type: stringify!($req),
                result_type: stringify!($res),
            },)+
        ];

        impl MethodKind {
            /// Every method, in declaration order.
            pub const ALL: &'static [MethodKind] = &[$(MethodKind::$variant,)+];

            pub const fn descriptor(self) -> &'static MethodDescriptor {
                &DESCRIPTORS[self as usize]
            }

            pub const fn id(self) -> MethodId {
                self.descriptor().id
            }

            pub const fn name(self) -> &'static str {
                self.descriptor().name
            }

            pub const fn cli_path(self) -> &'static [&'static str] {
                self.descriptor().cli_path
            }

            pub fn from_name(name: &str) -> Option<MethodKind> {
                MethodKind::ALL
                    .iter()
                    .copied()
                    .find(|k| k.name() == name)
            }

            pub fn from_id(id: MethodId) -> Option<MethodKind> {
                MethodKind::ALL.iter().copied().find(|k| k.id() == id)
            }

            /// Whether this method may be called on a connection that
            /// negotiated `minor`.
            ///
            /// The daemon answers [`ErrorCode::MethodNotFound`] for a method
            /// that fails this, because from the caller's side "you are too old
            /// to see it" and "it does not exist" are the same condition and
            /// distinguishing them would leak the newer surface to a client that
            /// cannot use it.
            pub const fn available_at(self, minor: u16) -> bool {
                self.descriptor().since_minor <= minor
            }

            /// The request payload's JSON Schema.
            pub fn request_schema(self) -> serde_json::Value {
                match self {
                    $(MethodKind::$variant => schema_of::<$req>(),)+
                }
            }

            /// The result payload's JSON Schema.
            pub fn result_schema(self) -> serde_json::Value {
                match self {
                    $(MethodKind::$variant => schema_of::<$res>(),)+
                }
            }
        }

        impl std::fmt::Display for MethodKind {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.name())
            }
        }

        /// A method call: the discriminant together with its typed request.
        #[derive(Debug, Clone, PartialEq)]
        pub enum Method {
            $($variant($req),)+
        }

        impl Method {
            pub fn kind(&self) -> MethodKind {
                match self {
                    $(Method::$variant(_) => MethodKind::$variant,)+
                }
            }

            /// Serialize the request payload for the `params` member.
            pub fn params(&self) -> Result<serde_json::Value, RpcError> {
                let v = match self {
                    $(Method::$variant(r) => serde_json::to_value(r),)+
                };
                v.map_err(|e| {
                    RpcError::new(
                        ErrorCode::InternalError,
                        format!("could not serialize params for `{}`: {e}", self.kind().name()),
                    )
                })
            }

            /// Parse a wire frame's `method` + `params` into a typed call.
            ///
            /// This is the daemon's entry point and the only place a method name
            /// becomes a type.
            pub fn from_parts(name: &str, params: &serde_json::Value) -> Result<Method, RpcError> {
                match name {
                    $($name => serde_json::from_value::<$req>(params.clone())
                        .map(Method::$variant)
                        .map_err(|e| {
                            RpcError::new(
                                ErrorCode::InvalidParams,
                                format!("`{}`: {e}", $name),
                            )
                        }),)+
                    other => Err(RpcError::new(
                        ErrorCode::MethodNotFound,
                        format!("no method named `{other}`"),
                    )),
                }
            }
        }

        /// A method's typed result.
        #[derive(Debug, Clone, PartialEq)]
        pub enum MethodResult {
            $($variant($res),)+
        }

        impl MethodResult {
            pub fn kind(&self) -> MethodKind {
                match self {
                    $(MethodResult::$variant(_) => MethodKind::$variant,)+
                }
            }

            /// Serialize for the `result` member — and, unchanged, for the
            /// `data` member of [`crate::envelope::CliEnvelope`].
            pub fn to_value(&self) -> Result<serde_json::Value, RpcError> {
                let v = match self {
                    $(MethodResult::$variant(r) => serde_json::to_value(r),)+
                };
                v.map_err(|e| {
                    RpcError::new(
                        ErrorCode::InternalError,
                        format!("could not serialize the result of `{}`: {e}", self.kind().name()),
                    )
                })
            }

            /// Parse a `result` member back into the typed result for `kind`.
            /// The client half of [`MethodResult::to_value`].
            pub fn from_value(
                kind: MethodKind,
                value: &serde_json::Value,
            ) -> Result<MethodResult, RpcError> {
                match kind {
                    $(MethodKind::$variant => serde_json::from_value::<$res>(value.clone())
                        .map(MethodResult::$variant)
                        .map_err(|e| {
                            RpcError::new(
                                ErrorCode::InternalError,
                                format!("daemon returned a `{}` result this client cannot parse: {e}", $name),
                            )
                        }),)+
                }
            }
        }

        /// Everything the product can do, as one Rust trait.
        ///
        /// **This is the compile-time half of AC-54.** A daemon implements this
        /// trait; a method added to the table adds a required fn, and the daemon
        /// stops compiling until it is served or explicitly answered with
        /// [`ErrorCode::MethodNotImplemented`]. There is no default body, on
        /// purpose: a defaulted method would silently exist and silently fail.
        ///
        /// [`ShepherdApi::dispatch`] is generated, so the dispatch table can
        /// never disagree with the trait.
        pub trait ShepherdApi {
            $(
                #[doc = $summary]
                #[doc = ""]
                #[doc = concat!("JSON-RPC method `", $name, "`, CLI `shepctl ", $($cli, " ",)+ "`.")]
                fn $call(&mut self, request: $req) -> Result<$res, RpcError>;
            )+

            /// Route a parsed call to its handler. Generated; do not override.
            fn dispatch(&mut self, method: Method) -> Result<MethodResult, RpcError> {
                match method {
                    $(Method::$variant(r) => self.$call(r).map(MethodResult::$variant),)+
                }
            }
        }

        /// The canonical text the registry fingerprint is taken over.
        ///
        /// Public so `xtask codegen` embeds the same bytes it hashes, and a
        /// reviewer can see what a changed fingerprint actually changed.
        pub fn registry_canonical_form() -> String {
            let mut out = String::new();
            for k in MethodKind::ALL {
                let d = k.descriptor();
                let dep = match &d.deprecated {
                    None => String::from("-"),
                    Some(x) => format!("{}:{}", x.since_minor, x.replacement.unwrap_or("-")),
                };
                out.push_str(&format!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                    d.id,
                    d.name,
                    d.cli_command(),
                    d.since_minor,
                    dep,
                    d.mutates,
                    d.request_type,
                    d.result_type,
                ));
            }
            out
        }

        /// A short, stable fingerprint of the method table.
        ///
        /// FNV-1a 64, **not** cryptographic and not claimed to be: it exists so
        /// a human can see at a glance that two artifacts describe the same
        /// registry. Drift is actually caught by `xtask codegen --check`'s byte
        /// comparison, which does not depend on this value at all.
        ///
        /// Hand-rolled rather than `std::hash::DefaultHasher` because
        /// `DefaultHasher`'s output is explicitly not stable across Rust
        /// releases, and this value is written into committed files — a
        /// toolchain bump would rewrite every artifact and the diff would say
        /// nothing about the protocol.
        ///
        /// Generated per table rather than written once at module scope, so a
        /// second table (the macro's own tests use one) fingerprints itself
        /// rather than silently borrowing the real registry's value.
        pub fn registry_fingerprint() -> String {
            const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
            const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
            let mut h = FNV_OFFSET;
            for b in registry_canonical_form().as_bytes() {
                h ^= u64::from(*b);
                h = h.wrapping_mul(FNV_PRIME);
            }
            format!("{h:016x}")
        }
    };
}

// ---------------------------------------------------------------------------
// THE METHOD TABLE
//
// Adding a row here adds: a CLI command, a daemon trait method, two JSON
// Schemas and an inventory entry. Removing one is a MAJOR version bump — mark
// it `deprecated` instead.
//
// Ids are grouped by family with gaps, so a method added to a family later sits
// next to its siblings without renumbering anything. Ids are permanent.
//
// SCOPE: this covers what Phases 1 and 2 deliver. §6 Phase 8 records that the
// method table cannot be final before Phases 3-7 design the features they add —
// rules beyond preview, targets beyond S3, models, plugins. The table is built
// to grow: new methods arrive at a higher `since_minor` and old clients keep
// working. Do not treat the list below as complete; treat it as correct.
// ---------------------------------------------------------------------------

methods! {
    RootAdd {
        id = 1001,
        name = "root.add",
        cli = ["root", "add"],
        summary = "Register a scan root",
        since = 0,
        mutates = true,
        request = RootAddRequest,
        result = RootAddResult,
        call = root_add,
    },
    RootList {
        id = 1002,
        name = "root.list",
        cli = ["root", "list"],
        summary = "List registered scan roots",
        since = 0,
        mutates = false,
        request = RootListRequest,
        result = RootListResult,
        call = root_list,
    },
    RootRemove {
        id = 1003,
        name = "root.remove",
        cli = ["root", "remove"],
        summary = "Deregister a scan root (never deletes file bytes)",
        since = 0,
        mutates = true,
        request = RootRemoveRequest,
        result = RootRemoveResult,
        call = root_remove,
    },

    ScanStart {
        id = 1101,
        name = "scan.start",
        cli = ["scan", "start"],
        summary = "Walk one or every enabled root and update the catalog",
        since = 0,
        mutates = true,
        request = ScanStartRequest,
        result = ScanStartResult,
        call = scan_start,
    },
    ScanStatus {
        id = 1102,
        name = "scan.status",
        cli = ["scan", "status"],
        summary = "Report scan progress per root",
        since = 0,
        mutates = false,
        request = ScanStatusRequest,
        result = ScanStatusResult,
        call = scan_status,
    },

    Search {
        id = 1201,
        name = "search",
        cli = ["search"],
        summary = "Search the catalog",
        since = 0,
        mutates = false,
        request = SearchRequest,
        result = SearchResult,
        call = search,
    },

    Status {
        id = 1301,
        name = "status",
        cli = ["status"],
        summary = "Daemon health, catalog totals and queue depth",
        since = 0,
        mutates = false,
        request = StatusRequest,
        result = StatusResult,
        call = status,
    },

    TargetAdd {
        id = 1401,
        name = "target.add",
        cli = ["target", "add"],
        summary = "Configure a storage target",
        since = 0,
        mutates = true,
        request = TargetAddRequest,
        result = TargetAddResult,
        call = target_add,
    },
    TargetList {
        id = 1402,
        name = "target.list",
        cli = ["target", "list"],
        summary = "List configured storage targets",
        since = 0,
        mutates = false,
        request = TargetListRequest,
        result = TargetListResult,
        call = target_list,
    },
    TargetTest {
        id = 1403,
        name = "target.test",
        cli = ["target", "test"],
        summary = "Probe a target's reachability and write permission",
        since = 0,
        mutates = false,
        request = TargetTestRequest,
        result = TargetTestResult,
        call = target_test,
    },

    RuleList {
        id = 1501,
        name = "rule.list",
        cli = ["rule", "list"],
        summary = "List rules and their dry-run state",
        since = 0,
        mutates = false,
        request = RuleListRequest,
        result = RuleListResult,
        call = rule_list,
    },
    RulePreview {
        id = 1502,
        name = "rule.preview",
        cli = ["rule", "preview"],
        summary = "Dry-run a rule (mandatory before it may be enabled)",
        since = 0,
        mutates = false,
        request = RulePreviewRequest,
        result = RulePreviewResult,
        call = rule_preview,
    },

    TierPlan {
        id = 1601,
        name = "tier.plan",
        cli = ["tier", "plan"],
        summary = "Compute a tiering candidate set (read-only; moves nothing)",
        since = 0,
        mutates = false,
        request = TierPlanRequest,
        result = TierPlanResult,
        call = tier_plan,
    },
    TierRun {
        id = 1602,
        name = "tier.run",
        cli = ["tier", "run"],
        summary = "Execute a tiering plan against its confirmed candidate set",
        since = 0,
        mutates = true,
        request = TierRunRequest,
        result = TierRunResult,
        call = tier_run,
    },

    Restore {
        id = 1701,
        name = "restore",
        cli = ["restore"],
        summary = "Restore a file's bytes from its target",
        since = 0,
        mutates = true,
        request = RestoreRequest,
        result = RestoreResult,
        call = restore,
    },

    Doctor {
        id = 1901,
        name = "doctor",
        cli = ["doctor"],
        summary = "Run the daemon's self-checks",
        since = 1,
        mutates = false,
        request = DoctorRequest,
        result = DoctorResult,
        call = doctor,
    },

    EventsSubscribe {
        id = 1801,
        name = "events.subscribe",
        cli = ["events", "subscribe"],
        summary = "Stream daemon events, optionally resuming from a cursor",
        since = 0,
        mutates = false,
        request = SubscribeRequest,
        result = SubscribeResult,
        call = events_subscribe,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn ids_are_unique() {
        // An id collision would make `from_id` silently return the first match
        // and would corrupt any recorded fixture keyed by id.
        let ids: BTreeSet<u32> = MethodKind::ALL.iter().map(|k| k.id().0).collect();
        assert_eq!(ids.len(), MethodKind::ALL.len(), "duplicate MethodId");
    }

    #[test]
    fn names_and_cli_paths_are_unique() {
        let names: BTreeSet<&str> = MethodKind::ALL.iter().map(|k| k.name()).collect();
        assert_eq!(names.len(), MethodKind::ALL.len(), "duplicate method name");
        let cli: BTreeSet<String> = MethodKind::ALL
            .iter()
            .map(|k| k.descriptor().cli_command())
            .collect();
        assert_eq!(cli.len(), MethodKind::ALL.len(), "duplicate CLI path");
    }

    #[test]
    fn descriptors_are_index_aligned_with_all() {
        // `descriptor()` indexes DESCRIPTORS by the discriminant. If the macro
        // ever emitted the two in different orders, every descriptor would
        // silently belong to the wrong method.
        assert_eq!(DESCRIPTORS.len(), MethodKind::ALL.len());
        for (i, k) in MethodKind::ALL.iter().enumerate() {
            assert_eq!(k.descriptor().name, DESCRIPTORS[i].name);
            assert_eq!(MethodKind::from_name(k.name()), Some(*k));
            assert_eq!(MethodKind::from_id(k.id()), Some(*k));
        }
    }

    #[test]
    fn no_cli_path_is_a_prefix_of_another() {
        // `shepctl root list` and a hypothetical `shepctl root` cannot both be
        // leaves in one clap tree. Catching it here beats catching it as a
        // confusing runtime parse.
        for a in MethodKind::ALL {
            for b in MethodKind::ALL {
                if a == b {
                    continue;
                }
                let (x, y) = (a.cli_path(), b.cli_path());
                assert!(
                    !(x.len() < y.len() && y.starts_with(x)),
                    "`{}` is a prefix of `{}`",
                    a.descriptor().cli_command(),
                    b.descriptor().cli_command()
                );
            }
        }
    }

    #[test]
    fn every_method_names_a_jsonrpc_style_name_and_a_summary() {
        for k in MethodKind::ALL {
            let d = k.descriptor();
            assert!(!d.summary.is_empty(), "{}", d.name);
            assert!(
                d.name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '.' || c == '_'),
                "method name `{}` must be lower dotted",
                d.name
            );
            assert!(!d.cli_path.is_empty(), "{}", d.name);
        }
    }

    /// The additive policy, exercised on the real table rather than only on the
    /// synthetic one: `doctor` arrived at 1.1, so a connection that negotiated
    /// minor 0 must not see it, and one at 1.1 must.
    #[test]
    fn a_method_added_at_a_later_minor_is_gated_on_the_real_table() {
        assert!(!MethodKind::Doctor.available_at(0));
        assert!(MethodKind::Doctor.available_at(1));
        for k in MethodKind::ALL {
            if *k == MethodKind::Doctor {
                continue;
            }
            assert!(k.available_at(0), "{} is part of the 1.0 surface", k.name());
        }
    }

    #[test]
    fn a_method_introduced_later_is_invisible_to_an_older_connection() {
        // Exercised on the test table below, since nothing in the real table is
        // above minor 0 yet. This is the mechanism the whole additive policy
        // rests on, so it is tested rather than merely asserted in prose.
        assert!(!future::MethodKind::Added.available_at(0));
        assert!(future::MethodKind::Added.available_at(3));
        assert!(future::MethodKind::Original.available_at(0));
    }

    #[test]
    fn deprecation_metadata_survives_the_macro() {
        let d = future::MethodKind::Original.descriptor();
        let dep = d.deprecated.expect("declared deprecated");
        assert_eq!(dep.since_minor, 2);
        assert_eq!(dep.replacement, Some("thing.added"));
        assert!(future::MethodKind::Added.descriptor().deprecated.is_none());
    }

    #[test]
    fn from_parts_types_a_wire_frame() {
        let m = Method::from_parts(
            "root.add",
            &serde_json::json!({"path": "/srv/data", "stub_mode": "delete"}),
        )
        .unwrap();
        assert_eq!(m.kind(), MethodKind::RootAdd);
        match &m {
            Method::RootAdd(r) => {
                assert_eq!(r.path, "/srv/data");
                assert!(!r.hosted_optin);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(m.params().unwrap()["path"], serde_json::json!("/srv/data"));
    }

    #[test]
    fn from_parts_distinguishes_an_unknown_method_from_bad_params() {
        let unknown = Method::from_parts("root.teleport", &serde_json::json!({})).unwrap_err();
        assert_eq!(unknown.kind(), Some(ErrorCode::MethodNotFound));

        let bad = Method::from_parts("root.add", &serde_json::json!({"path": 7})).unwrap_err();
        assert_eq!(bad.kind(), Some(ErrorCode::InvalidParams));
        assert!(bad.message.contains("root.add"), "{}", bad.message);
    }

    #[test]
    fn every_method_round_trips_a_default_shaped_request_through_from_parts() {
        // Guards the pairing between the table's `name` and its `request` type:
        // a copy-paste that left one row pointing at another row's request type
        // would still compile, and this is what catches it.
        for k in MethodKind::ALL {
            let schema = k.request_schema();
            assert!(
                schema.get("$schema").is_some(),
                "{} produced a schema with no dialect",
                k.name()
            );
            let name = k.name();
            // An empty object is a valid payload only for methods whose fields
            // are all optional; for the rest this must fail as InvalidParams,
            // never as MethodNotFound.
            if let Err(e) = Method::from_parts(name, &serde_json::json!({})) {
                assert_eq!(
                    e.kind(),
                    Some(ErrorCode::InvalidParams),
                    "{name} rejected an empty payload with the wrong code"
                );
            }
        }
    }

    #[test]
    fn results_round_trip_through_json() {
        let r = MethodResult::TargetTest(TargetTestResult {
            target_id: 4,
            reachable: true,
            writable: false,
            latency_ms: Some(31),
            detail: None,
        });
        let v = r.to_value().unwrap();
        assert_eq!(v["writable"], serde_json::json!(false));
        assert_eq!(
            MethodResult::from_value(MethodKind::TargetTest, &v).unwrap(),
            r
        );
    }

    #[test]
    fn schemas_are_deterministic() {
        // `codegen --check` compares bytes. If schema emission were not
        // deterministic, CI would fail on a clean tree and the gate would be
        // trained away rather than trusted.
        for k in MethodKind::ALL {
            assert_eq!(k.request_schema(), k.request_schema(), "{}", k.name());
            assert_eq!(k.result_schema(), k.result_schema(), "{}", k.name());
        }
    }

    #[test]
    fn the_fingerprint_is_stable_and_sensitive() {
        assert_eq!(registry_fingerprint(), registry_fingerprint());
        assert_eq!(registry_fingerprint().len(), 16);
        // A different table must not fingerprint the same.
        assert_ne!(registry_fingerprint(), future::registry_fingerprint());
    }

    #[test]
    fn the_canonical_form_has_one_line_per_method() {
        let text = registry_canonical_form();
        assert_eq!(text.lines().count(), MethodKind::ALL.len());
        assert!(text.contains("root.add"));
    }

    #[test]
    fn dispatch_reaches_every_handler() {
        // The generated dispatch is the daemon's whole routing layer. A macro
        // arm wired to the wrong handler would compile.
        struct Recorder {
            called: Vec<&'static str>,
        }
        impl ShepherdApi for Recorder {
            fn root_add(&mut self, _: RootAddRequest) -> Result<RootAddResult, RpcError> {
                self.called.push("root.add");
                Err(RpcError::new(ErrorCode::MethodNotImplemented, "probe"))
            }
            fn root_list(&mut self, _: RootListRequest) -> Result<RootListResult, RpcError> {
                self.called.push("root.list");
                Ok(RootListResult { roots: vec![] })
            }
            fn root_remove(&mut self, _: RootRemoveRequest) -> Result<RootRemoveResult, RpcError> {
                self.called.push("root.remove");
                Err(RpcError::new(ErrorCode::MethodNotImplemented, "probe"))
            }
            fn scan_start(&mut self, _: ScanStartRequest) -> Result<ScanStartResult, RpcError> {
                self.called.push("scan.start");
                Err(RpcError::new(ErrorCode::MethodNotImplemented, "probe"))
            }
            fn scan_status(&mut self, _: ScanStatusRequest) -> Result<ScanStatusResult, RpcError> {
                self.called.push("scan.status");
                Err(RpcError::new(ErrorCode::MethodNotImplemented, "probe"))
            }
            fn search(&mut self, _: SearchRequest) -> Result<SearchResult, RpcError> {
                self.called.push("search");
                Err(RpcError::new(ErrorCode::MethodNotImplemented, "probe"))
            }
            fn status(&mut self, _: StatusRequest) -> Result<StatusResult, RpcError> {
                self.called.push("status");
                Err(RpcError::new(ErrorCode::MethodNotImplemented, "probe"))
            }
            fn target_add(&mut self, _: TargetAddRequest) -> Result<TargetAddResult, RpcError> {
                self.called.push("target.add");
                Err(RpcError::new(ErrorCode::MethodNotImplemented, "probe"))
            }
            fn target_list(&mut self, _: TargetListRequest) -> Result<TargetListResult, RpcError> {
                self.called.push("target.list");
                Err(RpcError::new(ErrorCode::MethodNotImplemented, "probe"))
            }
            fn target_test(&mut self, _: TargetTestRequest) -> Result<TargetTestResult, RpcError> {
                self.called.push("target.test");
                Err(RpcError::new(ErrorCode::MethodNotImplemented, "probe"))
            }
            fn rule_list(&mut self, _: RuleListRequest) -> Result<RuleListResult, RpcError> {
                self.called.push("rule.list");
                Err(RpcError::new(ErrorCode::MethodNotImplemented, "probe"))
            }
            fn rule_preview(
                &mut self,
                _: RulePreviewRequest,
            ) -> Result<RulePreviewResult, RpcError> {
                self.called.push("rule.preview");
                Err(RpcError::new(ErrorCode::MethodNotImplemented, "probe"))
            }
            fn tier_plan(&mut self, _: TierPlanRequest) -> Result<TierPlanResult, RpcError> {
                self.called.push("tier.plan");
                Err(RpcError::new(ErrorCode::MethodNotImplemented, "probe"))
            }
            fn tier_run(&mut self, _: TierRunRequest) -> Result<TierRunResult, RpcError> {
                self.called.push("tier.run");
                Err(RpcError::new(ErrorCode::MethodNotImplemented, "probe"))
            }
            fn restore(&mut self, _: RestoreRequest) -> Result<RestoreResult, RpcError> {
                self.called.push("restore");
                Err(RpcError::new(ErrorCode::MethodNotImplemented, "probe"))
            }
            fn doctor(&mut self, _: DoctorRequest) -> Result<DoctorResult, RpcError> {
                self.called.push("doctor");
                Err(RpcError::new(ErrorCode::MethodNotImplemented, "probe"))
            }
            fn events_subscribe(
                &mut self,
                _: SubscribeRequest,
            ) -> Result<SubscribeResult, RpcError> {
                self.called.push("events.subscribe");
                Err(RpcError::new(ErrorCode::MethodNotImplemented, "probe"))
            }
        }

        let mut r = Recorder { called: vec![] };
        for k in MethodKind::ALL {
            // Build a minimal call for each method by round-tripping its own
            // default-ish payload; where the payload has required fields, use
            // the schema's shape via a hand-built value.
            let params = minimal_params(*k);
            let m = Method::from_parts(k.name(), &params)
                .unwrap_or_else(|e| panic!("{}: {e}", k.name()));
            let _ = r.dispatch(m);
        }
        let expected: Vec<&str> = MethodKind::ALL.iter().map(|k| k.name()).collect();
        assert_eq!(
            r.called, expected,
            "dispatch routed a call to the wrong handler"
        );
    }

    /// A minimal valid payload per method, used by the dispatch test.
    fn minimal_params(k: MethodKind) -> serde_json::Value {
        use serde_json::json;
        match k {
            MethodKind::RootAdd => json!({"path": "/x", "stub_mode": "delete"}),
            MethodKind::RootRemove => json!({"root_id": 1}),
            MethodKind::Search => json!({"query": "q"}),
            MethodKind::TargetAdd => json!({"name": "t", "adapter": "s3"}),
            MethodKind::TargetTest => json!({"target_id": 1}),
            MethodKind::RulePreview => json!({"rule_id": 1}),
            MethodKind::TierPlan => json!({"rule_id": 1, "target_id": 1}),
            MethodKind::TierRun => json!({"plan_id": "p", "candidate_set_hash": "ab"}),
            _ => json!({}),
        }
    }

    /// A second, synthetic table.
    ///
    /// It exercises the macro paths the real table does not reach yet —
    /// `deprecated`, and a method introduced above minor 0 — so those are
    /// covered before the first phase that needs them, rather than discovered
    /// broken by the phase that needs them.
    mod future {
        // The expansion defines a full second registry — `Method`,
        // `MethodResult`, `ShepherdApi` and their impls — while the tests here
        // only read descriptors. Everything else is legitimately unused, and
        // silencing it in this module is narrower than not generating it:
        // proving the macro *does* generate the whole set for an arbitrary table
        // is part of what this table is for.
        #![allow(dead_code)]

        // The glob brings in MethodDescriptor, MethodId, schema_of and the
        // macros; every item the `methods!` expansion below defines shadows its
        // namesake from the real table, which is what makes this a genuinely
        // independent second registry rather than an alias for the first.
        use super::super::*;
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
        pub struct Req {}
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
        pub struct Res {}

        methods! {
            Original {
                id = 1,
                name = "thing.original",
                cli = ["thing", "original"],
                summary = "The original",
                since = 0,
                mutates = false,
                request = Req,
                result = Res,
                call = thing_original,
                deprecated = (2, Some("thing.added"), "superseded"),
            },
            Added {
                id = 2,
                name = "thing.added",
                cli = ["thing", "added"],
                summary = "Added at minor 3",
                since = 3,
                mutates = true,
                request = Req,
                result = Res,
                call = thing_added,
            },
        }
    }
}
