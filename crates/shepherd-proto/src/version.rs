//! The connection handshake, version compatibility and capability negotiation.
//!
//! # Why the handshake handles more than a major mismatch
//!
//! §4.3 says "every connection opens with `hello { proto_version, client }`; a
//! major mismatch is rejected". A major-only check is not enough for the skew
//! case §4.3 itself calls the most common one: **a just-updated app talking to
//! the still-running old daemon**. That pair usually agrees on `major` and
//! disagrees on `minor`, and rejecting it would make an ordinary update look
//! like a broken install, while accepting it blindly lets the new client call a
//! method the old daemon has never heard of.
//!
//! So negotiation produces three outputs, not one verdict:
//!
//! 1. **major** — mismatch is fatal, and [`VersionMismatch`] carries both
//!    versions and the upgrade command (AC-61 forbids a bare "connection
//!    refused").
//! 2. **minor** — the connection settles on `min(client, server)`. A method
//!    whose `since_minor` exceeds the negotiated minor is *not callable*; see
//!    [`crate::MethodKind::available_at`]. This is the mechanism that lets the
//!    method table grow additively across seven phases without a major bump.
//! 3. **capabilities** — named, unordered, order-independent feature flags for
//!    things that are not expressible as "a newer minor": optional subsystems,
//!    platform-gated features, build-time-excluded providers. A client
//!    capability the server does not know is reported back rather than being an
//!    error, so a newer client degrades instead of failing.
//!
//! # `hello` is not in the method table, on purpose
//!
//! [`crate::MethodKind`] is "what the product can do" (P3), and AC-54 asserts
//! the UI has no capability the CLI lacks. `hello` is not a capability — it is
//! the preamble every client sends before any capability exists, and it is
//! performed identically by `shepctl`, the UI relay and any future client.
//! Putting it in the table would force a `shepctl hello` command into the CLI
//! surface to keep `CLI == registered_methods` true, which would be a command
//! that exists to satisfy a checker. The negotiated result is observable
//! through `shepctl status` instead.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The protocol version this build speaks.
///
/// `minor` is bumped by **any** additive change to the method table or to a
/// request/result schema. `major` is bumped only by a change that an old client
/// cannot be expected to tolerate; see [`COMPATIBILITY_POLICY`].
/// Minor history, so a reader can see the additive policy actually being used
/// rather than only described:
///
/// * **1.0** — the initial Phase 1 surface.
/// * **1.1** — added `doctor` (§4.2 and the §9 gate both require
///   `shepctl doctor`; it is a real capability, so it is a registered method
///   rather than an exemption from AC-54's `CLI == registered_methods`).
/// * **1.2** — added the optional `root.add.ignore_patterns` field. AC-9's
///   `**User**` ignore patterns had a column (`scan_root.ignore_patterns_json`)
///   and a matcher (`shepherd_scan::IgnoreSet`) but no way for a client to
///   supply them, so every scan ran against `'[]'`. An optional request field
///   is exactly what the policy below permits at a minor.
///
///   **The skew direction is worth naming, because it is silent.** By the
///   unknown-fields rule a 1.1 daemon *ignores* `ignore_patterns` from a 1.2
///   client rather than rejecting it, so the root registers with no exclusions
///   and files the user meant to exclude are scanned — and, under a rule that
///   tiers them, destroyed. Singular packaging (§4.2) makes client-newer skew
///   a restart-window phenomenon rather than a steady state, which is the only
///   reason this is tolerable; a client that must be sure can compare
///   `root.list`'s echo of what was stored against what it sent.
pub const PROTO_VERSION: ProtoVersion = ProtoVersion::new(1, 2);

/// The additive-evolution rules, stated once so they can be quoted in review.
///
/// This is a `&str` rather than prose in a doc comment because
/// `xtask codegen` embeds it in `schemas/ipc-inventory.json`: the policy ships
/// with the artifact it governs.
pub const COMPATIBILITY_POLICY: &str = "\
Additive-only within a major version.
  * A new method may be added at any minor. It carries since_minor and is not \
callable on a connection whose negotiated minor is lower.
  * A new OPTIONAL field may be added to any request or result at any minor. \
Required fields may never be added, removed or retyped.
  * A method's stable numeric id is permanent. Ids are never reused, including \
after the method is removed.
  * A method is deprecated before it is removed: it keeps working, keeps its \
id, and advertises a replacement. Removal is a major bump.
  * Unknown fields are ignored by both peers. No request or result type may \
deny unknown fields.
  * Unknown capabilities are reported, never rejected.
A major bump re-issues the whole table and is negotiated as incompatible.";

/// A `major.minor` protocol version.
///
/// Serialized as an object rather than a `"1.0"` string so a future `patch` or
/// build-metadata field is an additive change instead of a parse change.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
pub struct ProtoVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtoVersion {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
}

impl std::fmt::Display for ProtoVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// A named, optional feature of one peer.
///
/// Capabilities are compared by string equality and are never parsed. A peer
/// that does not recognise one must ignore it.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct Capability(pub String);

impl Capability {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Capability names this build knows about.
///
/// Declared as constants so a typo is a compile error on the side that emits
/// them. A peer may still send a name absent from this list; that is the
/// forward-compatibility case and it is reported, not rejected.
pub mod capability {
    /// The peer can serve `events.subscribe` with a resume cursor
    /// ([`crate::event`]). A daemon built without the event buffer omits it and
    /// clients fall back to polling.
    pub const EVENT_RESUME: &str = "event.resume";
    /// The peer can produce OS placeholders (Windows CfAPI / macOS File
    /// Provider). Absent on Linux, which is delete-mode only (§3).
    pub const PLACEHOLDERS: &str = "placeholder.stub";
    /// The peer exposes hosted-inference methods (Phase 7). Absent until then.
    pub const HOSTED_INFERENCE: &str = "infer.hosted";
}

/// Who is on the other end. Diagnostic only; never used for authorization —
/// §4.3 is explicit that authorization is filesystem/pipe permissions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PeerInfo {
    /// e.g. `"shepctl"`, `"shepherd-ui"`, `"shepherdd"`.
    pub name: String,
    /// Human-readable build version, e.g. `"0.1.0"`. Not the protocol version.
    pub build: String,
}

/// The first frame a client sends on a new connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Hello {
    pub proto_version: ProtoVersion,
    pub client: PeerInfo,
    /// Capabilities the client can make use of. Empty is legal.
    #[serde(default)]
    pub capabilities: Vec<Capability>,
}

/// The server's answer to an accepted [`Hello`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HelloResult {
    pub proto_version: ProtoVersion,
    pub server: PeerInfo,
    /// Everything the server can do, whether or not the client asked for it.
    pub capabilities: Vec<Capability>,
    pub negotiated: Negotiated,
}

/// What the two peers actually agreed on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Negotiated {
    /// `min(client.minor, server.minor)`. Methods with a higher `since_minor`
    /// are not callable on this connection.
    pub minor: u16,
    /// Capabilities both peers named. Sorted, so the value is comparable.
    pub capabilities: Vec<Capability>,
    /// Capabilities the client named that this server does not know. Returned
    /// so a newer client can degrade deliberately instead of discovering the
    /// gap through a failed call.
    pub unsupported_client_capabilities: Vec<Capability>,
}

impl Negotiated {
    pub fn has(&self, name: &str) -> bool {
        self.capabilities.iter().any(|c| c.as_str() == name)
    }
}

/// A rejected handshake.
///
/// Every field exists because AC-61 forbids an error the user cannot act on:
/// the message names both versions and the exact command that fixes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, thiserror::Error)]
#[error(
    "protocol major version mismatch: client speaks {client}, daemon speaks {server}. \
     They cannot interoperate. Run `{upgrade_command}`"
)]
pub struct VersionMismatch {
    pub client: ProtoVersion,
    pub server: ProtoVersion,
    pub upgrade_command: String,
}

/// The command a user runs to resolve a major mismatch.
///
/// Singular packaging (§4.2) means client and daemon ship together, so the
/// resolution is always "restart the daemon on the version you just installed",
/// never "install a matching client".
pub const UPGRADE_COMMAND: &str = "shepctl daemon restart";

/// Decide whether a client may proceed, and on what terms.
///
/// `server_capabilities` is what this build can do; it does not need to be
/// sorted.
pub fn negotiate(
    hello: &Hello,
    server_version: ProtoVersion,
    server_capabilities: &[Capability],
) -> Result<Negotiated, VersionMismatch> {
    if hello.proto_version.major != server_version.major {
        return Err(VersionMismatch {
            client: hello.proto_version,
            server: server_version,
            upgrade_command: UPGRADE_COMMAND.to_string(),
        });
    }

    let mut agreed: Vec<Capability> = hello
        .capabilities
        .iter()
        .filter(|c| server_capabilities.contains(c))
        .cloned()
        .collect();
    agreed.sort();
    agreed.dedup();

    let mut unsupported: Vec<Capability> = hello
        .capabilities
        .iter()
        .filter(|c| !server_capabilities.contains(c))
        .cloned()
        .collect();
    unsupported.sort();
    unsupported.dedup();

    Ok(Negotiated {
        minor: hello.proto_version.minor.min(server_version.minor),
        capabilities: agreed,
        unsupported_client_capabilities: unsupported,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(major: u16, minor: u16, caps: &[&str]) -> Hello {
        Hello {
            proto_version: ProtoVersion::new(major, minor),
            client: PeerInfo {
                name: "shepctl".into(),
                build: "0.1.0".into(),
            },
            capabilities: caps.iter().map(|c| Capability::new(*c)).collect(),
        }
    }

    #[test]
    fn major_mismatch_names_both_versions_and_the_fix() {
        let err = negotiate(&hello(2, 0, &[]), ProtoVersion::new(1, 3), &[]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("2.0"), "{msg}");
        assert!(msg.contains("1.3"), "{msg}");
        assert!(msg.contains(UPGRADE_COMMAND), "{msg}");
    }

    #[test]
    fn newer_client_against_older_daemon_settles_on_the_older_minor() {
        // The skew case §4.3 calls the most common one. It must not be fatal.
        let n = negotiate(&hello(1, 7, &[]), ProtoVersion::new(1, 2), &[]).unwrap();
        assert_eq!(n.minor, 2);
    }

    #[test]
    fn older_client_against_newer_daemon_also_settles_on_the_older_minor() {
        let n = negotiate(&hello(1, 1, &[]), ProtoVersion::new(1, 9), &[]).unwrap();
        assert_eq!(n.minor, 1);
    }

    #[test]
    fn unknown_client_capability_is_reported_not_rejected() {
        let server = [
            Capability::new(capability::EVENT_RESUME),
            Capability::new(capability::PLACEHOLDERS),
        ];
        let n = negotiate(
            &hello(1, 0, &[capability::EVENT_RESUME, "some.future.thing"]),
            ProtoVersion::new(1, 0),
            &server,
        )
        .unwrap();
        assert!(n.has(capability::EVENT_RESUME));
        assert!(!n.has(capability::PLACEHOLDERS), "server-only, not agreed");
        assert_eq!(
            n.unsupported_client_capabilities,
            vec![Capability::new("some.future.thing")]
        );
    }

    #[test]
    fn negotiated_capabilities_are_order_independent() {
        let server = [
            Capability::new(capability::PLACEHOLDERS),
            Capability::new(capability::EVENT_RESUME),
        ];
        let a = negotiate(
            &hello(1, 0, &[capability::EVENT_RESUME, capability::PLACEHOLDERS]),
            ProtoVersion::new(1, 0),
            &server,
        )
        .unwrap();
        let b = negotiate(
            &hello(1, 0, &[capability::PLACEHOLDERS, capability::EVENT_RESUME]),
            ProtoVersion::new(1, 0),
            &server,
        )
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn hello_tolerates_an_absent_capabilities_field() {
        // Additive rule: a peer built before capabilities existed still parses.
        let h: Hello = serde_json::from_str(
            r#"{"proto_version":{"major":1,"minor":0},
                "client":{"name":"shepctl","build":"0.1.0"}}"#,
        )
        .unwrap();
        assert!(h.capabilities.is_empty());
    }

    #[test]
    fn hello_ignores_unknown_fields() {
        // Additive rule: no wire type may deny unknown fields.
        let h: Hello = serde_json::from_str(
            r#"{"proto_version":{"major":1,"minor":0},
                "client":{"name":"ui","build":"9","locale":"ko-KR"},
                "capabilities":[],
                "invented_later":true}"#,
        )
        .unwrap();
        assert_eq!(h.client.name, "ui");
    }
}
