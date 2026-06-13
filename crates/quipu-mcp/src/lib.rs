//! # quipu-mcp
//!
//! A [Model Context Protocol](https://modelcontextprotocol.io) server that puts
//! a [Quipu-Log](https://github.com/draft-dhgo/Quipu-Log) audit store in front
//! of an LLM agent — an "AI auditor" that can search the log, walk an entity's
//! history, and verify the store's integrity, all in natural language.
//!
//! ## The shape, and why
//!
//! The agent talks MCP to this server; this server talks the **ordinary
//! token-authenticated HTTP API** to `quipu-server` — it is an HTTP client, not
//! an embedded store. That choice is deliberate:
//!
//! - **The store is single-writer.** `quipu-server` holds a file lock on the
//!   store root. An embedded MCP process could not open the same store while
//!   the daemon is running, which is exactly the "AI auditor alongside the live
//!   system" case this is for. Going through HTTP sidesteps the lock entirely.
//! - **Reuse the existing trust boundary.** Auth, role-based scopes, the query
//!   concurrency cap, and the key boundary (a private-key-less server returns
//!   ciphertext) already live in `quipu-server`. The agent gets exactly the
//!   capabilities its token's role grants — nothing new to secure here.
//! - **Access is audited for free.** Every tool call is an HTTP query/verify
//!   against the server, so when the meta-audit feature (which records who
//!   queried the audit log) is in play, the agent's own reads land in the
//!   ledger through the same path — the "AI's lookups are themselves audited"
//!   property, without this crate doing anything special.
//!
//! ## Pieces
//!
//! - [`server::Server`] — JSON-RPC 2.0 / MCP dispatch over a [`Backend`], with
//!   a newline-delimited stdio loop.
//! - [`tools`] — the three exposed tools (`query_logs`, `get_entity_history`,
//!   `verify_store_integrity`) and their schemas.
//! - [`HttpBackend`] — the shipped backend: a std-only plaintext HTTP client
//!   for `quipu-server`.
//! - [`issuer`] — mint a scoped bearer token and the config line for it.

pub mod backend;
pub mod http;
pub mod issuer;
pub mod server;
pub mod tools;

pub use backend::{Backend, BackendError, BackendResult};
pub use http::HttpBackend;
pub use server::Server;
