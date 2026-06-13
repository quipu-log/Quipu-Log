//! Cross-shard query fan-out and timestamp merge.
//!
//! There is no global chain and no global index (ADR-2): a query that spans
//! shards asks each shard its own sub-query and k-way merges the answers by
//! `(timestamp_micros, log_id)`. `log_id` is a time-ordered ULID, so that pair
//! is a total order with a deterministic tie-break — no two rows ever compare
//! equal across shards.
//!
//! Pagination without a global index works by carrying, per shard, the exact
//! opaque position cursor *after the last row emitted from that shard*. Each
//! page:
//!
//! 1. fetches `limit` rows from each shard at its carried cursor,
//! 2. merges and emits the next `limit` rows globally,
//! 3. for every shard that contributed rows, advances its cursor to just past
//!    the rows that were emitted (re-deriving a precise prefix cursor when a
//!    shard contributed only part of its fetched page); a shard that
//!    contributed nothing keeps its cursor so its rows are reconsidered next
//!    page.
//!
//! That makes pagination exact — no gaps, no duplicates — when a shard's append
//! order matches its timestamp order (the normal case). Heavy late arrival
//! (events whose `occurred_at` lags their append position) is still surfaced
//! and ordered across shards by timestamp; that is the documented clock-vs-
//! arrival corner of ADR-2.

use crate::pipeline::MiddlewareError;
use quipu_core::{LogView, Order, QueryPage};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use super::shard_map::ShardId;

/// Resumable cursor for a cross-shard query. Opaque to callers: get it from a
/// [`MergedPage::next_cursor`] and feed it back unchanged for the next page.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MultiCursor {
    /// Per-shard opaque position cursor, pointing just past the last row this
    /// shard has already contributed. A shard absent from both this map and
    /// `done` resumes from its start.
    per_shard: BTreeMap<u32, String>,
    /// Shards fully drained — skipped entirely on the next page. Distinct from
    /// "absent", which means "resume from the start": an exhausted shard must
    /// not be restarted, or it would re-serve its rows forever.
    done: BTreeSet<u32>,
}

impl MultiCursor {
    /// Base64 of the bincode encoding, for putting the cursor on the wire.
    pub fn encode(&self) -> String {
        use base64::Engine;
        let bytes = bincode::serialize(self).unwrap_or_default();
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)
    }

    /// Inverse of [`encode`](Self::encode).
    pub fn decode(s: &str) -> Option<Self> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(s)
            .ok()?;
        bincode::deserialize(&bytes).ok()
    }
}

/// One page of a merged cross-shard query.
#[derive(Debug)]
pub struct MergedPage {
    pub logs: Vec<LogView>,
    /// Present when more rows remain; feed back as the next page's cursor.
    pub next_cursor: Option<MultiCursor>,
    /// Sum of segments opened across all shard sub-queries (observability).
    pub segments_scanned: u64,
    /// Shards that failed their sub-query and were skipped. A non-empty list
    /// means the page is partial — surface it to the caller (HTTP "degraded").
    pub degraded: Vec<ShardId>,
}

#[inline]
fn key_of(lv: &LogView) -> (u64, u128) {
    (lv.timestamp_micros, lv.log_id.0)
}

/// Fan a query out across `targets`, merge by timestamp, return one page.
///
/// `fetch(shard, cursor, limit)` runs the per-shard sub-query. A shard whose
/// fetch errors is recorded in `degraded` and skipped; if *every* target fails,
/// the first error is returned.
pub(crate) fn query_merged<F>(
    targets: &[ShardId],
    order: Order,
    limit: usize,
    cursor: Option<MultiCursor>,
    mut fetch: F,
) -> Result<MergedPage, MiddlewareError>
where
    F: FnMut(ShardId, Option<String>, usize) -> Result<QueryPage, MiddlewareError>,
{
    let prev = cursor.unwrap_or_default();

    // (sort key, shard, view), plus per-shard bookkeeping for cursor advance.
    let mut candidates: Vec<((u64, u128), ShardId, LogView)> = Vec::new();
    let mut shard_returned: BTreeMap<u32, usize> = BTreeMap::new();
    let mut shard_next: BTreeMap<u32, Option<String>> = BTreeMap::new();
    let mut segments_scanned: u64 = 0;
    let mut degraded: Vec<ShardId> = Vec::new();
    let mut first_err: Option<MiddlewareError> = None;

    if limit == 0 {
        return Ok(MergedPage {
            logs: Vec::new(),
            next_cursor: None,
            segments_scanned: 0,
            degraded,
        });
    }

    let mut fetched_targets = 0usize;
    for &shard in targets {
        if prev.done.contains(&shard.0) {
            continue; // exhausted on an earlier page — never re-query
        }
        fetched_targets += 1;
        let start = prev.per_shard.get(&shard.0).cloned();
        match fetch(shard, start, limit) {
            Ok(page) => {
                segments_scanned += page.segments_scanned;
                shard_returned.insert(shard.0, page.logs.len());
                shard_next.insert(shard.0, page.next_cursor);
                for lv in page.logs {
                    candidates.push((key_of(&lv), shard, lv));
                }
            }
            Err(e) => {
                degraded.push(shard);
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
    }

    // Every shard we tried failed (and at least one was tried) → surface it.
    if fetched_targets > 0 && degraded.len() == fetched_targets {
        return Err(first_err.unwrap_or(MiddlewareError::WorkerGone));
    }

    // Global order: ascending by key, reversed for Desc.
    candidates.sort_by_key(|c| c.0);
    if order == Order::Desc {
        candidates.reverse();
    }

    let total = candidates.len();
    let take = limit.min(total);
    let mut logs = Vec::with_capacity(take);
    let mut emitted_per_shard: BTreeMap<u32, usize> = BTreeMap::new();
    for (_k, shard, lv) in candidates.into_iter().take(take) {
        *emitted_per_shard.entry(shard.0).or_default() += 1;
        logs.push(lv);
    }

    // A full page (take == limit) means more rows might remain; a short page
    // means every reachable row was emitted (each shard returned < limit, i.e.
    // is exhausted), so we are done. One extra empty round is possible when a
    // full page happens to coincide with the true end — harmless.
    let more = take == limit && total > 0;

    let next_cursor = if more {
        // Carry forward shards already marked done, plus this page's outcomes.
        let mut per_shard = BTreeMap::new();
        let mut done = prev.done.clone();
        for &shard in targets {
            if done.contains(&shard.0) {
                continue;
            }
            let returned = shard_returned.get(&shard.0).copied();
            let Some(returned) = returned else {
                // Shard wasn't fetched this page (degraded) — keep prior cursor.
                if let Some(c) = prev.per_shard.get(&shard.0) {
                    per_shard.insert(shard.0, c.clone());
                }
                continue;
            };
            let emitted = emitted_per_shard.get(&shard.0).copied().unwrap_or(0);
            if emitted == 0 {
                // Contributed nothing this page (its rows lost the merge, or it
                // returned none). Keep its prior cursor so its rows are
                // reconsidered next page. If it returned nothing at all, it is
                // exhausted — mark done so it is not restarted.
                if returned == 0 {
                    done.insert(shard.0);
                } else if let Some(c) = prev.per_shard.get(&shard.0) {
                    per_shard.insert(shard.0, c.clone());
                }
            } else if emitted == returned {
                // Whole fetched page was emitted — continue past it, or finish.
                match shard_next.get(&shard.0) {
                    Some(Some(c)) => {
                        per_shard.insert(shard.0, c.clone());
                    }
                    // No further cursor: the shard is drained. Mark done so the
                    // next page skips it instead of restarting it from zero.
                    _ => {
                        done.insert(shard.0);
                    }
                }
            } else {
                // Partial: re-derive the precise cursor just past the `emitted`
                // rows this shard contributed (a prefix of its fetched page).
                let start = prev.per_shard.get(&shard.0).cloned();
                let prefix = fetch(shard, start, emitted)?;
                match prefix.next_cursor {
                    Some(c) => {
                        per_shard.insert(shard.0, c);
                    }
                    None => {
                        done.insert(shard.0);
                    }
                }
            }
        }
        Some(MultiCursor { per_shard, done })
    } else {
        None
    };

    Ok(MergedPage {
        logs,
        next_cursor,
        segments_scanned,
        degraded,
    })
}
