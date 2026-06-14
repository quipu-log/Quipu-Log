use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Mutex;

/// 128-bit, time-ordered unique id (monotonic ULID layout):
/// upper 48 bits = unix milliseconds, lower 80 bits = randomness.
/// Sorting by `Uid` therefore sorts by creation time, which keeps
/// log ids aligned with the append order of the segment files.
///
/// **Monotonic** (ULID monotonic mode): ids generated within the same
/// millisecond strictly increase — the low 80 bits are reseeded randomly when
/// the millisecond advances, and incremented by one within a millisecond. So
/// `Uid` order equals generation order *exactly*, not just to millisecond
/// resolution. Cross-shard pagination depends on this: it merges by
/// `(timestamp_micros, log_id)` and assumes that order matches each shard's
/// append order, which only holds if the `log_id` tie-break is itself
/// append-monotonic within a microsecond. (Plain random low bits broke that and
/// produced rare duplicate/out-of-order rows at page boundaries under ties.)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Uid(pub u128);

const LOW_BITS: u32 = 80;
const LOW_MASK: u128 = (1u128 << LOW_BITS) - 1;

/// Last (millisecond, low-80-bits) handed out, for ULID monotonic generation.
static LAST: Mutex<(u64, u128)> = Mutex::new((0, 0));

fn random_low() -> u128 {
    let mut bytes = [0u8; 10];
    rand::Rng::fill(&mut rand::thread_rng(), &mut bytes[..]);
    let mut low: u128 = 0;
    for b in bytes {
        low = (low << 8) | b as u128;
    }
    // keep the top bit clear so the within-millisecond increments below cannot
    // overflow into the timestamp field (2^79 ids in one ms is unreachable)
    low & (LOW_MASK >> 1)
}

impl Uid {
    pub fn generate() -> Self {
        let now_ms = crate::time::now_micros() / 1000;
        let mut last = LAST.lock().expect("uid lock poisoned");
        let (last_ms, last_low) = *last;
        let (ms, low) = if now_ms > last_ms {
            // millisecond advanced: fresh randomness
            (now_ms, random_low())
        } else {
            // same millisecond, or the clock went backwards: keep the (>=) ms
            // and strictly increment so ids stay monotonic regardless of clock
            let next = (last_low + 1) & LOW_MASK;
            if next == 0 {
                // wrapped within a ms (impossible in practice) — step the ms
                (last_ms + 1, random_low())
            } else {
                (last_ms, next)
            }
        };
        *last = (ms, low);
        Uid(((ms as u128) << LOW_BITS) | low)
    }

    /// Millisecond timestamp embedded in the id.
    pub fn timestamp_ms(&self) -> u64 {
        (self.0 >> 80) as u64
    }

    pub fn to_hex(&self) -> String {
        format!("{:032x}", self.0)
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        u128::from_str_radix(s, 16).ok().map(Uid)
    }
}

impl fmt::Display for Uid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Serialize a [`Uid`] as a 32-char hex string (for `#[serde(with = ...)]`).
///
/// The derived `Serialize` emits the raw `u128`, which JSON encoders without
/// 128-bit integer support silently round through `f64` — lossy for a 128-bit
/// id. Wire DTOs that must round-trip an id (e.g. [`crate::LogView`], so a
/// client can ask for its Merkle inclusion proof) use this instead. Storage
/// (bincode) keeps the compact derived form.
pub mod hex_serde {
    use super::Uid;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(uid: &Uid, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&uid.to_hex())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Uid, D::Error> {
        let s = String::deserialize(d)?;
        Uid::from_hex(&s).ok_or_else(|| serde::de::Error::custom(format!("invalid uid hex: {s}")))
    }
}

impl fmt::Debug for Uid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Uid({})", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uids_are_unique_and_ordered() {
        let a = Uid::generate();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = Uid::generate();
        assert!(a < b);
        assert_ne!(a, b);
        assert_eq!(Uid::from_hex(&a.to_hex()), Some(a));
    }

    /// A burst generated within the same millisecond must still be strictly
    /// increasing — this is what cross-shard pagination's `(ts, log_id)` merge
    /// relies on. A plain-random low field would order these arbitrarily.
    #[test]
    fn same_millisecond_burst_is_strictly_monotonic() {
        let ids: Vec<Uid> = (0..10_000).map(|_| Uid::generate()).collect();
        for w in ids.windows(2) {
            assert!(w[0] < w[1], "ids not strictly increasing within a burst");
        }
        // sanity: many of them landed in the same millisecond (else the test
        // wouldn't be exercising the increment path)
        let same_ms = ids
            .windows(2)
            .filter(|w| w[0].timestamp_ms() == w[1].timestamp_ms())
            .count();
        assert!(same_ms > 100, "burst did not share milliseconds: {same_ms}");
    }
}
