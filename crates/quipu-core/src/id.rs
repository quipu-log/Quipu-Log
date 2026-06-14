use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// 128-bit, time-ordered unique id (ULID-style layout):
/// upper 48 bits = unix milliseconds, lower 80 bits = randomness.
/// Sorting by `Uid` therefore sorts by creation time, which keeps
/// log ids aligned with the append order of the segment files.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Uid(pub u128);

/// Monotonic counter mixed into the random part so that ids generated within
/// the same millisecond on the same process never collide.
static SEQ: AtomicU64 = AtomicU64::new(0);

impl Uid {
    pub fn generate() -> Self {
        let ms = crate::time::now_micros() / 1000;
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let mut rand_part = [0u8; 10];
        rand::Rng::fill(&mut rand::thread_rng(), &mut rand_part[..]);
        // fold the sequence counter into the low bytes of the random part
        rand_part[8] ^= (seq >> 8) as u8;
        rand_part[9] ^= seq as u8;
        let mut low: u128 = 0;
        for b in rand_part {
            low = (low << 8) | b as u128;
        }
        Uid(((ms as u128) << 80) | low)
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
}
