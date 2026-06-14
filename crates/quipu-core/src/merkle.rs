//! Append-only Merkle history tree (RFC 6962 / Certificate Transparency).
//!
//! This is the integrity backbone the store is migrating to, replacing the
//! per-record hash chain. The chain proved that retained records were not
//! edited in place, but it offered no *compact* proof to a third party: to
//! show that one event is in the committed log you had to hand over the whole
//! chain from that record to the head (O(n)), and to show the log only ever
//! grew (no retroactive deletion) you had to recompute it.
//!
//! A history tree fixes both. Every record is a leaf; the tree commits to a
//! single 32-byte root. From that root anyone can verify, with an O(log n)
//! proof and no access to the rest of the log:
//!
//! * **inclusion** — record `m` is the `m`-th leaf of the tree of size `n`
//!   whose root is `R` ([`inclusion_proof`] / [`verify_inclusion`]); and
//! * **consistency** — the tree of size `n` is an append-only extension of the
//!   earlier tree of size `m` — nothing in the first `m` leaves changed or was
//!   removed ([`consistency_proof`] / [`verify_consistency`]).
//!
//! Hashing follows RFC 6962 §2.1 exactly so an external verifier can be written
//! straight from the RFC:
//!
//! ```text
//! MTH({})        = SHA-256()
//! leaf hash      = SHA-256(0x00 || record)
//! interior node  = SHA-256(0x01 || left || right)
//! ```
//!
//! The prover ([`mth`], [`inclusion_proof`], [`consistency_proof`]) is a direct
//! transcription of the recursive definitions in the RFC and needs the list of
//! leaf hashes. The verifiers are the standalone iterative algorithms from
//! §2.1.1 / §2.1.2 — they take only the root(s) and the proof, so a relying
//! party never sees the log. [`Roots`] maintains the current root incrementally
//! (amortised O(1) per append, O(log n) stored peaks) for the write hot path.

use sha2::{Digest, Sha256};

/// A node/leaf/root hash. Same width as the storage layer's `ChainHash`, which
/// lets the v2 segment frame keep its 32-byte hash field and just reinterpret
/// it as an RFC 6962 leaf hash.
pub type Hash = [u8; 32];

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// `SHA-256(0x00 || record)` — the leaf hash of one record's bytes.
pub fn leaf_hash(record: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([LEAF_PREFIX]);
    h.update(record);
    h.finalize().into()
}

/// `SHA-256(0x01 || left || right)` — an interior node over two child hashes.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([NODE_PREFIX]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Root of the empty tree: `SHA-256()` of no input, per RFC 6962.
pub fn empty_root() -> Hash {
    Sha256::new().finalize().into()
}

/// Largest power of two strictly less than `n` (`n >= 2`). This is the split
/// point `k` in every RFC 6962 recursion: the left child is the perfect
/// subtree over the first `k` leaves.
fn split(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1usize;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// Merkle Tree Hash of `leaves` (each already a [`leaf_hash`]), i.e. the root
/// over that list. Reference recursive definition; the hot path uses [`Roots`].
pub fn mth(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
        }
    }
}

/// Audit path proving the leaf at index `m` belongs to the tree over `leaves`.
/// Ordered leaf-to-root (closest sibling first), as the verifier consumes it.
/// Direct transcription of RFC 6962 §2.1.1 `PATH(m, D[n])`.
pub fn inclusion_proof(leaves: &[Hash], m: usize) -> Vec<Hash> {
    let n = leaves.len();
    assert!(m < n, "leaf index {m} out of range for tree size {n}");
    if n == 1 {
        return Vec::new();
    }
    let k = split(n);
    if m < k {
        let mut path = inclusion_proof(&leaves[..k], m);
        path.push(mth(&leaves[k..]));
        path
    } else {
        let mut path = inclusion_proof(&leaves[k..], m - k);
        path.push(mth(&leaves[..k]));
        path
    }
}

/// Consistency proof that the tree over the first `m` leaves is a prefix of the
/// tree over all `leaves` (size `n >= m`). RFC 6962 §2.1.2 `PROOF(m, D[n])`.
pub fn consistency_proof(leaves: &[Hash], m: usize) -> Vec<Hash> {
    let n = leaves.len();
    assert!(m <= n, "prior size {m} exceeds tree size {n}");
    if m == 0 || m == n {
        // The empty prefix and the whole tree are trivially consistent.
        return Vec::new();
    }
    subproof(m, leaves, true)
}

fn subproof(m: usize, leaves: &[Hash], b: bool) -> Vec<Hash> {
    let n = leaves.len();
    if m == n {
        return if b { Vec::new() } else { vec![mth(leaves)] };
    }
    let k = split(n);
    if m <= k {
        let mut p = subproof(m, &leaves[..k], b);
        p.push(mth(&leaves[k..]));
        p
    } else {
        let mut p = subproof(m - k, &leaves[k..], false);
        p.push(mth(&leaves[..k]));
        p
    }
}

/// Verify an inclusion proof: that `leaf` is the `leaf_index`-th of `tree_size`
/// leaves under `root`. Standalone — no access to the log. RFC 6962 §2.1.1.
pub fn verify_inclusion(
    leaf: &Hash,
    leaf_index: usize,
    tree_size: usize,
    proof: &[Hash],
    root: &Hash,
) -> bool {
    if leaf_index >= tree_size {
        return false;
    }
    let mut f_n = leaf_index;
    let mut s_n = tree_size - 1;
    let mut r = *leaf;
    for p in proof {
        if s_n == 0 {
            return false; // proof longer than the tree is tall
        }
        if f_n & 1 == 1 || f_n == s_n {
            r = node_hash(p, &r);
            if f_n & 1 == 0 {
                loop {
                    f_n >>= 1;
                    s_n >>= 1;
                    if f_n & 1 == 1 || f_n == 0 {
                        break;
                    }
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        f_n >>= 1;
        s_n >>= 1;
    }
    s_n == 0 && r == *root
}

/// Verify a consistency proof between an earlier tree (`first_size`,
/// `first_root`) and a later one (`second_size`, `second_root`). Standalone.
/// RFC 6962 §2.1.2.
pub fn verify_consistency(
    first_size: usize,
    second_size: usize,
    first_root: &Hash,
    second_root: &Hash,
    proof: &[Hash],
) -> bool {
    if first_size > second_size {
        return false;
    }
    if first_size == second_size {
        return proof.is_empty() && first_root == second_root;
    }
    if first_size == 0 {
        // Every tree is consistent with the empty tree.
        return proof.is_empty();
    }

    // Step 1: if `first` is a power of two the proof omits its root; prepend it.
    let mut path: Vec<Hash> = Vec::with_capacity(proof.len() + 1);
    if first_size & (first_size - 1) == 0 {
        path.push(*first_root);
    }
    path.extend_from_slice(proof);
    if path.is_empty() {
        return false;
    }

    let mut f_n = first_size - 1;
    let mut s_n = second_size - 1;
    // Step 3: shift past the trailing ones of fn.
    while f_n & 1 == 1 {
        f_n >>= 1;
        s_n >>= 1;
    }

    let mut iter = path.iter();
    let seed = *iter.next().unwrap();
    let mut f_r = seed;
    let mut s_r = seed;
    for c in iter {
        if s_n == 0 {
            return false;
        }
        if f_n & 1 == 1 || f_n == s_n {
            f_r = node_hash(c, &f_r);
            s_r = node_hash(c, &s_r);
            if f_n & 1 == 0 {
                loop {
                    f_n >>= 1;
                    s_n >>= 1;
                    if f_n & 1 == 1 || f_n == 0 {
                        break;
                    }
                }
            }
        } else {
            s_r = node_hash(&s_r, c);
        }
        f_n >>= 1;
        s_n >>= 1;
    }

    f_n == 0 && f_r == *first_root && s_r == *second_root
}

/// Incremental root tracker for the append hot path. Holds the perfect-subtree
/// "peaks" (RFC 6962's left-leaning structure is a forest of perfect trees over
/// the binary expansion of the size); appending merges equal-height peaks, so
/// each append is amortised O(1) hashes and the state is O(log n). Persisting
/// `peaks` + `size` is enough to resume appends and serve the current root
/// after a restart without rehashing the whole log.
#[derive(Debug, Clone, Default)]
pub struct Roots {
    /// `(height, hash)` of each perfect subtree, left (tallest) to right.
    peaks: Vec<(u32, Hash)>,
    size: u64,
}

impl Roots {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild the tracker from an existing run of leaf hashes (e.g. on store
    /// open, replaying the segment frames). O(n) hashes, done once.
    pub fn from_leaves(leaves: &[Hash]) -> Self {
        let mut r = Self::new();
        for leaf in leaves {
            r.push(*leaf);
        }
        r
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    /// Append one leaf hash, merging equal-height peaks.
    pub fn push(&mut self, leaf: Hash) {
        let mut carry = (0u32, leaf);
        while let Some(&(h, _)) = self.peaks.last() {
            if h != carry.0 {
                break;
            }
            let (_, left) = self.peaks.pop().unwrap();
            carry = (carry.0 + 1, node_hash(&left, &carry.1));
        }
        self.peaks.push(carry);
        self.size += 1;
    }

    /// Current Merkle root. Equals [`mth`] over every leaf pushed so far.
    pub fn root(&self) -> Hash {
        match self.peaks.split_last() {
            None => empty_root(),
            Some((&(_, last), rest)) => {
                // Bag peaks right-to-left: root = node(p0, node(p1, .. last)).
                let mut acc = last;
                for &(_, h) in rest.iter().rev() {
                    acc = node_hash(&h, &acc);
                }
                acc
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n)
            .map(|i| leaf_hash(format!("rec-{i}").as_bytes()))
            .collect()
    }

    #[test]
    fn incremental_root_matches_reference_mth() {
        for n in 0..=300usize {
            let ls = leaves(n);
            let inc = Roots::from_leaves(&ls).root();
            assert_eq!(inc, mth(&ls), "root mismatch at n={n}");
        }
    }

    #[test]
    fn inclusion_proofs_verify_for_every_leaf() {
        for n in 1..=130usize {
            let ls = leaves(n);
            let root = mth(&ls);
            for m in 0..n {
                let proof = inclusion_proof(&ls, m);
                assert!(
                    verify_inclusion(&ls[m], m, n, &proof, &root),
                    "inclusion failed n={n} m={m}"
                );
                // A wrong leaf must not verify against the same path.
                let bad = leaf_hash(b"forged");
                assert!(
                    !verify_inclusion(&bad, m, n, &proof, &root),
                    "forged leaf accepted n={n} m={m}"
                );
            }
        }
    }

    #[test]
    fn consistency_proofs_verify_for_every_prefix() {
        for n in 1..=130usize {
            let ls = leaves(n);
            let second_root = mth(&ls);
            for m in 0..=n {
                let first_root = mth(&ls[..m]);
                let proof = consistency_proof(&ls, m);
                assert!(
                    verify_consistency(m, n, &first_root, &second_root, &proof),
                    "consistency failed m={m} n={n}"
                );
                // Tampering with the earlier root must break consistency.
                if m > 0 {
                    let mut forged = first_root;
                    forged[0] ^= 0xff;
                    assert!(
                        !verify_consistency(m, n, &forged, &second_root, &proof),
                        "forged first_root accepted m={m} n={n}"
                    );
                }
            }
        }
    }

    #[test]
    fn tampered_consistency_path_is_rejected() {
        let ls = leaves(50);
        let second_root = mth(&ls);
        let first_root = mth(&ls[..21]);
        let mut proof = consistency_proof(&ls, 21);
        assert!(verify_consistency(
            21,
            50,
            &first_root,
            &second_root,
            &proof
        ));
        proof[0][0] ^= 0x01;
        assert!(!verify_consistency(
            21,
            50,
            &first_root,
            &second_root,
            &proof
        ));
    }
}
