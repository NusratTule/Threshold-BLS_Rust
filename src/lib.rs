//! Threshold BLS signatures over BLS12-381.
//!
//! A compact, readable reference implementation of Boldyreva's (t, n)
//! threshold BLS signature scheme (PKC 2003), built on the
//! Boneh–Lynn–Shacham signature scheme (ASIACRYPT 2001).
//!
//! # Design (min-pk variant)
//! * Secret-key shares live in the scalar field **Fₙ** (curve order r).
//! * Public keys / key shares live in **G₂**.
//! * Message hashes H(m) and signatures live in **G₁** (IETF SSWU map, RFC 9380).
//!
//! Verification uses the bilinear pairing e : G₁ × G₂ → Gₜ and checks
//! ```text
//! e(σ, g₂) == e(H(m), pk)
//! ```
//!
//! Key shares are produced via Shamir (t,n) secret sharing of a master
//! secret `sk`; any t valid partial signatures recombine (Lagrange at 0)
//! into the same single-element signature `H(m)^sk` that a non-threshold
//! signer would produce. The verifier therefore cannot distinguish a
//! threshold signature from an ordinary BLS signature.
//!
//! # Module favours clarity over speed.
//! It is intended to accompany the review paper and to generate benchmark
//! numbers for the Implementations section.

use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    multi_miller_loop, pairing, G1Affine, G1Projective, G2Affine, G2Prepared,
    G2Projective, Gt, Scalar,
};
use ff::Field;
use rand::rngs::OsRng;

// Domain-separation tag: min-pk / G1-signature variant, threshold review.
pub const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_THRESHOLD_REVIEW_";

// ── Field / polynomial helpers ────────────────────────────────────────────────

/// Uniform non-zero scalar in Fₙ.
pub fn rand_scalar() -> Scalar {
    loop {
        let s = Scalar::random(&mut OsRng);
        if s != Scalar::zero() {
            return s;
        }
    }
}

/// Evaluate polynomial `coeffs[0] + coeffs[1]·x + …` at `x` (Horner's rule).
pub fn poly_eval(coeffs: &[Scalar], x: Scalar) -> Scalar {
    coeffs.iter().rev().fold(Scalar::zero(), |acc, &c| acc * x + c)
}

/// Lagrange basis coefficient λᵢ(0) for reconstructing at x = 0.
/// `indices` are 1-based signer identifiers.
///
/// λᵢ(0) = ∏_{j≠i} (0 − j) / (i − j)  mod r
pub fn lagrange_coefficient(i: usize, indices: &[usize]) -> Scalar {
    let xi = Scalar::from(i as u64);
    let mut num = Scalar::one();
    let mut den = Scalar::one();
    for &j in indices {
        if j == i {
            continue;
        }
        let xj = Scalar::from(j as u64);
        num *= Scalar::zero() - xj;   // (0 - x_j)
        den *= xi - xj;               // (x_i - x_j)
    }
    let den_inv = Option::<Scalar>::from(den.invert())
        .expect("duplicate signer index in Lagrange interpolation");
    num * den_inv
}

// ── Data types ────────────────────────────────────────────────────────────────

/// A single signer's key material.
#[derive(Clone, Debug)]
pub struct KeyShare {
    /// Signer identifier (x-coordinate, 1..=n).
    pub index: usize,
    /// Secret-key share sₖ ∈ Fₙ.
    pub secret: Scalar,
    /// Public-key share vkᵢ = g₂^{sₖ} ∈ G₂.
    pub public: G2Projective,
}

/// Output of trusted-dealer or distributed key generation.
#[derive(Clone, Debug)]
pub struct ThresholdKey {
    pub t: usize,
    pub n: usize,
    /// Group public key pk = g₂^{sk} ∈ G₂.
    pub group_public_key: G2Projective,
    pub shares: Vec<KeyShare>,
}

/// One signer's contribution to the threshold signature.
#[derive(Clone, Debug)]
pub struct PartialSignature {
    pub index: usize,
    /// σᵢ = H(m)^{skᵢ} ∈ G₁.
    pub sig: G1Projective,
}

// ── Core scheme ───────────────────────────────────────────────────────────────

/// Hash an arbitrary byte string to a point in G₁ (IETF SSWU map, RFC 9380).
pub fn hash_to_g1(msg: &[u8]) -> G1Projective {
    <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(msg, DST)
}

/// (t, n) key generation via Shamir secret sharing of a fresh master secret.
///
/// Models the *output distribution* of an ideal DKG: a real deployment would
/// run a distributed key generation protocol so no single party ever learns
/// the master secret `sk`.
///
/// # Panics
/// Panics if `t == 0` or `t > n`.
pub fn keygen_threshold(t: usize, n: usize) -> ThresholdKey {
    assert!(t >= 1 && t <= n, "require 1 ≤ t ≤ n, got t={t}, n={n}");

    // Degree-(t−1) polynomial; constant term is the master secret.
    let coeffs: Vec<Scalar> = (0..t).map(|_| rand_scalar()).collect();
    let master_secret = coeffs[0];

    let g2 = G2Projective::generator();
    let shares: Vec<KeyShare> = (1..=n)
        .map(|i| {
            let secret = poly_eval(&coeffs, Scalar::from(i as u64));
            KeyShare {
                index: i,
                secret,
                public: g2 * secret,
            }
        })
        .collect();

    ThresholdKey {
        t,
        n,
        group_public_key: g2 * master_secret,
        shares,
    }
}

/// Signer `i` produces σᵢ = H(m)^{skᵢ}. Non-interactive.
pub fn partial_sign(share: &KeyShare, msg: &[u8]) -> PartialSignature {
    PartialSignature {
        index: share.index,
        sig: hash_to_g1(msg) * share.secret,
    }
}

/// Check a single partial signature against the signer's public-key share.
///
/// Checks: e(σᵢ, g₂) == e(H(m), vkᵢ)
pub fn verify_partial(share_public: &G2Projective, msg: &[u8], partial: &PartialSignature) -> bool {
    let h = hash_to_g1(msg);
    pairing(&G1Affine::from(&partial.sig), &G2Affine::from(&G2Projective::generator()))
        == pairing(&G1Affine::from(&h), &G2Affine::from(share_public))
}

/// Combine ≥ t partial signatures into the full threshold signature σ = H(m)^{sk}
/// via Lagrange interpolation in the exponent.
///
/// # Errors
/// Returns `Err` if `partials` is empty or contains duplicate signer indices.
pub fn aggregate(partials: &[PartialSignature]) -> Result<G1Projective, String> {
    if partials.is_empty() {
        return Err("need at least one partial signature".into());
    }
    let indices: Vec<usize> = partials.iter().map(|p| p.index).collect();
    let unique: std::collections::HashSet<usize> = indices.iter().copied().collect();
    if unique.len() != indices.len() {
        return Err("duplicate signer indices".into());
    }

    let sigma = partials
        .iter()
        .fold(G1Projective::identity(), |acc, p| {
            acc + p.sig * lagrange_coefficient(p.index, &indices)
        });
    Ok(sigma)
}

/// Verify a (threshold or plain) BLS signature.
///
/// Identical to non-threshold BLS verification: e(σ, g₂) == e(H(m), pk).
pub fn verify(group_public_key: &G2Projective, msg: &[u8], sig: &G1Projective) -> bool {
    let h = hash_to_g1(msg);
    pairing(&G1Affine::from(sig), &G2Affine::from(&G2Projective::generator()))
        == pairing(&G1Affine::from(&h), &G2Affine::from(group_public_key))
}

// ── Plain (non-threshold) BLS, for equivalence checks ────────────────────────

pub fn plain_keygen() -> (Scalar, G2Projective) {
    let sk = rand_scalar();
    (sk, G2Projective::generator() * sk)
}

pub fn plain_sign(sk: Scalar, msg: &[u8]) -> G1Projective {
    hash_to_g1(msg) * sk
}

/// Derive the G₂ public key from a scalar secret key.
pub fn pubkey_from_secret(sk: Scalar) -> G2Projective {
    G2Projective::generator() * sk
}

// ── Precomputation / space-time tradeoff helpers ──────────────────────────────

/// Combine with *precomputed* Lagrange coefficients (signing set S fixed).
/// Stores |S| × 32 B; skips |S| field inversions per signature.
pub fn aggregate_precomp(partials: &[PartialSignature], lambdas: &[Scalar]) -> G1Projective {
    partials
        .iter()
        .zip(lambdas.iter())
        .fold(G1Projective::identity(), |acc, (p, &l)| acc + p.sig * l)
}

/// Verify with *precomputed* G₂-prepared points via a single multi-Miller loop
/// and one final exponentiation: e(σ, g₂) · e(−H(m), pk) =? 1.
/// Stores one `G2Prepared` per fixed g₂ and per public key (≈ 19 KB each).
pub fn verify_precomp(
    sig: &G1Projective,
    pk_prep: &G2Prepared,
    g2_prep: &G2Prepared,
    msg: &[u8],
) -> bool {
    let h_neg = -hash_to_g1(msg);
    let ml = multi_miller_loop(&[
        (&G1Affine::from(sig), g2_prep),
        (&G1Affine::from(&h_neg), pk_prep),
    ]);
    ml.final_exponentiation() == Gt::identity()
}

/// Precompute Lagrange coefficients for a fixed signing set.
pub fn precompute_lagrange(indices: &[usize]) -> Vec<Scalar> {
    indices.iter().map(|&i| lagrange_coefficient(i, indices)).collect()
}

/// Precompute G₂-prepared points for fast verification.
pub fn precompute_g2(pk: &G2Projective) -> (G2Prepared, G2Prepared) {
    let g2_prep = G2Prepared::from(G2Affine::generator());
    let pk_prep = G2Prepared::from(G2Affine::from(pk));
    (g2_prep, pk_prep)
}

// ── Secret reconstruction (test / demo use only) ─────────────────────────────

/// Lagrange-interpolate the master secret from secret shares (test-only).
/// In production, `sk` is never reconstructed in the clear.
pub fn reconstruct_secret(shares: &[KeyShare], indices: &[usize]) -> Scalar {
    indices.iter().fold(Scalar::zero(), |acc, &i| {
        let share = shares.iter().find(|s| s.index == i).expect("share not found");
        acc + share.secret * lagrange_coefficient(i, indices)
    })
}
