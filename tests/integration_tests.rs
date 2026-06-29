//! Integration tests for the threshold BLS reference implementation.
//!
//! Mirrors every test in the original Python test_threshold_bls.py.
//! Run with: `cargo test`

use threshold_bls::{
    aggregate, keygen_threshold, partial_sign, plain_sign, precompute_g2,
    precompute_lagrange, pubkey_from_secret, reconstruct_secret, verify,
    verify_partial, verify_precomp, aggregate_precomp,
};

const MSG: &[u8] = b"CRC 2026 threshold BLS review";

// ── Test 1 ──────────────────────────────────────────────────────────────────
/// A valid aggregate of t partials must verify under the group public key.
#[test]
fn test_threshold_signing_verifies() {
    let tk = keygen_threshold(3, 5);
    let partials = vec![
        partial_sign(&tk.shares[0], MSG),
        partial_sign(&tk.shares[2], MSG),
        partial_sign(&tk.shares[4], MSG),
    ];
    let sig = aggregate(&partials).expect("aggregate failed");
    assert!(verify(&tk.group_public_key, MSG, &sig));
}

// ── Test 2 ──────────────────────────────────────────────────────────────────
/// Every individual partial signature must verify against its key share.
#[test]
fn test_partial_signatures_verify() {
    let tk = keygen_threshold(3, 5);
    for share in &tk.shares {
        let p = partial_sign(share, MSG);
        assert!(
            verify_partial(&share.public, MSG, &p),
            "partial verify failed for share {}",
            share.index
        );
    }
}

// ── Test 3 ──────────────────────────────────────────────────────────────────
/// A partial signature presented under the wrong signer's public key must fail.
#[test]
fn test_tampered_partial_rejected() {
    let tk = keygen_threshold(3, 5);
    let good = partial_sign(&tk.shares[0], MSG);
    // Build a partial from signer 1 but claim it belongs to signer 0.
    let mut forged = partial_sign(&tk.shares[1], MSG);
    forged.index = tk.shares[0].index;

    assert!(!verify_partial(&tk.shares[0].public, MSG, &forged));
    assert!(verify_partial(&tk.shares[0].public, MSG, &good));
}

// ── Test 4 ──────────────────────────────────────────────────────────────────
/// Any t-subset must recombine to the SAME unique signature (uniqueness).
#[test]
fn test_signature_independent_of_signing_set() {
    use bls12_381::G1Affine;
    let tk = keygen_threshold(3, 5);
    let sig_a = aggregate(&[
        partial_sign(&tk.shares[0], MSG),
        partial_sign(&tk.shares[1], MSG),
        partial_sign(&tk.shares[2], MSG),
    ])
    .unwrap();
    let sig_b = aggregate(&[
        partial_sign(&tk.shares[2], MSG),
        partial_sign(&tk.shares[3], MSG),
        partial_sign(&tk.shares[4], MSG),
    ])
    .unwrap();
    assert_eq!(
        G1Affine::from(&sig_a),
        G1Affine::from(&sig_b),
        "two t-subsets produced different signatures"
    );
}

// ── Test 5 ──────────────────────────────────────────────────────────────────
/// A threshold signature is identical to the ordinary BLS signature produced
/// by a single signer holding the reconstructed master secret.
#[test]
fn test_equivalent_to_nonthreshold_bls() {
    use bls12_381::G1Affine;
    let tk = keygen_threshold(3, 5);
    let indices = &[1usize, 2, 3];
    let secret = reconstruct_secret(&tk.shares, indices);

    let plain_sig = plain_sign(secret, MSG);
    let threshold_sig = aggregate(&[
        partial_sign(&tk.shares[0], MSG),
        partial_sign(&tk.shares[1], MSG),
        partial_sign(&tk.shares[2], MSG),
    ])
    .unwrap();

    assert_eq!(
        G1Affine::from(&plain_sig),
        G1Affine::from(&threshold_sig),
        "threshold sig does not match plain BLS sig on reconstructed key"
    );
    // And the reconstructed key matches the published group public key.
    use bls12_381::G2Affine;
    assert_eq!(
        G2Affine::from(&pubkey_from_secret(secret)),
        G2Affine::from(&tk.group_public_key)
    );
}

// ── Test 6 ──────────────────────────────────────────────────────────────────
/// Fewer than t partial signatures must NOT produce a valid signature.
#[test]
fn test_insufficient_shares_do_not_verify() {
    let tk = keygen_threshold(3, 5);
    let partials = vec![
        partial_sign(&tk.shares[0], MSG),
        partial_sign(&tk.shares[1], MSG), // only 2 < t=3
    ];
    let sig = aggregate(&partials).unwrap();
    assert!(!verify(&tk.group_public_key, MSG, &sig));
}

// ── Test 7 ──────────────────────────────────────────────────────────────────
/// A valid signature must not verify under a different message.
#[test]
fn test_wrong_message_rejected() {
    let tk = keygen_threshold(2, 3);
    let partials = vec![
        partial_sign(&tk.shares[0], MSG),
        partial_sign(&tk.shares[1], MSG),
    ];
    let sig = aggregate(&partials).unwrap();
    assert!(verify(&tk.group_public_key, MSG, &sig));
    assert!(!verify(&tk.group_public_key, b"different message", &sig));
}

// ── Test 8 ──────────────────────────────────────────────────────────────────
/// Duplicate signer indices must be rejected by aggregate().
#[test]
fn test_duplicate_indices_rejected() {
    let tk = keygen_threshold(2, 3);
    let p = partial_sign(&tk.shares[0], MSG);
    let result = aggregate(&[p.clone(), p]);
    assert!(
        result.is_err(),
        "expected Err on duplicate signer indices but got Ok"
    );
}

// ── Test 9 — Precomputation correctness ──────────────────────────────────────
/// Precomputed verify and aggregate must match on-the-fly results.
#[test]
fn test_precomputation_matches_baseline() {
    use bls12_381::G1Affine;
    let tk = keygen_threshold(3, 5);
    let indices = vec![1usize, 2, 3];
    let partials: Vec<_> = indices
        .iter()
        .map(|&i| partial_sign(&tk.shares[i - 1], MSG))
        .collect();

    // Baseline aggregate + verify.
    let sig_baseline = aggregate(&partials).unwrap();
    assert!(verify(&tk.group_public_key, MSG, &sig_baseline));

    // Precomputed aggregate.
    let lambdas = precompute_lagrange(&indices);
    let sig_precomp = aggregate_precomp(&partials, &lambdas);
    assert_eq!(G1Affine::from(&sig_baseline), G1Affine::from(&sig_precomp));

    // Precomputed verify.
    let (g2_prep, pk_prep) = precompute_g2(&tk.group_public_key);
    assert!(verify_precomp(&sig_baseline, &pk_prep, &g2_prep, MSG));
}
