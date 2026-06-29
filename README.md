# Threshold BLS (BLS12-381) — Rust Reference Implementation

A compact, readable Rust implementation of **Boldyreva's (t, n) threshold BLS signature scheme** over the **BLS12-381** curve, built on the Boneh–Lynn–Shacham (BLS) signature scheme.

Companion code for the review paper:

> **Threshold BLS Signatures and Their Extensions: A Review of Security,
> Implementations, Applications, and Standardization** (CRC 2026).

The goal is **clarity and reproducibility** for the paper's implementation section—not production deployment.

## Features

- Shamir `(t, n)` secret sharing of the BLS signing key
- Non-interactive partial signing (one message per signer, no coordination)
- Lagrange interpolation to combine partial signatures into a single 48-byte signature
- Standard BLS verification: `e(σ, g₂) = e(H(m), pk)` — verifiers cannot tell threshold vs single-party signing
- Partial-signature verification before aggregation
- Precomputation helpers (prepared G₂ points, cached Lagrange coefficients) for space–time tradeoff study
- Integration tests mirroring the Python reference
- Benchmark harness with CSV and LaTeX table output

## Cryptographic design

| Item | Choice |
|------|--------|
| Curve | BLS12-381 |
| Variant | IETF **min-pk** (`pk ∈ G₂`, `σ ∈ G₁`) |
| Hash-to-curve | SSWU (RFC 9380 style) via `bls12_381` |
| Key generation | Trusted Shamir dealer (not a full DKG protocol) |
| Library | `bls12_381` v0.8 (zkcrypto reference; pure Rust) |

**Threshold flow**

1. **KeyGen** — dealer splits `sk` into `n` shares; group public key `pk = g₂^sk`
2. **PartialSign** — signer `i` outputs `σᵢ = H(m)^{skᵢ}`
3. **Combine** — combiner applies Lagrange weights on `t` partials → `σ = H(m)^sk`
4. **Verify** — same pairing check as plain BLS

## Project structure

```
.
├── Cargo.toml
├── Cargo.lock
├── README.md
├── src/
│   ├── lib.rs              # core library
│   └── bin/
│       └── benchmark.rs    # timing harness
└── tests/
    └── integration_tests.rs   # correctness tests (9 tests)
```

## Requirements

- **Rust** 1.70+ (tested with Rust 1.94)
- No other system dependencies

## Quick start

Clone the repository, then from the project root:

```bash
cargo test --release
```

```bash
cargo run --release --bin benchmark -- -r 50
```

Release mode (`--release`) is required for meaningful benchmark numbers.

## Run tests

Nine integration tests cover:

- Threshold signing and verification
- Partial-signature verification
- Tampered partial rejection
- Equivalence to non-threshold BLS on the same key
- Signature independence across different qualified signer subsets
- Insufficient shares cannot verify
- Precomputation matches on-the-fly baseline

```bash
cargo test --release
```

Verbose output:

```bash
cargo test --release -- --nocapture
```

## Run benchmarks

Default: 50 trials per operation, committees `(5,3)`, `(10,6)`, `(20,11)`, `(50,26)`:

```bash
cargo run --release --bin benchmark
```

Custom trial count:

```bash
cargo run --release --bin benchmark -- -r 50
```

Quick mode (only `(5,3)` and `(10,6)`):

```bash
cargo run --release --bin benchmark -- --quick -r 50
```

### Benchmark output

The harness prints median execution times in **microseconds (µs)** for:

| Phase | Description |
|-------|-------------|
| KeyGen | Trusted-dealer share generation |
| Sign | One partial signature |
| Partial Verify | Check one partial against its verification key |
| Aggregate | Lagrange combine `t` partials |
| Verify | Final BLS pairing verification |

It also runs a **space–time tradeoff** study on `(10, 6)`:

- **Verify** with prepared G₂ points (~1.8–1.9× speedup, ~19–39 KB stored per verifier)
- **Combine** with cached Lagrange coefficients (~1.04–1.06× speedup, 192 B stored)

Results are written to:

- `benchmark_results.csv`
- `benchmark_results.tex` (LaTeX `tabular` rows)

### Example output (abbreviated)

```
=== Threshold BLS Benchmark (BLS12-381, Rust) ===
   n    t     keygen       sign    pverify       aggr     verify
----------------------------------------------------------------
   5    3     9803.5      549.0     4221.0     1315.0     4157.5
  10    6    16848.0      550.5     4123.0     2686.0     4351.5
  ...
```

Timings are **relative trends** across committee sizes. Absolute numbers depend on CPU, Rust version, and `opt-level`. Production libraries such as [`blst`](https://github.com/supranational/blst) are typically several times faster on the same curve.

## Library API (selected)

```rust
use threshold_bls::{keygen_threshold, partial_sign, aggregate, verify};

let tk = keygen_threshold(6, 10);           // t=6, n=10
let msg = b"hello";

let partials: Vec<_> = tk.shares[..6]
    .iter()
    .map(|s| partial_sign(s, msg))
    .collect();

let sig = aggregate(&partials).expect("aggregate");
assert!(verify(&tk.group_public_key, msg, &sig));
```

Other public functions: `verify_partial`, `plain_sign`, `reconstruct_secret`, `aggregate_precomp`, `verify_precomp`, `precompute_lagrange`, `precompute_g2`.


## Authors

Nusrat Sultana, Sook-Chin Yip, Ji-Jian Chin, Ivan Ku — CRC 2026 review paper.

## References

- Boldyreva, PKC 2003 — threshold BLS construction
- Boneh, Lynn, Shacham, ASIACRYPT 2001 — BLS signatures
- IETF CFRG BLS draft — min-pk ciphersuite and hash-to-curve
- RFC 9380 — hash-to-curve (SSWU)
