# Threshold BLS Signatures and Their Extensions

Companion repository for the review paper:

> **Threshold BLS Signatures and Their Extensions: A Review of Security,
> Implementations, Applications, and Standardization** (CRC 2026).

## Repository layout

```
.
├── README.md
├── code/
│   ├── requirements.txt
│   ├── threshold_bls.py              # Python reference implementation
│   ├── benchmark.py                  # Python benchmark harness
│   ├── test_threshold_bls.py         # Python tests
│   └── threshold_bls_bench/          # Rust benchmark (paper Table IV)
├── threshold_bls_rust/               # Rust library + tests + multi-(n,t) benchmark
├── paper/                            # LaTeX source (working draft)
└── paper_final/                      # LaTeX source (6-page submission version)
```

## Python setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r code/requirements.txt
```

### Tests

```bash
cd code
python -m pytest test_threshold_bls.py -v
```

### Benchmark

```bash
cd code
python benchmark.py
```

## Rust (recommended — matches paper benchmarks)

### Library + integration tests

```bash
cd threshold_bls_rust
cargo test --release
```

### Multi-committee benchmark + CSV/LaTeX output

```bash
cd threshold_bls_rust
cargo run --release --bin benchmark -- -r 50
```

### Paper comparison table (Standard BLS vs Threshold (10,6))

```bash
cd code/threshold_bls_bench
cargo run --release -- -r 50
```

Uses `bls12_381` v0.8 (zkcrypto reference implementation; not assembly-optimized).
Production libraries such as `blst` are typically several times faster on the same curve.

## Build the paper

```bash
cd paper_final   # or paper/
pdflatex main && bibtex main && pdflatex main && pdflatex main
```

IEEE class files (`IEEEtran.cls`, `IEEEtran.bst`) are vendored in each paper folder.

## Scope and caveats

These implementations prioritize clarity and reproducibility for the review paper.
They are **not** constant-time or side-channel hardened. Key generation uses a
trusted Shamir dealer (not a full DKG protocol). For production deployments, use
an audited library and a proper DKG.
