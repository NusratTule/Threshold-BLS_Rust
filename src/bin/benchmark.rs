//! Benchmark harness for the threshold BLS Rust implementation.
//!
//! Measures per-operation cost of (t, n) threshold BLS as the committee size
//! grows, plus a space-time tradeoff study for precomputed variants.
//!
//! Emits results to stdout, a CSV file, and a LaTeX table file.
//!
//! Usage:
//!   cargo run --release --bin benchmark              # default (50 trials)
//!   cargo run --release --bin benchmark -- -r 20    # custom trial count
//!   cargo run --release --bin benchmark -- --quick  # only (5,3) and (10,6)

use bls12_381::{G1Affine, G2Affine, G2Prepared};
use std::time::Instant;
use threshold_bls::{
    aggregate, aggregate_precomp, keygen_threshold, partial_sign, precompute_lagrange,
    verify, verify_partial, verify_precomp,
};

// ── Statistics ────────────────────────────────────────────────────────────────

fn median(v: &mut Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    if n % 2 == 0 {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    } else {
        v[n / 2]
    }
}

fn mean(v: &[f64]) -> f64 {
    v.iter().sum::<f64>() / v.len() as f64
}

fn std_dev(v: &[f64], m: f64) -> f64 {
    (v.iter().map(|x| (x - m).powi(2)).sum::<f64>() / v.len() as f64).sqrt()
}

/// Run `f` for `trials` iterations; return (mean_µs, median_µs, std_µs).
fn bench<F: FnMut()>(trials: usize, mut f: F) -> (f64, f64, f64) {
    let mut times: Vec<f64> = (0..trials)
        .map(|_| {
            let t0 = Instant::now();
            f();
            t0.elapsed().as_micros() as f64
        })
        .collect();
    let m = mean(&times);
    let med = median(&mut times);
    let sd = std_dev(&times, m);
    (m, med, sd)
}

// ── Row type ─────────────────────────────────────────────────────────────────

struct BenchRow {
    n: usize,
    t: usize,
    keygen_us:    (f64, f64, f64),
    sign_us:      (f64, f64, f64),
    pverify_us:   (f64, f64, f64),
    aggregate_us: (f64, f64, f64),
    verify_us:    (f64, f64, f64),
}

// ── Benchmark one (n, t) configuration ────────────────────────────────────────

fn bench_config(n: usize, t: usize, trials: usize) -> BenchRow {
    // Trusted-dealer share generation.
    let keygen_us = bench(trials, || { keygen_threshold(t, n); });

    let tk = keygen_threshold(t, n);
    let msg = b"CRC 2026 threshold BLS benchmark";

    // Partial sign (one signer).
    let sign_us = bench(trials, || { partial_sign(&tk.shares[0], msg); });

    // Partial verify (one partial).
    let ps0 = partial_sign(&tk.shares[0], msg);
    let pverify_us = bench(trials, || { verify_partial(&tk.shares[0].public, msg, &ps0); });

    // Aggregate t partials.
    let partials: Vec<_> = (0..t).map(|i| partial_sign(&tk.shares[i], msg)).collect();
    let aggregate_us = bench(trials, || { let _ = aggregate(&partials); });

    // Final verify.
    let sig = aggregate(&partials).unwrap();
    assert!(verify(&tk.group_public_key, msg, &sig), "sanity check failed");
    let verify_us = bench(trials, || { verify(&tk.group_public_key, msg, &sig); });

    BenchRow { n, t, keygen_us, sign_us, pverify_us, aggregate_us, verify_us }
}

// ── Precomputation / space-time tradeoff study ────────────────────────────────

struct PrecompRow {
    combine_baseline_us: f64,
    combine_precomp_us:  f64,
    verify_baseline_us:  f64,
    verify_precomp_us:   f64,
    lambda_bytes:        usize,
    g2prep_bytes:        usize,
}

fn bench_precomp(n: usize, t: usize, trials: usize) -> PrecompRow {
    let tk = keygen_threshold(t, n);
    let msg = b"CRC 2026 threshold BLS benchmark";
    let indices: Vec<usize> = (1..=t).collect();
    let partials: Vec<_> = (0..t).map(|i| partial_sign(&tk.shares[i], msg)).collect();
    let sig = aggregate(&partials).unwrap();

    // Combine: baseline vs precomputed Lagrange.
    let combine_baseline_us = bench(trials, || { let _ = aggregate(&partials); }).1;
    let lambdas = precompute_lagrange(&indices);
    let combine_precomp_us = bench(trials, || { aggregate_precomp(&partials, &lambdas); }).1;

    // Verify: baseline vs prepared-G2 multi-Miller loop.
    let verify_baseline_us = bench(trials, || { verify(&tk.group_public_key, msg, &sig); }).1;
    let g2_prep = G2Prepared::from(G2Affine::generator());
    let pk_prep = G2Prepared::from(G2Affine::from(&tk.group_public_key));
    let verify_precomp_us = bench(trials, || {
        verify_precomp(&sig, &pk_prep, &g2_prep, msg);
    }).1;

    // Confirm precomputed results agree.
    assert!(
        verify_precomp(&sig, &pk_prep, &g2_prep, msg) == verify(&tk.group_public_key, msg, &sig),
        "precomp verify mismatch"
    );
    assert_eq!(
        G1Affine::from(&aggregate_precomp(&partials, &lambdas)),
        G1Affine::from(&sig),
        "precomp aggregate mismatch"
    );

    // 32 B per BLS12-381 scalar; ~68 coefficient triples × 3 × 96 B per G2Prepared.
    let lambda_bytes = lambdas.len() * 32;
    let g2prep_bytes = 68 * 3 * 96;

    PrecompRow {
        combine_baseline_us,
        combine_precomp_us,
        verify_baseline_us,
        verify_precomp_us,
        lambda_bytes,
        g2prep_bytes,
    }
}

// ── Output helpers ────────────────────────────────────────────────────────────

fn write_csv(rows: &[BenchRow], path: &str) {
    let mut out = String::from(
        "n,t,keygen_us_med,sign_us_med,pverify_us_med,aggregate_us_med,verify_us_med\n",
    );
    for r in rows {
        out += &format!(
            "{},{},{:.1},{:.1},{:.1},{:.1},{:.1}\n",
            r.n, r.t,
            r.keygen_us.1, r.sign_us.1, r.pverify_us.1,
            r.aggregate_us.1, r.verify_us.1
        );
    }
    std::fs::write(path, out).expect("failed to write CSV");
}

fn write_latex(rows: &[BenchRow], path: &str) {
    let mut lines = vec![
        r"\begin{tabular}{rr rrrrr}".to_string(),
        r"\toprule".to_string(),
        r"$n$ & $t$ & KeyGen & PartSign & PartVrfy & Aggregate & Verify \\".to_string(),
        r" & & ($\mu$s) & ($\mu$s) & ($\mu$s) & ($\mu$s) & ($\mu$s) \\".to_string(),
        r"\midrule".to_string(),
    ];
    for r in rows {
        lines.push(format!(
            "{} & {} & {:.0} & {:.0} & {:.0} & {:.0} & {:.0} \\\\",
            r.n, r.t,
            r.keygen_us.1, r.sign_us.1, r.pverify_us.1,
            r.aggregate_us.1, r.verify_us.1
        ));
    }
    lines.push(r"\bottomrule".to_string());
    lines.push(r"\end{tabular}".to_string());
    std::fs::write(path, lines.join("\n") + "\n").expect("failed to write LaTeX");
}

fn print_table(rows: &[BenchRow]) {
    let header = format!(
        "{:>4} {:>4} {:>10} {:>10} {:>10} {:>10} {:>10}",
        "n", "t", "keygen", "sign", "pverify", "aggr", "verify"
    );
    println!("{}", header);
    println!("{}", "-".repeat(header.len()));
    for r in rows {
        println!(
            "{:>4} {:>4} {:>10.1} {:>10.1} {:>10.1} {:>10.1} {:>10.1}",
            r.n, r.t,
            r.keygen_us.1, r.sign_us.1, r.pverify_us.1,
            r.aggregate_us.1, r.verify_us.1
        );
    }
    println!("(all times in µs, median over trials)");
}

fn print_precomp(p: &PrecompRow, n: usize, t: usize) {
    println!("\n── Space-time tradeoff: precomputation study (n={n}, t={t}) ──");
    println!(
        "  {:<26} {:>10} {:>10} {:>10} {:>12}",
        "Operation", "baseline", "precomp", "speedup", "stored"
    );
    println!(
        "  {:<26} {:>10} {:>10} {:>10} {:>12}",
        "", "(µs,med)", "(µs,med)", "", "(bytes)"
    );
    println!("  {}", "-".repeat(62));
    println!(
        "  {:<26} {:>10.1} {:>10.1} {:>10.2}× {:>11}",
        "Verify (prepared G₂)",
        p.verify_baseline_us, p.verify_precomp_us,
        p.verify_baseline_us / p.verify_precomp_us.max(1.0),
        format!("≈{}K", p.g2prep_bytes / 1024)
    );
    println!(
        "  {:<26} {:>10.1} {:>10.1} {:>10.2}× {:>11}",
        "Combine (cached λ)",
        p.combine_baseline_us, p.combine_precomp_us,
        p.combine_baseline_us / p.combine_precomp_us.max(1.0),
        format!("{} B", p.lambda_bytes)
    );
    println!("  Correctness: PASS ✓ (precomp results match on-the-fly)");
}

// ── main ─────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut trials = 50usize;
    let mut quick = false;
    let mut it = args[1..].iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-r" | "--trials" => {
                if let Some(v) = it.next() { trials = v.parse().unwrap_or(50); }
            }
            "--quick" => quick = true,
            _ => {}
        }
    }

    let configs: &[(usize, usize)] = if quick {
        &[(5, 3), (10, 6)]
    } else {
        &[(5, 3), (10, 6), (20, 11), (50, 26)]
    };

    println!("=== Threshold BLS Benchmark (BLS12-381, Rust) ===");
    println!("Library : bls12_381 v0.8 (zkcrypto; not assembly-optimised)");
    println!("Curve   : BLS12-381 min-pk (pk ∈ G₂, σ ∈ G₁)");
    println!("Trials  : {trials}, warmup = 1 full signing cycle\n");

    // Warmup: force JIT of hash-to-curve etc.
    {
        let tk = keygen_threshold(3, 5);  // t=3, n=5
        let p = partial_sign(&tk.shares[0], b"warmup");
        let _ = verify(&tk.group_public_key, b"warmup", &p.sig);
    }

    let rows: Vec<BenchRow> = configs
        .iter()
        .map(|&(n, t)| {
            print!("  Benchmarking ({n},{t})... ");
            std::io::Write::flush(&mut std::io::stdout()).ok();
            let row = bench_config(n, t, trials);
            println!("done.");
            row
        })
        .collect();

    println!();
    print_table(&rows);

    // Space-time tradeoff on the (10,6) configuration.
    let precomp = bench_precomp(10, 6, trials);
    print_precomp(&precomp, 10, 6);

    // Output files.
    write_csv(&rows, "benchmark_results.csv");
    write_latex(&rows, "benchmark_results.tex");
    println!("\nWrote benchmark_results.csv and benchmark_results.tex");
}
