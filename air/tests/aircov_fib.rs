//! AIRCov feasibility demonstrator.
//!
//! Shows the core premise: on a degenerate test trace, Rust line coverage of
//! `FibonacciAir::eval` is 100% (every `assert_eq` statement runs on every
//! trace), yet the two *transition* constraints are never SEMANTICALLY active
//! because their `is_transition` guard is zero on a 1-row trace. AIRCov reports
//! that gap; line coverage cannot.
//!
//! Run: cargo test -p p3-air --features aircov --test aircov_fib -- --nocapture
#![cfg(feature = "aircov")]

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess, collect_coverage};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

const NUM_FIBONACCI_COLS: usize = 2;

struct FibonacciRow<F> {
    left: F,
    right: F,
}
impl<F> FibonacciRow<F> {
    const fn new(left: F, right: F) -> Self {
        Self { left, right }
    }
}
impl<F> Borrow<FibonacciRow<F>> for [F] {
    fn borrow(&self) -> &FibonacciRow<F> {
        debug_assert_eq!(self.len(), NUM_FIBONACCI_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<FibonacciRow<F>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

struct FibonacciAir {}

impl<F> BaseAir<F> for FibonacciAir {
    fn width(&self) -> usize {
        NUM_FIBONACCI_COLS
    }
    fn num_public_values(&self) -> usize {
        3
    }
}

impl<AB: AirBuilder> Air<AB> for FibonacciAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let pis = builder.public_values();
        let a = pis[0];
        let b = pis[1];
        let x = pis[2];

        let local: &FibonacciRow<AB::Var> = main.current_slice().borrow();
        let next: &FibonacciRow<AB::Var> = main.next_slice().borrow();

        let mut when_first_row = builder.when_first_row();
        when_first_row.assert_eq(local.left, a); // site 0
        when_first_row.assert_eq(local.right, b); // site 1

        let mut when_transition = builder.when_transition();
        when_transition.assert_eq(local.right, next.left); // site 2
        when_transition.assert_eq(local.left + local.right, next.right); // site 3

        builder.when_last_row().assert_eq(local.right, x); // site 4
    }
}

fn generate_trace_rows(a: u64, b: u64, n: usize) -> RowMajorMatrix<BabyBear> {
    assert!(n.is_power_of_two());
    let mut trace = RowMajorMatrix::new(
        BabyBear::zero_vec(n * NUM_FIBONACCI_COLS),
        NUM_FIBONACCI_COLS,
    );
    let (prefix, rows, suffix) =
        unsafe { trace.values.align_to_mut::<FibonacciRow<BabyBear>>() };
    assert!(prefix.is_empty());
    assert!(suffix.is_empty());
    rows[0] = FibonacciRow::new(BabyBear::from_u64(a), BabyBear::from_u64(b));
    for i in 1..n {
        rows[i].left = rows[i - 1].right;
        rows[i].right = rows[i - 1].left + rows[i - 1].right;
    }
    trace
}

/// Last `right` value of an n-row Fibonacci trace (the valid public output).
fn last_right(a: u64, b: u64, n: usize) -> u64 {
    let (mut l, mut r) = (a, b);
    for _ in 1..n {
        let nl = r;
        let nr = l + r;
        l = nl;
        r = nr;
    }
    r
}

#[test]
fn aircov_detects_untested_transition_constraints() {
    let air = FibonacciAir {};

    // --- Full trace (8 rows): every guard fires at least once. ---
    let n = 8;
    let trace = generate_trace_rows(0, 1, n);
    let pis = vec![
        BabyBear::ZERO,
        BabyBear::ONE,
        BabyBear::from_u64(last_right(0, 1, n)),
    ];
    let cov_full = collect_coverage(&air, &trace, &pis);
    println!("\n=== AIRCov: FibonacciAir, {n}-row VALID trace ===");
    print_cov(&cov_full);
    for site in 0..5 {
        assert!(
            cov_full.per.get(&site).map(|c| c.ever_active()).unwrap_or(false),
            "site {site} should be active on the full trace"
        );
    }

    // --- Degenerate trace (1 row): line coverage of eval() is IDENTICAL
    // (every assert_eq statement executes), but the transition guard is 0. ---
    let trace1 = generate_trace_rows(0, 1, 1);
    let pis1 = vec![
        BabyBear::ZERO,
        BabyBear::ONE,
        BabyBear::from_u64(last_right(0, 1, 1)),
    ];
    let cov_deg = collect_coverage(&air, &trace1, &pis1);
    println!("\n=== AIRCov: FibonacciAir, 1-row DEGENERATE trace ===");
    print_cov(&cov_deg);

    // The money shot: transition sites 2 and 3 are NEVER semantically active,
    // even though eval() ran every statement (line coverage = 100%).
    assert!(!cov_deg.per[&2].ever_active(), "site 2 (transition) must be untested");
    assert!(!cov_deg.per[&3].ever_active(), "site 3 (transition) must be untested");
    // ...while the first-row and last-row constraints ARE active.
    assert!(cov_deg.per[&0].ever_active());
    assert!(cov_deg.per[&1].ever_active());
    assert!(cov_deg.per[&4].ever_active());

    let untested: Vec<usize> = (0..5)
        .filter(|s| !cov_deg.per.get(s).map(|c| c.ever_active()).unwrap_or(false))
        .collect();
    println!(
        "\nRESULT: line coverage of eval() = 100% on BOTH traces, \
         but AIRCov flags constraint sites {untested:?} as never semantically \
         exercised by the 1-row trace.\n"
    );
}

fn print_cov(rec: &p3_air::aircov::Recorder) {
    println!(
        "{:<6} {:>8} {:>8} {:>8} {:>8}  {}",
        "site", "active", "inactive", "held", "violate", "ever_active/both_states"
    );
    for (site, c) in &rec.per {
        println!(
            "{:<6} {:>8} {:>8} {:>8} {:>8}  {}/{}",
            site,
            c.active_rows,
            c.inactive_rows,
            c.active_zero,
            c.active_nonzero,
            c.ever_active(),
            c.both_states()
        );
    }
}
