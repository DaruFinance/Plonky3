//! AIRCov go/no-go gate: a FAITHFUL reconstruction of a REAL, documented SP1
//! soundness bug, not one designed for the metric.
//!
//! Source: SP1 audit `audits/rkm0959.md`, Issue #11 [High] "incorrect
//! constraints in exp_reverse_bits" (fix PR succinctlabs/sp1#1482). The
//! exponentiation-by-squaring accumulation recurrence
//!     assert_eq(accum, prev_accum_squared_times_multiplier)
//! was guarded by `when_not(is_last)` when it should have been
//! `when_not(is_first)`. Effect: the recurrence is never enforced on the LAST
//! row, so a malicious prover can forge the final exponentiation result.
//!
//! This test does four things:
//!  1. MUTATION ADEQUACY: the honest test trace passes under BOTH the correct
//!     guard and the mutated (buggy) guard -> the honest suite does NOT kill the
//!     mutant -> the test is inadequate. (This is why the bug shipped.)
//!  2. EXPLOIT: under the buggy guard, a forged trace claiming a FALSE result is
//!     ACCEPTED (a valid proof of a false statement).
//!  3. The CORRECT guard REJECTS the same forged trace.
//!  4. AIRCov distinguishes correct vs buggy by ROW-POSITION activation
//!     (correct recurrence reaches the last/output row; buggy does not), a
//!     signal line/opcode coverage cannot see (identical program, identical
//!     statements).
//!
//! Run: cargo test -p p3-air --features aircov --test aircov_sp1_expbits -- --nocapture
#![cfg(feature = "aircov")]

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess, check_all_constraints, collect_coverage};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

const COLS: usize = 3; // accum, psm (= prev_accum^2 * mult), mult

#[repr(C)]
struct ExpRow<F> {
    accum: F,
    psm: F,
    mult: F,
}
impl<F> Borrow<ExpRow<F>> for [F] {
    fn borrow(&self) -> &ExpRow<F> {
        let (p, s, suf) = unsafe { self.align_to::<ExpRow<F>>() };
        debug_assert!(p.is_empty() && suf.is_empty() && s.len() == 1);
        &s[0]
    }
}

/// Minimal exp-by-squaring accumulation chip. `buggy == true` reproduces the
/// exact rkm0959 #11 guard mistake (`when_not(is_last)` instead of
/// `when_not(is_first)`) on the accumulation recurrence.
struct ExpChip {
    buggy: bool,
}
impl<F> BaseAir<F> for ExpChip {
    fn width(&self) -> usize {
        COLS
    }
    fn num_public_values(&self) -> usize {
        1 // claimed final result
    }
}
impl<AB: AirBuilder> Air<AB> for ExpChip {
    fn eval(&self, builder: &mut AB) {
        let claimed = builder.public_values()[0];
        let main = builder.main();
        let local: &ExpRow<AB::Var> = main.current_slice().borrow();
        let next: &ExpRow<AB::Var> = main.next_slice().borrow();

        // site 0: base case, first accum = first multiplier.
        builder.when_first_row().assert_eq(local.accum, local.mult);

        // site 1: define psm[i+1] = accum[i]^2 * mult[i+1] (ties psm to prev row).
        builder
            .when_transition()
            .assert_eq(next.psm, local.accum * local.accum * next.mult);

        // site 2: THE RECURRENCE (the bug lives on its guard).
        let recurrence_guard = if self.buggy {
            AB::Expr::ONE - builder.is_last_row() // BUG: when_not(is_last)
        } else {
            AB::Expr::ONE - builder.is_first_row() // CORRECT: when_not(is_first)
        };
        builder
            .when(recurrence_guard)
            .assert_eq(local.accum, local.psm);

        // site 3: output boundary, last accum = claimed public result.
        builder.when_last_row().assert_eq(local.accum, claimed);
    }
}

fn b(v: u64) -> BabyBear {
    BabyBear::from_u64(v)
}

const N: usize = 8;

/// Honest exp-by-squaring trace (mult = 2 every row). accum[0] = 2;
/// accum[i] = accum[i-1]^2 * 2. Returns (trace, honest_final_result).
fn honest_trace() -> (RowMajorMatrix<BabyBear>, BabyBear) {
    let mut accum = vec![BabyBear::ZERO; N];
    let mut psm = vec![BabyBear::ZERO; N];
    let mult = b(2);
    accum[0] = mult;
    psm[0] = accum[0]; // free witness; set trivially so buggy row-0 check holds
    for i in 1..N {
        psm[i] = accum[i - 1] * accum[i - 1] * mult;
        accum[i] = psm[i];
    }
    let mut vals = Vec::with_capacity(N * COLS);
    for i in 0..N {
        vals.push(accum[i]);
        vals.push(psm[i]);
        vals.push(mult);
    }
    (RowMajorMatrix::new(vals, COLS), accum[N - 1])
}

/// Forged trace: identical to honest except the LAST row's accum is replaced by
/// a false result. psm is left honest, so only the (mis-guarded) recurrence
/// could catch the mismatch.
fn forged_trace(false_result: BabyBear) -> RowMajorMatrix<BabyBear> {
    let (m, _) = honest_trace();
    let mut vals = m.values;
    vals[(N - 1) * COLS] = false_result; // accum of last row
    RowMajorMatrix::new(vals, COLS)
}

#[test]
fn aircov_gate_on_real_sp1_exp_reverse_bits_bug() {
    let correct = ExpChip { buggy: false };
    let buggy = ExpChip { buggy: true };

    let (honest, honest_result) = honest_trace();
    let pis_true = vec![honest_result];
    let false_result = honest_result + BabyBear::ONE;
    let pis_false = vec![false_result];

    // --- 1) MUTATION ADEQUACY ---
    let honest_on_correct = check_all_constraints(&correct, &honest, &pis_true, None).is_ok();
    let honest_on_buggy = check_all_constraints(&buggy, &honest, &pis_true, None).is_ok();
    println!("\n=== 1) MUTATION ADEQUACY (honest test trace) ===");
    println!("honest trace passes CORRECT guard: {honest_on_correct}");
    println!("honest trace passes BUGGY  guard: {honest_on_buggy}");
    println!(
        "=> the honest suite does NOT kill the is_first->is_last mutant (both pass). \
         An inadequate test suite is exactly why the real bug shipped."
    );
    assert!(honest_on_correct && honest_on_buggy, "honest trace must pass both (mutant survives)");

    // --- 2) EXPLOIT: forged false result accepted by the buggy AIR ---
    let forged = forged_trace(false_result);
    let buggy_accepts = check_all_constraints(&buggy, &forged, &pis_false, None);
    println!("\n=== 2) EXPLOIT (malicious prover forges the exponentiation result) ===");
    println!(
        "buggy AIR accepts forged FALSE result? {}  (constraint failures: {})",
        buggy_accepts.is_ok(),
        buggy_accepts.failures.len()
    );
    assert!(buggy_accepts.is_ok(), "buggy AIR must accept the forged false result");

    // --- 3) The correct AIR rejects the same forged trace ---
    let correct_rejects = check_all_constraints(&correct, &forged, &pis_false, None);
    println!("\n=== 3) CORRECT guard rejects the same forged trace ===");
    println!(
        "correct AIR rejects forged trace? {}  (constraint failures: {})",
        !correct_rejects.is_ok(),
        correct_rejects.failures.len()
    );
    assert!(!correct_rejects.is_ok(), "correct AIR must reject the forged trace");

    // --- 4) AIRCov signal vs baseline ---
    let cov_correct = collect_coverage(&correct, &honest, &pis_true);
    let cov_buggy = collect_coverage(&buggy, &honest, &pis_true);
    // site 2 is the recurrence in both.
    let c = &cov_correct.per[&2];
    let g = &cov_buggy.per[&2];
    println!("\n=== 4) AIRCov row-position activation of the recurrence (site 2), honest test ===");
    println!(
        "CORRECT: active rows {}..={}  active_on_first={} active_on_last={}",
        c.min_active_row.unwrap(),
        c.max_active_row.unwrap(),
        c.active_on_first(),
        c.active_on_last(N)
    );
    println!(
        "BUGGY:   active rows {}..={}  active_on_first={} active_on_last={}  <-- output row NOT covered by recurrence",
        g.min_active_row.unwrap(),
        g.max_active_row.unwrap(),
        g.active_on_first(),
        g.active_on_last(N)
    );
    println!(
        "\nBASELINE: line coverage and executed-opcode coverage are IDENTICAL for both \
         (same program, same single assert_eq statement, only the guard expression differs). \
         Only AIRCov distinguishes them: the buggy recurrence never reaches the last/output row."
    );

    // The security-relevant, baseline-invisible distinction:
    assert!(c.active_on_last(N), "correct recurrence must cover the output (last) row");
    assert!(!g.active_on_last(N), "buggy recurrence must NOT cover the output (last) row");
    assert!(!c.active_on_first(), "correct recurrence must skip the first row");
    assert!(g.active_on_first(), "buggy recurrence wrongly covers the first row");
}
