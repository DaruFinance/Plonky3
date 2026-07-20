//! AIRCov HELD-OUT validation (metric frozen in FROZEN_METRIC_v1.md; predictions
//! pre-registered BEFORE this ran). Four real SP1 bug classes reconstructed
//! faithfully from the in-repo audits. For each: prove it is a real exploitable
//! bug (buggy AIR accepts a forged trace the correct AIR rejects), then apply the
//! FROZEN detection criterion:
//!
//!   distinguishes(bug) := the frozen per-site metric vector, on a VALID trace,
//!   differs between the correct and buggy AIR for a site present in BOTH.
//!
//! Pre-registered predictions:
//!   H1 next_pc missing (sp1-v4 #6)          -> MISS
//!   H2 one-limb narrow check (BNEINC class) -> MISS
//!   H3 wrong selector (is_memory class)     -> CATCH
//!   H4 spurious valid-true guard            -> MISS
//!
//! Run: cargo test -p p3-air --features aircov --test aircov_heldout -- --nocapture
#![cfg(feature = "aircov")]

use p3_air::aircov::Recorder;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess, check_all_constraints, collect_coverage};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

type F = BabyBear;
const N: usize = 4;

fn f(v: u64) -> F {
    F::from_u64(v)
}
fn mat<const W: usize>(rows: &[[u64; W]]) -> RowMajorMatrix<F> {
    let mut v = Vec::new();
    for r in rows {
        for &x in r {
            v.push(f(x));
        }
    }
    RowMajorMatrix::new(v, W)
}

/// True if the two coverage runs differ on any site present in BOTH.
fn distinguishes(a: &Recorder, b: &Recorder) -> bool {
    a.per
        .keys()
        .filter(|k| b.per.contains_key(k))
        .any(|k| a.per[k] != b.per[k])
}

// ---------------- H1: next_pc == pc+4 missing on non-HALT (sp1-v4 #6) ----------------
// cols: pc(0), next_pc(1), is_halt(2). Shared site 0 = pc chaining; correct adds
// the next_pc==pc+4 constraint (a MISSING constraint in the buggy AIR).
struct NextPc {
    buggy: bool,
}
impl<T> BaseAir<T> for NextPc {
    fn width(&self) -> usize {
        3
    }
}
impl<AB: AirBuilder> Air<AB> for NextPc {
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let (cur, nxt) = (m.current_slice(), m.next_slice());
        let (pc, next_pc, is_halt, npc) = (cur[0], cur[1], cur[2], nxt[0]);
        // site 0 (shared): pc chains: next.pc == cur.next_pc
        b.when_transition().assert_eq(npc, next_pc);
        if !self.buggy {
            // site 1 (correct only): if not halt, next_pc == pc + 4
            let four = AB::Expr::ONE + AB::Expr::ONE + AB::Expr::ONE + AB::Expr::ONE;
            let not_halt = AB::Expr::ONE - is_halt.into();
            b.when(not_halt).assert_eq(next_pc, pc.into() + four);
        }
    }
}

// ---------------- H2: value checked on only one limb (BNEINC class) ----------------
// cols: a0..a3 (0..3), e0..e3 (4..7). Shared site 0 = a0==e0; correct adds a1..a3.
struct OneLimb {
    buggy: bool,
}
impl<T> BaseAir<T> for OneLimb {
    fn width(&self) -> usize {
        8
    }
}
impl<AB: AirBuilder> Air<AB> for OneLimb {
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let cur = m.current_slice();
        let a = [cur[0], cur[1], cur[2], cur[3]];
        let e = [cur[4], cur[5], cur[6], cur[7]];
        b.assert_eq(a[0], e[0]); // site 0 (shared)
        if !self.buggy {
            b.assert_eq(a[1], e[1]); // sites 1..3 (correct only)
            b.assert_eq(a[2], e[2]);
            b.assert_eq(a[3], e[3]);
        }
    }
}

// ---------------- H3: constraint on the WRONG selector (is_memory class) ----------------
// cols: val(0), expected(1), flagA(2), flagB(3). Site 0 in both, different guard.
struct WrongSel {
    buggy: bool,
}
impl<T> BaseAir<T> for WrongSel {
    fn width(&self) -> usize {
        4
    }
}
impl<AB: AirBuilder> Air<AB> for WrongSel {
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let cur = m.current_slice();
        let (val, expected, flag_a, flag_b) = (cur[0], cur[1], cur[2], cur[3]);
        let guard = if self.buggy { flag_b } else { flag_a };
        b.when(guard).assert_eq(val, expected); // site 0
    }
}

// ---------------- H4: spurious guard, satisfied on valid traces ----------------
// cols: val(0), expected(1), is_real(2), extra(3). Site 0 in both; buggy adds a
// guard factor that is 1 on all valid rows (invisible to valid-trace coverage).
struct Spurious {
    buggy: bool,
}
impl<T> BaseAir<T> for Spurious {
    fn width(&self) -> usize {
        4
    }
}
impl<AB: AirBuilder> Air<AB> for Spurious {
    fn eval(&self, b: &mut AB) {
        let m = b.main();
        let cur = m.current_slice();
        let (val, expected, is_real, extra) = (cur[0], cur[1], cur[2], cur[3]);
        if self.buggy {
            b.when(is_real * extra).assert_eq(val, expected); // site 0 (extra=1 on valid)
        } else {
            b.when(is_real).assert_eq(val, expected); // site 0
        }
    }
}

fn report(id: &str, exploit_ok: bool, dist: bool, predicted_catch: bool) {
    let outcome = if dist { "CATCH" } else { "MISS" };
    let predicted = if predicted_catch { "CATCH" } else { "MISS" };
    let ok = if outcome == predicted { "as predicted" } else { "!! PREDICTION WRONG" };
    println!(
        "{id:<4} exploit_confirmed={exploit_ok:<5}  AIRCov={outcome:<5} (predicted {predicted})  {ok}"
    );
}

#[test]
fn aircov_heldout_validation() {
    println!("\n===== AIRCov held-out validation (frozen metric, pre-registered) =====");

    // ---- H1 ----
    let honest = mat(&[[0, 4, 0], [4, 8, 0], [8, 12, 0], [12, 16, 0]]);
    // forged: next_pc[1] = 999 (not pc+4); pc chain updated so only next_pc==pc+4 catches it.
    let forged = mat(&[[0, 4, 0], [4, 999, 0], [999, 1003, 0], [1003, 1007, 0]]);
    let e1 = check_all_constraints(&NextPc { buggy: true }, &forged, &[], None).is_ok()
        && !check_all_constraints(&NextPc { buggy: false }, &forged, &[], None).is_ok();
    let d1 = distinguishes(
        &collect_coverage(&NextPc { buggy: false }, &honest, &[]),
        &collect_coverage(&NextPc { buggy: true }, &honest, &[]),
    );
    report("H1", e1, d1, false);

    // ---- H2 ----
    let honest = mat(&[[1, 2, 3, 4, 1, 2, 3, 4]; 4]);
    let forged = mat(&[[1, 9, 9, 9, 1, 2, 3, 4]; 4]); // a1..a3 forged, a0 matches
    let e2 = check_all_constraints(&OneLimb { buggy: true }, &forged, &[], None).is_ok()
        && !check_all_constraints(&OneLimb { buggy: false }, &forged, &[], None).is_ok();
    let d2 = distinguishes(
        &collect_coverage(&OneLimb { buggy: false }, &honest, &[]),
        &collect_coverage(&OneLimb { buggy: true }, &honest, &[]),
    );
    report("H2", e2, d2, false);

    // ---- H3 ---- flagA on even rows, flagB on odd rows; val==expected on valid.
    let honest = mat(&[[5, 5, 1, 0], [5, 5, 0, 1], [5, 5, 1, 0], [5, 5, 0, 1]]);
    // forged: corrupt val on row0 (a flagA row). Correct(flagA) catches; buggy(flagB) misses row0.
    let forged = mat(&[[7, 5, 1, 0], [5, 5, 0, 1], [5, 5, 1, 0], [5, 5, 0, 1]]);
    let e3 = check_all_constraints(&WrongSel { buggy: true }, &forged, &[], None).is_ok()
        && !check_all_constraints(&WrongSel { buggy: false }, &forged, &[], None).is_ok();
    let d3 = distinguishes(
        &collect_coverage(&WrongSel { buggy: false }, &honest, &[]),
        &collect_coverage(&WrongSel { buggy: true }, &honest, &[]),
    );
    report("H3", e3, d3, true);

    // ---- H4 ---- is_real=1, extra=1 on all valid rows; val==expected.
    let honest = mat(&[[5, 5, 1, 1]; 4]);
    // forged: row1 sets extra=0 and val!=expected. buggy guard is_real*extra=0 -> skipped.
    let forged = mat(&[[5, 5, 1, 1], [7, 5, 1, 0], [5, 5, 1, 1], [5, 5, 1, 1]]);
    let e4 = check_all_constraints(&Spurious { buggy: true }, &forged, &[], None).is_ok()
        && !check_all_constraints(&Spurious { buggy: false }, &forged, &[], None).is_ok();
    let d4 = distinguishes(
        &collect_coverage(&Spurious { buggy: false }, &honest, &[]),
        &collect_coverage(&Spurious { buggy: true }, &honest, &[]),
    );
    report("H4", e4, d4, false);

    println!("\n(exploit_confirmed=true means: buggy AIR accepted a forged trace the correct AIR rejected.)");

    // All four exploits must be real, and every prediction must hold.
    assert!(e1 && e2 && e3 && e4, "every reconstructed bug must be a real exploitable vulnerability");
    assert!(!d1, "H1 predicted MISS");
    assert!(!d2, "H2 predicted MISS");
    assert!(d3, "H3 predicted CATCH");
    assert!(!d4, "H4 predicted MISS");
}
