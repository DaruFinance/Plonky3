//! AIRCov: semantic test-adequacy coverage for AIR constraint evaluation.
//!
//! Records, per constraint site (identified by the `DebugConstraintBuilder`'s
//! `constraint_index`) and across all rows of a concrete trace, whether the
//! constraint's *guard* was actually active (nonzero) and whether the guarded
//! term held. The point: a `FilteredAirBuilder` disables a constraint
//! *algebraically* (multiplies it by its guard), so an inactive guard makes the
//! Rust `assert_zero` statement run while enforcing nothing. Line coverage
//! saturates; this records whether the constraint was ever semantically active.
//!
//! Feature-gated behind `aircov` (pulls in `std` for a thread-local recorder).
//! When disabled, the hooks are no-ops, so normal builders pay nothing.

#[cfg(feature = "aircov")]
mod imp {
    extern crate std;

    use alloc::collections::BTreeMap;
    use core::cell::RefCell;

    /// Per-constraint-site coverage tallies, aggregated over all trace rows.
    #[derive(Default, Clone, Debug, PartialEq, Eq)]
    pub struct ConstraintCov {
        /// Rows where the guard was nonzero (constraint actually enforced).
        pub active_rows: usize,
        /// Rows where the guard was zero (constraint algebraically disabled).
        pub inactive_rows: usize,
        /// Active rows where the guarded term evaluated to zero (constraint held).
        pub active_zero: usize,
        /// Active rows where the guarded term was nonzero (would-be violation).
        pub active_nonzero: usize,
        /// Lowest row index on which the guard was active (activation profile).
        pub min_active_row: Option<usize>,
        /// Highest row index on which the guard was active (activation profile).
        pub max_active_row: Option<usize>,
    }

    impl ConstraintCov {
        /// Guard was nonzero on at least one row (constraint ever enforced).
        pub const fn ever_active(&self) -> bool {
            self.active_rows > 0
        }
        /// Guard took BOTH zero and nonzero values across the trace
        /// (selector/guard exercised in both states).
        pub const fn both_states(&self) -> bool {
            self.active_rows > 0 && self.inactive_rows > 0
        }
        /// Whether the constraint was enforced on the first row (row 0).
        pub fn active_on_first(&self) -> bool {
            self.min_active_row == Some(0)
        }
        /// Whether the constraint was enforced on the last row of a
        /// `height`-row trace.
        pub fn active_on_last(&self, height: usize) -> bool {
            self.max_active_row == Some(height.saturating_sub(1))
        }
    }

    /// Coverage accumulator for one `collect_coverage` pass.
    #[derive(Default, Debug)]
    pub struct Recorder {
        /// constraint_index -> tallies.
        pub per: BTreeMap<usize, ConstraintCov>,
        /// Guard-active flag stashed by `note_guard` for the next assertion.
        pending: Option<bool>,
    }

    std::thread_local! {
        static REC: RefCell<Option<Recorder>> = const { RefCell::new(None) };
    }

    /// Start a fresh coverage recording session.
    pub fn begin() {
        REC.with(|r| *r.borrow_mut() = Some(Recorder::default()));
    }

    /// Stash the guard activity applying to the next asserted constraint.
    pub fn note_guard(active: bool) {
        REC.with(|r| {
            if let Some(rec) = r.borrow_mut().as_mut() {
                rec.pending = Some(active);
            }
        });
    }

    /// Record one asserted constraint on one row. `term_zero` is whether the
    /// (post-guard) asserted expression evaluated to zero. An unguarded
    /// constraint (no preceding `note_guard`) is treated as always-active.
    pub fn on_assert(cid: usize, row: usize, term_zero: bool) {
        REC.with(|r| {
            if let Some(rec) = r.borrow_mut().as_mut() {
                let active = rec.pending.take().unwrap_or(true);
                let e = rec.per.entry(cid).or_default();
                if active {
                    e.active_rows += 1;
                    if term_zero {
                        e.active_zero += 1;
                    } else {
                        e.active_nonzero += 1;
                    }
                    e.min_active_row = Some(e.min_active_row.map_or(row, |m| m.min(row)));
                    e.max_active_row = Some(e.max_active_row.map_or(row, |m| m.max(row)));
                } else {
                    e.inactive_rows += 1;
                }
            }
        });
    }

    /// End the session and return the accumulated coverage.
    pub fn take() -> Option<Recorder> {
        REC.with(|r| r.borrow_mut().take())
    }
}

#[cfg(feature = "aircov")]
pub use imp::*;

#[cfg(not(feature = "aircov"))]
mod imp {
    #[inline(always)]
    pub fn note_guard(_active: bool) {}
    #[inline(always)]
    pub fn on_assert(_cid: usize, _row: usize, _term_zero: bool) {}
}

#[cfg(not(feature = "aircov"))]
pub use imp::*;
