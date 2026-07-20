# AIRCov: semantic activation coverage for AIR constraints

This branch adds a small coverage instrument to the `p3-air` crate. It measures
something ordinary line coverage cannot see: whether each guarded AIR constraint
was actually enforced by a trace, and on which rows.

## The problem

A constraint that should apply only under a condition is written as a guarded
assertion:

```rust
builder.when(guard).assert_eq(a, b);
```

The framework does not skip a disabled constraint. It disables it algebraically,
by multiplying the expression by the guard (see `FilteredAirBuilder::assert_zero`):

```rust
self.inner.assert_zero(self.condition() * x);
```

When `guard == 0` on a row, the whole term is zero and the constraint is trivially
satisfied, yet the Rust statement still executed. A line coverage tool reports that
constraint as covered even on a trace where it was never once enforced. A class of
soundness bugs, a constraint attached to the wrong guard or the wrong selector,
lives exactly in that gap: it runs, it shows green, and it constrains nothing on
the rows that matter.

## What this adds

`air/src/aircov.rs` is a thread-local recorder. It is fed by one hook in
`FilteredAirBuilder::assert_zero` (which owns the guard multiply) and by the
concrete-trace `DebugConstraintBuilder`. For each constraint site it records, over
a valid trace:

- `active_rows` / `inactive_rows`: rows where the guard was nonzero vs zero
- `active_zero` / `active_nonzero`: under an active guard, whether the term held
- `min_active_row` / `max_active_row`: the row-position activation profile, giving
  `active_on_first`, `active_on_last`, `ever_active`, `both_states`

The recorder is gated behind the `aircov` Cargo feature and is inert unless a
recording session is open, so ordinary builds pay nothing.

One finding worth stating: a naive `ever_active` boolean does not catch the real
bugs. The signal is in which rows activate, not whether any did. The activation
profile is the metric.

## Tests

Run with the feature on, for example:

```
cargo test -p p3-air --features aircov --test aircov_fib -- --nocapture
```

- `aircov_fib`: a degenerate one-row trace leaves transition constraints never
  enforced while line coverage of `eval` is still 100 percent.
- `aircov_exploit`: a mis-guarded recurrence lets a forged trace claim `fib(8) = 999`
  and be accepted with zero constraint failures; the correct AIR rejects it.
- `aircov_sp1_expbits`: a faithful reconstruction of a documented audit finding
  (SP1 `exp_reverse_bits`, guard `is_last` where it should be `is_first`). The
  honest test passes under both the correct and the buggy guard, so the suite does
  not kill the mutant, which is why such bugs ship. The forged final result is
  accepted by the buggy AIR and rejected by the correct one.
- `aircov_heldout`: the metric is frozen and predictions are registered in advance,
  then four real bug classes are tested. Results held on all four:

  | class | exploitable | AIRCov | predicted |
  |---|---|---|---|
  | missing constraint (`next_pc == pc + 4`) | yes | miss | miss |
  | narrow expression (one limb checked) | yes | miss | miss |
  | wrong selector | yes | catch | catch |
  | spurious guard satisfied on valid traces | yes | miss | miss |

## Scope

This catches only guard and selector bugs whose activation profile differs on a
valid trace. It does not catch missing constraints (no site to measure),
narrow-expression bugs (same site, same guard, same activation), or guard bugs that
honest data happens to satisfy (invisible to any coverage measured on valid
traces). It surfaces a fingerprint that a reviewer then interprets; it does not
emit a verdict. The boundary is characterized rather than glossed.
