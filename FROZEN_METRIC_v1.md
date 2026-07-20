# AIRCov metric v1 — FROZEN + pre-registered predictions (2026-07-19)

Written BEFORE reconstructing/running the held-out bugs, to defeat the circularity
objection (the metric was extended while looking at a row-position bug). The metric
below is frozen; I do not add dimensions to catch the held-out cases.

## Frozen metric (per constraint site, computed on a VALID trace)
- `active_rows`, `inactive_rows` (guard nonzero / zero counts)
- `active_zero`, `active_nonzero` (term held / would-violate under active guard)
- `min_active_row`, `max_active_row` -> `active_on_first`, `active_on_last(height)`
- derived: `ever_active`, `both_states`

## Frozen detection criterion (objective, no "should" oracle)
`AIRCov distinguishes(bug) := the frozen per-site metric vector, computed on a
valid trace, differs between the CORRECT and BUGGY AIR for at least one constraint
site present in BOTH.`
This is a proxy for "AIRCov's coverage report could have revealed the bug." Its
key, honest limitation (stated up front): it can only catch guard bugs whose
activation profile differs ON A VALID TRACE. A bug that only diverges on malicious
inputs is invisible to any coverage measured on valid traces, AIRCov included.

## Pre-registered predictions (committed before running)
| id | real SP1 bug | class | prediction |
|----|--------------|-------|-----------|
| REF | exp_reverse_bits is_last vs is_first (rkm0959 #11) | wrong row-guard | CATCH (already shown) |
| H1 | next_pc == pc+4 missing on non-HALT ECALL (sp1-v4 #6) | MISSING constraint | **MISS** |
| H2 | value check on only one limb (BNEINC class) | narrow EXPRESSION | **MISS** |
| H3 | constraint on the WRONG selector (is_memory/opcode class) | wrong selector, valid-trace-visible | **CATCH** |
| H4 | spurious extra guard that is satisfied on valid traces | guard bug, valid-trace-INVISIBLE | **MISS** |

## What each outcome means
- H1/H2 MISS as predicted -> AIRCov's scope excludes missing + narrow-expression bugs (a precise, honest boundary; these need different tools).
- H3 CATCH as predicted, on a DIFFERENT mechanism than REF -> evidence the frozen metric generalizes beyond the bug it was shaped on (the anti-circularity win).
- H4 MISS as predicted -> demonstrates the fundamental limit: coverage on valid traces cannot catch guard bugs invisible on valid traces.
- Any prediction WRONG -> update honestly; a wrong CATCH-prediction that misses is a partial kill signal.

## RESULTS (ran 2026-07-19, after freezing above)
`air/tests/aircov_heldout.rs`, all predictions held:
| id | exploit real? | AIRCov | predicted | |
|----|----|----|----|----|
| H1 next_pc missing | yes | MISS | MISS | ok |
| H2 one-limb narrow | yes | MISS | MISS | ok |
| H3 wrong selector  | yes | CATCH | CATCH | ok |
| H4 spurious guard  | yes | MISS | MISS | ok |

Interpretation:
- ANTI-CIRCULARITY WIN: H3 is a CATCH on a DIFFERENT mechanism (wrong selector) than the bug the metric was shaped on (exp_reverse_bits row-guard). The frozen metric generalized to a held-out bug it was not designed around -> the circularity objection is answered for at least this case.
- HONEST SCOPE (the misses are the finding): AIRCov catches ONLY guard/selector bugs whose activation profile differs on a VALID trace. It does NOT catch: missing constraints (H1), narrow-expression bugs (H2), or guard bugs invisible on valid traces (H4). 3 of 4 classes missed.
- Survives the advisor kill criterion (adds held-out signal line/opcode coverage cannot see), but the honest paper claim is MODEST and scope-bounded: a cheap semantic-coverage metric for one specific, currently-unmeasured bug class, with a precisely characterized boundary.

## Citation note (added 2026-07-20; does not alter the frozen metric or the predictions above)
The REF row labels the real-world anchor as `exp_reverse_bits is_last vs is_first (rkm0959 #11)`. The verified public record is the KALOS audit of SP1 by rkm0959, which documents row-guard soundness findings of exactly this wrong first/last row class (see `audits/kalos.md` in `succinctlabs/sp1`). The exact chip name and issue number in the REF label are not independently confirmed here and should be read as the bug class rather than a pinned issue identifier. REF is not one of the four scored held-out predictions (H1 through H4), so this note changes none of the validation results.
