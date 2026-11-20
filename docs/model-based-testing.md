# Model-based testing of the edge state machines

`tests/ztest_edge_model` drives seeded pseudo-random operation traces
(up to 64 ops, 64 seeds per module) through an abstract model and the real
module in lock step. Every op returns a violation code and is followed by
the module's own `*_audit()`, giving two oracles per step (code 1 = audit
failed, >= 2 = model property violated).

| Module | Model | Properties |
|--------|-------|-----------|
| principal | revoked set + quarantine deadlines | quarantine is sticky across re-register, tick and expiry |
| session | ledger of opens/closes per principal | quota and slot accounting, double close, first id 1 |
| credential | set of revoked ids | revocation terminal, tombstones never recycled |
| policy | epoch history + staged bundles | stale promote refused, epoch changes only via promote/rollback, ids sequential |

## Markers (contract with `scripts/run_model_checks.py`)

    PQCP_MODEL_CHECK module=<m> seeds=<n> ops=<n> violations=<n> status=PASS|FAIL
    PQCP_MODEL_COUNTEREXAMPLE module=<m> seed=<hex16> violation=<code> ops=<n> trace=<hex>
    PQCP_MODEL_SUMMARY modules=4 traces=<n> ops=<n> violations=0 status=PASS

A counterexample trace is ddmin-shrunk (1-minimal) and hex encoded, 7 bytes
per op (kind, a, b, dt little-endian u32). Replay any counterexample as a
hand-written ztest before treating it as a firmware defect.

## Historical-defect rediscovery

`python3 scripts/run_model_checks.py --rediscover` copies the sources,
re-introduces each of ten fixed defects (H1-H10) one at a time, builds,
runs the models and requires a counterexample for the expected module.
Outcomes: rediscovered, missed, STALE (pattern no longer matches once) or
ERROR. First measurement was 6/10; strengthening the models (tombstone
capacity, real acknowledgements, id sequence, real revocation epochs)
brought it to 10/10, which shows why the score is worth measuring.
