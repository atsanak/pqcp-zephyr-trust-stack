# Sovereign audit export

`CONFIG_PQCP_SOVEREIGN_RUNTIME` provides allocation-free adapters from nine
source types into a tenant-scoped, hash-chained event ledger:

- crypto broker receipts and fleet journal entries;
- edge incidents, deployment rollouts and key ceremonies;
- privacy budgets, erasure records, recovery approvals and continuity exercises.

The cursor exporter projects that ledger into CBOR, CEF/syslog or OCSF JSON.
It can sign each batch using an opaque ML-DSA key-store handle. These are
experimental interfaces in `include/pqcp_zephyr/sovereign_audit.h`.

## Source boundary and identities

The caller supplies a stable source snapshot and authenticates its origin and
tenant ownership. Several source records carry no tenant. The adapters do not
infer that ownership from a caller-supplied tenant string. Fleet entries undergo
their existing entry-digest check; broker receipt signature verification still
requires the broker context. A source claiming to contain a signature never
automatically gains the `SIGNED_SOURCE` audit flag.

Adapters reject malformed schemas, unterminated text, invalid time ordering and
contradictory terminal states, leaving the output unchanged on error. They
preserve source evidence digests and project state-specific attributes. An
expired recovery approval reads as expired; an active retention record reads as
pending erasure. A controller-completed rollout can include failed targets:
its success, failure and unavailable counts remain explicit attributes.

For adapters with separate source and ingestion timestamps, re-ingestion of the
same projection preserves its event ID. The identity commits the normalized
projection, including tenant, realm, source bindings and attributes, with
ingestion time normalized to observation time. Privacy/recovery/continuity APIs
take an observation time: a new observation is a new event. IDs identify
observations; the ledger does not enforce duplicate suppression.

## Delivery protocol

1. Initialize a ledger and exporter with caller-owned storage and, optionally,
   an ML-DSA signing key. Authorize the consumer and tenant in the calling layer.
2. Open a cursor with a policy epoch and expiry. Sequence zero selects the oldest
   retained event. An evicted starting sequence returns `-ESTALE`.
3. Prepare a batch with the same tenant and policy epoch. Filters cover realm,
   event class, activity, severity, classification and required/forbidden flags.
4. Persist or transmit the encoded bytes. Repeating prepare with the same policy
   returns the same bytes, source snapshot, digest and signature. A changed retry
   policy returns `-ESTALE`.
5. Acknowledge the exact first/last sequence and batch digest. A forged range or
   digest cannot advance the cursor. Successful acknowledgement advances through
   the scanned range, chains the next batch and clears the frozen workspace.

Multiple cursors may be open, but one outstanding batch owns the shared workspace.
A different cursor receives `-EBUSY` until acknowledgement, close or expiry.
No matches returns `-ENOENT` without advancing the cursor. `batch.events` is
read-only and expires with the outstanding batch. Caller-owned buffers must not
alias exporter storage or output arguments.

## Commitments and redaction

The batch commitment is:

```text
SHA256("PQCP-SOVEREIGN-AUDIT-BATCH-V1" || canonical_CBOR_batch_body)
```

The body includes source anchor/head, previous batch digest, scanned range,
tenant, policy epoch, format, redaction mode, ordered receipt commitment and
projected events. All output formats use that same CBOR commitment. ML-DSA signs
the commitment with context `pqcp-sovereign-audit-batch-v1`.

Redacted events retain their original source event digest. Their changed fields
are authenticated by the batch commitment/signature; calling the original
event verifier on a changed projection cannot validate that source commitment.
The exporter also checks a process-local frozen-state hash before retries,
acknowledgement and exporter audits. That memory hash is not a wire format.

## Tested behavior and limits

`tests/ztest_sovereign_audit` covers all nine adapters, event identities, malformed
snapshots, real ML-DSA signatures, frozen retries, tenant filtering, expiry,
redaction, source-history eviction, buffer failures and tampering. The integration
case exports all nine sources as three linked signed batches and detects source
corruption on the next scan while preserving an already frozen retransmission.

State is volatile. This work does not provide reboot persistence, a remote
collector, authorization of callers, source-signature verification for every
source type, or an independent parser/verifier for exported batch bytes.
`complete` and `resumed` are local delivery metadata, not authenticated body fields.
Persisted cursor checkpoints and an independent collector verifier are the next
hardware-free steps toward crash-safe evidence delivery.
