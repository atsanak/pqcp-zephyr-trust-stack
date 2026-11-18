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

## Durable host collection

Build the host signature verifier with CMake, then submit the raw signed CBOR
batch. Provision the public key and stream pins from a trusted source.

```sh
cmake -S tools/evidence_verifier -B build-host-verifier
cmake --build build-host-verifier --target pqcp-sovereign-signature-verify
python3 scripts/sovereign_audit_collect.py \
  --database collector.db --stream-id deployment-7 \
  --tenant tenant-a --cursor 1 --policy-epoch 7 --first-sequence 1 \
  --public-key public-key.bin \
  --verifier ./build-host-verifier/pqcp-sovereign-signature-verify batch.cbor
```

The collector independently parses canonical CBOR, recomputes the commitment
from the wire bytes, verifies ML-DSA-65 with the pinned key, and checks the
previous digest and sequence high-water mark. One SQLite transaction stores
both the complete wire batch and the stream checkpoint. Standard output carries
the sender's exact acknowledgement fields (`first_sequence`, `last_sequence`,
and `batch_digest`) only after the transaction commits. If the process exits
after commit but before the sender receives the acknowledgement, submitting the
same latest batch returns the same acknowledgement. Older replays and forks
are rejected.

`--first-sequence` is a floor. Filtering permits gaps, and the wire commits to
the scanned-through sequence but carries no scan-start field. A successful
receipt therefore authenticates the transmitted projection and its order in the
stream. Source completeness requires separate evidence. Retain the trusted
SQLite database across restarts. Rollback of the database itself requires an
external checkpoint or anchor.

## Tested behavior and limits

`tests/ztest_sovereign_audit` covers all nine adapters, event identities, malformed
snapshots, real ML-DSA signatures, frozen retries, tenant filtering, expiry,
redaction, source-history eviction, buffer failures and tampering. The integration
case exports all nine sources as three linked signed batches and detects source
corruption on the next scan while preserving an already frozen retransmission.

## Firmware checkpoint recovery

Restore the source ledger and signing key first. Initialize the exporter, then
call `pqcp_sovereign_audit_exporter_recover` before opening cursors. A pair of
empty slots returns `-ENOENT` and binds the store for the first save. Allocate
one scratch buffer and two independent durable slots, each sized by
`pqcp_sovereign_audit_exporter_checkpoint_capacity`. Give the store a stable
binding for the firmware image and stream/key identity.

Save after opening a cursor before advertising its ID. After prepare, save
before handing the bytes to transport. After acknowledge, close, or expiry,
save before acting on the new state. If a save fails, retry it before proceeding
or restart and recover the last committed state. Serialize these operations
at the application layer. Store callbacks must report success only after the
write is durable and must preserve the other slot through an interrupted write.

Recovery selects the newest intact slot and refuses a rollback below the
caller-provided generation floor. It rejects an older source ledger or a
different source head at the same retained position. Keep the signing key and
time basis stable across reboot. Slots contain sensitive projected events and
use an image-local format with a corruption checksum. Trust the storage and
protect access to it. An independent generation floor is needed to detect
rollback of both slots. If an older source head has already been evicted, the
restored ledger's continuity relies on the source storage.

## Verification

The host regression consumes three signed batches and the temporary signing
key's public half captured from the QEMU cross-plane test at `55e01b2`. It
terminates the collector mid-transaction and checks that restart recovers the
previous receipt. It also resubmits a committed batch to simulate a lost
acknowledgement and rejects a subsequently altered journal head.

QEMU tests simulate a torn checkpoint write and a restart with new exporter
RAM. The restored batch retains its original ML-DSA signature and identical
wire bytes, even after the original events leave the ledger. Board integration
provides the durable slot callbacks and protects the source ledger. Caller
authorization and source authentication remain application responsibilities.
`complete` and `resumed` are local delivery metadata outside the authenticated
body.
