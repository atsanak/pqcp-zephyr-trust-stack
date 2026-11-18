# Transparent appraisal receipts: wire and file formats

Byte-level contract shared by the C implementation
(`tools/evidence_verifier/src/receipt_*.c`, `tools/evidence_register`) and the
independent Python RFC 9162 reference verifier (`scripts/rfc9162_reference.py`).
Everything here is fixed; either side that disagrees is wrong.

## 1. CBOR profile

Deterministic CBOR (RFC 8949 section 4.2.1), restricted subset:

* Only definite-length items. Major types used: 0 (uint), 2 (byte string),
  3 (text string, UTF-8, ASCII in practice), 4 (array), 5 (map), and the
  simple values `false` (0xf4), `true` (0xf5), `null` (0xf6).
* No negative integers, tags, floats, indefinite lengths, or other simple values.
* Integers use the shortest head form (an argument below 24 is one byte;
  `0x18 nn` for 24..255; `0x19` for up to 65535; `0x1a` for up to 2^32-1;
  `0x1b` otherwise). A head that is not shortest is rejected as non-canonical.
* Maps use unsigned-integer keys in strictly ascending numeric order. No
  duplicate keys, no unknown keys, all listed keys mandatory. Map values are
  decoded in the order the schema lists them.
* A decoded file must consume all of its bytes: trailing bytes are rejected.
* Truncation anywhere is rejected.

## 2. Hashes

* `H` = SHA-256 (FIPS 180-4).
* Leaf hash = `H(0x00 || statement_bytes)`.
* Node hash = `H(0x01 || left || right)`.
* Empty tree root = `H("")`.
* Merkle tree hash, inclusion proof and consistency proof follow RFC 9162
  sections 2.1.1, 2.1.3 and 2.1.4 exactly. Split point for `n` leaves is the
  largest power of two strictly less than `n`. Proof node arrays are ordered
  from the leaf level toward the root (RFC 9162 `PATH` / `PROOF` order).
* Consistency proof for `old_size == new_size` has zero nodes and requires equal
  roots. Consistency proof for `old_size == 0` has zero nodes and requires the
  old root to be `H("")`.

## 3. Statement (the exact bytes are the log leaf)

CBOR map with 8 entries, keys 1..8 in ascending order. Leading byte is
`0xa8`. Byte strings are exactly 32 bytes unless stated.

| key | type | meaning |
|----:|------|---------|
| 1 | text | the literal `"pqcp-appraisal/1"` |
| 2 | text, 64 lowercase hex chars, or empty text `""` | passport digest from the replay; `""` when the passport layer did not replay |
| 3 | bstr(32) or `null` | `SHA-256(device ML-DSA-65 public key, 1952 bytes)`; `null` when the transcript carries no complete device signature |
| 4 | text, 64 lowercase hex chars, or empty text `""` | evidence trail head digest; `""` when the transcript has no trail |
| 5 | text | verdict, exactly `"CHAIN OK"` or `"REJECT"` |
| 6 | bstr(32) | SHA-256 of the verifier binary that produced the appraisal |
| 7 | bool | `signature_verified` (device passport signature verified) |
| 8 | bstr(32) | SHA-256 of the raw transcript file bytes |

Example prefix: `a8 01 70 "pqcp-appraisal/1" 02 78 40 <64 hex> 03 58 20 <32> ...`
(a `null` key-3 value encodes as `03 f6`; verdict encodes as `05 68 "CHAIN OK"`
or `05 66 "REJECT"`).

## 4. Checkpoint

Mirrors `struct pqcp_fleet_transparency_checkpoint`. CBOR map with 9 entries,
keys 1..9 ascending (leading byte `0xa9`):

| key | type | field |
|----:|------|-------|
| 1 | uint | `schema_version` (must be 1) |
| 2 | uint | `tree_size` |
| 3 | uint | `timestamp_ms` |
| 4 | uint | `sequence` (must be non-zero, strictly increasing per log) |
| 5 | bstr(32) | `log_id` = `SHA-256(log public key)` |
| 6 | bstr(32) | `root` (Merkle root at `tree_size`) |
| 7 | bstr(32) | `signer_key_id` = `SHA-256(log public key)` (equal to `log_id`) |
| 8 | bstr(32) | `transcript_digest` = `SHA-256(signed_bytes)` |
| 9 | bstr(3309) | ML-DSA-65 signature over `signed_bytes` |

### Signed bytes (161 bytes, concatenated, no separators)

```
"PQCP-FLEET-TRANSPARENCY-CHECKPOINT-V1"   37 bytes ASCII, no NUL
schema_version                             4 bytes big-endian
log_id                                    32 bytes
tree_size                                  8 bytes big-endian
root                                      32 bytes
timestamp_ms                               8 bytes big-endian
sequence                                   8 bytes big-endian
signer_key_id                             32 bytes
```

Signature: pure ML-DSA-65 (FIPS 204 `ML-DSA.Sign`, context string
`"PQCP-APPRAISAL-LOG-V1"`, 21 bytes) over `signed_bytes`; the fixtures use the
deterministic variant (`rnd` = 32 zero bytes), so a given seed, tree and
`(timestamp_ms, sequence)` always yields the same file. The public key is the
raw 1952-byte ML-DSA-65 key (`--log-pk` file, `log.pk`). The Python reference
verifier cannot check ML-DSA; it checks structure, `transcript_digest`, and the
Merkle math only. Signature verification is the C verifier's job.

## 5. Receipt (`*.receipt.cbor`)

CBOR map, 5 entries (`0xa5`):

| key | type | meaning |
|----:|------|---------|
| 1 | bstr | the exact statement bytes (section 3) |
| 2 | uint | `leaf_index` |
| 3 | uint | `tree_size` the proof is against |
| 4 | array of bstr(32) | inclusion path nodes, leaf to root, at most 65 |
| 5 | map | checkpoint (section 4) the proof must verify against |

Receipt invariants checked by the verifiers: checkpoint signature and
`log_id`/`signer_key_id` bind to the pinned log key (C only); `receipt.tree_size
== checkpoint.tree_size`; the root recomputed from
`H(0x00 || statement) + path` equals `checkpoint.root`.

## 6. Consistency file (`*.consistency.cbor`)

CBOR map, 5 entries (`0xa5`):

| key | type | meaning |
|----:|------|---------|
| 1 | uint | `old_size` |
| 2 | uint | `new_size` |
| 3 | array of bstr(32) | consistency proof nodes (RFC 9162 `PROOF`), at most 65 |
| 4 | map | old checkpoint (section 4) |
| 5 | map | new checkpoint (section 4) |

`old_size` must equal `old_ckpt.tree_size` and `new_size` must equal
`new_ckpt.tree_size`. The proof's old and new roots are taken from the two
checkpoints, never from separate fields.

Verifier decision order and reason tokens (C verifier output
`PQCP_APPRAISAL_CONSISTENCY REJECT reason=<token>`):

1. `malformed` (decode failure, non-canonical, trailing bytes, size field mismatch)
2. `log_id_mismatch`: a checkpoint's `log_id` or `signer_key_id` is not `SHA-256(--log-pk)`
3. `bad_signature` (either checkpoint: transcript digest or ML-DSA signature fails)
4. `equivocation`: same `tree_size` with different `root`, or same `sequence` with a different `(tree_size, root)`. Both signatures were valid; this pair is proof of a forked log.
5. `rollback`: `new.sequence <= old.sequence` or `new.tree_size < old.tree_size`
6. `consistency_proof_invalid`

## 7. On-disk log directory (`pqcp-evidence-register --log-dir D`)

| file | layout |
|------|--------|
| `D/log.leaves` | concatenation of 32-byte leaf hashes (`H(0x00 \|\| statement)`), index order, no header |
| `D/log.statements` | for each entry in index order: 4-byte big-endian length, then the statement bytes |

On every command the tool re-reads both files, checks that entry count matches
and that every leaf equals `H(0x00 || statement)`, restores the log with
`pqcp_fleet_transparency_log_restore` and runs `pqcp_fleet_transparency_log_verify`
before any append. A missing directory is an empty log. Keys: `log.pk` (raw
1952 bytes) and the 32-byte raw seed file are supplied by option, not stored in `D`.

## 8. Tool surface (for fixture generation)

```
pqcp-evidence-register keygen --seed-file S --pk-out P
pqcp-evidence-register register --log-dir D --log-pk P --statement STMT.cbor [--raw]
pqcp-evidence-register checkpoint --log-dir D --seed-file S --sequence N [--timestamp-ms T] [--tree-size K] --out CKPT.cbor
pqcp-evidence-register receipt --log-dir D --checkpoint CKPT.cbor --leaf-index I --out R.cbor [--allow-mismatch]
pqcp-evidence-register prove-consistency --log-dir D --old-checkpoint OLD.cbor --new-checkpoint NEW.cbor --out C.cbor [--allow-mismatch]
pqcp-evidence-register sign-file --seed-file S --in F --out SIG
pqcp-evidence-register verify-file --pk P --in F --sig SIG
pqcp-evidence-verify --emit-statement STMT.cbor [--verifier-bin B] transcript.log
pqcp-evidence-verify --receipt R.cbor --log-pk P [--verifier-bin B] transcript.log
pqcp-evidence-verify --consistency C.cbor --log-pk P
```

`sign-file` / `verify-file` are not part of the log: they sign arbitrary file
bytes (kit provenance, `docs/kit-provenance.md`) with deterministic ML-DSA-65
under the separate context `PQCP-KIT-PROVENANCE-V1`; the raw signature file is
3309 bytes. The checkpoint context above is never accepted by `verify-file`.

Seed files are exactly 32 raw bytes; no tool in this chain ever reads
randomness. Statements for REJECT verdicts are emitted too (the verifier exits 1
for CHAIN BROKEN but still writes the statement when `--emit-statement` is given).

`register` rejects bytes that do not decode as a statement unless `--raw` is
given (fixtures for malformed-statement tests). `receipt` and
`prove-consistency` refuse a checkpoint whose root does not match the log unless
`--allow-mismatch` is given (fixtures: equivocation, rewritten history, wrong
checkpoint). `register` needs `--log-pk` only to derive `log_id`.

## 9. Verifier output markers and reasons

All on stdout, one line each. Exit 0 only on PASS; 1 on REJECT; 2 on usage or
I/O error (unreadable file, missing `--log-pk`).

```
PQCP_APPRAISAL_STATEMENT written verdict=<CHAIN OK|REJECT>          (--emit-statement; exit = chain verdict)
PQCP_APPRAISAL_RECEIPT PASS leaf_index=N tree_size=M verdict=V log_id=<hex>
PQCP_APPRAISAL_RECEIPT REJECT reason=<token>
PQCP_APPRAISAL_CONSISTENCY PASS consistency=ok old_size=N new_size=M
PQCP_APPRAISAL_CONSISTENCY REJECT reason=<token>
```

Receipt reason tokens, in decision order: `log_pk_malformed`, `malformed`,
`log_id_mismatch`, `bad_signature`, `tree_size_mismatch`,
`inclusion_proof_invalid`, `statement_malformed`, `verifier_hash_mismatch`
(only with `--verifier-bin`), `passport_digest_mismatch`, `trail_head_mismatch`,
`transcript_hash_mismatch`, `device_pk_mismatch`, `signature_flag_mismatch`,
`verdict_mismatch`. The last six compare the receipt's statement with a fresh
replay of the transcript argument. A receipt for a `REJECT` statement passes if
the fresh replay also rejects; the chain verdict is the `verdict=` field.
Consistency reason tokens are listed in section 6, plus `log_pk_malformed`.

`--verifier-bin B` (emit) records `SHA-256(B)` as statement key 6; it defaults to
`argv[0]`. With `--receipt` it is opt-in and compared to key 6. Transcript hash
is over the raw file bytes; the replay flags (`--lenient`, `--require-signature`)
must match between emit and receipt time or `verdict_mismatch` can result.
