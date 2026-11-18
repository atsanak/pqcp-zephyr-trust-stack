# Evidence-verifier kit provenance and signature

`scripts/package_evidence_verifier.py` writes two sidecars next to the kit
tarball. They reuse the transparent-appraisal machinery
(`pqcp-evidence-register`, ML-DSA-65 via mldsa-native, deterministic seed-file
signing, no randomness) rather than adding a second signing stack.

```
pqcp-evidence-verifier-<ver>-<os>-<arch>.tar.gz
pqcp-evidence-verifier-<ver>-<os>-<arch>.tar.gz.sha256
pqcp-evidence-verifier-<ver>-<os>-<arch>.tar.gz.provenance.json
pqcp-evidence-verifier-<ver>-<os>-<arch>.tar.gz.provenance.sig.json   (only when signed)
```

## provenance.json (schema 1)

Canonical JSON (sorted keys, no insignificant whitespace, ASCII, one trailing
newline). The file's exact bytes are what is signed. Fields:

| field | meaning |
|-------|---------|
| `schema_version`, `kind` | `1`, `pqcp-evidence-verifier-kit-provenance` |
| `kit` | `name`, `sha256`, `size_bytes` of the tarball |
| `source` | `version` (version.h), `git_commit`, `git_dirty` (tracked files only; untracked files are ignored), `tag` (exact tag at HEAD or `null`) |
| `builder` | `system`, `release`, `machine`, `compiler` (first line of `cc --version` of the CMake C compiler), `cmake` |
| `source_date_epoch` | `SOURCE_DATE_EPOCH` if set, else the HEAD commit time; also used as every tar mtime |
| `timestamp_utc` | `source_date_epoch` rendered as ISO 8601 UTC |
| `files` | SHA-256 of every file in the kit (binaries, scripts, docs, examples) |
| `claims` | assurance claim ids the kit supports (checked to exist in `scripts/assurance_claims.json` when packaging) |

Given the same kit bytes, commit and builder, the provenance and its signature
are byte-identical (the tarball itself is written deterministically: sorted
entries, fixed mtime, uid/gid 0, no gzip timestamp). This is NOT a
reproducible-build claim: compiled binaries can still differ between toolchains.

## provenance.sig.json

`schema_version`, `algorithm` (`ML-DSA-65`), `context`
(`PQCP-KIT-PROVENANCE-V1`), `key_id` (SHA-256 of the public key),
`public_key_hex`, `signature_hex` (3309 bytes). The signature is FIPS 204 pure
ML-DSA-65, deterministic (`rnd` = 32 zero bytes), over the provenance bytes
under the context `PQCP-KIT-PROVENANCE-V1`. That context differs from the
log-checkpoint context `PQCP-APPRAISAL-LOG-V1`, so a checkpoint-context
signature never verifies as kit provenance, and vice versa.

```
pqcp-evidence-register sign-file   --seed-file S --in F --out SIG
pqcp-evidence-register verify-file --pk P --in F --sig SIG
```

## Key custody (demo grade)

The signing seed is a 32-byte raw file supplied with `--signing-seed-file` or
the environment variable `PQCP_KIT_SIGNING_SEED_FILE`; it is never stored in
this repository. In CI it comes from the repository secret `KIT_SIGNING_SEED`
(base64). When no seed is supplied the packager still writes the provenance,
prints `PQCP_KIT_PROVENANCE UNSIGNED` and a warning, deletes any stale
signature file, and the verifier reports `UNSIGNED`. A seed that is supplied
but unusable is an error, never a silent downgrade.

## Verification

```
python3 scripts/verify_kit_provenance.py KIT.tar.gz [--pin-key-id HEX | --pin-pk FILE]
                                          [--register-bin TRUSTED] [--require-signature]
```

Result markers: `PASS` (signed, verified, signer pinned), `UNPINNED` (valid
only under the key embedded in the signature file), `UNSIGNED`, `REJECT
reasons=...`. The check recomputes the kit hash and size, every per-file hash,
the kit name and README version against the provenance fields, and verifies
the signature with the `verify-file` command of the register binary shipped in
the kit (or `--register-bin`).

## Non-claims

* The key is a demo key. There is no PKI, no certificate, no enrollment, no
  revocation and no rotation story; a leaked seed cannot be revoked.
* A signature proves the provenance file was produced by the holder of that
  key and was not altered afterwards. It does NOT prove the kit was built
  correctly, from the stated commit, or on the stated host: those fields are
  attested by the builder, not independently measured.
* Without a pin the embedded public key authenticates nothing: anyone can sign
  with their own key and embed it. Publish the signer key id out of band and
  pass `--pin-key-id`. Use `--require-signature` to refuse unsigned or
  unpinned results; deleting the signature file otherwise downgrades to
  `UNSIGNED`.
* A kit verified with its own shipped register binary vouches for itself. Use a
  `--register-bin` you built or trust when the kit source is not trusted.
* `git_dirty` ignores untracked files, and `claims` lists what the kit is meant
  to support, not that those claims currently pass.
