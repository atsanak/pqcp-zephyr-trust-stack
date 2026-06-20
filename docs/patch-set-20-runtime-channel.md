# Patch Set 20 Runtime and Channel Completion

Patch Set 20 turns the adaptive PQC control plane into executable runtime and
protected-channel services. The implementation is allocation-free, uses
caller-owned storage, and keeps generated policy material reproducible.

## Operational services

The runtime layer now provides event chaining, weighted scheduling, command
routing, checkpoint storage, SLO metrics, resource governance, recovery
policy, and orchestration over the existing key, session, migration, lease,
transaction, and executor services.

The protected channel adds multiplexed streams, bounded flow control,
authenticated rekeying, encrypted resumption tickets, peer-health tracking,
validated path migration, and explicit fault policy over the exporter-bound
channel.

## Conformance witnesses

`CONFIG_PQCP_OPERATION_CONFORMANCE_CATALOGS` enables 3,072 replayable policy
witnesses:

- 512 runtime state/command cases;
- 512 runtime resource/command cases;
- 512 runtime recovery/command cases;
- 512 channel state/control cases;
- 512 channel path/control cases;
- 512 channel fault/control cases.

Each case has a stable identifier and expected decision fields. Runtime audits
cross-check every witness against the executable lookup table. The generic API
also supports case lookup and deterministic 64-bit fingerprints for evidence
capture. The catalogs are disabled by default so production images do not
carry validation-only data.

Regenerate and verify them with:

```sh
python3 scripts/generate_runtime_channel_policy_catalogs.py --check
python3 scripts/generate_operation_conformance_catalogs.py
python3 scripts/generate_operation_conformance_catalogs.py --check
```

## Fresh `src/*.c` growth proof

The fresh-growth baseline is commit
`5b052784017db8b739b65999c34572a735546fc5`, after the pre-existing Patch Set
20 work was stabilized and committed. That baseline contains 145 tracked
top-level `src/*.c` files and 103,307 lines.

After committing the conformance implementation, verify the net-new line count
with:

```sh
python3 scripts/check_src_c_growth.py \
  --baseline 5b052784017db8b739b65999c34572a735546fc5 \
  --minimum 20000
```

The checker reads both Git trees directly, so ignored build output, untracked
files, headers, tests, scripts, and older Patch Set 20 edits cannot inflate the
result.
