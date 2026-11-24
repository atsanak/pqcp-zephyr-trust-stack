# Runtime and protected channel

The runtime layer turns the adaptive PQC control plane into executable runtime and
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

## Composite operation planning

`pqcp_runtime_operation_plan()` combines runtime lifecycle, resource, and
recovery decisions into one disposition with an effective next state,
concurrency and reservation limits, retry policy, reason mask, and error.

`pqcp_channel_operation_plan()` applies explicit precedence across channel
lifecycle, path, and fault decisions and returns the required allow, retry,
probe, migration, rekey, drain, reset, close, or termination action.

The planners are part of the normal runtime/channel implementation. Their large
replay catalogs remain optional.

## Validation catalogs

`CONFIG_PQCP_OPERATION_CONFORMANCE_CATALOGS` enables 5,120 replayable policy
and planning witnesses:

- 512 runtime state/command cases;
- 512 runtime resource/command cases;
- 512 runtime recovery/command cases;
- 512 channel state/control cases;
- 512 channel path/control cases;
- 512 channel fault/control cases;
- 1,024 runtime operation-plan cases;
- 1,024 channel operation-plan cases.

Each case has a stable identifier and expected decision fields. Runtime audits
cross-check every witness against the executable lookup table or planner. The
generic APIs also support case lookup and deterministic 64-bit fingerprints
for evidence capture.

`CONFIG_PQCP_OPERATION_SCENARIO_CATALOGS` adds 3,072 two-operation scenarios.
Lifecycle scenarios propagate successful state transitions into the second
operation; resource, recovery, path, and fault scenarios retain their external
condition and verify aggregate reason/error behavior.

`CONFIG_PQCP_RUNTIME_CHANNEL_GUARD_CATALOGS` adds four 16 by 32 guard planes:

- runtime authorization;
- runtime continuity;
- protected-channel key epoch;
- protected-channel stream lifecycle.

The runtime and channel guard evaluators combine those planes with lifecycle
policy and return one enforceable verdict.

`CONFIG_PQCP_OPERATION_TRANSITION_CATALOGS` adds 1,024 deterministic eight-step
traces. Runtime traces replay the composite runtime planner; channel traces
replay the composite channel planner. Generated fingerprint tables are kept
compact, while trace inputs are reconstructed deterministically and every
transition is executed during audit.

All catalog options are disabled by default so production images do not carry
validation-only data.

The catalog sources are generated at CMake configure time into the build
directory; they are not kept in `src/`. To render them by hand:

```sh
for g in scripts/generate_runtime_channel_policy_catalogs.py \
         scripts/generate_runtime_channel_guard_catalogs.py \
         scripts/generate_operation_conformance_catalogs.py \
         scripts/generate_operation_plan_catalogs.py \
         scripts/generate_operation_scenario_catalogs.py \
         scripts/generate_operation_transition_catalogs.py; do
  python3 "$g" --output-dir build/generated
done
```

`scripts/run_local_tool_tests.py` runs every generator twice and fails if the
output is not deterministic.

