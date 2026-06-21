# PQC Fleet Trust Fabric

This sample runs a complete device-to-gateway lifecycle using the production
runtime primitives:

1. a gateway registrar admits a factory ML-DSA identity;
2. the device sends a signed enrollment request;
3. the registrar issues an ownership voucher;
4. the device generates an operational key locally and atomically installs the
   voucher and credential;
5. the registrar publishes a signed crypto-policy bundle;
6. the operational credential rotates with overlapping old and new keys;
7. a signed firmware-update manifest is authorized and committed;
8. the active credential is revoked;
9. operational keys are destroyed and a decommission tombstone is persisted.

The terminal marker retains the last applied policy and revocation epochs even
after decommissioning zeroizes the corresponding credential and policy
material.

The sample uses the two-slot in-memory fleet store. Production firmware can
enable `CONFIG_PQCP_FLEET_STORE_ITS` on a target that provides PSA Internal
Trusted Storage. Firmware installation remains platform-owned; the fleet
layer authorizes the exact component, version, size, flags, and image digest.

The same fleet module also exposes a bounded operations and resilience plane:
device policy, idempotent commands, update probation and rollback,
tamper-evident audit, telemetry, signed attestation, secure-time uncertainty,
offline leases, revocation indexing, rollout control, health circuit breaking,
admission control, recovery evidence, risk scoring, and maintenance
scheduling. These APIs are composed by `pqcp_fleet_operations` but remain
platform-driven so products retain control over transport, installation,
storage, clocks, and actuator execution.

Build and run from the Zephyr workspace:

```sh
west build -p always -b qemu_x86_64 \
  pqcp-zephyr-trust-stack/samples/pqcp_fleet_trust
west build -t run
```
