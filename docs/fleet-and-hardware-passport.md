# Fleet drift audit and hardware passport status

This covers a fleet-level drift audit
(implemented and validated on host) and the on-hardware passport capture
(designed, board-gated).

## Fleet drift audit (implemented)

`scripts/run_fleet_audit.py` ingests one evidence transcript per device,
verifies each device's full chain with the C verifier
`pqcp-evidence-verify`, and then aggregates the per-device results:

- **Every device must verify individually** (chain replays, digests bind,
  and, with `--require-signature`, the ML-DSA-65 signature checks out).
- **Homogeneous fleet** (default): all devices must share one passport
  digest and one board identity. Output: `PQCP_FLEET_AUDIT PASS`.
- **Drift**: devices that each verify individually but disagree on passport
  digest or board are flagged `PQCP_FLEET_AUDIT DRIFT`. Strict mode fails;
  `--allow-drift` accepts a deliberately heterogeneous fleet while still
  requiring every device to verify.
- **Tamper**: a device whose transcript does not self-verify fails the
  fleet regardless of drift policy.

This is the on-device audit modules' "stable across N results" idea lifted
to fleet scope: the cross-device comparison is set logic over the C
verifier's JSON output, so all cryptographic and replay decisions stay in
the single-source C verifier.

Validated on host (`scripts/test_fleet_audit.py`, 7/7): homogeneous PASS,
drift FAIL in strict mode, drift PASS under `--allow-drift`, tampered
device FAIL, and a well-formed fleet JSON summary.

## Hardware passport (board-gated, not yet captured)

The full chain, including the ML-DSA-signed passport, is hardware-ready:
the evidence modules use no QEMU-specific facilities, and `nucleo_h743zi`
already builds in this repository's MCU matrix. The remaining step is
physical: flash `samples/pqcp_deployment_advisor` (with the signature and
passport options) to a `nucleo_h743zi`, capture the UART console, and run
the captured transcript through `pqcp-evidence-verify --require-signature`
and `scripts/run_fleet_audit.py` exactly as the QEMU transcripts are
verified today.

This is deliberately **not** claimed as done: no measured on-hardware
transcript exists in the repository, and `resource_budgets.json` is not
updated with a measured signed-chain ROM/RAM figure. When a board is
available, capturing that transcript closes the loop with zero code
changes to the verifier, because the host verifier is the same C as the
firmware. Until then, the QEMU transcripts are the authoritative evidence
and the hardware passport remains an honest open item.
