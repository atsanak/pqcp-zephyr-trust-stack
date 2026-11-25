# PQCP Zephyr Trust Stack

[![CI](https://github.com/atsanak/pqcp-zephyr-trust-stack/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/atsanak/pqcp-zephyr-trust-stack/actions/workflows/ci.yml)
[![Release dry-run](https://github.com/atsanak/pqcp-zephyr-trust-stack/actions/workflows/release-dry-run.yml/badge.svg?branch=main)](https://github.com/atsanak/pqcp-zephyr-trust-stack/actions/workflows/release-dry-run.yml)

An out-of-tree Zephyr module that integrates the PQ Code Package libraries
[`mlkem-native`](https://github.com/pq-code-package/mlkem-native) (ML-KEM,
FIPS 203) and [`mldsa-native`](https://github.com/pq-code-package/mldsa-native)
(ML-DSA, FIPS 204), plus a method for testing the deployed firmware image for
constant-time behaviour and fault resistance under emulation.

> **Status.** Research and engineering project under the MIT license. All
> results come from the host and QEMU. There are **no hardware measurements**,
> and the constant-time results are tests under a stated latency model, not
> proofs. Each result lists its limits and non-claims in
> [`docs/prior-art-and-contributions.md`](docs/prior-art-and-contributions.md).

## Why it exists

Constant-time and fault-resistance properties are usually argued about source
code or a reference build. What ships on a microcontroller is a specific
linked image built with a specific compiler and Kconfig. This project tests
that image directly. It runs the real firmware under QEMU, records what the
CPU does, and checks that executions which differ only in secret data cannot
be told apart.

## What is in the box

- **Primitives.** ML-KEM-512/768/1024 and ML-DSA-44/65/87 with a Zephyr RNG
  backend, Kconfig and CMake integration, and PSA driver glue.
- **Known-answer tests.** NIST ACVP vectors pinned to the vendored constants,
  exercised over a serial wire format on QEMU and Nucleo-class boards.
- **Relational constant-time testing.** A QEMU TCG plugin records instruction
  addresses, data addresses, cache lines and operand-dependent latency of the
  firmware image. Secret-varying runs must produce identical traces, and
  ML-DSA's declassification points inside signing are honoured.
  See [`docs/ct-trace-leakage.md`](docs/ct-trace-leakage.md).
- **Fault injection.** An emulated campaign over the boot image that measures
  how a negative-vector self-test changes the set of exploitable instruction
  skips. See [`docs/fault-campaign.md`](docs/fault-campaign.md).
- **Assurance ledger.** Release statements are typed claims in
  [`scripts/assurance_claims.json`](scripts/assurance_claims.json), each with
  an evaluator that reads captured transcripts. See
  [`docs/assurance-model.md`](docs/assurance-model.md).
- **Runtime and evidence services.** Key and session governance, a protected
  channel, fleet policy and signed audit export, described in
  [`docs/feature-overview.md`](docs/feature-overview.md). The fleet,
  sovereign and adaptive families live under `src/experimental/`, select
  Zephyr's `EXPERIMENTAL` Kconfig symbol and carry less test coverage than
  the cryptographic core.

## Main results

All of these are emulation results with the limits stated in each linked
document.

- Relational trace testing of ML-KEM and ML-DSA on `qemu_x86_64` and on
  Cortex-M3, M4 and M33 models, with measured detector power against planted
  leaks.
- Two secret-dependent multiplies found under a Cortex-M3 operand-latency
  model (ML-KEM compression and the ML-DSA Montgomery path), with opt-in
  fixed-latency repairs verified under two latency models
  ([`docs/ct-latency-model-sensitivity.md`](docs/ct-latency-model-sensitivity.md)).
- A study of whether the ML-DSA signing-attempt count depends on the key.
- Fault timing as a measured axis, with a countermeasure ablation.

The constant-time studies are run with **hypotheses registered before the
measurement**: each hypothesis is committed to the repository first, and the
result commit records whether it was confirmed at the registered level,
including the ones that were not.

## Quick start

```bash
west init -m https://github.com/atsanak/pqcp-zephyr-trust-stack my-workspace
cd my-workspace && west update
python3 pqcp-zephyr-trust-stack/scripts/run_host_assurance.py
python3 pqcp-zephyr-trust-stack/scripts/run_local_tool_tests.py
```

Build and run a sample on QEMU:

```bash
west build -p always -b qemu_x86_64 pqcp-zephyr-trust-stack/samples/pqcp_basic_kem
west build -t run
```

The full local release gate is `python3 scripts/release_check.py --tag v1.0.0`.
Prerequisites, Kconfig options and the C API are in
[`docs/getting-started.md`](docs/getting-started.md).

## Source layout

| Path | Contents |
|------|----------|
| `src/crypto/` | ML-KEM and ML-DSA glue, RNG backends, PSA drivers, ACVP and KAT support |
| `src/evidence/` | Build manifest, evidence sessions, transcripts and deployment evidence |
| `src/runtime/`, `src/channel/` | Runtime services and the protected channel |
| `src/edge/` | Edge security services |
| `src/experimental/` | Fleet, sovereign and adaptive families |
| `include/pqcp_zephyr/` | Public headers |
| `scripts/`, `tools/` | Host-side test, evidence and release tooling |

The runtime and channel decision catalogs are generated into the build
directory at configure time from `scripts/generate_*_catalogs.py`.

## Supported targets

- `qemu_x86_64` for CI and host-side validation
- `mps2/an385` (Cortex-M3) for Cortex-M validation; the constant-time studies
  also use Cortex-M4 and Cortex-M33 board models
- `nucleo_h743zi` for build-only validation of an STM32H7 path

Tested against Zephyr `v4.5.0` with Zephyr SDK `1.0.1`.

## Samples

| Sample | Description |
|--------|-------------|
| `pqcp_basic_kem` | ML-KEM keygen, encapsulation and decapsulation |
| `pqcp_basic_sig` | ML-DSA keygen, sign and verify |
| `pqcp_kat_deterministic` | Known-answer tests with a deterministic RNG |
| `pqcp_streaming_hash_mldsa` | Streaming signatures over large messages |
| `pqcp_tls_mbedtls_psa` | TLS and PSA self-test path |
| `pqcp_bench_protocol` | Protocol benchmark on the shared TLS harness |
| `pqcp_serial_acvp` | UART-based ACVP test interface |

## Documentation

| Topic | Document |
|-------|----------|
| Build, configuration and API | [`docs/getting-started.md`](docs/getting-started.md), [`docs/api-overview.md`](docs/api-overview.md) |
| Constant-time testing | [`docs/ct-trace-leakage.md`](docs/ct-trace-leakage.md), [`docs/ct-latency-model-sensitivity.md`](docs/ct-latency-model-sensitivity.md) |
| Fault injection | [`docs/fault-campaign.md`](docs/fault-campaign.md) |
| Contributions and prior art | [`docs/prior-art-and-contributions.md`](docs/prior-art-and-contributions.md) |
| Benchmarks (emulation only) | [`docs/benchmarks.md`](docs/benchmarks.md), [`docs/performance-methodology.md`](docs/performance-methodology.md) |
| Serial ACVP interface | [`docs/serial-acvp.md`](docs/serial-acvp.md) |
| Testing, CI and releases | [`docs/testing-and-release.md`](docs/testing-and-release.md), [`docs/release.md`](docs/release.md) |
| Security properties | [`docs/security-notes.md`](docs/security-notes.md), [`SECURITY.md`](SECURITY.md) |
| Assurance model and evidence | [`docs/assurance-model.md`](docs/assurance-model.md), [`docs/evidence-schema-contract.md`](docs/evidence-schema-contract.md) |

## Security

The cryptographic implementations are `mlkem-native` and `mldsa-native`,
pinned in [`west.yml`](west.yml); consult their documentation for their
constant-time guarantees. The QEMU-only baseline provider makes none and is
not a production path. Report vulnerabilities as described in
[`SECURITY.md`](SECURITY.md).

## References

- [FIPS 203 - ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 - ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [mlkem-native](https://github.com/pq-code-package/mlkem-native) and
  [mldsa-native](https://github.com/pq-code-package/mldsa-native)

## License

MIT, see [`LICENSE`](LICENSE). The vendored libraries under `ext/` keep their
own licenses. Contributions are welcome under the same terms; see
[`CONTRIBUTING.md`](CONTRIBUTING.md). To cite this work, use
[`CITATION.cff`](CITATION.cff).
