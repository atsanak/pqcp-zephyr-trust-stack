# PQCP Zephyr Trust Stack

An out-of-tree Zephyr RTOS module providing first-class support for Post-Quantum Cryptography (PQC) using the PQ Code Package's `mlkem-native` (ML-KEM, FIPS-203) and `mldsa-native` (ML-DSA, FIPS-204) reference implementations.

## Performance

> QEMU x86_64 emulation. Cycle counts are emulation-approximate; generate the
> full dataset with `scripts/export_results.py` and inspect
> `results/benchmark_results.csv` plus `results/benchmark_summary.md` for the
> complete publication-ready export.

| Operation | Param Set | PQCP cycles | Baseline cycles | Overhead |
|-----------|-----------|-------------|-----------------|----------|
| ML-KEM KeyGen | 512 | 3743 | 3286 | +13.91% |
| ML-KEM KeyGen | 768 | 2311 | 3421 | -32.45% |
| ML-KEM KeyGen | 1024 | 2503 | 3368 | -25.68% |
| ML-KEM Encaps | 512 | 1486 | 998 | +48.90% |
| ML-KEM Encaps | 768 | 1176 | 1213 | -3.05% |
| ML-KEM Encaps | 1024 | 1204 | 1834 | -34.35% |
| ML-KEM Decaps | 512 | 988 | 2295 | -56.95% |
| ML-KEM Decaps | 768 | 841 | 1274 | -33.99% |
| ML-KEM Decaps | 1024 | 1044 | 2033 | -48.65% |
| ML-DSA KeyGen | 44 | 6253 | 3476 | +79.89% |
| ML-DSA KeyGen | 65 | 7501 | 3723 | +101.48% |
| ML-DSA KeyGen | 87 | 3929 | 4820 | -18.49% |
| ML-DSA Sign | 44 | 10157 | 7593 | +33.77% |
| ML-DSA Sign | 65 | 11989 | 7162 | +67.40% |
| ML-DSA Sign | 87 | 13425 | 17551 | -23.51% |
| ML-DSA Verify | 44 | 1437 | 1309 | +9.78% |
| ML-DSA Verify | 65 | 3555 | 1643 | +116.37% |
| ML-DSA Verify | 87 | 6067 | 2543 | +138.58% |

## Security Properties

### Cryptographic Correctness
- ML-KEM-512/768/1024 implemented per FIPS 203 (final)
- ML-DSA-44/65/87 implemented per FIPS 204 (final)
- NIST KAT vectors verified in CI ([`tests/ztest_acvp_kat`](/Users/angelostsanaktsidis/code/PQC/zephyr-ws/pqcp-zephyr-trust-stack/tests/ztest_acvp_kat))
- Baseline provider is QEMU-only; not a production path

### Side-Channel Posture
- The PQCP provider implementations are the `mlkem-native` and `mldsa-native` modules (see [`west.yml`](/Users/angelostsanaktsidis/code/PQC/zephyr-ws/pqcp-zephyr-trust-stack/west.yml) for pinned revisions). Consult those modules' documentation for their constant-time guarantees.
- The baseline provider makes no constant-time guarantees.

### PSA Driver Guarantees
- Output buffer bounds validated before any write
- Unsupported key types rejected before internal state mutation
- All error paths return specific `PSA_ERROR_*` codes

### Out of Scope for This Module
- Hardware RNG quality (depends on platform entropy source)
- TLS record-layer security (provided by mbedTLS)

## Roadmap to v1.0.0

- [x] CI: west Twister discovery job
- [x] CI: KAT vector NIST provenance verification
- [x] CI: `nucleo_h743zi` protocol suite builds on CI runners
- [x] Completeness: ML-KEM-1024 + ML-DSA-87 KAT vectors
- [x] Robustness: ACVP readline timeout / deeper mid-frame stall detection coverage

## Features

- **ML-KEM (FIPS-203)**: Key Encapsulation Mechanism for quantum-resistant key exchange
  - Security levels: ML-KEM-512, ML-KEM-768, ML-KEM-1024
  - Full keygen, encapsulation, decapsulation support
  
- **ML-DSA (FIPS-204)**: Digital Signature Algorithm for quantum-resistant authentication
  - Security levels: ML-DSA-44, ML-DSA-65, ML-DSA-87
  - Deterministic and randomized signing
  - Streaming API for large message signing

- **RNG Integration**: Proper entropy integration with Zephyr
  - Zephyr entropy via `sys_csrand_get()` (default, crypto-safe)
  - PSA Crypto RNG support
  - Custom RNG registration
  - Deterministic DRBG for Known Answer Tests (KAT)

- **PSA Crypto Drivers**: PSA-compliant driver shims
  - ML-DSA driver following TF-PSA-Crypto design
  - ML-KEM driver for key encapsulation

- **Benchmarking Harness**: Comprehensive performance measurement
  - Primitive-level benchmarks (cycles, stack, code size)
  - Protocol-level benchmarks (TLS handshake latency, memory)

## Supported Targets

- `qemu_x86_64` for CI and host-side validation
- `mps2/an385` for Cortex-M validation, including no-entropy overlays
- `nucleo_h743zi` for build-only extended-check validation of a realistic STM32H7 MCU path
- Other Cortex-M4/M7 class boards once stack sizing and entropy sources are tuned for the target

## Quick Start

### Prerequisites

- Zephyr SDK installed
- West meta-tool configured
- Python 3.8+

### West Workspace Setup

For a fresh workspace, use the repository-root `west.yml` directly:

```bash
west init -m https://github.com/atsana01/pqcp-zephyr-trust-stack my-workspace
cd my-workspace && west update
west build -b qemu_x86_64 pqcp-zephyr-trust-stack/samples/pqcp_serial_acvp
```

That leaves the manifest repository at `pqcp-zephyr-trust-stack/`, Zephyr at
`zephyr/`, and the PQ Code Package backends at:

- `modules/crypto/mlkem-native`
- `modules/crypto/mldsa-native`

The module still supports the existing in-repo `ext/` layout for local
development checkouts, so older workspaces and direct in-tree builds continue
to work.

For release-oriented integrations, pin the manifest repo revision to the tag or
commit that matches the documented version macros in
`include/pqcp_zephyr/version.h` and the top release entry in `CHANGELOG.md`.

### Adding to Your Zephyr Project

**Option 1: Via west.yml**

```yaml
manifest:
  projects:
    - name: pqcp-zephyr-trust-stack
      url: https://github.com/atsana01/pqcp-zephyr-trust-stack
      revision: main  # Prefer a pinned tag or commit for release integration
      path: modules/pqcp
```

Then run `west update`.

For release-oriented integrations, pin `revision` to the tag or commit that
matches both `PQCP_VERSION_STRING` in `include/pqcp_zephyr/version.h` and the
top release entry in `CHANGELOG.md`. That gives downstream applications a
simple, auditable mapping between the manifest revision and the documented PQCP
module release.

**Option 2: Via EXTRA_ZEPHYR_MODULES**

```bash
# Clone the repository
git clone https://github.com/your-org/pqcp-zephyr-trust-stack
cd pqcp-zephyr-trust-stack
python ext/setup_libs.py  # Fetch mlkem-native and mldsa-native

# Build with the module
export EXTRA_ZEPHYR_MODULES=/path/to/pqcp-zephyr-trust-stack
west build -p always -b qemu_x86_64 samples/pqcp_basic_kem
```

### Module Integration

Downstream Zephyr applications can consume this repository in two supported
ways, depending on whether you are integrating it as a normal west module or
working in this repository itself during development.

Path 1: west consumer

When the repository is used as the workspace manifest repository, `west.yml`
pulls Zephyr plus the pinned PQ Code Package dependencies automatically and
`zephyr/module.yml` injects the module’s CMake/Kconfig integration with no
extra glue:

```bash
west init -m https://github.com/atsana01/pqcp-zephyr-trust-stack my-workspace
cd my-workspace && west update
west build -b qemu_x86_64 pqcp-zephyr-trust-stack/samples/pqcp_serial_acvp
```

For an application workspace that already has its own manifest, add this repo as
another project and pin it to the release tag or commit that matches both
`PQCP_VERSION_STRING` in `include/pqcp_zephyr/version.h` and the top release
entry in `CHANGELOG.md`.

The ACVP command library can be enabled without the full native/lab profile if
your application needs just the parser/formatter surface, but production-style
builds should still keep deterministic RNG disabled and select a production RNG
backend such as `CONFIG_PQCP_RNG_ZEPHYR_ENTROPY=y` or `CONFIG_PQCP_RNG_PSA=y`.

If you are not using the repository root `west.yml`, the equivalent explicit
external-module injection flow is still:

```bash
west build -p always -b qemu_x86_64 /path/to/app -- \
  -DZEPHYR_EXTRA_MODULES=/path/to/pqcp-zephyr-trust-stack
```

Path 2: in-tree development

The repo's own samples and tests keep
`cmake/pqcp_local_module.cmake` so local development builds still work even if
this repository has not been added to the surrounding workspace manifest yet.
That helper is included before `find_package(Zephyr)` in the repo-local apps,
which is why commands such as
`west build -p always -b qemu_x86_64 tests/ztest_acvp_serial` work directly
from a checkout inside an arbitrary Zephyr workspace.

External consumer applications should prefer Path 1 or explicit
`ZEPHYR_EXTRA_MODULES` injection. The local helper exists to keep in-tree
sample and test development friction low; it is not a replacement for
`zephyr/module.yml` in downstream workspaces.

### Building and Running Samples

**Basic ML-KEM Demo:**
```bash
west build -p always -b qemu_x86_64 samples/pqcp_basic_kem
west build -t run
```

**Basic ML-DSA Demo:**
```bash
west build -p always -b qemu_x86_64 samples/pqcp_basic_sig
west build -t run
```

**KAT (Known Answer Tests):**
```bash
west build -p always -b qemu_x86_64 samples/pqcp_kat_deterministic
west build -t run
```

**Streaming ML-DSA (Large Messages):**
```bash
west build -p always -b qemu_x86_64 samples/pqcp_streaming_hash_mldsa
west build -t run
```

**TLS Sample (with PSA Crypto):**
```bash
west build -p always -b qemu_x86_64 samples/pqcp_tls_mbedtls_psa -- -DOVERLAY_CONFIG=overlay-mbedtls.conf
west build -t run
```

**Running Tests:**
```bash
# Base tests (13 tests)
west build -p always -b qemu_x86_64 tests/ztest_primitive
west build -t run

# With PSA driver tests (18 tests)
west build -p always -b qemu_x86_64 tests/ztest_primitive -- -DOVERLAY_CONFIG=overlay-psa.conf
west build -t run

# On Cortex-M (mps2/an385 with 4MB RAM)
west build -p always -b mps2/an385 tests/ztest_primitive -- -DOVERLAY_CONFIG=overlay-no-entropy.conf
west build -t run
```

### Running Tests with Twister

The repo now ships `testcase.yaml` manifests for all four ztest suites, so
downstream Zephyr workspaces can discover them through the standard Twister
runner instead of relying on repo-local helper scripts alone.

To discover and build the QEMU-covered tests without running them:

```bash
/Users/angelostsanaktsidis/code/PQC/zephyr-ws/.venv/bin/west twister \
  -T tests/ \
  -p qemu_x86_64 \
  --build-only
```

To focus on just the PQCP-tagged scenarios, use Twister's tag filter:

```bash
/Users/angelostsanaktsidis/code/PQC/zephyr-ws/.venv/bin/west twister \
  -T tests/ \
  -p qemu_x86_64 \
  --build-only \
  -t pqcp
```

The current manifests cover:

- `tests/ztest_rng`
- `tests/ztest_primitive` plus the PSA and `overlay-no-entropy.conf` variants
- `tests/ztest_tls_selftest`
- `tests/ztest_acvp_serial`

### Enable in Your Application

Add to your `prj.conf`:

```
CONFIG_PQCP=y
CONFIG_PQCP_MLKEM_LEVEL_768=y
CONFIG_PQCP_MLDSA_LEVEL_65=y
CONFIG_MAIN_STACK_SIZE=131072
```

## Repository Structure

```
pqcp-zephyr-trust-stack/
├── zephyr/
│   └── module.yml              # Zephyr module registration
├── CMakeLists.txt              # Main CMake configuration
├── Kconfig                     # Module Kconfig options
│
├── include/pqcp_zephyr/
│   ├── mlkem.h                 # ML-KEM public API
│   ├── mldsa.h                 # ML-DSA public API
│   ├── rng.h                   # RNG abstraction
│   └── bench.h                 # Benchmarking types
│
├── src/
│   ├── mlkem_zephyr.c          # ML-KEM wrapper
│   ├── mldsa_zephyr.c          # ML-DSA wrapper
│   ├── mldsa_streaming.c       # Streaming ML-DSA API
│   ├── rng_*.c                 # RNG backends
│   ├── psa_mldsa_driver.c      # PSA ML-DSA driver
│   ├── psa_mlkem_driver.c      # PSA ML-KEM driver
│   └── bench_*.c               # Benchmarking harness
│
├── samples/
│   ├── pqcp_basic_kem/         # Basic ML-KEM demo
│   ├── pqcp_basic_sig/         # Basic ML-DSA demo
│   ├── pqcp_bench_protocol/    # Protocol benchmark sample
│   ├── pqcp_kat_deterministic/ # Known Answer Tests
│   ├── pqcp_streaming_hash_mldsa/
│   ├── pqcp_tls_mbedtls_psa/   # TLS integration
│   └── pqcp_serial_acvp/       # ACVP test interface
│
├── tests/
│   ├── ztest_primitive/        # Primitive operation tests
│   ├── ztest_rng/              # RNG subsystem tests
│   ├── ztest_acvp_serial/      # ACVP command-library tests
│   └── ztest_tls_selftest/     # Shared TLS self-test helper tests
│
├── scripts/
│   ├── run_benchmarks.py       # Benchmark orchestration
│   ├── parse_logs.py           # Log parsing to CSV
│   ├── summarize_cost_of_assurance.py
│   │                          # Backend-comparison report generation
│   ├── run_extended_checks.py  # Slower validation and compatibility checks
│   └── resource_budgets.json   # Curated ROM/RAM envelopes for CI smokes
│
└── ext/                        # External library integration
```

## Configuration Options

### Build Profiles

The module provides pre-configured profiles for common use cases:

```
# Minimal MCU profile: single level of each algorithm
CONFIG_PQCP_PROFILE_MCU_MINIMAL=y

# Gateway profile: all levels, PSA drivers, streaming
CONFIG_PQCP_PROFILE_GATEWAY=y

# Native/Lab profile: all features + benchmarking
CONFIG_PQCP_PROFILE_NATIVE_LAB=y
```

| Profile | ML-KEM Levels | ML-DSA Levels | PSA | Streaming | Bench | Use Case |
|---------|---------------|---------------|-----|-----------|-------|----------|
| MCU_MINIMAL | 768 | 65 | No | No | No | Constrained devices |
| GATEWAY | 512/768/1024 | 44/65/87 | Yes | Yes | No | PSA/TLS-capable devices |
| NATIVE_LAB | 512/768/1024 | 44/65/87 | No | Yes | Yes | Deterministic tests, ACVP, and protocol benchmarking |

`GATEWAY` and `NATIVE_LAB` use the module's multilevel native build path so one
image can expose the full set of configured ML-KEM and ML-DSA levels at
runtime. `MCU_MINIMAL` stays conservative by default and does not enable
deterministic RNG, ACVP, or protocol benchmarking.

### Validated Profile Coverage

The repository keeps human-readable and machine-readable profile validation in
sync through `scripts/profile_validation_matrix.json`. The currently validated
coverage is:

| Profile | Validated combinations |
|---------|------------------------|
| MCU_MINIMAL | `qemu_x86_64`: `tests/ztest_primitive`, `tests/ztest_rng`, `samples/pqcp_basic_kem`; `mps2/an385`: `tests/ztest_primitive` with `overlay-no-entropy.conf`; `nucleo_h743zi`: build-only `tests/ztest_primitive` and `samples/pqcp_basic_kem` |
| GATEWAY | `qemu_x86_64`: `tests/ztest_primitive` with `overlay-psa.conf`, `tests/ztest_tls_selftest`, `samples/pqcp_tls_mbedtls_psa` with `overlay-selftest.conf` |
| NATIVE_LAB | `qemu_x86_64`: `samples/pqcp_basic_sig`, `tests/ztest_acvp_serial`, `samples/pqcp_bench_protocol`, `samples/pqcp_kat_deterministic` |

### Algorithm Selection

```
# ML-KEM levels (enable one or more)
CONFIG_PQCP_MLKEM_LEVEL_512=y
CONFIG_PQCP_MLKEM_LEVEL_768=y  # Default
CONFIG_PQCP_MLKEM_LEVEL_1024=y

# ML-DSA levels
CONFIG_PQCP_MLDSA_LEVEL_44=y
CONFIG_PQCP_MLDSA_LEVEL_65=y   # Default
CONFIG_PQCP_MLDSA_LEVEL_87=y
```

### RNG Configuration

```
# Use Zephyr entropy (default, recommended)
CONFIG_PQCP_RNG_ZEPHYR_ENTROPY=y

# Use PSA Crypto RNG
CONFIG_PQCP_RNG_PSA=y

# Use custom RNG
CONFIG_PQCP_RNG_CUSTOM=y

# Deterministic mode (TEST ONLY)
CONFIG_PQCP_RNG_DETERMINISTIC_TEST=y
```

### Backend Selection

```
# Auto-select (recommended)
CONFIG_PQCP_BACKEND_AUTO=y

# Force C reference implementation
CONFIG_PQCP_BACKEND_FORCE_C=y

# Force native/optimized (requires ISA support)
CONFIG_PQCP_BACKEND_FORCE_NATIVE=y
```

### PSA Drivers

```
# Enable PSA ML-DSA driver
CONFIG_PQCP_PSA_DRIVER_MLDSA=y

# Enable PSA ML-KEM driver
CONFIG_PQCP_PSA_DRIVER_MLKEM=y
```

## API Usage

### ML-KEM (Key Encapsulation)

```c
#include <pqcp_zephyr/mlkem.h>
#include <pqcp_zephyr/rng.h>

/* Initialize RNG (required before any crypto ops) */
pqcp_rng_init();

/* Key generation */
static uint8_t pk[PQCP_MLKEM_PK_SIZE_MAX];
static uint8_t sk[PQCP_MLKEM_SK_SIZE_MAX];
int ret = pqcp_mlkem_keypair(PQCP_MLKEM_768, pk, sk);

/* Encapsulation (sender) */
static uint8_t ct[PQCP_MLKEM_CT_SIZE_MAX];
static uint8_t ss1[PQCP_MLKEM_SS_SIZE];
pqcp_mlkem_encapsulate(PQCP_MLKEM_768, pk, ct, ss1);

/* Decapsulation (receiver) */
static uint8_t ss2[PQCP_MLKEM_SS_SIZE];
pqcp_mlkem_decapsulate(PQCP_MLKEM_768, ct, sk, ss2);
/* ss1 == ss2 */
```

### ML-DSA (Digital Signatures)

```c
#include <pqcp_zephyr/mldsa.h>
#include <pqcp_zephyr/rng.h>

/* Initialize RNG */
pqcp_rng_init();

/* Key generation */
static uint8_t pk[PQCP_MLDSA_PK_SIZE_MAX];
static uint8_t sk[PQCP_MLDSA_SK_SIZE_MAX];
pqcp_mldsa_keypair(PQCP_MLDSA_65, pk, sk);

/* Sign message */
static uint8_t sig[PQCP_MLDSA_SIG_SIZE_MAX];
const uint8_t msg[] = "Hello, PQC!";
pqcp_mldsa_sign(PQCP_MLDSA_65, sk, msg, sizeof(msg)-1, NULL, 0, sig);

/* Verify signature */
int ret = pqcp_mldsa_verify(PQCP_MLDSA_65, pk, msg, sizeof(msg)-1, NULL, 0, sig);
/* ret == PQCP_MLDSA_SUCCESS if valid */
```

### Streaming ML-DSA (Large Messages)

```c
#include <pqcp_zephyr/mldsa.h>

/* Allocate context buffer */
static uint8_t ctx_buffer[PQCP_MLDSA_STREAM_CTX_SIZE];
pqcp_mldsa_stream_ctx_t *ctx = (pqcp_mldsa_stream_ctx_t *)ctx_buffer;

/* Initialize streaming signing */
pqcp_mldsa_sign_stream_init(ctx, PQCP_MLDSA_65, sk, NULL, 0);

/* Feed data in chunks */
while (more_data) {
    pqcp_mldsa_sign_stream_update(ctx, chunk, chunk_len);
}

/* Finalize and get signature */
static uint8_t sig[PQCP_MLDSA_SIG_SIZE_MAX];
pqcp_mldsa_sign_stream_final(ctx, sig);
```

### Custom RNG Registration

```c
#include <pqcp_zephyr/rng.h>

static int my_rng_get_bytes(void *ctx, uint8_t *out, size_t len)
{
    /* Your RNG implementation */
    return 0;
}

static struct pqcp_rng_iface my_rng = {
    .get_bytes = my_rng_get_bytes,
    .ctx = NULL,
};

void init(void)
{
    pqcp_rng_register(&my_rng);
}
```

## Running Benchmarks

### Quick Benchmark

```bash
python scripts/run_benchmarks.py \
  --board qemu_x86_64 \
  --profile MCU_MINIMAL \
  --sample pqcp_basic_kem \
  --output benchmark_results/quick
```

### Curated Benchmark Matrix

```bash
python scripts/run_benchmarks.py --benchmark-matrix
```

### Profile Validation Matrix

```bash
python scripts/run_benchmarks.py --profile-validation
```

### Custom Matrix File

```bash
python scripts/run_benchmarks.py --config scripts/benchmark_matrix.json
```

### Filtering the Curated Matrices

The benchmark runner accepts the same `--board`, `--profile`, and `--sample`
filters for curated JSON matrices as it does for ad-hoc runs. Backend-policy
comparison runs also accept `--backend-policy` / `--backend-policies`. This
makes it easy to iterate on a single entry without copying or editing the
matrix file.

```bash
# Run just one curated benchmark entry
python scripts/run_benchmarks.py \
  --benchmark-matrix \
  --board qemu_x86_64 \
  --profile MCU_MINIMAL \
  --sample pqcp_basic_kem

# Run only the protocol-oriented benchmark entries
python scripts/run_benchmarks.py --benchmark-matrix --protocol-only

# Run only primitive-oriented entries
python scripts/run_benchmarks.py --benchmark-matrix --skip-protocol

# Smoke-check one profile-validation entry without launching QEMU
python scripts/run_benchmarks.py \
  --profile-validation \
  --board qemu_x86_64 \
  --profile MCU_MINIMAL \
  --sample ztest_rng \
  --build-only

# Run only the forced-native rows from the cost-of-assurance matrix
python scripts/run_benchmarks.py \
  --cost-of-assurance-matrix \
  --backend-policy force_native
```

### Protocol Benchmark Sample

```bash
west build -p always -b qemu_x86_64 samples/pqcp_bench_protocol
west build -t run
```

The protocol benchmark sample reuses the shared TLS self-test harness and emits
`PQCP_METRIC` lines for:

- total handshake latency
- ML-DSA authentication stage time
- ML-KEM key exchange stage time
- derived provider/framework overhead after subtracting the direct ML-KEM and
  ML-DSA stage timings
- certificate and key-exchange payload bytes plus transport-overhead bytes
- client/server payload sizes
- transcript bytes
- packet estimates
- stack and working-set usage where available

To add lightweight RTOS-aware context during manual protocol runs, enable the
sample overlay:

```bash
west build -p always -b qemu_x86_64 samples/pqcp_bench_protocol -- \
  -DOVERLAY_CONFIG=overlay-rtos-metrics.conf
west build -t run
```

That overlay keeps the normal benchmark path intact but adds opt-in
`PQCP_METRIC` handshake rows for:

- `rtos_isr_count`: periodic timer expiries observed during the handshake
- `rtos_yield_count`: background load-thread yields during the run
- `rtos_jitter_p50`, `rtos_jitter_p90`, `rtos_jitter_p99`: wake-up jitter of
  the low-priority load thread in microseconds

The runner:

- auto-discovers a working `west` command
- injects this module via `-DZEPHYR_EXTRA_MODULES=...`
- builds each board/profile/sample combination into its own build directory
- captures per-run build logs and runtime logs
- parses each run with `scripts/parse_logs.py`
- writes consolidated CSV/JSON datasets for analysis
- strips common host compiler environment variables such as `CFLAGS`,
  `CXXFLAGS`, `CPPFLAGS`, `LDFLAGS`, `CPATH`, and `SDKROOT` before invoking
  `west`, which avoids host toolchain leakage into Zephyr builds
- exits non-zero when any selected build/run fails, while still succeeding for
  build-only or validation-only matrices that intentionally emit no metrics

### Output Layout

By default results are written under `benchmark_results/`:

```text
benchmark_results/
├── consolidated_metrics.csv
├── consolidated_metrics.json
├── all_results.json
├── runs.json
├── build/
│   └── <run-id>/...
└── runs/
    └── <run-id>/
        ├── build.log
        ├── run.log
        ├── run_metrics.csv
        ├── run_primitives.csv
        ├── run_protocols.csv
        └── run_summary.txt
```

### Matrix Configuration

The repository includes two machine-readable configuration files:

- `scripts/benchmark_matrix.json`: curated benchmark runs for thesis and performance data collection, keeping at least one primitive-oriented entry per profile plus protocol/TLS-oriented coverage where that profile supports it
- `scripts/cost_of_assurance_matrix.json`: curated cost-of-assurance comparison runs for runnable QEMU PQCP-vs-baseline experiments and build-only MCU footprint captures
- `scripts/profile_validation_matrix.json`: recommended board/test coverage per profile for humans and CI, including the explicit `mps2/an385` Cortex-M no-entropy validation path

### Cost-of-Assurance Matrix

The repository now includes an opt-in cost-of-assurance matrix that measures the
cost of using the currently supported PQCP backend policies under identical
Zephyr builds. Each run now carries:

- `implementation`: the cryptographic provider family. Today this is always
  `pqcp` for the production implementation family and `baseline` for the
  QEMU-only clean reference comparator.
- `backend`: the backend-selection policy within that implementation family.
- `run_mode`: whether the row is a fully runnable benchmark (`run`) or a
  build-only footprint capture (`build_only`).

- `auto`: the default target-dependent PQCP backend policy
- `force_c`: the portable C backend forced on
- `force_native`: the native backend forced on

This is the in-tree "cost of assurance" comparison that can be automated today.
The curated QEMU matrix now includes:

- `implementation=pqcp` rows using the normal PQCP wrappers and backend-policy
  switches (`auto`, `force_c`, `force_native`)
- `implementation=baseline` rows using a vendored PQClean-derived clean
  reference provider for ML-KEM-512 / ML-KEM-768 and ML-DSA-65 / ML-DSA-87 on
  `qemu_x86_64`

That means the QEMU cost-of-assurance flow can now compare PQCP against a real
second implementation family instead of only comparing PQCP backend variants to
each other.

Run the curated matrix with:

```bash
python scripts/run_benchmarks.py \
  --cost-of-assurance-matrix \
  --output benchmark_results/cost-of-assurance
```

Useful filtered variants:

```bash
# Only the runnable QEMU rows (PQCP + baseline)
python scripts/run_benchmarks.py \
  --cost-of-assurance-matrix \
  --board qemu_x86_64

# Only the real-board STM32H7 build-only footprint rows
python scripts/run_benchmarks.py \
  --cost-of-assurance-matrix \
  --board nucleo_h743zi
```

The curated matrix currently contains:

- fully runnable `qemu_x86_64` rows for primitive and protocol comparisons,
  including `implementation=baseline` clean-reference rows for ML-KEM-768,
  ML-KEM-512, ML-DSA-65, ML-DSA-87, the ML-KEM-768 + ML-DSA-65 protocol suite,
  and the single-level ML-KEM-512 + ML-DSA-87 protocol benchmark
- build-only `nucleo_h743zi` rows that capture real MCU footprint and code-size
  deltas without claiming hardware runtime measurements
- analysis-only `COA_QEMU_SINGLE_LEVEL` rows that override the sample defaults
  without using the production profile `select` paths, so extra QEMU comparison
  levels do not silently change the semantics of `MCU_MINIMAL`, `GATEWAY`, or
  `NATIVE_LAB`
- analysis-only `COA_MCU_SINGLE_LEVEL` rows that do the same for build-only MCU
  footprint captures, so the ML-KEM-512 + ML-DSA-87 protocol build is labeled
  honestly instead of masquerading as `MCU_MINIMAL`

The curated protocol rows intentionally enable
`samples/pqcp_bench_protocol/overlay-rtos-metrics.conf`, so
`cost_of_assurance_protocols.csv` includes the RTOS load counters, jitter
percentiles, and TLS layer-decomposition fields for both
`implementation=pqcp` and `implementation=baseline`.

#### MCU protocol footprint

For the current `nucleo_h743zi` build-only protocol slice, the default
`implementation=pqcp`, `backend=auto` rows land at `rom_bytes=61176` and
`ram_bytes=175257` for the production-style ML-KEM-768 + ML-DSA-65 build, and
`rom_bytes=61068` plus `ram_bytes=240793` for the analysis-only ML-KEM-512 +
ML-DSA-87 build. Those numbers come directly from
`cost_of_assurance_builds.csv`, and the current `force_c` rows match them on
this board, so the builds CSV is the right place to watch MCU protocol
footprints evolve without pretending we already have production-grade runtime
measurements on hardware.

For manual confirmation, the two protocol footprint configurations are:

```bash
west build -p always -b nucleo_h743zi samples/pqcp_bench_protocol --cmake-only -- \
  -DOVERLAY_CONFIG=overlay-rtos-metrics.conf

west build -p always -b nucleo_h743zi samples/pqcp_bench_protocol --cmake-only -- \
  -DOVERLAY_CONFIG=overlay-rtos-metrics.conf \
  -DCONFIG_PQCP_MLKEM_LEVEL_512=y \
  -DCONFIG_PQCP_MLKEM_LEVEL_768=n \
  -DCONFIG_PQCP_MLKEM_LEVEL_1024=n \
  -DCONFIG_PQCP_MLDSA_LEVEL_44=n \
  -DCONFIG_PQCP_MLDSA_LEVEL_65=n \
  -DCONFIG_PQCP_MLDSA_LEVEL_87=y \
  -DCONFIG_MAIN_STACK_SIZE=196608
```

`python scripts/release_check.py` now runs both of those
`nucleo_h743zi` protocol configurations as `west build --cmake-only` steps, so
the release path keeps a lightweight check on the real-MCU protocol footprint
lane even though hosted CI still treats those rows as build-only analysis data.

The `mps2/an385` sample path is intentionally not part of the curated
cost-of-assurance matrix yet. Those samples currently depend on a production
entropy-backed RNG path that the board does not provide, and the project keeps
deterministic test RNG isolated from production-oriented comparison runs.

Each run carries `implementation`, `backend`, and `run_mode` fields in
`runs.json`, `consolidated_metrics.json`, and `consolidated_metrics.csv`, so
the raw metric rows are already keyed by `(board, profile, sample,
implementation, backend, algorithm, level)`.

Older artifact directories that predate this schema still summarize cleanly:
the summarizer falls back to the legacy `build_only` flag when `run_mode` is
not present in `runs.json`.

To flatten those raw rows into comparison-oriented CSVs, run:

```bash
python scripts/summarize_cost_of_assurance.py \
  --input-dir benchmark_results/cost-of-assurance
```

That produces:

- `cost_of_assurance_builds.csv`: one row per run with `board`, `profile`,
  `sample`, `implementation`, `backend`, `run_mode`, and build/resource columns
  such as `text_bytes`, `data_bytes`, `bss_bytes`, `total_bytes`, `rom_bytes`,
  and `ram_bytes`
- `cost_of_assurance_primitives.csv`: one row per primitive algorithm/level with
  columns such as `board`, `profile`, `sample`, `implementation`, `backend`,
  `algorithm`, `level`, `keygen_cycles`, `sign_cycles`, `total_stack`,
  `text_bytes`, `rom_bytes`, and `ram_bytes`
- `cost_of_assurance_protocols.csv`: one row per protocol suite block with
  columns such as `board`, `profile`, `sample`, `implementation`, `backend`,
  `suite`, `suite_mode`, `auth_algorithm`, `auth_level`,
  `key_exchange_algorithm`, `key_exchange_level`, `handshake_time`,
  `handshake_p50`, `handshake_p90`, `handshake_p99`,
  `handshake_transcript_bytes`, `handshake_packets`, `auth_time`,
  `key_exchange_time`, `handshake_provider_overhead`,
  `handshake_certificate_bytes`, `handshake_key_exchange_bytes`,
  `handshake_transport_overhead_bytes`, `handshake_rtos_isr_count`,
  `handshake_rtos_yield_count`, `handshake_rtos_jitter_p50`,
  `handshake_rtos_jitter_p90`, `handshake_rtos_jitter_p99`, `rom_bytes`, and
  `ram_bytes`

Example interpretation:

```text
cost_of_assurance_builds.csv
board,profile,sample,implementation,backend,run_mode,text_bytes,rom_bytes,ram_bytes
nucleo_h743zi,MCU_MINIMAL,pqcp_basic_kem,pqcp,force_c,build_only,<text>,<rom>,<ram>

cost_of_assurance_protocols.csv
board,profile,sample,implementation,backend,suite,suite_mode,handshake_time,auth_time,key_exchange_time,handshake_provider_overhead
qemu_x86_64,NATIVE_LAB,pqcp_bench_protocol,pqcp,force_native,MLKEM768+MLDSA65,pure_pq,<time>,<auth>,<kex>,<provider_us>
```

The checked-in QEMU smoke for Extended Checks also reads
`scripts/qemu_cost_of_assurance_regression.json`, which defines conservative
PQCP-vs-baseline ratio limits for ML-KEM-768, ML-KEM-512, ML-DSA-65, and
ML-DSA-87 primitive rows plus the ML-KEM-768 + ML-DSA-65 and ML-KEM-512 +
ML-DSA-87 protocol rows. The protocol guardrails now cover not just handshake
latency and ROM/RAM, but also `handshake_provider_overhead`,
`handshake_transport_overhead_bytes`, and `handshake_rtos_jitter_p90`. Those
thresholds are intentionally loose: they are there to catch obvious
catastrophes such as a multi-x slowdown or a footprint explosion, not to act as
a precise performance benchmark gate. For the RTOS/TLS decomposition fields the
checked-in regression file now uses both relative and absolute ceilings, so a
run can fail either because PQCP grew far beyond the baseline provider or
because the raw provider-overhead / transport-overhead / p90 jitter numbers
blew past a conservative upper bound.

For cost-of-assurance runs that do not invoke Zephyr's dedicated `rom_report` and
`ram_report` targets, the runner still records `rom_bytes` and `ram_bytes` using
the standard Zephyr section approximation (`rom = text + data`, `ram = data +
bss`) so board-to-board build-footprint rows stay self-contained.

Use the existing profile-validation matrix and checked-in resource budgets for
policy-enforced MCU validation, and use the cost-of-assurance matrix when you
want reproducible backend-policy comparisons plus real-board build footprints.

Quick inspection patterns:

```bash
# Compare qemu_x86_64 primitive rows across backend policy
grep '^qemu_x86_64,MCU_MINIMAL,pqcp_basic_kem' \
  benchmark_results/cost-of-assurance/cost_of_assurance_primitives.csv

# Compare PQCP vs baseline for the same qemu_x86_64 primitive sample
grep '^qemu_x86_64,MCU_MINIMAL,pqcp_basic_sig' \
  benchmark_results/cost-of-assurance/cost_of_assurance_primitives.csv

# Inspect only build-only STM32H7 rows
grep '^nucleo_h743zi' \
  benchmark_results/cost-of-assurance/cost_of_assurance_builds.csv

# Inspect protocol overhead and optional RTOS metrics for the protocol sample
csvcut -c board,sample,backend,suite,handshake_provider_overhead,handshake_rtos_isr_count,handshake_rtos_jitter_p90 \
  benchmark_results/cost-of-assurance/cost_of_assurance_protocols.csv | \
  grep '^qemu_x86_64,pqcp_bench_protocol'

# If csvkit is available, compare qemu_x86_64 build footprints by backend
csvcut -c board,profile,sample,implementation,backend,run_mode,text_bytes,total_bytes \
  benchmark_results/cost-of-assurance/cost_of_assurance_builds.csv | \
  grep '^qemu_x86_64'
```

When the checked-in QEMU baseline or the PQCP implementation changes
intentionally, update `scripts/qemu_cost_of_assurance_regression.json` together
with the code change. Keep the ratio thresholds conservative, explain the reason
in the commit or changelog entry, and re-run:

```bash
python scripts/run_extended_checks.py \
  --strict \
  --run-cost-of-assurance-smoke
```

The `baseline` implementation in the matrix is strictly a QEMU-only comparison
provider. It exists to quantify the cost of assurance against a second
implementation family under the same Zephyr-facing APIs; it is not a supported
production provider, not part of the PSA validation path, and not intended for
MCU deployment.

### Resource Budget Enforcement

The curated profile-validation matrix also has an optional checked-in budget file
at `scripts/resource_budgets.json`. When passed to `scripts/run_benchmarks.py`,
the runner:

- extracts section-level `text/data/bss` figures from the built ELF using
  `objdump`
- runs Zephyr's `rom_report` and `ram_report` targets for matching entries
- emits `build` rows such as `rom_bytes` and `ram_bytes` in the consolidated
  metrics output
- fails non-zero if any matched run exceeds its configured ROM or RAM envelope

For example:

```bash
python scripts/run_benchmarks.py \
  --profile-validation \
  --board qemu_x86_64 \
  --build-only \
  --resource-budgets scripts/resource_budgets.json \
  --output benchmark_results/profile-budget-smoke
```

The checked-in budgets are based on the current Zephyr `v4.3.0` baseline builds
with modest headroom for toolchain and configuration drift. Update them
deliberately when a real feature change increases footprint, and keep the
profile matrix, README, and release checklist in sync when doing so.

### Profile Cookbook

### Production Profiles

The project keeps the production profile story deliberately explicit:

| Profile | Status | Intended use | Notes |
|---------|--------|--------------|-------|
| `MCU_MINIMAL` | Production-supported | Resource-constrained MCU firmware | Single-level ML-KEM-768 + ML-DSA-65 with Zephyr entropy RNG and no lab/test features enabled by default. |
| `GATEWAY` | Production-supported | Gateway-class devices with more memory | Multi-level ML-KEM / ML-DSA plus PSA-driver support and streaming enabled for richer integrations. |
| `NATIVE_LAB` | Lab/test only | Desktop, QEMU, ACVP, benchmarking, and development workflows | Enables broader benchmarking and lab-oriented workflows; not the profile to ship verbatim into production firmware. |
| `COA_QEMU_SINGLE_LEVEL` | Analysis-only runner label | Cost-of-assurance QEMU experiments | Not a Kconfig profile at all. This runner-only label exists so the comparison matrix can switch single levels without mutating the production profile `select` behavior. |
| `COA_MCU_SINGLE_LEVEL` | Analysis-only runner label | Cost-of-assurance MCU build-only experiments | Also not a Kconfig profile. It exists so build-only MCU footprint rows can pin a single protocol suite such as ML-KEM-512 + ML-DSA-87 without pretending that `MCU_MINIMAL` changed. |

Recommended production defaults:

- Constrained MCU products: start from `MCU_MINIMAL`, keep Zephyr entropy or PSA RNG, and stay on ML-KEM-768 + ML-DSA-65 unless a documented product requirement pushes you higher.
- Gateway-style products: start from `GATEWAY`, keep PSA enabled, and selectively trim unused levels only after validating the new footprint against `scripts/resource_budgets.json`.
- ACVP, comparative benchmarking, and host validation: use `NATIVE_LAB` or the dedicated cost-of-assurance matrix paths instead of trying to repurpose production profiles.

Common profile-oriented invocations:

```bash
# Conservative MCU-oriented build
west build -p always -b qemu_x86_64 samples/pqcp_basic_kem -- \
  -DCONFIG_PQCP_PROFILE_MCU_MINIMAL=y

# Conservative Cortex-M validation build without hardware entropy
west build -p always -b mps2/an385 tests/ztest_primitive -- \
  -DOVERLAY_CONFIG=overlay-no-entropy.conf \
  -DCONFIG_PQCP_PROFILE_MCU_MINIMAL=y

# Real STM32H7 MCU build-only validation path used in extended checks
west build -p always -b nucleo_h743zi samples/pqcp_basic_kem -- \
  -DCONFIG_PQCP_PROFILE_MCU_MINIMAL=y

# PSA/TLS-capable gateway-style build
west build -p always -b qemu_x86_64 samples/pqcp_tls_mbedtls_psa -- \
  -DOVERLAY_CONFIG=overlay-selftest.conf \
  -DCONFIG_PQCP_PROFILE_GATEWAY=y

# Lab-style build with deterministic KATs and protocol benchmarking
python scripts/run_benchmarks.py \
  --benchmark-matrix \
  --profile NATIVE_LAB
```

### Hardware Validation

CI keeps `nucleo_h743zi` in the build-only lane so hosted runs stay bounded,
but it is the recommended lab board for a real MCU validation pass.

For the primitive sample:

```bash
west build -p always -b nucleo_h743zi samples/pqcp_basic_kem -- \
  -DZEPHYR_EXTRA_MODULES="$PWD" \
  -DCONFIG_PQCP_PROFILE_MCU_MINIMAL=y
west flash
```

Then attach to the board's USB CDC ACM console at 115200 baud and look for
`PQCP_METRIC,primitive,...` lines from the sample.

For the primitive regression ztest:

```bash
west build -p always -b nucleo_h743zi tests/ztest_primitive -- \
  -DZEPHYR_EXTRA_MODULES="$PWD" \
  -DCONFIG_PQCP_PROFILE_MCU_MINIMAL=y
west flash
```

Treat `PROJECT EXECUTION SUCCESSFUL` on the serial console as the pass signal.
These hardware runs are recommended for local lab validation only; GitHub
Actions intentionally keeps this board in build-only mode.

### Metric Format

Benchmark logs use two formats:

**PQCP_METRIC format (new, recommended):**
```
PQCP_METRIC,primitive,keygen,MLKEM,768,cycles,3120,cyc
PQCP_METRIC,primitive,encaps,MLKEM,768,stack,18392,B
PQCP_METRIC,primitive,sign,MLDSA,65,time,10,ms
PQCP_METRIC,protocol,handshake,TLS13,0,transcript_bytes,6661,B
```

**Legacy PRIM format:**
```
PRIM,MLKEM768,KEYGEN,cycles=450000,stack=2048,text=8192,bss=256
```

Use `scripts/parse_logs.py` to convert logs to CSV:
```bash
python scripts/parse_logs.py sample_output.log -o results/
```

## Serial ACVP Interface

The `pqcp_serial_acvp` sample provides a UART-based interface for running ACVP test vectors and KATs.

The wire-format response serializer is shared by the sample and tests through
`pqcp_acvp_format_response_line()` in
`include/pqcp_zephyr/acvp_cmd.h`, so the documented `RESULT:*` / `ERROR:*`
grammar is enforced in one place.

For external-tool integration, the repository also includes
`scripts/run_acvp_serial_session.py`, a small host-side smoke driver that can
either talk to a real serial port or launch the sample through QEMU/stdin.
It tolerates prompt prefixes and unrelated debug lines around the stable
`RESULT:*` / `ERROR:*` records, which makes it friendlier to real lab logs.

### Building

```bash
west build -p always -b qemu_x86_64 samples/pqcp_serial_acvp
west build -t run
```

### Protocol Format

Commands are sent as colon-separated strings:
```
CMD:ALG:LEVEL:HEX_DATA
```

### Supported Commands

| Command | Format | Description |
|---------|--------|-------------|
| SEED | `SEED:DRBG:0:<hexseed>` | Seed deterministic RNG |
| KEYGEN | `KEYGEN:MLKEM:768:` | Generate ML-KEM keypair |
| ENCAPS | `ENCAPS:MLKEM:768:<pk_hex>` | Encapsulate with public key |
| DECAPS | `DECAPS:MLKEM:768:<ct_sk_hex>` | Decapsulate ciphertext |
| KEYGEN | `KEYGEN:MLDSA:65:` | Generate ML-DSA keypair |
| SIGN | `SIGN:MLDSA:65:<sk_msg_hex>` | Sign message |
| VERIFY | `VERIFY:MLDSA:65:<pk_msg_sig_hex>` | Verify signature |
| SELFTEST | `SELFTEST::` | Run internal self-test |
| HELP | `HELP::` | Show command help |

`HELP` and `SELFTEST` are intentionally accepted only in their exact public
forms (`HELP`, `HELP::`, `SELFTEST`, `SELFTEST::`). Malformed variants such as
`HELP:` are rejected with `ERROR:INVALID_CMD`, which keeps the serial harness
more predictable under noisy lab tooling or partial-line glitches.

### Response Format

```
RESULT:<hex_data>  # Success with payload
RESULT:OK          # Success without payload
RESULT:INVALID     # Signature verification failed cleanly
ERROR:<error_code> # Error (stable machine-readable code)
```

For compatibility, error responses stay on the `ERROR:<code>` wire format. The
`<code>` token is stable and suitable for host-side parsing.

### Error Codes

Common error codes emitted by the ACVP sample and command library:

- `INVALID_HEX`
- `INVALID_LEVEL`
- `INVALID_ALG`
- `INVALID_CMD`
- `MISSING_ARGS`
- `WRONG_SIZE`
- `BUFFER_TOO_SMALL`
- `KEYGEN_FAILED`
- `ENCAPS_FAILED`
- `DECAPS_FAILED`
- `SIGN_FAILED`
- `VERIFY_FAILED`
- `SEED_FAILED`
- `NOT_ENABLED`

The shipped negative-scenario file at `scripts/acvp_negative_scenarios.json`
now exercises truncated commands, strict `HELP` form handling, wrong-size
signing input, invalid seed hex, unsupported levels, truncated verify payloads,
invalid ML-DSA sign hex, and extra-field framing errors through the full QEMU
serial sample path.

The ML-DSA `SIGN` / `VERIFY` command family is also bounded by
`PQCP_ACVP_MAX_MESSAGE_BYTES` in the shared command library. That keeps the
serial harness from silently turning into an unbounded message tunnel while
still allowing realistic lab-side sign/verify payloads.

The public ACVP command API is declared in
`include/pqcp_zephyr/acvp_cmd.h` and includes helpers for:

- bounded response initialization (`pqcp_acvp_response_init`)
- command execution (`pqcp_acvp_process_command`)
- stable line serialization (`pqcp_acvp_format_response_line`)
- shared hex encoding/decoding utilities used by the serial sample and ztests

### Example Session

```
> SELFTEST::
RESULT:OK

> HELP::
RESULT:OK

> SEED:DRBG:0:0102030405060708090a0b0c0d0e0f10...
RESULT:OK

> KEYGEN:MLKEM:768:
RESULT:<pk_hex><sk_hex>

> ENCAPS:MLKEM:768:<pk_hex>
RESULT:<ct_hex><ss_hex>

> DECAPS:MLKEM:768:<ct_hex><sk_hex>
RESULT:<ss_hex>

> KEYGEN:MLDSA:65:
RESULT:<pk_hex><sk_hex>

> SIGN:MLDSA:65:<sk_hex><msg_hex>
RESULT:<sig_hex>

> VERIFY:MLDSA:65:<pk_hex><msg_hex><sig_hex>
RESULT:OK

> VERIFY:MLDSA:65:<pk_hex><msg_hex><tampered_sig_hex>
RESULT:INVALID
```

If a command line exceeds the input buffer, the sample rejects it cleanly with:

```
ERROR:BUFFER_TOO_SMALL
```

### Host Script Example

```python
import serial

ser = serial.Serial('/dev/ttyUSB0', 115200)

def acvp_command(cmd):
    ser.write((cmd + '\n').encode())
    return ser.readline().decode().strip()

# Seed RNG
result = acvp_command('SEED:DRBG:0:' + '00' * 48)

# Generate keypair
result = acvp_command('KEYGEN:MLKEM:768:')
pk_sk = bytes.fromhex(result.split(':')[1])
```

### Host Driver Smoke Script

QEMU/stdin example:

```bash
west build -p always -b qemu_x86_64 samples/pqcp_serial_acvp

python scripts/run_acvp_serial_session.py \
  --cwd /path/to/zephyrproject \
  --run-command "west build -d build -t run" \
  --json-out acvp-session.json \
  --transcript-out acvp-session.log
```

Real serial-port example:

```bash
python -m pip install pyserial

python scripts/run_acvp_serial_session.py \
  --serial-port /dev/ttyUSB0 \
  --baudrate 115200 \
  --json-out acvp-session.json
```

The script performs a deterministic smoke session covering:

- `SELFTEST`
- `SEED`
- ML-KEM `KEYGEN` / `ENCAPS` / `DECAPS`
- ML-DSA `KEYGEN` / `SIGN` / `VERIFY`
- a tampered-signature `VERIFY` that must return `RESULT:INVALID`

### Scenario-Driven Host Runs

For repeatable lab sessions, the host driver can also read a small JSON
scenario file:

```bash
python scripts/run_acvp_serial_session.py \
  --cwd /path/to/zephyrproject \
  --run-command "west build -d build -t run" \
  --scenario-file scripts/acvp_smoke_scenarios.json \
  --json-out acvp-session.json
```

The example `scripts/acvp_smoke_scenarios.json` format is:

```json
{
  "scenarios": [
    {
      "name": "default-l3-seed-a",
      "kem_level": 768,
      "sig_level": 65,
      "seed_hex": "...",
      "message_hex": "...",
      "step_expectations": {
        "VERIFY_MLDSA_TAMPERED": {
          "status": "invalid",
          "response": "RESULT:INVALID"
        }
      },
      "expected_errors": [
        {
          "name": "INVALID_SEED_HEX",
          "command": "SEED:DRBG:0:abc",
          "response": "ERROR:INVALID_HEX"
        }
      ]
    }
  ]
}
```

Each scenario summary includes:

- the requested ML-KEM / ML-DSA levels
- derived key, ciphertext, and signature sizes
- per-command status (`ok`, `payload`, `invalid`, or `error`)
- optional expectation metadata and mismatch markers when a scenario defines
  `step_expectations` or `expected_errors`
- the raw command/response transcript entries

The shipped `scripts/acvp_negative_scenarios.json` file demonstrates how to
exercise negative-path commands while keeping the stable `RESULT:*` /
`ERROR:*` grammar intact. The host driver exits non-zero whenever an expected
outcome does not match what the target returned.

To regression-check the parser itself without booting Zephyr, run:

```bash
python scripts/run_acvp_serial_session.py --self-test
```

## Security Considerations

### RNG Safety

**CRITICAL**: This module uses `sys_csrand_get()` for all cryptographic operations. This is the ONLY safe Zephyr RNG for cryptography. Never use `sys_rand_get()` or `sys_rand32_get()` for security-sensitive operations.

### Deterministic Mode

The `CONFIG_PQCP_RNG_DETERMINISTIC_TEST` option enables deterministic RNG for testing (KAT, ACVP). This MUST NEVER be enabled in production:

```
# WARNING: Test builds only!
CONFIG_PQCP_RNG_DETERMINISTIC_TEST=y
```

### Memory Considerations

PQC algorithms require significant stack space:

| Algorithm   | Stack (keygen) | Stack (sign/encaps) |
|-------------|----------------|---------------------|
| ML-KEM-768  | ~18 KB         | ~16 KB              |
| ML-KEM-1024 | ~24 KB         | ~20 KB              |
| ML-DSA-65   | ~86 KB         | ~80 KB              |
| ML-DSA-87   | ~100 KB        | ~95 KB              |

Configure adequate stack sizes:

```
CONFIG_MAIN_STACK_SIZE=131072  # 128KB for ML-DSA-65
```

### Stable API Surface

Headers intended for external application use and versioned dependency:

- `include/pqcp_zephyr/mlkem.h`: stable ML-KEM keypair / encapsulate / decapsulate API and size helpers.
- `include/pqcp_zephyr/mldsa.h`: stable ML-DSA sign / verify / hash / streaming API plus size helpers.
- `include/pqcp_zephyr/rng.h`: stable RNG abstraction hooks for Zephyr entropy, PSA RNG, or a caller-supplied RNG backend.
- `include/pqcp_zephyr/version.h`: stable version macros such as `PQCP_VERSION_STRING` for downstream integration and release pinning.

Headers that are intentionally more specialized and should be treated as
lab-oriented or internal-module surfaces unless you own both sides of the
integration:

- `include/pqcp_zephyr/acvp_cmd.h`: stable wire grammar for the serial ACVP harness, but still a lab/test command API rather than a production transport interface.
- `include/pqcp_zephyr/bench.h`: structured `PQCP_METRIC` logging helpers used by samples, profiling, and thesis-style analysis flows.
- `include/pqcp_zephyr/tls_selftest.h`: reusable TLS self-test helpers shared by the offline TLS sample and ztests; suitable for harness integration, but still primarily a validation surface rather than a general-purpose application API.

If you change a stable header, public Kconfig option, or production profile
meaning, update this README, the affected samples/tests, and the relevant
cost-of-assurance or resource-budget documentation in the same change.

### Release Checklist / v1.0 Criteria

Before tagging a release, we should be able to say all of the following are
true:

- `MCU_MINIMAL` and `GATEWAY` still match the documented production-supported
  profile intent, while `NATIVE_LAB`, ACVP helpers, and the QEMU-only
  `baseline` provider remain lab/analysis-only.
- The stable external API surface is still limited to
  `include/pqcp_zephyr/mlkem.h`, `include/pqcp_zephyr/mldsa.h`,
  `include/pqcp_zephyr/rng.h`, and `include/pqcp_zephyr/version.h`, with any
  change shipped alongside updated samples, tests, and README guidance.
- Fast CI passes, including the existing ztests, ACVP/QEMU smokes, and the
  profile-validation budget checks.
- `python scripts/run_extended_checks.py --strict` passes, including the
  focused static-analysis and release-metadata checks.
- `python scripts/run_extended_checks.py --strict --run-cost-of-assurance-smoke`
  passes, proving that the PQCP-vs-baseline QEMU comparison slice still builds,
  summarizes, and stays within the conservative regression guardrails.
- `python scripts/release_check.py` passes before tagging, so the strict
  extended checks, cost-of-assurance smoke, ACVP ztest run, and budget-enforced
  profile validation have all been exercised in one repeatable sequence.
- The baseline provider is still clearly documented as QEMU-only and
  benchmarking-only. It is never a supported production provider and must not
  be used to justify deterministic RNG or MCU-only shortcuts in production
  firmware.

## Integration with External Libraries

### mlkem-native Setup

```bash
cd ext/
git clone https://github.com/pq-code-package/mlkem-native
```

### mldsa-native Setup

```bash
cd ext/
git clone https://github.com/pq-code-package/mldsa-native
```

The module detects these libraries via `__has_include()` and switches from stub implementations to real PQC code.

## Testing

```bash
# Run primitive tests
west build -p always -b qemu_x86_64 tests/ztest_primitive
west build -t run

# Run primitive tests with PSA drivers
west build -p always -b qemu_x86_64 tests/ztest_primitive -- -DOVERLAY_CONFIG=overlay-psa.conf
west build -t run

# Run RNG tests
west build -p always -b qemu_x86_64 tests/ztest_rng
west build -t run

# Run ACVP command-library tests
west build -p always -b qemu_x86_64 tests/ztest_acvp_serial
west build -t run

# Run shared TLS self-test helper tests
west build -p always -b qemu_x86_64 tests/ztest_tls_selftest
west build -t run

# Optional stress-oriented ACVP parser coverage
west build -p always -b qemu_x86_64 tests/ztest_acvp_serial -- \
  -DOVERLAY_CONFIG=overlay-fuzz.conf
west build -t run

# Optional stress-oriented TLS self-test coverage
west build -p always -b qemu_x86_64 tests/ztest_tls_selftest -- \
  -DOVERLAY_CONFIG=overlay-fuzz.conf
west build -t run

# Optional ASan/UBSan coverage on native_sim/native/64
python scripts/run_sanitizer_checks.py \
  --west-root /path/to/zephyrproject \
  --module-path "$PWD"

# Run primitive tests on mps2/an385 without entropy hardware
west build -p always -b mps2/an385 tests/ztest_primitive -- -DOVERLAY_CONFIG=overlay-no-entropy.conf
west build -t run
```

`CONFIG_PQCP_FUZZ_TESTS` is disabled by default and only enabled by the
`overlay-fuzz.conf` test overlays. It is intended for local hardening runs and
extended workflows, not for the default smoke CI path.

The optional ACVP fuzz overlay keeps the normal command-coverage suite intact
while adding randomized valid and invalid command sequences plus direct wire
format stress checks. The TLS fuzz overlay adds repeated self-test runs across
the enabled KEM/DSA levels to catch state-leak and reinitialization regressions
without affecting the default qemu smoke path.

The sanitizer runner uses dedicated `overlay-sanitize.conf` files for
`tests/ztest_acvp_serial` and `tests/ztest_tls_selftest` on
`native_sim/native/64`, which makes it easy to get ASan/UBSan coverage for the
highest-risk glue code without changing the default `qemu_x86_64` smoke flow.
Because Zephyr's POSIX/native architecture is Linux-only, this sanitizer helper
is intended for Linux hosts (including GitHub Actions) rather than macOS or
Windows shells.

## Shared Harness APIs

The shared ACVP and TLS helper APIs are declared in:

- `include/pqcp_zephyr/acvp_cmd.h`
- `include/pqcp_zephyr/tls_selftest.h`

The ACVP command header documents the lab/test-oriented serial-command helpers
used by:

- `samples/pqcp_serial_acvp`
- `tests/ztest_acvp_serial`

It provides:

- `pqcp_acvp_response_init()` for bounded caller-owned response buffers
- `pqcp_acvp_result_str()` and `pqcp_acvp_format_response_line()` for stable
  `RESULT:*` / `ERROR:*` wire serialization
- `pqcp_acvp_process_command()` for shared command parsing/execution
- shared hex helpers used by both the sample and the tests

The TLS helper header documents the shared offline self-test and benchmark flow
used by:

- `samples/pqcp_tls_mbedtls_psa`
- `samples/pqcp_bench_protocol`
- `tests/ztest_tls_selftest`

It provides:

- `pqcp_tls_selftest_init_psa()` for explicit PSA setup checks
- `pqcp_tls_selftest_run()` for offline TLS/PSA/PQCP self-test and protocol-benchmark flows
- `pqcp_tls_selftest_log_metrics()` for emitting stable `PQCP_METRIC` records

These callers share the same report structure and metric names, which keeps the
protocol benchmark and TLS self-test paths aligned.

## Extended Checks

For slower pre-release or refactor-oriented checks, run:

```bash
python scripts/run_extended_checks.py \
  --west-root /path/to/zephyrproject \
  --module-path "$PWD" \
  --strict
```

This helper:

- configures a lightweight Zephyr target and writes a CMake graphviz file
- runs focused `cppcheck` analysis on the ACVP, TLS self-test, protocol bench,
  primitive benchmark, streaming helper, PSA driver glue, selected RNG wrapper
  sources, and the module header/version glue
- verifies that `PQCP_VERSION_STRING` and the top release entry in
  `CHANGELOG.md` stay in sync
- checks that the example west manifest snippet still reminds integrators to
  pin a tag or commit that matches `PQCP_VERSION_STRING` and `CHANGELOG.md`
- strips common host compiler environment variables before invoking `west`
- runs a tiny cost-of-assurance smoke on `qemu_x86_64` that exercises both the
  PQCP and baseline implementations for ML-KEM and ML-DSA, keeps the protocol
  path alive, and checks conservative PQCP-vs-baseline numeric guardrails from
  `scripts/qemu_cost_of_assurance_regression.json`

Use it before large refactors, before cutting a release, or when touching the
shared ACVP/TLS/benchmark infrastructure.

For memory-safety oriented hardening, pair it with the sanitizer runner:

```bash
python scripts/run_sanitizer_checks.py \
  --west-root /path/to/zephyrproject \
  --module-path "$PWD"
```

By default this builds and runs the ACVP and TLS harness ztests on
`native_sim/native/64` with ASan and UBSan enabled. Run it from Linux, or use
the manual `run_sanitizers` toggle in `.github/workflows/extended-checks.yml`.

To probe a newer Zephyr branch or tag before bumping the documented baseline,
run:

```bash
python scripts/run_extended_checks.py \
  --west-root /path/to/zephyrproject \
  --module-path "$PWD" \
  --zephyr-ref v4.4.0-rc1 \
  --skip-graphviz \
  --run-compatibility-smoke \
  --strict
```

That compatibility smoke builds a small, explicit set of PQCP targets against
the selected Zephyr ref and reports success or failure separately from the
static-analysis work. By default it covers the primitive, ACVP, and TLS
self-test harness targets on `qemu_x86_64`.

To probe both the default QEMU path and the STM32H7 build-only path for an
upcoming Zephyr revision, use:

```bash
python scripts/run_extended_checks.py \
  --west-root /path/to/zephyrproject \
  --module-path "$PWD" \
  --zephyr-ref v4.4.0-rc1 \
  --skip-graphviz \
  --run-compatibility-smoke \
  --compatibility-board-list qemu_x86_64,nucleo_h743zi \
  --strict
```

## CI

GitHub Actions coverage is defined in `.github/workflows/ci.yml`. The workflow
sets up a Zephyr workspace, installs the Zephyr SDK toolchains needed for
`qemu_x86_64`, and runs on `ubuntu-22.04` with Python 3.12 and Zephyr v4.3.0.
The fast CI path runs:

- `tests/ztest_rng`
- `tests/ztest_primitive`
- `tests/ztest_acvp_serial`
- `tests/ztest_tls_selftest`
- `samples/pqcp_basic_kem`
- `samples/pqcp_basic_sig`
- build-only `samples/pqcp_bench_protocol` for `nucleo_h743zi` in both the
  default ML-KEM-768 + ML-DSA-65 lane and the single-level ML-KEM-512 +
  ML-DSA-87 lane
- a filtered `--benchmark-matrix` smoke run
- a filtered `--profile-validation` build-only smoke run with
  `scripts/resource_budgets.json`

In addition, a `release-gate` advisory job now runs on every push to `main` and
every pull request targeting `main`. It executes `python scripts/release_check.py`
and uploads the resulting log/artifact bundle, including the structured
`release_check_results.xml` JUnit report, so maintainers can spot release
workflow regressions early without turning the full release sequence into a
brittle hard gate for every branch push.

The sample runs are bounded with `timeout` and checked for expected
`PQCP_METRIC` lines so CI can validate metric emission without waiting for QEMU
samples to exit on their own.

For deeper maintenance checks, `.github/workflows/extended-checks.yml` provides
a scheduled/manual workflow that runs `scripts/run_extended_checks.py` to:

- configure a lightweight Zephyr target and emit a CMake dependency graph
- run focused `cppcheck` analysis on the ACVP, TLS self-test, protocol bench,
  primitive benchmark, selected RNG wrappers, PSA driver glue, and primitive
  wrapper sources
- smoke the serial ACVP sample through the host-side driver script on
  `qemu_x86_64`
- enforce the checked-in ROM/RAM budgets for the full `qemu_x86_64`
  profile-validation matrix
- build-validate the `mps2/an385` MCU profile path through
  `tests/ztest_primitive` with `overlay-no-entropy.conf` and matching budgets

The advisory `release-gate` job in `.github/workflows/ci.yml` now runs
`python scripts/release_check.py` with a standalone `cppcheck` step before the
broader extended-checks sequence, so the uploaded JUnit report shows static
analysis as its own release criterion instead of burying it inside a larger job.
- build-validate the `nucleo_h743zi` MCU profile path through
  `tests/ztest_primitive` and `samples/pqcp_basic_kem`, again with matching
  resource budgets
- optionally probe a newer Zephyr ref by rebuilding the primitive, ACVP, and
  TLS self-test harnesses through the compatibility-smoke mode

When launched manually, the extended-checks workflow also accepts:

- a `zephyr_ref` input for trying a newer Zephyr tag/branch/commit
- a `run_sanitizers` toggle for native_sim ASan/UBSan coverage

If the manual `zephyr_ref` differs from the baseline `v4.3.0`, the workflow
also runs an explicit compatibility-smoke build step so Zephyr drift is called
out separately from the default static-analysis output.

## Releasing

Keep the next release notes in the `## [Unreleased]` block in
[`CHANGELOG.md`](/Users/angelostsanaktsidis/code/PQC/zephyr-ws/pqcp-zephyr-trust-stack/CHANGELOG.md).
Before tagging, run the full release gate locally:

```bash
python scripts/release_check.py
```

Then validate the full GitHub Actions release path without publishing:

```bash
gh workflow run release-dry-run.yml --ref main
```

Wait for `release-dry-run.yml` to complete successfully on `main`, then create
and push the annotated release tag:

```bash
git tag -a v1.0.0 -m "Release v1.0.0: publication-quality PQC stack"
git push origin v1.0.0
```

The tag-triggered workflow at
[`release.yml`](/Users/angelostsanaktsidis/code/PQC/zephyr-ws/pqcp-zephyr-trust-stack/.github/workflows/release.yml)
automatically:

- runs `python scripts/release_check.py` and stops the release if it fails;
- builds every sample and ztest on `qemu_x86_64`;
- uploads `release_check_results.xml`, `build_summary.txt`, the release log, and the per-build logs as workflow artifacts;
- creates a GitHub Release titled with the tag name and populated from the current `## [Unreleased]` changelog block.

The companion
[`release-dry-run.yml`](/Users/angelostsanaktsidis/code/PQC/zephyr-ws/pqcp-zephyr-trust-stack/.github/workflows/release-dry-run.yml)
workflow runs the same gate, QEMU builds, and changelog extraction steps
without publishing a GitHub Release. Use it to validate the release pipeline on
`main` before pushing any release tag.

Once the tagged release is out, move the `## [Unreleased]` content into a
versioned heading such as `## [0.9.0] - 2026-04-17`, add a fresh empty
`## [Unreleased]` section above it, and commit that rollover to start the next
cycle cleanly.

Fast CI is therefore pinned to a known-good baseline, while extended checks can
be used to probe upcoming Zephyr drift before it reaches downstream consumers.

## Release Metadata

Downstream consumers can track the formal module version through:

- `include/pqcp_zephyr/version.h`
- `CHANGELOG.md`

The current pre-release version is `0.9.0`, exported through both
`PQCP_ZEPHYR_VERSION_STRING` and the compatibility alias `PQCP_VERSION_STRING`.
The extended-checks helper verifies that the compatibility macro and the top
release entry in `CHANGELOG.md` stay aligned. It also checks that the README's
example west manifest snippet keeps the release pinning guidance intact for
integrators.

### Release Candidate Checklist

For a release-candidate pass, run the following sequence from the module root:

```bash
python scripts/run_extended_checks.py \
  --west-root /path/to/zephyrproject \
  --module-path "$PWD" \
  --strict

python scripts/run_benchmarks.py \
  --profile-validation \
  --build-only \
  --resource-budgets scripts/resource_budgets.json \
  --west-root /path/to/zephyrproject \
  --module-path "$PWD" \
  --output benchmark_results/profile-budget-rc

python scripts/run_extended_checks.py \
  --west-root /path/to/zephyrproject \
  --module-path "$PWD" \
  --zephyr-ref v4.4.0-rc1 \
  --skip-graphviz \
  --run-compatibility-smoke \
  --compatibility-board-list qemu_x86_64,nucleo_h743zi \
  --strict

python scripts/run_sanitizer_checks.py \
  --west-root /path/to/zephyrproject \
  --module-path "$PWD" \
  --build-only

west build -p always -d build-acvp-release -b qemu_x86_64 samples/pqcp_serial_acvp -- \
  -DZEPHYR_EXTRA_MODULES="$PWD"
python scripts/run_acvp_serial_session.py \
  --cwd /path/to/zephyrproject \
  --run-command "west build -d build-acvp-release -t run" \
  --scenario-file scripts/acvp_smoke_scenarios.json \
  --json-out acvp-release-smoke.json
```

## Zephyr Compatibility

The GitHub workflows currently validate this module against Zephyr `v4.3.0`.
That is the tested baseline for release-quality integration.

Nearby Zephyr revisions may also work, but they should be treated as
best-effort until they are exercised explicitly through local testing or the
manual `zephyr_ref` override in `.github/workflows/extended-checks.yml`.

For early drift checks against a newer tag or branch, use the compatibility
smoke mode shown in the Extended Checks section above.

## Sample Applications

| Sample | Description |
|--------|-------------|
| `pqcp_basic_kem` | Basic ML-KEM keygen/encap/decap demo with timing |
| `pqcp_basic_sig` | Basic ML-DSA keygen/sign/verify demo with timing |
| `pqcp_kat_deterministic` | Known Answer Tests using deterministic RNG |
| `pqcp_streaming_hash_mldsa` | Streaming signature for large messages |
| `pqcp_tls_mbedtls_psa` | TLS/PSA self-test path with structured metrics |
| `pqcp_bench_protocol` | Protocol benchmark sample using the shared TLS self-test harness |
| `pqcp_serial_acvp` | UART-based ACVP test interface |

```bash
# Build and run a sample
west build -p always -b qemu_x86_64 samples/pqcp_basic_kem
west build -t run
```

## References

- [FIPS 203 - ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 - ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [mlkem-native](https://github.com/pq-code-package/mlkem-native)
- [mldsa-native](https://github.com/pq-code-package/mldsa-native)
- [Zephyr Random Subsystem](https://docs.zephyrproject.org/latest/services/crypto/random/index.html)
- [TF-PSA-Crypto ML-DSA Driver](https://github.com/Mbed-TLS/TF-PSA-Crypto/issues/633)

## License

SPDX-License-Identifier: Apache-2.0

## Contributing

1. Fork and create a feature branch
2. Ensure all tests pass on `qemu_x86_64`
3. Add tests for new functionality
4. Submit a pull request

## Authors

- PQCP Zephyr Trust Stack Contributors
