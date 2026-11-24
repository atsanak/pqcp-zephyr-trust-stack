# Getting started

See the [README](../README.md) for the project overview.

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
west init -m https://github.com/atsanak/pqcp-zephyr-trust-stack my-workspace
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

### Consumer Integration

The repository-root manifest makes this project usable as the west manifest
repository for a clean consumer workspace:

```bash
west init -m https://github.com/atsanak/pqcp-zephyr-trust-stack my-workspace
cd my-workspace
west update
python3 pqcp-zephyr-trust-stack/scripts/consumer_smoke.py --module-mode manifest
```

After `west update`, the workspace layout is:

- `pqcp-zephyr-trust-stack/`: this module and its samples/tests
- `zephyr/`: the Zephyr tree imported by the manifest
- `modules/crypto/mlkem-native`: pinned ML-KEM backend
- `modules/crypto/mldsa-native`: pinned ML-DSA backend

Zephyr discovers the module through `pqcp-zephyr-trust-stack/zephyr/module.yml`,
which points Zephyr's module loader at this repository's top-level
`CMakeLists.txt` and `Kconfig`. Consumer applications do not need to copy
module CMake fragments when the project is present in the west workspace.

The release baseline encoded in `west.yml` is the pinned Zephyr revision
`684c9e8f32e4373a21098559f748f06915f950c9` (the Zephyr v4.4.0 release
commit). Newer Zephyr revisions may work, but treat them as compatibility
probes until they have been validated with `scripts/run_extended_checks.py`.

The minimum consumer validation build is the RNG ztest on `qemu_x86_64`.
`scripts/consumer_smoke.py --module-mode manifest` proves west/module.yml
discovery without injecting `ZEPHYR_EXTRA_MODULES`. For local development
checkouts that are not listed in the active west manifest, use
`--module-mode extra-module`. To use another target or board:

```bash
python3 pqcp-zephyr-trust-stack/scripts/consumer_smoke.py \
  --module-mode manifest \
  --board qemu_x86_64 \
  --target tests/ztest_acvp_serial
```

### Adding to Your Zephyr Project

**Option 1: Via west.yml**

```yaml
manifest:
  projects:
    - name: pqcp-zephyr-trust-stack
      url: https://github.com/atsanak/pqcp-zephyr-trust-stack
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
west init -m https://github.com/atsanak/pqcp-zephyr-trust-stack my-workspace
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

**PQC Fleet Trust Fabric:**
```bash
west build -p always -b qemu_x86_64 samples/pqcp_fleet_trust
west build -t run
```

The fleet sample also enables `CONFIG_PQCP_EDGE_SECURITY`, compiling the
allocation-free zero-trust edge plane. Applications include
`<pqcp_zephyr/edge_security.h>`, provide fixed-capacity arrays through
`pqcp_edge_runtime_storage`, and initialize the composed runtime with
`pqcp_edge_runtime_init()`. The runtime integrates service identity and
routing, policy admission, messaging, vault storage, incident response,
attestation, provenance, isolation, scheduling, SLA, configuration, and
compliance reporting without heap allocation.

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
west twister \
  -T tests/ \
  -p qemu_x86_64 \
  --build-only
```

To focus on just the PQCP-tagged scenarios, use Twister's tag filter:

```bash
west twister \
  -T tests/ \
  -p qemu_x86_64 \
  --build-only \
  -t pqcp
```

> If `west` is not on your `PATH`, substitute `python3 -m west twister ...`
> or the full path to the `west` binary in your Zephyr workspace's Python
> environment (typically `$ZEPHYR_BASE/../.venv/bin/west`).

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

## Zephyr Compatibility

The GitHub workflows currently validate this module against Zephyr `v4.4.0`
with Zephyr SDK `1.0.1`.
That is the tested baseline for release-quality integration.

Nearby Zephyr revisions may also work, but they should be treated as
best-effort until they are exercised explicitly through local testing or the
manual `zephyr_ref` override in `.github/workflows/extended-checks.yml`.

For early drift checks against a newer tag or branch, use the compatibility
smoke mode shown in the Extended Checks section above.
