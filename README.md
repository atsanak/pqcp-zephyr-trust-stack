# PQCP Zephyr Trust Stack

An out-of-tree Zephyr RTOS module providing first-class support for Post-Quantum Cryptography (PQC) using the PQ Code Package's `mlkem-native` (ML-KEM, FIPS-203) and `mldsa-native` (ML-DSA, FIPS-204) reference implementations.

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
│   └── parse_logs.py           # Log parsing to CSV
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
filters for curated JSON matrices as it does for ad-hoc runs. This makes it
easy to iterate on a single entry without copying or editing the matrix file.

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
- client/server payload sizes
- transcript bytes
- packet estimates
- stack and working-set usage where available

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
- `scripts/profile_validation_matrix.json`: recommended board/test coverage per profile for humans and CI, including the explicit `mps2/an385` Cortex-M no-entropy validation path

### Profile Cookbook

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
      "message_hex": "..."
    }
  ]
}
```

Each scenario summary includes:

- the requested ML-KEM / ML-DSA levels
- derived key, ciphertext, and signature sizes
- per-command status (`ok`, `payload`, or `invalid`)
- the raw command/response transcript entries

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
- strips common host compiler environment variables before invoking `west`

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
  --skip-cppcheck \
  --run-compatibility-smoke \
  --strict
```

That compatibility smoke builds a small, explicit set of PQCP targets against
the selected Zephyr ref and reports success or failure separately from the
static-analysis work.

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
- a filtered `--benchmark-matrix` smoke run
- a filtered `--profile-validation` build-only smoke run

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
- build-validate the `mps2/an385` MCU profile path through
  `tests/ztest_primitive` with `overlay-no-entropy.conf`
- build-validate the `nucleo_h743zi` MCU profile path through
  `tests/ztest_primitive` and `samples/pqcp_basic_kem`

When launched manually, the extended-checks workflow also accepts:

- a `zephyr_ref` input for trying a newer Zephyr tag/branch/commit
- a `run_sanitizers` toggle for native_sim ASan/UBSan coverage

If the manual `zephyr_ref` differs from the baseline `v4.3.0`, the workflow
also runs an explicit compatibility-smoke build step so Zephyr drift is called
out separately from the default static-analysis output.

Fast CI is therefore pinned to a known-good baseline, while extended checks can
be used to probe upcoming Zephyr drift before it reaches downstream consumers.

## Release Metadata

Downstream consumers can track the formal module version through:

- `include/pqcp_zephyr/version.h`
- `CHANGELOG.md`

The current release macro is `PQCP_VERSION_STRING`, which is set to `1.0.0`.
The extended-checks helper now verifies that this macro and the top release
entry in `CHANGELOG.md` stay aligned.

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
