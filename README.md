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

- `native_sim` (for development/testing)
- `qemu_cortex_m3` (QEMU emulation)
- Cortex-M4/M7 boards (STM32F4, nRF52840, etc.)

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
      url: https://github.com/your-org/pqcp-zephyr-trust-stack
      revision: main
      path: modules/pqcp
```

Then run `west update`.

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
│   ├── pqcp_kat_deterministic/ # Known Answer Tests
│   ├── pqcp_streaming_hash_mldsa/
│   ├── pqcp_tls_mbedtls_psa/   # TLS integration
│   └── pqcp_serial_acvp/       # ACVP test interface
│
├── tests/
│   ├── ztest_primitive/        # Primitive operation tests
│   └── ztest_rng/              # RNG subsystem tests
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
| GATEWAY | 512/768/1024 | 44/65/87 | Yes | Yes | No | Capable devices |
| NATIVE_LAB | 512/768/1024 | 44/65/87 | No | Yes | Yes | Development/testing |

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
  --sample pqcp_basic_kem
```

### Full Matrix

```bash
python scripts/run_benchmarks.py --matrix --config scripts/benchmark_matrix.json
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

- `scripts/benchmark_matrix.json`: sample benchmark matrix for `run_benchmarks.py`
- `scripts/profile_validation_matrix.json`: recommended board/test coverage per profile for humans and CI

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

### Example Session

```
> SELFTEST::
RESULT:OK

> SEED:DRBG:0:0102030405060708090a0b0c0d0e0f10...
RESULT:OK

> KEYGEN:MLKEM:768:
RESULT:<pk_hex><sk_hex>
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

## Security Considerations

### RNG Safety

**CRITICAL**: This module uses `sys_csrand_get()` for all cryptographic operations. This is the ONLY safe Zephyr RNG for cryptography. Never use `sys_rand_get()` or `sys_rand32_get()` for security-sensitive operations.

### Deterministic Mode

The `CONFIG_PQCP_RNG_DETERMINISTIC_TEST` option enables deterministic RNG for testing (KAT, ACVP). This MUST NEVER be enabled in production:

```
# WARNING: Test builds only!
CONFIG_PQCP_RNG_CUSTOM=y  # Required for deterministic
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

# Run primitive tests on mps2/an385 without entropy hardware
west build -p always -b mps2/an385 tests/ztest_primitive -- -DOVERLAY_CONFIG=overlay-no-entropy.conf
west build -t run
```

## CI

GitHub Actions coverage is defined in `.github/workflows/ci.yml`. The workflow
sets up a Zephyr workspace, installs the Zephyr SDK toolchains needed for
`qemu_x86_64`, and runs:

- `tests/ztest_rng`
- `tests/ztest_primitive`
- `tests/ztest_acvp_serial`
- `tests/ztest_tls_selftest`
- `samples/pqcp_basic_kem`
- `samples/pqcp_basic_sig`
- `samples/pqcp_bench_protocol`

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
