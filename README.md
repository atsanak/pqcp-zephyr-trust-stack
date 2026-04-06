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

1. Add this module to your `west.yml`:

```yaml
manifest:
  projects:
    - name: pqcp-zephyr-trust-stack
      url: https://github.com/your-org/pqcp-zephyr-trust-stack
      revision: main
      path: modules/pqcp
```

2. Update west:

```bash
west update
```

3. Enable in your `prj.conf`:

```
CONFIG_PQCP=y
CONFIG_PQCP_MLKEM_LEVEL_768=y
CONFIG_PQCP_MLDSA_LEVEL_65=y
```

### Building a Sample

```bash
# Build for native_sim
west build -b native_sim samples/pqcp_basic_kem

# Build for QEMU Cortex-M3
west build -b qemu_cortex_m3 samples/pqcp_basic_sig

# Run
west build -t run
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

/* Key generation */
uint8_t pk[PQCP_MLKEM768_PUBLIC_KEY_BYTES];
uint8_t sk[PQCP_MLKEM768_SECRET_KEY_BYTES];
pqcp_mlkem768_keypair(pk, sk);

/* Encapsulation (sender) */
uint8_t ct[PQCP_MLKEM768_CIPHERTEXT_BYTES];
uint8_t ss1[PQCP_MLKEM_SHARED_SECRET_BYTES];
pqcp_mlkem768_enc(ct, ss1, pk);

/* Decapsulation (receiver) */
uint8_t ss2[PQCP_MLKEM_SHARED_SECRET_BYTES];
pqcp_mlkem768_dec(ss2, ct, sk);
/* ss1 == ss2 */
```

### ML-DSA (Digital Signatures)

```c
#include <pqcp_zephyr/mldsa.h>

/* Key generation */
uint8_t pk[PQCP_MLDSA65_PUBLIC_KEY_BYTES];
uint8_t sk[PQCP_MLDSA65_SECRET_KEY_BYTES];
pqcp_mldsa65_keypair(pk, sk);

/* Sign message */
uint8_t sig[PQCP_MLDSA65_SIGNATURE_BYTES];
size_t sig_len;
pqcp_mldsa65_sign(sig, &sig_len, message, msg_len, sk);

/* Verify signature */
int valid = pqcp_mldsa65_verify(sig, sig_len, message, msg_len, pk);
```

### Streaming ML-DSA (Large Messages)

```c
#include <pqcp_zephyr/mldsa.h>

/* Initialize streaming context */
pqcp_mldsa_streaming_ctx_t ctx;
pqcp_mldsa_streaming_sign_init(&ctx, sk, PQCP_MLDSA65_SECRET_KEY_BYTES);

/* Feed data in chunks */
while (more_data) {
    pqcp_mldsa_streaming_sign_update(&ctx, chunk, chunk_len);
}

/* Finalize and get signature */
uint8_t sig[PQCP_MLDSA65_SIGNATURE_BYTES];
size_t sig_len;
pqcp_mldsa_streaming_sign_final(&ctx, sig, &sig_len);
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
cd scripts/
python run_benchmarks.py --target native_sim
```

### Full Matrix

```bash
python run_benchmarks.py --target native_sim --matrix
python parse_logs.py benchmark_results_*.json --from-json -o results/
```

### Output Format

Benchmark logs use structured lines:

```
PRIM,MLKEM768,KEYGEN,cycles=450000,stack=2048,text=8192,bss=256
PRIM,MLDSA65,SIGN,cycles=1200000,stack=4096,text=16384,bss=512
TLS,MLKEM768+MLDSA65,handshake_ms=150,cpu_pct=45,peak_kib=32,transcript_bytes=8192,frags=12
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

| Algorithm | Stack (keygen) | Stack (sign/encaps) |
|-----------|----------------|---------------------|
| ML-KEM-768 | ~3 KB | ~2.5 KB |
| ML-KEM-1024 | ~4 KB | ~3.5 KB |
| ML-DSA-65 | ~5 KB | ~6 KB |
| ML-DSA-87 | ~6 KB | ~7 KB |

Configure adequate stack sizes:

```
CONFIG_MAIN_STACK_SIZE=16384
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
west build -b native_sim tests/ztest_primitive
west build -t run

# Run RNG tests
west build -b native_sim tests/ztest_rng
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
2. Ensure all tests pass on `native_sim`
3. Add tests for new functionality
4. Submit a pull request

## Authors

- PQCP Zephyr Trust Stack Contributors
# pqcp-zephyr-trust-stack
