## Overview

This sample exercises the shared PQCP TLS self-test path with ML-KEM and ML-DSA routed through the PQCP PSA drivers, then prints TLS-planning notes and structured `PQCP_METRIC` rows. It is validated as a runnable self-test on `qemu_x86_64` with `overlay-selftest.conf`, and it also build-verifies on `nucleo_h743zi`; a successful run prints the sample banner, per-operation timings for ML-KEM and ML-DSA, handshake payload sizes, and a final `Sample completed successfully!` banner.

## Prerequisites

- Zephyr SDK 1.0.1 was used for the verified commands below.
- A west workspace already set up from the repository root `west.yml`.
- Supported boards:
  - `qemu_x86_64` for development, CI, and self-test runs with `overlay-selftest.conf`.
  - `nucleo_h743zi` for build verification of the self-test path; flashing is not CI-tested.

## Building and Running

### QEMU (development)

```bash
west build -p always -b qemu_x86_64 samples/pqcp_tls_mbedtls_psa -- \
  -DOVERLAY_CONFIG=overlay-selftest.conf
west build -d build -t run
```

### nucleo_h743zi (hardware)

Build verified, flash not CI-tested.

```bash
west build -p always -b nucleo_h743zi samples/pqcp_tls_mbedtls_psa -- \
  -DOVERLAY_CONFIG=overlay-selftest.conf
west flash
```

Use `overlay-selftest.conf` for the offline PSA/TLS helper path shown here. The separate `overlay-mbedtls.conf` is for future network-enabled TLS integration work and is not the path exercised by the verified sample run below.

## Expected Output

The following excerpt is from a real `qemu_x86_64` run with `overlay-selftest.conf`:

```text
========================================
  PQCP TLS mbedTLS PSA Sample
========================================

Initializing shared TLS self-test path...
PSA Crypto initialized successfully
PQCP_METRIC,driver,keygen,MLKEM,768,time,2120,us
PQCP_METRIC,driver,encaps,MLKEM,768,time,1188,us
PQCP_METRIC,driver,decaps,MLKEM,768,time,856,us
PQCP_METRIC,driver,selftest,MLKEM,768,status,PASS,
PQCP_METRIC,driver,keygen,MLDSA,65,time,3052,us
PQCP_METRIC,driver,sign,MLDSA,65,time,3454,us
PQCP_METRIC,driver,verify,MLDSA,65,time,1491,us
PQCP_METRIC,driver,selftest,MLDSA,65,status,PASS,
PQCP_METRIC,protocol,auth,MLDSA,65,time,7997,us
PQCP_METRIC,protocol,key_exchange,MLKEM,768,time,4164,us
PQCP_METRIC,protocol,handshake,TLS13,0,time,12258,us
PQCP_METRIC,protocol,handshake,TLS13,0,provider_overhead,97,us
PQCP_METRIC,protocol,handshake,TLS13,0,transcript_bytes,7789,B
PQCP_METRIC,protocol,handshake,TLS13,0,status,PASS,

--- Shared TLS Self-Test Report ---
ML-KEM-768 keygen:   2120 us
ML-KEM-768 encaps:   1188 us
ML-KEM-768 decaps:   856 us
ML-DSA-65 keygen:   3052 us
ML-DSA-65 sign:     3454 us
ML-DSA-65 verify:   1491 us
Auth stage:         7997 us
Key exchange stage: 4164 us
Handshake total:    12258 us
Client payload:     1216 bytes
Server payload:     6573 bytes
Transcript total:   7789 bytes
Packets (approx):   6
Stack usage:        86360 bytes
Working set:        14029 bytes
PSA active:         yes
========================================
  Sample completed successfully!
========================================
```

## Configuration

The sample-specific PQCP options below come from `prj.conf` plus the shared module Kconfig:

| Symbol | Sample value | Kconfig default | Valid values / effect |
| --- | --- | --- | --- |
| `CONFIG_PQCP` | `y` | `n` | `y` enables the module; `n` removes all PQCP code. |
| `CONFIG_PQCP_TLS_SELFTEST` | `y` | `y` if `CONFIG_PQCP_PROFILE_GATEWAY`, otherwise `n` | `y` enables the shared offline TLS self-test helper used by this sample. |
| `CONFIG_PQCP_MLKEM` | `y` | `y` | `y` enables ML-KEM support. |
| `CONFIG_PQCP_MLKEM_LEVEL_768` | `y` | `y` | `y` / `n`; this sample's default ML-KEM level is 768. |
| `CONFIG_PQCP_MLDSA` | `y` | `y` | `y` enables ML-DSA support. |
| `CONFIG_PQCP_MLDSA_LEVEL_65` | `y` | `y` | `y` / `n`; this sample's default ML-DSA level is 65. |
| `CONFIG_PQCP_RNG_PSA` | `y` | `n` | `y` selects PSA RNG when PSA crypto is available; `n` leaves another RNG backend active. |
| `CONFIG_PQCP_PSA_DRIVER` | `y` | `y` if `CONFIG_MBEDTLS_PSA_CRYPTO_C`, otherwise `n` | `y` enables PQCP PSA driver shims used by the sample's ML-KEM and ML-DSA operations. |
| `CONFIG_PQCP_PSA_DRIVER_MLDSA` | `y` | `y` | `y` / `n`; controls ML-DSA PSA driver support. |
| `CONFIG_PQCP_PSA_DRIVER_MLKEM` | `y` | `y` | `y` / `n`; controls ML-KEM PSA driver support. |

The sample's verified self-test path also uses `overlay-selftest.conf` to enable mbedTLS, PSA Crypto, thread-stack analysis, and stack initialization without requiring live network setup.
