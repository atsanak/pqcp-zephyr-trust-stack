## Overview

This sample exposes the shared PQCP ACVP command library over a Zephyr console/UART transport so a host can drive ML-KEM and ML-DSA validation flows with stable `RESULT:*` / `ERROR:*` responses. It is used for QEMU development and CI smoke runs on `qemu_x86_64`, and it also build-verifies on `nucleo_h743zi`; a successful run shows the banner, a `>` prompt, and machine-parseable command responses such as `RESULT:OK`, `ERROR:INVALID_CMD`, or hex-encoded `RESULT:<payload>`.

## Prerequisites

- Zephyr SDK 1.0.1 was used for the verified commands below.
- A west workspace already set up from the repository root `west.yml`.
- Supported boards:
  - `qemu_x86_64` for development and CI-run command/response checks.
  - `nucleo_h743zi` for build verification and lab flashing over UART.

## Building and Running

### QEMU (development)

```bash
west build -p always -b qemu_x86_64 samples/pqcp_serial_acvp
west build -d build -t run
```

### nucleo_h743zi (hardware)

Build verified, flash not CI-tested.

```bash
west build -p always -b nucleo_h743zi samples/pqcp_serial_acvp
west flash
```

After flashing, connect to the board UART console at the board's configured serial port and send ASCII commands terminated by `\n`, for example `HELP::`.

## Expected Output

The following transcript is from a real `qemu_x86_64` run followed by a real `HELP::` request:

```text
PQCP Serial ACVP Interface
==========================
Ready for commands. Format: CMD:ALG:LEVEL:HEX_DATA
Commands: SEED, KEYGEN, ENCAPS, DECAPS, SIGN, VERIFY, SELFTEST, HELP

> HELP::
Commands:
  SEED:DRBG:0:<hexseed>     - Seed deterministic RNG
  KEYGEN:MLKEM:<512|768|1024>: - Generate ML-KEM keypair
  ENCAPS:MLKEM:<level>:<pk>    - Encapsulate with public key
  DECAPS:MLKEM:<level>:<ct||sk> - Decapsulate ciphertext
  KEYGEN:MLDSA:<44|65|87>:  - Generate ML-DSA keypair
  SIGN:MLDSA:<level>:<sk||msg> - Sign message
  VERIFY:MLDSA:<level>:<pk||msg||sig> - Verify signature
  SELFTEST::                - Run internal self-test
RESULT:OK
>
```

## Configuration

The sample-specific PQCP options below come from `prj.conf` plus the shared module Kconfig:

| Symbol | Sample value | Kconfig default | Valid values / effect |
| --- | --- | --- | --- |
| `CONFIG_PQCP` | `y` | `n` | `y` enables the module; `n` removes all PQCP code. |
| `CONFIG_PQCP_MLKEM` | `y` | `y` | `y` enables ML-KEM support; `n` disables ML-KEM commands. |
| `CONFIG_PQCP_MLKEM_LEVEL_512` | `y` | `n` | `y` / `n`; enables ML-KEM-512 keygen and KEM commands. |
| `CONFIG_PQCP_MLKEM_LEVEL_768` | `y` | `y` | `y` / `n`; enables ML-KEM-768 keygen and KEM commands. |
| `CONFIG_PQCP_MLKEM_LEVEL_1024` | `y` | `n` | `y` / `n`; enables ML-KEM-1024 keygen and KEM commands. |
| `CONFIG_PQCP_MLDSA` | `y` | `y` | `y` enables ML-DSA support; `n` disables signature commands. |
| `CONFIG_PQCP_MLDSA_LEVEL_44` | `y` | `n` | `y` / `n`; enables ML-DSA-44 signing and verification. |
| `CONFIG_PQCP_MLDSA_LEVEL_65` | `y` | `y` | `y` / `n`; enables ML-DSA-65 signing and verification. |
| `CONFIG_PQCP_MLDSA_LEVEL_87` | `y` | `n` | `y` / `n`; enables ML-DSA-87 signing and verification. |
| `CONFIG_PQCP_ACVP` | `y` | `y` if `CONFIG_PQCP_PROFILE_NATIVE_LAB`, otherwise `n` | `y` enables the reusable ACVP parser/formatter and command handlers. |
| `CONFIG_PQCP_RNG_CUSTOM` | `y` | `n` | `y` selects application-registered RNG hooks; `n` leaves the sample on another RNG backend. |
| `CONFIG_PQCP_RNG_DETERMINISTIC_TEST` | `y` | `n` | `y` enables deterministic DRBG seeding for ACVP/KAT only; `n` disables deterministic mode. |
| `CONFIG_PQCP_ACVP_READLINE_TIMEOUT_MS` | inherited `5000` | `5000` | Integer range `100..60000`; partial command lines time out to `ERROR:TIMEOUT` after this many milliseconds. |

This sample intentionally enables deterministic test RNG support so ACVP hosts can seed reproducible vectors. Do not reuse this RNG configuration in production firmware.
