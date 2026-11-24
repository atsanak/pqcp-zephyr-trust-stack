# Serial ACVP interface

See the [README](../README.md) for the project overview.

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
