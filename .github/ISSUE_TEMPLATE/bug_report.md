---
name: Bug report
about: Report a build failure, test regression, or incorrect output
labels: bug
---

## Describe the bug

A clear and concise description of what the bug is. If this is a build
failure, paste the first error message. If this is a test regression,
name the ztest suite and test case.

## To reproduce

Steps to reproduce the behaviour. Where relevant, paste the exact
commands:

```
# example
west build -p always -b native_sim/native/64 tests/ztest_primitive
west build -d build -t run
```

## Expected behaviour

What you expected to happen.

## Environment

- Zephyr SDK version:
- Zephyr workspace version (`west manifest --resolve | head`):
- Board / platform:
- Host OS:
- pqcp-zephyr-trust-stack commit SHA:
- Build profile (`baseline`, `pqcp`, `MCU_MINIMAL`, `GATEWAY`, ...):
- Algorithm / level (for example `MLKEM-768`, `MLDSA-65`):

## Relevant log output

<!-- Paste the failing ztest output, west build log, PQCP_METRIC lines,
     or ACVP frame exchange. Prefer `<details>` for long logs. -->

```
```

## Additional context

Anything else the maintainers should know (recent local changes,
non-default Kconfig overrides, out-of-tree patches).
