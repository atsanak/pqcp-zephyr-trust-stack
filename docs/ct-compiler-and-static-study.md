# Compiler and static/dynamic constant-time study

## Registered hypotheses

The workload is ML-KEM-768 decapsulation in `tests/ztest_ct_trace`. The
comparison uses QEMU on Zephyr 4.5.0 with Zephyr SDK 1.0.1, covering x86_64
and Cortex-M3 at multiple compiler and optimisation settings.

- **H1.** On x86_64 every variant produces a clean relational result on the
  instruction-address, data-address, cache-line and division channels.
- **H2.** On Cortex-M3 every variant retains a secret-varying long multiply
  attributable to the 32×32-to-64-bit product in `compress_d10`.
- **H3.** LTO introduces no additional secret-varying site or divergent channel
  compared with the matching non-LTO build.
- **H4.** The static inventory contains every dynamically executed Cortex-M
  variable-latency site (100% recall).
- **H5.** Fewer than 10% of inventoried variable-latency instructions show
  secret-correlated operand or model variation in the sampled traces. Static
  conditional branch counts are positive and the dynamic trace detects zero
  secret-dependent control-flow divergences.

Report refutations as observed. Report unbuildable cells as `BUILD_FAIL` with
an error excerpt. A cell without a validated trace cannot confirm a hypothesis.
An empty dynamic or static denominator yields an undefined rate. Compare LTO
sites by source location and instruction kind, with unresolved attribution
recorded as such, since link-time optimisation can change addresses and names.
