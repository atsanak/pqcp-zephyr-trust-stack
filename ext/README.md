# External Libraries

This directory contains or references the PQ Code Package libraries.

## Setup

### Option 1: Git Submodules (Recommended)

```bash
# From the repository root
git submodule add https://github.com/pq-code-package/mlkem-native ext/mlkem-native
git submodule add https://github.com/pq-code-package/mldsa-native ext/mldsa-native
```

### Option 2: Manual Clone

```bash
cd ext/
git clone https://github.com/pq-code-package/mlkem-native
git clone https://github.com/pq-code-package/mldsa-native
```

## Library Versions

For reproducible builds, pin to specific releases:

```bash
cd ext/mlkem-native && git checkout v1.0.0
cd ext/mldsa-native && git checkout v1.0.0-alpha
```

## Integration

The CMakeLists.txt automatically detects these libraries and integrates them.
Source files use `__has_include()` to detect library presence and switch
from stub implementations to real PQC code.

## Documentation

- [mlkem-native](https://github.com/pq-code-package/mlkem-native)
- [mldsa-native](https://github.com/pq-code-package/mldsa-native)
