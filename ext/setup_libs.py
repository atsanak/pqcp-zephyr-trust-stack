#!/usr/bin/env python3
"""
Setup external libraries for PQCP Zephyr Trust Stack.

Clones mlkem-native and mldsa-native into the ext/ directory.
"""

import subprocess
import sys
from pathlib import Path

LIBRARIES = [
    {
        "name": "mlkem-native",
        "url": "https://github.com/pq-code-package/mlkem-native",
        "tag": None,  # Use latest main
    },
    {
        "name": "mldsa-native",
        "url": "https://github.com/pq-code-package/mldsa-native",
        "tag": None,  # Use latest main
    },
]

def main():
    ext_dir = Path(__file__).parent
    
    for lib in LIBRARIES:
        lib_path = ext_dir / lib["name"]
        
        if lib_path.exists():
            print(f"✓ {lib['name']} already exists")
            continue
        
        print(f"Cloning {lib['name']}...")
        cmd = ["git", "clone", lib["url"], str(lib_path)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"✗ Failed to clone {lib['name']}: {result.stderr}")
            sys.exit(1)
        
        if lib["tag"]:
            subprocess.run(
                ["git", "checkout", lib["tag"]],
                cwd=str(lib_path),
                capture_output=True
            )
        
        print(f"✓ Cloned {lib['name']}")
    
    print("\nSetup complete!")
    print("Run 'west build' to build with PQC libraries.")

if __name__ == "__main__":
    main()
