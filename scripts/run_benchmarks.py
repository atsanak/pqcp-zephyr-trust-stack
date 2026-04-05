#!/usr/bin/env python3
"""
PQCP Zephyr Benchmark Runner

Orchestrates building, running, and collecting benchmark results for the
PQCP Zephyr module across different configurations and targets.

Usage:
    python run_benchmarks.py [options]

Options:
    --target    Target board (default: native_sim)
    --matrix    Run full configuration matrix
    --output    Output directory for results
    --qemu      Use QEMU for embedded targets
"""

import argparse
import subprocess
import sys
import os
import json
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional

# Configuration matrix
TARGETS = [
    "native_sim",
    "qemu_cortex_m3",
    "nucleo_f411re",
    "nrf52840dk/nrf52840",
]

KEM_LEVELS = [512, 768, 1024]
DSA_LEVELS = [44, 65, 87]

BACKENDS = ["auto", "force_c"]

class BenchmarkRunner:
    def __init__(self, west_root: Path, output_dir: Path):
        self.west_root = west_root
        self.output_dir = output_dir
        self.results: List[Dict] = []
        
    def build(self, target: str, sample: str, extra_conf: Dict[str, str] = None) -> bool:
        """Build a sample for a target with optional extra config."""
        build_dir = self.west_root / "build"
        
        # Clean previous build
        if build_dir.exists():
            subprocess.run(["rm", "-rf", str(build_dir)], check=True)
        
        cmd = [
            "west", "build",
            "-b", target,
            f"samples/{sample}",
            "--pristine"
        ]
        
        # Add extra Kconfig options
        if extra_conf:
            defines = " ".join(f"-D{k}={v}" for k, v in extra_conf.items())
            cmd.extend(["--", defines])
        
        print(f"Building {sample} for {target}...")
        print(f"  Command: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            cwd=str(self.west_root),
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(f"  Build FAILED:")
            print(result.stderr[-2000:] if len(result.stderr) > 2000 else result.stderr)
            return False
        
        print(f"  Build OK")
        return True
    
    def run(self, target: str, timeout: int = 60) -> Optional[str]:
        """Run the built sample and capture output."""
        print(f"Running on {target}...")
        
        if target == "native_sim":
            # Run directly
            binary = self.west_root / "build/zephyr/zephyr.exe"
            if not binary.exists():
                print("  Binary not found")
                return None
            
            result = subprocess.run(
                [str(binary)],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout
        
        elif target.startswith("qemu"):
            # Use west flash with QEMU
            result = subprocess.run(
                ["west", "build", "-t", "run"],
                cwd=str(self.west_root),
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout
        
        else:
            # Physical board - use J-Link or OpenOCD
            print(f"  Physical board {target} - manual run required")
            return None
    
    def parse_output(self, output: str) -> List[Dict]:
        """Parse benchmark output lines."""
        results = []
        
        # Match lines like: PRIM,MLKEM768,KEYGEN,cycles=12345,stack=2048,...
        prim_pattern = re.compile(
            r'PRIM,(\w+)(\d+),(\w+),'
            r'(?:cycles|us)=(\d+),'
            r'stack=(\d+),'
            r'text=(\d+),'
            r'bss=(\d+)'
        )
        
        # Match TLS lines
        tls_pattern = re.compile(
            r'TLS,(\w+),handshake_ms=(\d+),'
            r'cpu_pct=(\d+),'
            r'peak_kib=(\d+),'
            r'transcript_bytes=(\d+),'
            r'frags=(\d+)'
        )
        
        for line in output.split('\n'):
            line = line.strip()
            
            m = prim_pattern.match(line)
            if m:
                results.append({
                    'type': 'primitive',
                    'algorithm': m.group(1),
                    'level': int(m.group(2)),
                    'operation': m.group(3),
                    'cycles': int(m.group(4)),
                    'stack': int(m.group(5)),
                    'text': int(m.group(6)),
                    'bss': int(m.group(7)),
                })
                continue
            
            m = tls_pattern.match(line)
            if m:
                results.append({
                    'type': 'tls',
                    'suite': m.group(1),
                    'handshake_ms': int(m.group(2)),
                    'cpu_pct': int(m.group(3)),
                    'peak_kib': int(m.group(4)),
                    'transcript_bytes': int(m.group(5)),
                    'fragments': int(m.group(6)),
                })
        
        return results
    
    def get_code_size(self) -> Dict[str, int]:
        """Extract code size from build artifacts."""
        elf = self.west_root / "build/zephyr/zephyr.elf"
        
        if not elf.exists():
            return {}
        
        result = subprocess.run(
            ["size", str(elf)],
            capture_output=True,
            text=True
        )
        
        # Parse size output
        sizes = {}
        for line in result.stdout.split('\n'):
            parts = line.split()
            if len(parts) >= 4 and parts[0].isdigit():
                sizes['text'] = int(parts[0])
                sizes['data'] = int(parts[1])
                sizes['bss'] = int(parts[2])
                sizes['total'] = int(parts[3])
                break
        
        return sizes
    
    def run_benchmark_suite(self, target: str, 
                           kem_levels: List[int] = None,
                           dsa_levels: List[int] = None,
                           backend: str = "auto"):
        """Run a complete benchmark suite for a target."""
        
        if kem_levels is None:
            kem_levels = [768]
        if dsa_levels is None:
            dsa_levels = [65]
        
        timestamp = datetime.now().isoformat()
        
        # Configure for benchmark
        extra_conf = {
            "CONFIG_PQCP_BENCH": "y",
            "CONFIG_PQCP_BENCH_ITERATIONS": "100",
        }
        
        # Add level configurations
        for level in KEM_LEVELS:
            key = f"CONFIG_PQCP_MLKEM_LEVEL_{level}"
            extra_conf[key] = "y" if level in kem_levels else "n"
        
        for level in DSA_LEVELS:
            key = f"CONFIG_PQCP_MLDSA_LEVEL_{level}"
            extra_conf[key] = "y" if level in dsa_levels else "n"
        
        # Backend selection
        if backend == "force_c":
            extra_conf["CONFIG_PQCP_BACKEND_FORCE_C"] = "y"
        
        # Build
        if not self.build(target, "pqcp_basic_kem", extra_conf):
            return
        
        # Get code size
        sizes = self.get_code_size()
        
        # Run and collect output
        output = self.run(target)
        if output is None:
            return
        
        # Parse results
        results = self.parse_output(output)
        
        # Add metadata
        for r in results:
            r['target'] = target
            r['backend'] = backend
            r['timestamp'] = timestamp
            r['code_size'] = sizes
        
        self.results.extend(results)
        
        # Print summary
        print(f"\nResults for {target}:")
        for r in results:
            if r['type'] == 'primitive':
                print(f"  {r['algorithm']}-{r['level']} {r['operation']}: "
                      f"{r['cycles']} cycles, {r['stack']} bytes stack")
    
    def run_full_matrix(self, targets: List[str] = None):
        """Run benchmarks for all configurations."""
        if targets is None:
            targets = ["native_sim"]
        
        for target in targets:
            for backend in BACKENDS:
                print(f"\n{'='*60}")
                print(f"Target: {target}, Backend: {backend}")
                print('='*60)
                
                self.run_benchmark_suite(
                    target,
                    kem_levels=[768],
                    dsa_levels=[65],
                    backend=backend
                )
    
    def save_results(self, filename: str = None):
        """Save results to JSON file."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"benchmark_results_{timestamp}.json"
        
        output_path = self.output_dir / filename
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\nResults saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="PQCP Benchmark Runner")
    parser.add_argument("--target", default="native_sim",
                        help="Target board")
    parser.add_argument("--matrix", action="store_true",
                        help="Run full configuration matrix")
    parser.add_argument("--output", default="benchmark_results",
                        help="Output directory")
    parser.add_argument("--west-root", default=".",
                        help="West workspace root")
    
    args = parser.parse_args()
    
    west_root = Path(args.west_root).resolve()
    output_dir = Path(args.output).resolve()
    
    runner = BenchmarkRunner(west_root, output_dir)
    
    if args.matrix:
        runner.run_full_matrix([args.target])
    else:
        runner.run_benchmark_suite(args.target)
    
    runner.save_results()


if __name__ == "__main__":
    main()
