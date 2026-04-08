#!/usr/bin/env python3
"""
PQCP Zephyr Benchmark Runner

Orchestrates building, running, and collecting benchmark results for the
PQCP Zephyr module across different configurations and targets.

Usage:
    python run_benchmarks.py [options]

Options:
    --target    Target board (default: qemu_x86_64)
    --matrix    Run full configuration matrix
    --output    Output directory for results
    --config    Configuration file (YAML/JSON) for custom matrix
    --profile   Kconfig profile (MCU_MINIMAL, GATEWAY, NATIVE_LAB)
    --sample    Sample to build and run

Examples:
    # Run basic benchmarks on QEMU
    python run_benchmarks.py --target qemu_x86_64

    # Run full matrix
    python run_benchmarks.py --matrix

    # Use a specific profile
    python run_benchmarks.py --target mps2/an385 --profile MCU_MINIMAL
"""

import argparse
import subprocess
import sys
import os
import json
import re
import csv
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict

# =============================================================================
# Configuration
# =============================================================================

# Supported boards for benchmarking
TARGETS = [
    "qemu_x86_64",
    "mps2/an385",  # Cortex-M3 with 4MB RAM
    "native_sim",
]

# Security levels
KEM_LEVELS = [512, 768, 1024]
DSA_LEVELS = [44, 65, 87]

# Backend options
BACKENDS = ["auto", "force_c"]

# Kconfig profiles
PROFILES = {
    "MCU_MINIMAL": {
        "config": "CONFIG_PQCP_PROFILE_MCU_MINIMAL=y",
        "kem_levels": [768],
        "dsa_levels": [65],
    },
    "GATEWAY": {
        "config": "CONFIG_PQCP_PROFILE_GATEWAY=y",
        "kem_levels": [512, 768, 1024],
        "dsa_levels": [44, 65, 87],
    },
    "NATIVE_LAB": {
        "config": "CONFIG_PQCP_PROFILE_NATIVE_LAB=y",
        "kem_levels": [512, 768, 1024],
        "dsa_levels": [44, 65, 87],
    },
}

# Sample configurations
SAMPLES = {
    "pqcp_basic_kem": {
        "path": "samples/pqcp_basic_kem",
        "requires": ["MLKEM"],
        "overlays": [],
    },
    "pqcp_basic_sig": {
        "path": "samples/pqcp_basic_sig",
        "requires": ["MLDSA"],
        "overlays": [],
    },
    "pqcp_kat_deterministic": {
        "path": "samples/pqcp_kat_deterministic",
        "requires": ["MLKEM", "MLDSA", "DETERMINISTIC"],
        "overlays": [],
    },
    "pqcp_streaming_hash_mldsa": {
        "path": "samples/pqcp_streaming_hash_mldsa",
        "requires": ["MLDSA", "STREAMING"],
        "overlays": [],
    },
    "pqcp_tls_mbedtls_psa": {
        "path": "samples/pqcp_tls_mbedtls_psa",
        "requires": ["MLKEM", "MLDSA", "PSA"],
        "overlays": ["overlay-selftest.conf"],
    },
}


@dataclass
class BenchmarkResult:
    """Structured result from a benchmark run."""
    timestamp: str
    target: str
    profile: str
    sample: str
    component: str
    operation: str
    algorithm: str
    level: int
    metric: str
    value: str
    unit: str
    
    def to_dict(self) -> dict:
        return asdict(self)

class BenchmarkRunner:
    """Orchestrates benchmark builds and runs."""
    
    def __init__(self, west_root: Path, output_dir: Path, module_path: Path = None):
        self.west_root = west_root
        self.output_dir = output_dir
        self.module_path = module_path or west_root / "pqcp-zephyr-trust-stack"
        self.results: List[BenchmarkResult] = []
        self.timestamp = datetime.now().isoformat()
        
    def build(self, target: str, sample: str, 
              overlay_configs: List[str] = None,
              extra_conf: Dict[str, str] = None) -> Tuple[bool, str]:
        """Build a sample for a target with optional configuration.
        
        Returns:
            Tuple of (success, build_output)
        """
        build_dir = self.west_root / "build"
        
        # Clean previous build
        if build_dir.exists():
            subprocess.run(["rm", "-rf", str(build_dir)], check=True)
        
        cmd = [
            "west", "build",
            "-b", target,
            str(self.module_path / sample),
            "--pristine"
        ]
        
        # Add overlay configs
        cmake_args = []
        if overlay_configs:
            overlay_str = ";".join(overlay_configs)
            cmake_args.append(f"-DOVERLAY_CONFIG={overlay_str}")
        
        # Add extra Kconfig options
        if extra_conf:
            for k, v in extra_conf.items():
                cmake_args.append(f"-D{k}={v}")
        
        if cmake_args:
            cmd.extend(["--"])
            cmd.extend(cmake_args)
        
        print(f"\n{'='*60}")
        print(f"Building: {sample}")
        print(f"Target:   {target}")
        if overlay_configs:
            print(f"Overlays: {', '.join(overlay_configs)}")
        print(f"{'='*60}")
        
        result = subprocess.run(
            cmd,
            cwd=str(self.west_root),
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(f"BUILD FAILED:")
            # Print last 2000 chars of stderr
            print(result.stderr[-2000:] if len(result.stderr) > 2000 else result.stderr)
            return False, result.stderr
        
        print("Build: OK")
        return True, result.stdout
        
    def run(self, target: str, timeout: int = 120) -> Optional[str]:
        """Run the built sample and capture output.
        
        Returns:
            Captured stdout or None on failure
        """
        print(f"Running on {target}...")
        
        try:
            if target in ["native_sim", "native_posix"]:
                # Run native binary directly
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
            
            else:
                # Use west build -t run for QEMU targets
                result = subprocess.run(
                    ["west", "build", "-t", "run"],
                    cwd=str(self.west_root),
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                return result.stdout
                
        except subprocess.TimeoutExpired:
            print(f"  TIMEOUT after {timeout}s (this is expected for QEMU)")
            # For QEMU, timeout is normal - read what we got
            return None
        except Exception as e:
            print(f"  Error: {e}")
            return None
    
    def parse_pqcp_metrics(self, output: str, target: str, profile: str, 
                           sample: str) -> List[BenchmarkResult]:
        """Parse PQCP_METRIC lines from output.
        
        Format: PQCP_METRIC,<component>,<operation>,<algo>,<level>,<metric>,<value>,<unit>
        """
        results = []
        
        pattern = re.compile(
            r'PQCP_METRIC,(\w+),(\w+),(\w+),(\d+),(\w+),(\w+),(\w*)'
        )
        
        for line in output.split('\n'):
            line = line.strip()
            m = pattern.match(line)
            if m:
                results.append(BenchmarkResult(
                    timestamp=self.timestamp,
                    target=target,
                    profile=profile,
                    sample=sample,
                    component=m.group(1),
                    operation=m.group(2),
                    algorithm=m.group(3),
                    level=int(m.group(4)),
                    metric=m.group(5),
                    value=m.group(6),
                    unit=m.group(7) or '',
                ))
        
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
    
    def run_single_benchmark(self, target: str, sample: str, 
                              profile: str = None,
                              overlays: List[str] = None) -> bool:
        """Run a single benchmark configuration.
        
        Returns:
            True if successful
        """
        sample_info = SAMPLES.get(sample, {"path": f"samples/{sample}", "overlays": []})
        sample_path = sample_info["path"]
        
        # Combine overlays
        all_overlays = list(overlays or []) + sample_info.get("overlays", [])
        
        # Build extra config for profile
        extra_conf = {}
        if profile and profile in PROFILES:
            extra_conf[PROFILES[profile]["config"].split("=")[0]] = "y"
        
        # Build
        success, _ = self.build(target, sample_path, all_overlays, extra_conf)
        if not success:
            return False
        
        # Get code size
        sizes = self.get_code_size()
        if sizes:
            print(f"  Code size: text={sizes.get('text', 0)} "
                  f"data={sizes.get('data', 0)} bss={sizes.get('bss', 0)}")
        
        # Run and capture output
        output = self.run(target)
        if output is None:
            print("  No output captured")
            return False
        
        # Parse metrics
        metrics = self.parse_pqcp_metrics(output, target, profile or "default", sample)
        self.results.extend(metrics)
        
        print(f"  Captured {len(metrics)} PQCP_METRIC lines")
        return True
    
    def run_matrix(self, targets: List[str] = None,
                   profiles: List[str] = None,
                   samples: List[str] = None):
        """Run a matrix of benchmark configurations."""
        
        if targets is None:
            targets = ["qemu_x86_64"]
        if profiles is None:
            profiles = ["MCU_MINIMAL"]
        if samples is None:
            samples = ["pqcp_basic_kem", "pqcp_basic_sig"]
        
        total = len(targets) * len(profiles) * len(samples)
        current = 0
        
        for target in targets:
            for profile in profiles:
                for sample in samples:
                    current += 1
                    print(f"\n[{current}/{total}] {target} / {profile} / {sample}")
                    
                    try:
                        self.run_single_benchmark(target, sample, profile)
                    except Exception as e:
                        print(f"  ERROR: {e}")
    
    def save_results_json(self, filename: str = None):
        """Save results to JSON file."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"benchmark_results_{timestamp}.json"
        
        output_path = self.output_dir / filename
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        data = [r.to_dict() for r in self.results]
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"\nResults saved to {output_path}")
        return output_path
    
    def save_results_csv(self, filename: str = None):
        """Save results to CSV file."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"benchmark_results_{timestamp}.csv"
        
        output_path = self.output_dir / filename
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        if not self.results:
            print("No results to save")
            return None
        
        fieldnames = list(self.results[0].to_dict().keys())
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in self.results:
                writer.writerow(r.to_dict())
        
        print(f"Results saved to {output_path}")
        return output_path
    
    def print_summary(self):
        """Print a summary of collected results."""
        if not self.results:
            print("\nNo results collected")
            return
        
        print(f"\n{'='*60}")
        print("BENCHMARK SUMMARY")
        print(f"{'='*60}")
        print(f"Total metrics: {len(self.results)}")
        
        # Group by sample
        by_sample = {}
        for r in self.results:
            if r.sample not in by_sample:
                by_sample[r.sample] = []
            by_sample[r.sample].append(r)
        
        for sample, metrics in by_sample.items():
            print(f"\n{sample}:")
            for m in metrics[:10]:  # Limit output
                print(f"  {m.algorithm}-{m.level} {m.operation}: "
                      f"{m.metric}={m.value} {m.unit}")


def load_config_file(path: Path) -> dict:
    """Load a YAML or JSON config file."""
    if not path.exists():
        return {}
    
    content = path.read_text()
    
    if path.suffix in ['.yaml', '.yml']:
        try:
            import yaml
            return yaml.safe_load(content)
        except ImportError:
            print("Warning: PyYAML not installed, cannot load YAML config")
            return {}
    else:
        return json.loads(content)


def main():
    parser = argparse.ArgumentParser(
        description="PQCP Benchmark Runner - Orchestrate benchmarks across targets and profiles",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run basic benchmarks on QEMU x86_64
  python run_benchmarks.py --target qemu_x86_64

  # Run full matrix of targets x profiles x samples
  python run_benchmarks.py --matrix

  # Run specific samples with a profile
  python run_benchmarks.py --target mps2/an385 --profile MCU_MINIMAL \\
      --samples pqcp_basic_kem pqcp_basic_sig

  # Use a custom configuration file
  python run_benchmarks.py --config my_matrix.json
"""
    )
    
    parser.add_argument("--target", "-t", default="qemu_x86_64",
                        help="Target board (default: qemu_x86_64)")
    parser.add_argument("--targets", nargs="+",
                        help="List of target boards for matrix mode")
    parser.add_argument("--profile", "-p",
                        choices=list(PROFILES.keys()),
                        help="Kconfig profile")
    parser.add_argument("--profiles", nargs="+",
                        choices=list(PROFILES.keys()),
                        help="List of profiles for matrix mode")
    parser.add_argument("--sample", "-s",
                        choices=list(SAMPLES.keys()),
                        help="Sample to run")
    parser.add_argument("--samples", nargs="+",
                        help="List of samples for matrix mode")
    parser.add_argument("--matrix", action="store_true",
                        help="Run full configuration matrix")
    parser.add_argument("--config", type=Path,
                        help="YAML/JSON config file for custom matrix")
    parser.add_argument("--output", "-o", default="benchmark_results",
                        help="Output directory (default: benchmark_results)")
    parser.add_argument("--west-root", default=None,
                        help="West workspace root (auto-detected if not specified)")
    parser.add_argument("--module-path", default=None,
                        help="PQCP module path (auto-detected if not specified)")
    parser.add_argument("--timeout", type=int, default=120,
                        help="Timeout per run in seconds (default: 120)")
    parser.add_argument("--format", choices=["json", "csv", "both"], default="both",
                        help="Output format (default: both)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    
    args = parser.parse_args()
    
    # Auto-detect west root
    if args.west_root:
        west_root = Path(args.west_root).resolve()
    else:
        # Look for .west directory
        current = Path.cwd()
        while current != current.parent:
            if (current / ".west").exists():
                west_root = current
                break
            current = current.parent
        else:
            west_root = Path.cwd()
    
    # Auto-detect module path
    if args.module_path:
        module_path = Path(args.module_path).resolve()
    else:
        script_dir = Path(__file__).resolve().parent
        module_path = script_dir.parent
    
    output_dir = Path(args.output).resolve()
    
    print(f"PQCP Benchmark Runner")
    print(f"  West root:   {west_root}")
    print(f"  Module:      {module_path}")
    print(f"  Output:      {output_dir}")
    
    runner = BenchmarkRunner(west_root, output_dir, module_path)
    
    # Load config file if provided
    config = {}
    if args.config:
        config = load_config_file(args.config)
        print(f"  Config:      {args.config}")
    
    # Determine what to run
    if args.matrix:
        # Full matrix mode
        targets = args.targets or config.get("targets", ["qemu_x86_64"])
        profiles = args.profiles or config.get("profiles", list(PROFILES.keys()))
        samples = args.samples or config.get("samples", list(SAMPLES.keys()))
        
        runner.run_matrix(targets, profiles, samples)
        
    elif args.sample:
        # Single sample mode
        runner.run_single_benchmark(
            args.target,
            args.sample,
            args.profile
        )
        
    else:
        # Default: run basic benchmarks
        samples = ["pqcp_basic_kem", "pqcp_basic_sig"]
        for sample in samples:
            runner.run_single_benchmark(
                args.target,
                sample,
                args.profile
            )
    
    # Save results
    runner.print_summary()
    
    if args.format in ["json", "both"]:
        runner.save_results_json()
    if args.format in ["csv", "both"]:
        runner.save_results_csv()
    
    return 0 if runner.results else 1


if __name__ == "__main__":
    sys.exit(main())
