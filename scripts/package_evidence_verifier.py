#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Package the host evidence verifier as a self-contained release kit.

Builds tools/evidence_verifier, smoke-tests the produced binary against the
bundled signed transcript (the kit is not written unless the binary
verifies it), then emits:

  pqcp-evidence-verifier-<version>-<os>-<arch>.tar.gz
  pqcp-evidence-verifier-<version>-<os>-<arch>.tar.gz.sha256

The kit lets a third party check a device's evidence chain with nothing but
the binary: the same firmware C that produced the evidence, compiled for
host. Packaging only - every verification decision is made by that binary.
"""

import argparse
import hashlib
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parent.parent
TOOL_DIR = MODULE_ROOT / "tools" / "evidence_verifier"
TESTDATA = TOOL_DIR / "testdata"
FIXTURES = ("advisor_full_chain_transcript.log", "signed_passport_transcript.log")

README = """\
PQCP evidence verifier {version} ({system}-{machine})

Replays a captured device transcript and independently re-derives every
evidence digest using the same C the firmware ran, compiled for host.

  bin/pqcp-evidence-verify [--lenient] [--require-signature] [--quiet]
                           [--json <path>] <transcript.log>

  Exit 0  terminal chain consistent (and signature valid when required)
  Exit 1  missing, malformed, tampered, or unbound evidence
  Exit 2  usage or I/O error

Try it on the bundled, ML-DSA-65-signed device transcript:

  bin/pqcp-evidence-verify --require-signature examples/signed_passport_transcript.log

Scope: a valid result proves the transcript is internally consistent and
untampered. The signature uses a demo-custody boot-ephemeral key; it proves
integrity, not device identity or hardware attestation.
"""


def read_version() -> str:
    text = (MODULE_ROOT / "include/pqcp_zephyr/version.h").read_text(
        encoding="utf-8")
    match = re.search(r'#define\s+PQCP_VERSION_STRING\s+"([^"]+)"', text)
    if match is None:
        raise RuntimeError("PQCP_VERSION_STRING not found in version.h")
    return match.group(1)


def run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def build(build_dir: Path) -> Path:
    for cmd in (
        ["cmake", "-S", str(TOOL_DIR), "-B", str(build_dir),
         "-DCMAKE_BUILD_TYPE=Release"],
        ["cmake", "--build", str(build_dir)],
    ):
        result = run(cmd)
        if result.returncode != 0:
            print(result.stdout + result.stderr)
            raise RuntimeError(f"command failed: {' '.join(cmd)}")
    binary = build_dir / "pqcp-evidence-verify"
    if not binary.exists():
        raise RuntimeError("pqcp-evidence-verify was not produced")
    return binary


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--output-dir", type=Path,
                        default=MODULE_ROOT / "dist")
    args = parser.parse_args()

    version = read_version()
    system = platform.system().lower()
    machine = platform.machine().lower()
    stem = f"pqcp-evidence-verifier-{version}-{system}-{machine}"

    with tempfile.TemporaryDirectory(prefix="pqcp-kit-") as tmp:
        work = Path(tmp)
        binary = build(work / "build")

        smoke = run([str(binary), "--require-signature", "--quiet",
                     str(TESTDATA / "signed_passport_transcript.log")])
        if smoke.returncode != 0:
            print("[kit] FAIL: built binary does not verify the bundled "
                  "signed transcript; refusing to package")
            print(smoke.stdout + smoke.stderr)
            return 1
        tampered = work / "tampered.log"
        tampered.write_text(
            (TESTDATA / "signed_passport_transcript.log").read_text()
            .replace("verdict_digest=", "verdict_digest=0", 1))
        if run([str(binary), "--quiet", str(tampered)]).returncode == 0:
            print("[kit] FAIL: built binary accepted a tampered transcript; "
                  "refusing to package")
            return 1
        print("[kit] smoke test passed: signed transcript verifies, "
              "tampered transcript is rejected")

        root = work / stem
        (root / "bin").mkdir(parents=True)
        (root / "examples").mkdir()
        shutil.copy2(binary, root / "bin" / "pqcp-evidence-verify")
        for fixture in FIXTURES:
            shutil.copy2(TESTDATA / fixture, root / "examples" / fixture)
        (root / "README.txt").write_text(
            README.format(version=version, system=system, machine=machine),
            encoding="utf-8")

        args.output_dir.mkdir(parents=True, exist_ok=True)
        archive = args.output_dir / f"{stem}.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(root, arcname=stem)

    sidecar = archive.with_name(archive.name + ".sha256")
    sidecar.write_text(f"{sha256_of(archive)}  {archive.name}\n",
                       encoding="utf-8")
    print(f"PQCP_EVIDENCE_KIT PASS archive={archive.name} "
          f"sha256={sha256_of(archive)}")
    print(f"[kit] wrote {archive} and {sidecar.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
