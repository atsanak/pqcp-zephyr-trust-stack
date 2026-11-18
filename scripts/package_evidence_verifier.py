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
REGISTER_DIR = MODULE_ROOT / "tools" / "evidence_register"
REFERENCE_VERIFIER = MODULE_ROOT / "scripts" / "rfc9162_reference.py"
FORMAT_DOC = MODULE_ROOT / "docs" / "transparent-appraisal-format.md"
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

Transparent appraisal receipts (see docs/transparent-appraisal-format.md):

  bin/pqcp-evidence-verify --emit-statement S.cbor transcript.log
  bin/pqcp-evidence-register keygen|register|checkpoint|receipt|prove-consistency
  bin/pqcp-evidence-verify --receipt R.cbor --log-pk log.pk transcript.log
  bin/pqcp-evidence-verify --consistency C.cbor --log-pk log.pk
  python3 tools/rfc9162_reference.py --receipt R.cbor --log-pk log.pk

tools/rfc9162_reference.py is an independent standard-library RFC 9162
verifier (the ML-DSA checkpoint signature is delegated to the C verifier).
Scope: the log key is a demo key; there is no witness quorum.

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


def build(build_dir: Path, source_dir: Path = TOOL_DIR,
          target: str = "pqcp-evidence-verify") -> Path:
    for cmd in (
        ["cmake", "-S", str(source_dir), "-B", str(build_dir),
         "-DCMAKE_BUILD_TYPE=Release"],
        ["cmake", "--build", str(build_dir)],
    ):
        result = run(cmd)
        if result.returncode != 0:
            print(result.stdout + result.stderr)
            raise RuntimeError(f"command failed: {' '.join(cmd)}")
    binary = build_dir / target
    if not binary.exists():
        raise RuntimeError(f"{target} was not produced")
    return binary


def receipt_smoke(verifier: Path, register: Path, work: Path) -> bool:
    """Register the signed fixture's appraisal, then verify its receipt."""
    transcript = TESTDATA / "signed_passport_transcript.log"
    seed, pk = work / "seed", work / "log.pk"
    statement, ckpt = work / "stmt.cbor", work / "ckpt.cbor"
    receipt, log_dir = work / "receipt.cbor", work / "log"
    seed.write_bytes(bytes(range(32)))
    steps = (
        [str(verifier), "--emit-statement", str(statement),
         "--require-signature", "--quiet", str(transcript)],
        [str(register), "keygen", "--seed-file", str(seed),
         "--pk-out", str(pk)],
        [str(register), "register", "--log-dir", str(log_dir),
         "--log-pk", str(pk), "--statement", str(statement)],
        [str(register), "checkpoint", "--log-dir", str(log_dir),
         "--seed-file", str(seed), "--sequence", "1", "--out", str(ckpt)],
        [str(register), "receipt", "--log-dir", str(log_dir),
         "--checkpoint", str(ckpt), "--leaf-index", "0",
         "--out", str(receipt)],
    )
    for cmd in steps:
        if run(cmd).returncode != 0:
            return False
    good = run([str(verifier), "--receipt", str(receipt), "--log-pk",
                str(pk), "--require-signature", str(transcript)])
    if good.returncode != 0 or "PQCP_APPRAISAL_RECEIPT PASS" not in good.stdout:
        return False
    # A flipped receipt byte must be rejected.
    blob = bytearray(receipt.read_bytes())
    blob[40] ^= 0x01
    receipt.write_bytes(bytes(blob))
    bad = run([str(verifier), "--receipt", str(receipt), "--log-pk", str(pk),
               "--require-signature", str(transcript)])
    return bad.returncode == 1


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
        register = build(work / "build-register", REGISTER_DIR,
                         "pqcp-evidence-register")

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
        if not receipt_smoke(binary, register, work):
            print("[kit] FAIL: appraisal receipt smoke test failed "
                  "(register, receipt verify, or tampered-receipt reject); "
                  "refusing to package")
            return 1
        print("[kit] smoke test passed: signed transcript verifies, "
              "tampered transcript is rejected, appraisal receipt verifies "
              "and a flipped receipt is rejected")

        root = work / stem
        (root / "bin").mkdir(parents=True)
        (root / "examples").mkdir()
        shutil.copy2(binary, root / "bin" / "pqcp-evidence-verify")
        shutil.copy2(register, root / "bin" / "pqcp-evidence-register")
        (root / "tools").mkdir()
        shutil.copy2(REFERENCE_VERIFIER, root / "tools" / "rfc9162_reference.py")
        (root / "docs").mkdir()
        shutil.copy2(FORMAT_DOC, root / "docs" / FORMAT_DOC.name)
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
