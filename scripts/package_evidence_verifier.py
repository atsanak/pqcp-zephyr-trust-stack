#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Package the host evidence verifier as a self-contained release kit.

Builds tools/evidence_verifier, smoke-tests the produced binary against the
bundled signed transcript (the kit is not written unless the binary
verifies it), then emits:

  pqcp-evidence-verifier-<version>-<os>-<arch>.tar.gz
  pqcp-evidence-verifier-<version>-<os>-<arch>.tar.gz.sha256
  pqcp-evidence-verifier-<version>-<os>-<arch>.tar.gz.provenance.json
  pqcp-evidence-verifier-<version>-<os>-<arch>.tar.gz.provenance.sig.json

The provenance sidecar is canonical JSON (kit hash, commit, builder, per-file
hashes, supported claims). The signature sidecar is an ML-DSA-65 signature over
those exact bytes, made with `pqcp-evidence-register sign-file` from a seed
file (--signing-seed-file or PQCP_KIT_SIGNING_SEED_FILE). With no seed the
provenance is written UNSIGNED, loudly. See docs/kit-provenance.md.

The kit lets a third party check a device's evidence chain with nothing but
the binary: the same firmware C that produced the evidence, compiled for
host. Packaging only - every verification decision is made by that binary.
"""

import argparse
import datetime
import gzip
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import verify_kit_provenance as kp  # noqa: E402

MODULE_ROOT = Path(__file__).resolve().parent.parent
TOOL_DIR = MODULE_ROOT / "tools" / "evidence_verifier"
REGISTER_DIR = MODULE_ROOT / "tools" / "evidence_register"
REFERENCE_VERIFIER = MODULE_ROOT / "scripts" / "rfc9162_reference.py"
FORMAT_DOC = MODULE_ROOT / "docs" / "transparent-appraisal-format.md"
PROVENANCE_DOC = MODULE_ROOT / "docs" / "kit-provenance.md"
KIT_PROVENANCE_VERIFIER = MODULE_ROOT / "scripts" / "verify_kit_provenance.py"
CLAIMS_FILE = MODULE_ROOT / "scripts" / "assurance_claims.json"
SEED_ENV = "PQCP_KIT_SIGNING_SEED_FILE"
# Assurance claims the kit is meant to support: the host replay of firmware
# evidence, the parser fuzzing of that evidence grammar, and the transparent
# appraisal receipt machinery it ships.
KIT_CLAIMS = (
    "firmware.evidence_chain_replay",
    "security.evidence_parser_fuzzed",
    "supply_chain.transparent_appraisal_receipt",
)
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

Release provenance (see docs/kit-provenance.md): the kit ships next to
<kit>.provenance.json and, when signed, <kit>.provenance.sig.json.

  python3 tools/verify_kit_provenance.py <kit>.tar.gz --pin-key-id <hex>
                                         [--register-bin trusted-register]

The signing key is a demo key without revocation; the signature proves the
provenance file was not altered, not that the kit was built correctly.

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
    return kp.sha256_file(path)


def tool_line(cmd: list[str]) -> str:
    try:
        out = run(cmd).stdout.strip().splitlines()
    except OSError:
        return "unavailable"
    return out[0] if out else "unavailable"


def compiler_version(build_dir: Path) -> str:
    cache = build_dir / "CMakeCache.txt"
    if cache.exists():
        match = re.search(r"^CMAKE_C_COMPILER:\w+=(.+)$",
                          cache.read_text(encoding="utf-8", errors="replace"),
                          re.MULTILINE)
        if match:
            return tool_line([match.group(1), "--version"])
    return "unavailable"


def git(*cmd: str) -> str | None:
    result = run(["git", "-C", str(MODULE_ROOT), *cmd])
    return result.stdout.strip() if result.returncode == 0 else None


def source_info(version: str) -> tuple[dict, int]:
    """Git facts plus the SOURCE_DATE_EPOCH-style timestamp."""
    commit = git("rev-parse", "HEAD")
    status = git("status", "--porcelain", "--untracked-files=no")
    tag = git("describe", "--tags", "--exact-match", "HEAD")
    env_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if env_epoch:
        epoch = int(env_epoch)
    else:
        commit_time = git("log", "-1", "--format=%ct", "HEAD")
        if commit_time is None:
            raise RuntimeError("not a git checkout and SOURCE_DATE_EPOCH is "
                               "unset; cannot derive a reproducible timestamp")
        epoch = int(commit_time)
    return {
        "version": version,
        "git_commit": commit,
        "git_dirty": bool(status) if status is not None else True,
        "tag": tag or None,
    }, epoch


def validate_claims() -> list[str]:
    known = {c["id"] for c in
             json.loads(CLAIMS_FILE.read_text(encoding="utf-8"))["claims"]}
    missing = [c for c in KIT_CLAIMS if c not in known]
    if missing:
        raise RuntimeError(f"kit claims not in assurance_claims.json: "
                           f"{missing}")
    return sorted(KIT_CLAIMS)


def write_deterministic_archive(root: Path, archive: Path, epoch: int) -> None:
    """tar.gz with sorted entries, fixed mtime, uid/gid 0, no gzip name/time."""
    entries = sorted(root.rglob("*"), key=lambda p: p.relative_to(root.parent)
                     .as_posix())

    def info(path: Path) -> tarfile.TarInfo:
        arc = path.relative_to(root.parent).as_posix()
        ti = tarfile.TarInfo(arc)
        ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname = epoch, 0, 0, "", ""
        if path.is_dir():
            ti.type, ti.mode = tarfile.DIRTYPE, 0o755
        else:
            ti.size = path.stat().st_size
            ti.mode = 0o755 if path.parent.name == "bin" else 0o644
        return ti

    with archive.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw,
                           mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w",
                              format=tarfile.GNU_FORMAT) as tar:
                tar.addfile(info(root))
                for path in entries:
                    if path.is_dir():
                        tar.addfile(info(path))
                    else:
                        with path.open("rb") as handle:
                            tar.addfile(info(path), handle)


def tree_hashes(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): kp.sha256_file(p)
            for p in sorted(root.rglob("*")) if p.is_file()}


def build_provenance(archive: Path, root: Path, version: str, system: str,
                     machine: str, compiler: str, cmake: str,
                     source: dict, epoch: int, claims: list[str]) -> bytes:
    return kp.canonical_json({
        "schema_version": kp.PROVENANCE_SCHEMA,
        "kind": kp.PROVENANCE_KIND,
        "kit": {"name": archive.name, "sha256": kp.sha256_file(archive),
                "size_bytes": archive.stat().st_size},
        "source": source,
        "builder": {"system": system, "release": platform.release(),
                    "machine": machine, "compiler": compiler,
                    "cmake": cmake},
        "source_date_epoch": epoch,
        "timestamp_utc": datetime.datetime.fromtimestamp(
            epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": tree_hashes(root),
        "claims": claims,
    })


def resolve_seed(arg: Path | None) -> Path | None:
    """--signing-seed-file wins over the env var; empty env means absent.

    A seed that is named but unusable is an error, never a silent downgrade
    to unsigned.
    """
    chosen = arg
    if chosen is None and os.environ.get(SEED_ENV):
        chosen = Path(os.environ[SEED_ENV])
    if chosen is None:
        return None
    if not chosen.is_file() or chosen.stat().st_size != 32:
        raise RuntimeError(f"signing seed {chosen} must be an existing "
                           f"32-byte raw file")
    return chosen


def sign_provenance(register: Path, seed: Path, prov: Path, sig_json: Path,
                    work: Path) -> str:
    """Sign prov with the register tool; write sig_json; return the key id."""
    pk, raw_sig = work / "kit-signer.pk", work / "provenance.sig"
    for cmd in (
        [str(register), "keygen", "--seed-file", str(seed),
         "--pk-out", str(pk)],
        [str(register), "sign-file", "--seed-file", str(seed),
         "--in", str(prov), "--out", str(raw_sig)],
    ):
        result = run(cmd)
        if result.returncode != 0:
            raise RuntimeError(f"{cmd[1]} failed: "
                               f"{result.stdout}{result.stderr}")
    check = run([str(register), "verify-file", "--pk", str(pk),
                 "--in", str(prov), "--sig", str(raw_sig)])
    if check.returncode != 0 or "VERIFY-FILE PASS" not in check.stdout:
        raise RuntimeError("fresh signature does not verify: "
                           + check.stdout + check.stderr)
    pk_bytes = pk.read_bytes()
    key_id = kp.sha256_bytes(pk_bytes)
    sig_json.write_text(json.dumps({
        "schema_version": kp.SIGNATURE_SCHEMA,
        "algorithm": kp.ALGORITHM,
        "context": kp.CONTEXT,
        "key_id": key_id,
        "public_key_hex": pk_bytes.hex(),
        "signature_hex": raw_sig.read_bytes().hex(),
    }, sort_keys=True, indent=2) + "\n", encoding="ascii")
    return key_id


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--output-dir", type=Path,
                        default=MODULE_ROOT / "dist")
    parser.add_argument("--signing-seed-file", type=Path,
                        help="32-byte raw ML-DSA-65 seed that signs the "
                             f"provenance (or set {SEED_ENV}); without one "
                             "the provenance is emitted UNSIGNED")
    args = parser.parse_args()

    try:
        seed = resolve_seed(args.signing_seed_file)
        source, epoch = source_info(read_version())
        claims = validate_claims()
    except RuntimeError as exc:
        print(f"[kit] FAIL: {exc}")
        return 1
    version = source["version"]
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
        shutil.copy2(KIT_PROVENANCE_VERIFIER,
                     root / "tools" / "verify_kit_provenance.py")
        (root / "docs").mkdir()
        shutil.copy2(FORMAT_DOC, root / "docs" / FORMAT_DOC.name)
        shutil.copy2(PROVENANCE_DOC, root / "docs" / PROVENANCE_DOC.name)
        for fixture in FIXTURES:
            shutil.copy2(TESTDATA / fixture, root / "examples" / fixture)
        (root / "README.txt").write_text(
            README.format(version=version, system=system, machine=machine),
            encoding="utf-8")

        args.output_dir.mkdir(parents=True, exist_ok=True)
        archive = args.output_dir / f"{stem}.tar.gz"
        write_deterministic_archive(root, archive, epoch)

        prov_path = archive.with_name(archive.name + ".provenance.json")
        sig_path = archive.with_name(archive.name + ".provenance.sig.json")
        prov_path.write_bytes(build_provenance(
            archive, root, version, system, machine,
            compiler_version(work / "build"),
            tool_line(["cmake", "--version"]), source, epoch, claims))
        if seed is None:
            sig_path.unlink(missing_ok=True)  # never leave a stale signature
            signed_key = None
        else:
            try:
                signed_key = sign_provenance(register, seed, prov_path,
                                             sig_path, work)
            except RuntimeError as exc:
                print(f"[kit] FAIL: provenance signing: {exc}")
                return 1

    sidecar = archive.with_name(archive.name + ".sha256")
    sidecar.write_text(f"{sha256_of(archive)}  {archive.name}\n",
                       encoding="utf-8")
    print(f"PQCP_EVIDENCE_KIT PASS archive={archive.name} "
          f"sha256={sha256_of(archive)}")
    print(f"[kit] wrote {archive} and {sidecar.name}")
    if source["git_dirty"]:
        print("[kit] warning: tracked files differ from HEAD "
              "(git_dirty=true recorded in the provenance)")
    if signed_key is None:
        print(f"PQCP_KIT_PROVENANCE UNSIGNED provenance={prov_path.name} "
              f"reason=no signing seed (--signing-seed-file or {SEED_ENV})")
        print("[kit] WARNING: provenance written WITHOUT a signature; "
              "nothing authenticates its origin")
    else:
        print(f"PQCP_KIT_PROVENANCE SIGNED provenance={prov_path.name} "
              f"signature={sig_path.name} key_id={signed_key}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
