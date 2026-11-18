#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Verify an evidence-verifier release kit against its provenance sidecars.

  verify_kit_provenance.py KIT.tar.gz [--provenance P] [--signature S]
        [--pin-key-id HEX | --pin-pk FILE] [--register-bin B]
        [--require-signature]

Checks, in this order of authority:

  1. the provenance file is well-formed canonical JSON (schema 1);
  2. the kit's SHA-256 and size equal the provenance values;
  3. every file inside the tarball hashes to the provenance `files` map and
     no file is missing or unlisted; tarball members must be plain files or
     directories under one top-level directory (no links, no traversal);
  4. provenance fields agree with the kit contents (kit name stem is
     derived from version/system/machine, README version line);
  5. when `<kit>.provenance.sig.json` exists, the ML-DSA-65 signature over the
     exact provenance bytes is verified by `pqcp-evidence-register
     verify-file` (context PQCP-KIT-PROVENANCE-V1). Without a pin the signing
     key is only the one embedded in the signature file.

Result markers (stdout, one line):

  PQCP_KIT_PROVENANCE PASS      signed, verified, signer key pinned
  PQCP_KIT_PROVENANCE UNPINNED  signed and valid under the EMBEDDED key only
  PQCP_KIT_PROVENANCE UNSIGNED  no signature file; integrity checks only
  PQCP_KIT_PROVENANCE REJECT reasons=<token,...>

Exit 0 for PASS, UNPINNED and UNSIGNED (the line says which, never silent);
with --require-signature only PASS exits 0. Exit 1 for REJECT. Exit 2 for
usage errors. A kit that ships its own register binary vouches for itself:
for an adversarial setting pass a trusted `--register-bin` and a pin.

What this proves and does not prove: docs/kit-provenance.md.
"""

import argparse
import hashlib
import json
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

PROVENANCE_SCHEMA = 1
PROVENANCE_KIND = "pqcp-evidence-verifier-kit-provenance"
SIGNATURE_SCHEMA = 1
ALGORITHM = "ML-DSA-65"
CONTEXT = "PQCP-KIT-PROVENANCE-V1"
PK_BYTES = 1952
SIG_BYTES = 3309
REGISTER_MEMBER = "bin/pqcp-evidence-register"
REQUIRED_FILES = ("bin/pqcp-evidence-verify", REGISTER_MEMBER, "README.txt")
MAX_KIT_BYTES = 256 * 1024 * 1024
KIT_STEM = "pqcp-evidence-verifier-{version}-{system}-{machine}"
SIG_KEYS = frozenset((
    "schema_version", "algorithm", "context", "key_id", "public_key_hex",
    "signature_hex"))
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")


def canonical_json(obj) -> bytes:
    """The one serialisation the provenance is signed in."""
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("ascii")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Verdict:
    """Collects reject tokens; details go to stderr, tokens to the marker."""

    def __init__(self) -> None:
        self.reasons: list[str] = []

    def reject(self, token: str, detail: str = "") -> None:
        self.reasons.append(token)
        print(f"[kit-provenance] reject {token}"
              + (f": {detail}" if detail else ""), file=sys.stderr)


def scan_kit(path: Path, verdict: Verdict):
    """Return (top_dir, {relpath: sha256}, register_bytes, readme) or None."""
    files: dict[str, str] = {}
    register = None
    readme = ""
    top = None
    total = 0
    try:
        tar = tarfile.open(path, "r:gz")
    except (OSError, tarfile.TarError) as exc:
        verdict.reject("kit_unreadable", str(exc))
        return None
    with tar:
        try:
            members = tar.getmembers()
        except (OSError, EOFError, tarfile.TarError) as exc:
            verdict.reject("kit_unreadable", str(exc))
            return None
        seen: set[str] = set()
        for member in members:
            name = member.name
            parts = name.split("/")
            if (name.startswith("/") or "\\" in name or ".." in parts
                    or "" in parts and name != "./"):
                verdict.reject("kit_unsafe_member", name)
                return None
            if not (member.isreg() or member.isdir()):
                verdict.reject("kit_unsafe_member",
                               f"{name} is not a regular file or directory")
                return None
            if top is None:
                top = parts[0]
            elif parts[0] != top:
                verdict.reject("kit_unsafe_member",
                               f"{name} is outside {top}/")
                return None
            if name in seen:
                verdict.reject("kit_unsafe_member", f"duplicate {name}")
                return None
            seen.add(name)
            if member.isdir():
                continue
            rel = "/".join(parts[1:])
            if not rel:
                verdict.reject("kit_unsafe_member", f"{name} has no parent")
                return None
            total += member.size
            if total > MAX_KIT_BYTES:
                verdict.reject("kit_unsafe_member", "kit expands too large")
                return None
            handle = tar.extractfile(member)
            if handle is None:
                verdict.reject("kit_unreadable", name)
                return None
            data = handle.read()
            files[rel] = sha256_bytes(data)
            if rel == REGISTER_MEMBER:
                register = data
            elif rel == "README.txt":
                readme = data.decode("utf-8", "replace")
    if top is None:
        verdict.reject("kit_unreadable", "empty archive")
        return None
    return top, files, register, readme


def load_provenance(path: Path, verdict: Verdict):
    """Return (bytes, parsed) or None. Requires canonical bytes."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        verdict.reject("provenance_unreadable", str(exc))
        return None
    try:
        parsed = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        verdict.reject("provenance_malformed", str(exc))
        return None
    if not isinstance(parsed, dict):
        verdict.reject("provenance_malformed", "top level is not an object")
        return None
    if canonical_json(parsed) != raw:
        verdict.reject("provenance_not_canonical",
                       "bytes are not the canonical serialisation")
        return None
    return raw, parsed


def check_schema(prov: dict, verdict: Verdict) -> bool:
    ok = True

    def need(cond: bool, what: str) -> None:
        nonlocal ok
        if not cond:
            ok = False
            verdict.reject("provenance_malformed", what)

    need(prov.get("schema_version") == PROVENANCE_SCHEMA, "schema_version")
    need(prov.get("kind") == PROVENANCE_KIND, "kind")
    kit, src = prov.get("kit"), prov.get("source")
    build, files = prov.get("builder"), prov.get("files")
    need(isinstance(kit, dict) and isinstance(kit.get("name"), str)
         and isinstance(kit.get("sha256"), str)
         and HEX64.match(kit["sha256"]) is not None
         and isinstance(kit.get("size_bytes"), int), "kit")
    need(isinstance(src, dict) and isinstance(src.get("version"), str)
         and isinstance(src.get("git_dirty"), bool)
         and (src.get("git_commit") is None
              or (isinstance(src.get("git_commit"), str)
                  and HEX40.match(src["git_commit"]) is not None))
         and (src.get("tag") is None or isinstance(src.get("tag"), str)),
         "source")
    need(isinstance(build, dict)
         and all(isinstance(build.get(k), str)
                 for k in ("system", "release", "machine", "compiler",
                           "cmake")), "builder")
    need(isinstance(files, dict) and bool(files)
         and all(isinstance(k, str) and isinstance(v, str)
                 and HEX64.match(v) is not None for k, v in files.items()),
         "files")
    need(isinstance(prov.get("source_date_epoch"), int)
         and prov["source_date_epoch"] >= 0, "source_date_epoch")
    claims = prov.get("claims")
    need(isinstance(claims, list) and bool(claims)
         and all(isinstance(c, str) for c in claims), "claims")
    return ok


def check_content(prov: dict, kit_path: Path, scanned, verdict: Verdict):
    top, files, _register, readme = scanned
    kit = prov["kit"]
    actual_size = kit_path.stat().st_size
    if sha256_file(kit_path) != kit["sha256"]:
        verdict.reject("kit_hash_mismatch")
    if actual_size != kit["size_bytes"]:
        verdict.reject("kit_size_mismatch",
                       f"{actual_size} != {kit['size_bytes']}")
    declared = prov["files"]
    for rel in sorted(set(declared) | set(files)):
        if rel not in files:
            verdict.reject("file_missing", rel)
        elif rel not in declared:
            verdict.reject("file_unlisted", rel)
        elif files[rel] != declared[rel]:
            verdict.reject("file_hash_mismatch", rel)
    for rel in REQUIRED_FILES:
        if rel not in declared:
            verdict.reject("file_missing", f"{rel} not covered by provenance")
    src, build = prov["source"], prov["builder"]
    stem = KIT_STEM.format(version=src["version"], system=build["system"],
                           machine=build["machine"])
    if top != stem or kit["name"] != stem + ".tar.gz":
        verdict.reject("field_mismatch",
                       f"kit name/top dir {top!r} vs fields {stem!r}")
    first = readme.splitlines()[0] if readme else ""
    want = (f"PQCP evidence verifier {src['version']} "
            f"({build['system']}-{build['machine']})")
    if first != want:
        verdict.reject("field_mismatch",
                       f"README first line {first!r} vs {want!r}")


def load_signature(path: Path, verdict: Verdict):
    """Return (pk_bytes, sig_bytes, key_id) or None (already rejected)."""
    try:
        doc = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        verdict.reject("signature_malformed", str(exc))
        return None
    if not isinstance(doc, dict) or set(doc) != SIG_KEYS:
        verdict.reject("signature_malformed", "unexpected key set")
        return None
    if (doc["schema_version"] != SIGNATURE_SCHEMA
            or doc["algorithm"] != ALGORITHM or doc["context"] != CONTEXT):
        verdict.reject("signature_metadata",
                       "schema/algorithm/context do not match")
        return None
    try:
        pk = bytes.fromhex(doc["public_key_hex"])
        sig = bytes.fromhex(doc["signature_hex"])
    except (TypeError, ValueError):
        verdict.reject("signature_malformed", "bad hex")
        return None
    if len(pk) != PK_BYTES or len(sig) != SIG_BYTES:
        verdict.reject("signature_malformed", "wrong key/signature length")
        return None
    if doc["key_id"] != sha256_bytes(pk):
        verdict.reject("key_id_mismatch",
                       "key_id is not SHA-256 of the embedded public key")
        return None
    return pk, sig, doc["key_id"]


def run_register_verify(register: Path, pk: bytes, prov_bytes: bytes,
                        sig: bytes, work: Path, verdict: Verdict) -> bool:
    (work / "pk").write_bytes(pk)
    (work / "prov").write_bytes(prov_bytes)
    (work / "sig").write_bytes(sig)
    try:
        result = subprocess.run(
            [str(register), "verify-file", "--pk", str(work / "pk"),
             "--in", str(work / "prov"), "--sig", str(work / "sig")],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        verdict.reject("register_unavailable", str(exc))
        return False
    if result.returncode == 0 and "VERIFY-FILE PASS" in result.stdout:
        return True
    reason = re.search(r"reason=(\w+)", result.stdout)
    verdict.reject(reason.group(1) if reason else "bad_signature",
                   (result.stdout + result.stderr).strip())
    return False


def verify(kit_path: Path, provenance_path: Path, signature_path: Path,
           pin_key_id: str | None, pin_pk: bytes | None,
           register_bin: Path | None, require_signature: bool) -> int:
    verdict = Verdict()
    status = None
    key_id = ""

    def finish(code: int) -> int:
        if verdict.reasons:
            print("PQCP_KIT_PROVENANCE REJECT reasons="
                  + ",".join(dict.fromkeys(verdict.reasons)))
            return 1
        return code

    prov_loaded = load_provenance(provenance_path, verdict)
    scanned = scan_kit(kit_path, verdict)
    if prov_loaded is None or scanned is None:
        return finish(1)
    prov_bytes, prov = prov_loaded
    if not check_schema(prov, verdict):
        return finish(1)
    check_content(prov, kit_path, scanned, verdict)

    if not signature_path.exists():
        status = "unsigned"
    else:
        loaded = load_signature(signature_path, verdict)
        if loaded is not None:
            pk, sig, key_id = loaded
            pinned = pin_key_id is not None or pin_pk is not None
            if pin_pk is not None:
                if pk != pin_pk:
                    verdict.reject("signer_not_pinned",
                                   "embedded key differs from --pin-pk")
            elif pin_key_id is not None and key_id != pin_key_id:
                verdict.reject("signer_not_pinned",
                               "embedded key id differs from --pin-key-id")
            if not verdict.reasons:
                with tempfile.TemporaryDirectory(prefix="pqcp-kitverify-") \
                        as tmp:
                    work = Path(tmp)
                    register = register_bin
                    if register is None:
                        if scanned[2] is None:
                            verdict.reject("register_unavailable",
                                           "kit has no register binary")
                        else:
                            register = work / "register"
                            register.write_bytes(scanned[2])
                            register.chmod(register.stat().st_mode
                                           | stat.S_IXUSR)
                    if register is not None:
                        run_register_verify(register, pk, prov_bytes, sig,
                                            work, verdict)
            status = "signed" if pinned else "unpinned"

    if verdict.reasons:
        return finish(1)
    kit_sha = prov["kit"]["sha256"]
    commit = prov["source"]["git_commit"]
    summary = (f"kit_sha256={kit_sha} version={prov['source']['version']} "
               f"commit={commit} dirty="
               f"{str(prov['source']['git_dirty']).lower()}")
    if status == "signed":
        print(f"PQCP_KIT_PROVENANCE PASS key_id={key_id} {summary}")
        return 0
    if status == "unpinned":
        print("PQCP_KIT_PROVENANCE UNPINNED signature=valid "
              f"key_id={key_id} signer=embedded-key-only {summary}")
        print("[kit-provenance] warning: signature is valid under the key "
              "embedded in the signature file; pass --pin-key-id or --pin-pk "
              "to bind it to a signer you trust", file=sys.stderr)
        return 1 if require_signature else 0
    print(f"PQCP_KIT_PROVENANCE UNSIGNED integrity_checks=pass {summary}")
    print("[kit-provenance] warning: no signature file; the provenance is "
          "internally consistent but nothing authenticates its origin",
          file=sys.stderr)
    return 1 if require_signature else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("kit", type=Path)
    parser.add_argument("--provenance", type=Path)
    parser.add_argument("--signature", type=Path)
    pin = parser.add_mutually_exclusive_group()
    pin.add_argument("--pin-key-id", help="expected SHA-256 of the signer key")
    pin.add_argument("--pin-pk", type=Path,
                     help="expected raw 1952-byte ML-DSA-65 public key")
    parser.add_argument("--register-bin", type=Path,
                        help="trusted pqcp-evidence-register (default: the "
                             "copy shipped inside the kit)")
    parser.add_argument("--require-signature", action="store_true",
                        help="exit 1 unless the result is PASS (signed and "
                             "pinned)")
    args = parser.parse_args(argv)

    if args.pin_key_id is not None and not HEX64.match(args.pin_key_id):
        parser.error("--pin-key-id must be 64 lowercase hex characters")
    pin_pk = None
    if args.pin_pk is not None:
        pin_pk = args.pin_pk.read_bytes()
        if len(pin_pk) != PK_BYTES:
            parser.error(f"--pin-pk must be exactly {PK_BYTES} bytes")
    if not args.kit.is_file():
        parser.error(f"kit not found: {args.kit}")
    provenance = args.provenance or args.kit.with_name(
        args.kit.name + ".provenance.json")
    signature = args.signature or args.kit.with_name(
        args.kit.name + ".provenance.sig.json")
    return verify(args.kit, provenance, signature, args.pin_key_id, pin_pk,
                  args.register_bin, args.require_signature)


if __name__ == "__main__":
    sys.exit(main())
