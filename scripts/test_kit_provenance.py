#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for the evidence-verifier kit provenance and signature.

Builds the real pqcp-evidence-register once, assembles a miniature kit with
the packager's own helpers (real register binary, stub verifier), signs its
provenance, then drives scripts/verify_kit_provenance.py through controls and
forgeries: tampered kit, tampered provenance, other signer, signature over
other bytes, and a signature made under the log-checkpoint context.
"""

import contextlib
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import package_evidence_verifier as pkg  # noqa: E402
import verify_kit_provenance as kp  # noqa: E402

VERSION, SYSTEM, MACHINE = "9.9.9", "testos", "testarch"
STEM = f"pqcp-evidence-verifier-{VERSION}-{SYSTEM}-{MACHINE}"
EPOCH = 1700000000
SOURCE = {"version": VERSION, "git_commit": "ab" * 20,
          "git_dirty": False, "tag": "v9.9.9"}
CLAIMS = ["firmware.evidence_chain_replay"]


def run_verify(*argv) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = kp.main([str(a) for a in argv])
    return rc, out.getvalue(), err.getvalue()


def reasons_of(stdout: str) -> set[str]:
    for line in stdout.splitlines():
        if line.startswith("PQCP_KIT_PROVENANCE REJECT reasons="):
            return set(line.split("reasons=", 1)[1].split(","))
    return set()


class KitProvenance(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory(prefix="pqcp-kitprov-test-")
        cls.base = Path(cls.tmp.name)
        cls.register = pkg.build(cls.base / "build-register",
                                 pkg.REGISTER_DIR, "pqcp-evidence-register")
        cls.seed_a = cls.base / "seed-a"
        cls.seed_b = cls.base / "seed-b"
        cls.seed_a.write_bytes(bytes(range(32)))
        cls.seed_b.write_bytes(bytes(range(1, 33)))
        cls.key_a = cls.keygen(cls.seed_a, "a.pk")
        cls.key_b = cls.keygen(cls.seed_b, "b.pk")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    @classmethod
    def keygen(cls, seed: Path, name: str) -> str:
        result = pkg.run([str(cls.register), "keygen", "--seed-file",
                          str(seed), "--pk-out", str(cls.base / name)])
        assert result.returncode == 0, result.stdout + result.stderr
        return kp.sha256_bytes((cls.base / name).read_bytes())

    # ---- fixture construction ---------------------------------------

    def make_root(self, work: Path, readme_version: str = VERSION) -> Path:
        root = work / "root" / STEM
        for sub in ("bin", "tools", "docs", "examples"):
            (root / sub).mkdir(parents=True)
        shutil.copy2(self.register, root / "bin" / "pqcp-evidence-register")
        (root / "bin" / "pqcp-evidence-verify").write_bytes(b"stub verifier")
        (root / "tools" / "rfc9162_reference.py").write_text("# stub\n")
        (root / "docs" / "kit-provenance.md").write_text("doc\n")
        (root / "examples" / "t.log").write_text("transcript\n")
        (root / "README.txt").write_text(
            f"PQCP evidence verifier {readme_version} "
            f"({SYSTEM}-{MACHINE})\nrest\n")
        return root

    def make_kit(self, work: Path, seed: Path | None = None,
                 mutate_root=None) -> Path:
        """Build archive + provenance (+ signature when seed). Returns tar."""
        work.mkdir(parents=True, exist_ok=True)
        root = self.make_root(work)
        if mutate_root is not None:
            mutate_root(root)
        archive = work / f"{STEM}.tar.gz"
        pkg.write_deterministic_archive(root, archive, EPOCH)
        prov = archive.with_name(archive.name + ".provenance.json")
        prov.write_bytes(pkg.build_provenance(
            archive, root, VERSION, SYSTEM, MACHINE, "cc 1.0", "cmake 3.0",
            SOURCE, EPOCH, CLAIMS))
        if seed is not None:
            pkg.sign_provenance(self.register, seed, prov,
                                archive.with_name(
                                    archive.name + ".provenance.sig.json"),
                                work)
        return archive

    @staticmethod
    def prov_path(kit: Path) -> Path:
        return kit.with_name(kit.name + ".provenance.json")

    @staticmethod
    def sig_path(kit: Path) -> Path:
        return kit.with_name(kit.name + ".provenance.sig.json")

    def rewrite_prov(self, kit: Path, mutate) -> None:
        doc = json.loads(self.prov_path(kit).read_text())
        mutate(doc)
        self.prov_path(kit).write_bytes(kp.canonical_json(doc))

    def write_sig_json(self, kit: Path, seed_for_pk: Path, signature: bytes,
                       **override) -> None:
        pk = (self.base / ("a.pk" if seed_for_pk == self.seed_a
                           else "b.pk")).read_bytes()
        doc = {"schema_version": 1, "algorithm": "ML-DSA-65",
               "context": kp.CONTEXT, "key_id": kp.sha256_bytes(pk),
               "public_key_hex": pk.hex(), "signature_hex": signature.hex()}
        doc.update(override)
        self.sig_path(kit).write_text(json.dumps(doc))

    def raw_sign(self, seed: Path, data: Path, out: Path,
                 *extra: str) -> bytes:
        result = pkg.run([str(self.register), "sign-file", "--seed-file",
                          str(seed), "--in", str(data), "--out", str(out),
                          *extra])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return out.read_bytes()

    def verify_pinned(self, kit: Path, **kw):
        return run_verify(kit, "--pin-key-id", kw.get("key", self.key_a))

    # ---- controls ----------------------------------------------------

    def test_signed_pinned_passes(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            kit = self.make_kit(Path(t), self.seed_a)
            rc, out, _ = run_verify(kit, "--pin-key-id", self.key_a,
                                    "--require-signature")
            self.assertEqual(rc, 0, out)
            self.assertIn("PQCP_KIT_PROVENANCE PASS", out)
            self.assertIn(self.key_a, out)

    def test_pin_by_public_key_file_passes(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            kit = self.make_kit(Path(t), self.seed_a)
            rc, out, _ = run_verify(kit, "--pin-pk", self.base / "a.pk")
            self.assertEqual(rc, 0, out)
            self.assertIn("PQCP_KIT_PROVENANCE PASS", out)

    def test_unsigned_reports_unsigned_never_silently_passes(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            kit = self.make_kit(Path(t))
            rc, out, err = run_verify(kit)
            self.assertEqual(rc, 0, out)
            self.assertIn("PQCP_KIT_PROVENANCE UNSIGNED", out)
            self.assertNotIn("PQCP_KIT_PROVENANCE PASS", out)
            self.assertIn("warning", err)
            rc, out, _ = run_verify(kit, "--require-signature")
            self.assertEqual(rc, 1)

    def test_signed_without_pin_is_reported_unpinned(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            kit = self.make_kit(Path(t), self.seed_a)
            rc, out, _ = run_verify(kit)
            self.assertEqual(rc, 0, out)
            self.assertIn("PQCP_KIT_PROVENANCE UNPINNED", out)
            rc, _, _ = run_verify(kit, "--require-signature")
            self.assertEqual(rc, 1)

    def test_output_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as t1, \
                tempfile.TemporaryDirectory() as t2:
            k1 = self.make_kit(Path(t1), self.seed_a)
            k2 = self.make_kit(Path(t2), self.seed_a)
            for suffix in ("", ".provenance.json", ".provenance.sig.json"):
                self.assertEqual(
                    k1.with_name(k1.name + suffix).read_bytes(),
                    k2.with_name(k2.name + suffix).read_bytes(), suffix)

    def test_log_context_control_verifies_only_with_fixture_flag(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            data = Path(t) / "data"
            data.write_bytes(b"payload")
            sig = Path(t) / "sig"
            self.raw_sign(self.seed_a, data, sig, "--fixture-log-context")
            args = [str(self.register), "verify-file", "--pk",
                    str(self.base / "a.pk"), "--in", str(data), "--sig",
                    str(sig)]
            self.assertEqual(pkg.run(args + ["--fixture-log-context"])
                             .returncode, 0)
            self.assertEqual(pkg.run(args).returncode, 1)

    def test_resolve_seed(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(pkg.SEED_ENV, None)
            self.assertIsNone(pkg.resolve_seed(None))
            self.assertEqual(pkg.resolve_seed(self.seed_a), self.seed_a)
            os.environ[pkg.SEED_ENV] = str(self.seed_b)
            self.assertEqual(pkg.resolve_seed(None), self.seed_b)
            self.assertEqual(pkg.resolve_seed(self.seed_a), self.seed_a)
            os.environ[pkg.SEED_ENV] = ""
            self.assertIsNone(pkg.resolve_seed(None))
        bad = self.base / "short-seed"
        bad.write_bytes(b"short")
        with self.assertRaises(RuntimeError):
            pkg.resolve_seed(bad)
        with self.assertRaises(RuntimeError):
            pkg.resolve_seed(self.base / "missing-seed")

    # ---- forgeries: the kit ------------------------------------------

    def test_tampered_kit_content_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            kit = self.make_kit(Path(t), self.seed_a)
            prov, sig = self.prov_path(kit).read_bytes(), \
                self.sig_path(kit).read_bytes()
            # Rebuild the kit with one byte of one file changed but keep the
            # original provenance and signature.
            work = Path(t) / "forge"
            root = self.make_root(work)
            (root / "examples" / "t.log").write_text("transcripT\n")
            pkg.write_deterministic_archive(root, kit, EPOCH)
            self.prov_path(kit).write_bytes(prov)
            self.sig_path(kit).write_bytes(sig)
            rc, out, _ = self.verify_pinned(kit)
            self.assertEqual(rc, 1, out)
            self.assertTrue({"kit_hash_mismatch", "file_hash_mismatch"}
                            <= reasons_of(out), out)

    def test_flipped_archive_byte_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            kit = self.make_kit(Path(t), self.seed_a)
            blob = bytearray(kit.read_bytes())
            blob[len(blob) // 2] ^= 0x01
            kit.write_bytes(bytes(blob))
            rc, out, _ = self.verify_pinned(kit)
            self.assertEqual(rc, 1, out)
            self.assertIn("PQCP_KIT_PROVENANCE REJECT", out)

    def test_extra_and_missing_files_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            kit = self.make_kit(Path(t), self.seed_a)
            prov, sig = self.prov_path(kit).read_bytes(), \
                self.sig_path(kit).read_bytes()

            def forged(mutate) -> set[str]:
                work = Path(t) / "forge"
                shutil.rmtree(work, ignore_errors=True)
                root = self.make_root(work)
                mutate(root)
                pkg.write_deterministic_archive(root, kit, EPOCH)
                self.prov_path(kit).write_bytes(prov)
                self.sig_path(kit).write_bytes(sig)
                rc, out, _ = self.verify_pinned(kit)
                self.assertEqual(rc, 1, out)
                return reasons_of(out)

            self.assertIn("file_unlisted", forged(
                lambda r: (r / "bin" / "backdoor").write_bytes(b"x")))
            self.assertIn("file_missing", forged(
                lambda r: (r / "examples" / "t.log").unlink()))

    def test_unsafe_tar_members_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            kit = self.make_kit(Path(t))
            for name, kind in ((f"{STEM}/link", tarfile.SYMTYPE),
                               ("../evil", tarfile.REGTYPE),
                               ("/abs/evil", tarfile.REGTYPE),
                               ("other-top/x", tarfile.REGTYPE),
                               (f"{STEM}/README.txt", tarfile.REGTYPE)):
                with tarfile.open(kit, "w:gz") as tar:
                    first = tarfile.TarInfo(f"{STEM}/README.txt")
                    tar.addfile(first)
                    info = tarfile.TarInfo(name)
                    info.type = kind
                    if kind == tarfile.SYMTYPE:
                        info.linkname = "/etc/passwd"
                    tar.addfile(info)
                rc, out, _ = run_verify(kit)
                self.assertEqual(rc, 1, name)
                self.assertIn("kit_unsafe_member", reasons_of(out), name)

    # ---- forgeries: the provenance -----------------------------------

    def test_tampered_provenance_field_breaks_signature(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            kit = self.make_kit(Path(t), self.seed_a)
            self.rewrite_prov(
                kit, lambda d: d["source"].update(git_commit="cd" * 20))
            rc, out, _ = self.verify_pinned(kit)
            self.assertEqual(rc, 1, out)
            self.assertEqual(reasons_of(out), {"bad_signature"}, out)

    def test_tampered_claims_list_breaks_signature(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            kit = self.make_kit(Path(t), self.seed_a)
            self.rewrite_prov(kit, lambda d: d["claims"].append("x.y"))
            rc, out, _ = self.verify_pinned(kit)
            self.assertEqual(rc, 1, out)
            self.assertIn("bad_signature", reasons_of(out))

    def test_unsigned_provenance_field_tamper_cross_checks(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            kit = self.make_kit(Path(t))
            self.rewrite_prov(kit, lambda d: d["kit"].update(sha256="0" * 64))
            rc, out, _ = run_verify(kit)
            self.assertEqual(rc, 1, out)
            self.assertIn("kit_hash_mismatch", reasons_of(out))
        with tempfile.TemporaryDirectory() as t:
            kit = self.make_kit(Path(t))
            self.rewrite_prov(
                kit, lambda d: d["files"].update(
                    {"README.txt": "1" * 64}))
            rc, out, _ = run_verify(kit)
            self.assertIn("file_hash_mismatch", reasons_of(out))
        with tempfile.TemporaryDirectory() as t:
            kit = self.make_kit(Path(t))
            self.rewrite_prov(kit, lambda d: d["source"].update(
                version="1.2.3"))
            rc, out, _ = run_verify(kit)
            self.assertEqual(rc, 1, out)
            self.assertIn("field_mismatch", reasons_of(out))

    def test_unsigned_uncheckable_field_edit_is_unauthenticated(self) -> None:
        """Honest limit: with no signature a free-form field edit is not caught."""
        with tempfile.TemporaryDirectory() as t:
            kit = self.make_kit(Path(t))
            self.rewrite_prov(
                kit, lambda d: d["source"].update(git_commit="cd" * 20))
            rc, out, _ = run_verify(kit)
            self.assertEqual(rc, 0, out)
            self.assertIn("UNSIGNED", out)

    def test_noncanonical_provenance_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            kit = self.make_kit(Path(t), self.seed_a)
            doc = json.loads(self.prov_path(kit).read_text())
            self.prov_path(kit).write_text(json.dumps(doc, indent=2))
            rc, out, _ = self.verify_pinned(kit)
            self.assertEqual(rc, 1, out)
            self.assertIn("provenance_not_canonical", reasons_of(out))

    # ---- forgeries: the signature ------------------------------------

    def test_signature_from_a_different_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            kit = self.make_kit(Path(t), self.seed_a)
            raw = Path(t) / "forged.sig"
            sig = self.raw_sign(self.seed_b, self.prov_path(kit), raw)
            # Whole signature file replaced by the attacker's key + sig.
            self.write_sig_json(kit, self.seed_b, sig)
            rc, out, _ = self.verify_pinned(kit)
            self.assertEqual(rc, 1, out)
            self.assertIn("signer_not_pinned", reasons_of(out))
            # Honest limit: unpinned, the forgery is self-consistent.
            rc, out, _ = run_verify(kit)
            self.assertIn("UNPINNED", out)
            rc, _, _ = run_verify(kit, "--require-signature")
            self.assertEqual(rc, 1)
            # Attacker keeps the pinned public key but supplies their sig.
            self.write_sig_json(kit, self.seed_a, sig)
            rc, out, _ = self.verify_pinned(kit)
            self.assertEqual(rc, 1, out)
            self.assertIn("bad_signature", reasons_of(out))

    def test_signature_over_different_bytes_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            kit = self.make_kit(Path(t), self.seed_a)
            other = Path(t) / "other.json"
            other.write_bytes(self.prov_path(kit).read_bytes() + b" ")
            sig = self.raw_sign(self.seed_a, other, Path(t) / "o.sig")
            self.write_sig_json(kit, self.seed_a, sig)
            rc, out, _ = self.verify_pinned(kit)
            self.assertEqual(rc, 1, out)
            self.assertEqual(reasons_of(out), {"bad_signature"}, out)

    def test_signature_under_the_log_context_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            kit = self.make_kit(Path(t), self.seed_a)
            sig = self.raw_sign(self.seed_a, self.prov_path(kit),
                                Path(t) / "log.sig", "--fixture-log-context")
            # Correct key, correct bytes, wrong domain separation.
            self.write_sig_json(kit, self.seed_a, sig)
            rc, out, _ = self.verify_pinned(kit)
            self.assertEqual(rc, 1, out)
            self.assertEqual(reasons_of(out), {"bad_signature"}, out)
            # Claiming the log context in the metadata is refused too.
            self.write_sig_json(kit, self.seed_a, sig,
                                context="PQCP-APPRAISAL-LOG-V1")
            rc, out, _ = self.verify_pinned(kit)
            self.assertEqual(rc, 1, out)
            self.assertIn("signature_metadata", reasons_of(out))

    def test_malformed_signature_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            kit = self.make_kit(Path(t), self.seed_a)
            good = json.loads(self.sig_path(kit).read_text())
            cases = (
                ("signature_malformed", {"signature_hex": "00" * 100}),
                ("key_id_mismatch", {"key_id": "0" * 64}),
                ("signature_metadata", {"algorithm": "ML-DSA-44"}),
            )
            for token, patch in cases:
                self.sig_path(kit).write_text(json.dumps({**good, **patch}))
                rc, out, _ = self.verify_pinned(kit)
                self.assertEqual(rc, 1, token)
                self.assertIn(token, reasons_of(out), token)

    def test_deleting_the_signature_is_a_visible_downgrade(self) -> None:
        with tempfile.TemporaryDirectory() as t:
            kit = self.make_kit(Path(t), self.seed_a)
            self.sig_path(kit).unlink()
            rc, out, _ = run_verify(kit, "--pin-key-id", self.key_a,
                                    "--require-signature")
            self.assertEqual(rc, 1)
            self.assertNotIn("PQCP_KIT_PROVENANCE PASS", out)


if __name__ == "__main__":
    unittest.main()
