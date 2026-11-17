#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Focused tests for the host evidence verifier CLI.

Builds tools/evidence_verifier with the host toolchain, then drives it
against the checked-in advisor QEMU transcript fixture plus tampered and
degenerate variants. Pure subprocess orchestration: all verification logic
under test is the firmware C compiled for host.
"""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

MODULE_ROOT = Path(__file__).resolve().parent.parent
TOOL_DIR = MODULE_ROOT / "tools" / "evidence_verifier"
FIXTURE = TOOL_DIR / "testdata" / "advisor_qemu_transcript.log"
SIGNED_FIXTURE = TOOL_DIR / "testdata" / "signed_passport_transcript.log"
FULL_CHAIN_FIXTURE = (
    TOOL_DIR / "testdata" / "advisor_full_chain_transcript.log")


def build_tool(build_dir: Path) -> Path:
    subprocess.run(
        ["cmake", "-S", str(TOOL_DIR), "-B", str(build_dir),
         "-DCMAKE_BUILD_TYPE=Release"],
        check=True, capture_output=True, text=True)
    subprocess.run(
        ["cmake", "--build", str(build_dir)],
        check=True, capture_output=True, text=True)
    binary = build_dir / "pqcp-evidence-verify"
    if not binary.exists():
        raise RuntimeError("pqcp-evidence-verify was not produced")
    return binary


def run_tool(binary: Path, transcript: Path, *args: str):
    return subprocess.run(
        [str(binary), *args, str(transcript)],
        capture_output=True, text=True)


def write_variant(workdir: Path, name: str, text: str) -> Path:
    path = workdir / name
    path.write_text(text)
    return path


def main() -> int:
    if shutil.which("cmake") is None:
        print("SKIP: cmake not available on host")
        return 0
    if not FIXTURE.exists():
        print(f"FAIL: fixture missing: {FIXTURE}")
        return 1

    failures = []

    def check(label: str, condition: bool, detail: str = "") -> None:
        if condition:
            print(f"ok   - {label}")
        else:
            print(f"FAIL - {label} {detail}")
            failures.append(label)

    fixture_text = FIXTURE.read_text()

    with tempfile.TemporaryDirectory(prefix="pqcp-ev-") as tmp:
        workdir = Path(tmp)
        binary = build_tool(workdir / "build")

        # 1. Clean fixture verifies end to end and emits coherent JSON.
        json_path = workdir / "summary.json"
        result = run_tool(binary, FIXTURE, "--json", str(json_path))
        check("clean transcript verifies", result.returncode == 0,
              result.stdout + result.stderr)
        summary = json.loads(json_path.read_text())
        check("json reports chain_ok", summary.get("chain_ok") is True)
        check("json reports all three layers",
              summary["verdict"]["markers"] == 1
              and summary["seal"]["markers"] == 1
              and summary["passport"]["markers"] == 1)
        check("json bindings both true",
              summary["bindings"]["verdict_to_seal"] is True
              and summary["bindings"]["seal_to_passport"] is True)

        # 2. Tampering with the sealed verdict digest must break the chain.
        tampered = write_variant(
            workdir, "tampered_seal.log",
            fixture_text.replace("verdict_digest=731ff922",
                                 "verdict_digest=831ff922"))
        result = run_tool(binary, tampered, "--quiet")
        check("tampered seal digest rejected", result.returncode == 1)

        # 3. Tampering with the passport score must break passport replay.
        tampered = write_variant(
            workdir, "tampered_passport.log",
            fixture_text.replace(
                "PQCP_DEPLOYMENT_ASSURANCE_PASSPORT schema=1 profile=product"
                " status=FAIL errors=0x00000c14 warnings=0x00000003 score=0",
                "PQCP_DEPLOYMENT_ASSURANCE_PASSPORT schema=1 profile=product"
                " status=FAIL errors=0x00000c14 warnings=0x00000003 score=1"))
        result = run_tool(binary, tampered, "--quiet")
        check("tampered passport score rejected", result.returncode == 1)

        # 4. Dropping the passport fails strict mode but passes lenient mode.
        no_passport = write_variant(
            workdir, "no_passport.log",
            "\n".join(line for line in fixture_text.splitlines()
                      if not line.startswith(
                          "PQCP_DEPLOYMENT_ASSURANCE_PASSPORT ")) + "\n")
        result = run_tool(binary, no_passport, "--quiet")
        check("missing passport rejected in strict mode",
              result.returncode == 1)
        result = run_tool(binary, no_passport, "--quiet", "--lenient")
        check("missing passport tolerated in lenient mode",
              result.returncode == 0)

        # 5. A duplicated verdict marker is replay-rejected.
        verdict_line = next(
            line for line in fixture_text.splitlines()
            if line.startswith("PQCP_DEPLOYMENT_EVIDENCE_VERDICT schema="))
        duplicated = write_variant(
            workdir, "dup_verdict.log", fixture_text + verdict_line + "\n")
        result = run_tool(binary, duplicated, "--quiet")
        check("duplicate verdict marker rejected", result.returncode == 1)

        # 6. Degenerate inputs: empty and marker-free files never verify.
        empty = write_variant(workdir, "empty.log", "")
        result = run_tool(binary, empty, "--quiet")
        check("empty transcript rejected", result.returncode == 1)
        result = run_tool(binary, empty, "--quiet", "--lenient")
        check("empty transcript rejected even in lenient mode",
              result.returncode == 1)
        noise = write_variant(workdir, "noise.log",
                              "boot banner\nrandom text\n")
        result = run_tool(binary, noise, "--quiet")
        check("marker-free transcript rejected", result.returncode == 1)

        # 7. Signed-passport transcript: signature reassembles and verifies.
        signed_text = SIGNED_FIXTURE.read_text()
        json_path = workdir / "signed.json"
        result = run_tool(binary, SIGNED_FIXTURE,
                          "--require-signature", "--json", str(json_path))
        check("signed full-chain transcript verifies strictly",
              result.returncode == 0, result.stdout + result.stderr)
        check("signed fixture carries the full chain",
              json.loads(json_path.read_text())["bindings"][
                  "seal_to_passport"] is True)
        summary = json.loads(json_path.read_text())
        check("json reports signature verified",
              summary["signature"]["present"] is True
              and summary["signature"]["complete"] is True
              and summary["signature"]["digest_bound"] is True
              and summary["signature"]["verified"] is True)

        # 8. One flipped hex digit in a signature chunk must be rejected.
        idx = signed_text.find("SIG_CHUNK idx=12")
        idx = signed_text.find("data=", idx) + len("data=")
        flipped = "0" if signed_text[idx] != "0" else "1"
        tampered = write_variant(
            workdir, "sig_tampered.log",
            signed_text[:idx] + flipped + signed_text[idx + 1:])
        result = run_tool(binary, tampered, "--quiet")
        check("tampered signature chunk rejected", result.returncode == 1)

        # 9. A header claiming a different digest must be rejected.
        idx = signed_text.find("passport_digest=") + len("passport_digest=")
        flipped = "0" if signed_text[idx] != "0" else "1"
        tampered = write_variant(
            workdir, "sig_digest_tampered.log",
            signed_text[:idx] + flipped + signed_text[idx + 1:])
        result = run_tool(binary, tampered, "--quiet")
        check("tampered signature digest binding rejected",
              result.returncode == 1)

        # 10. Dropping one chunk leaves the capture incomplete.
        no_chunk = write_variant(
            workdir, "sig_missing_chunk.log",
            "\n".join(line for line in signed_text.splitlines()
                      if "SIG_CHUNK idx=7 " not in line) + "\n")
        result = run_tool(binary, no_chunk, "--lenient", "--quiet")
        check("missing signature chunk rejected", result.returncode == 1)

        # 11. The plain advisor transcript has no signature: required mode
        # fails, default mode still passes.
        result = run_tool(binary, FIXTURE, "--require-signature", "--quiet")
        check("unsigned transcript fails when signature required",
              result.returncode == 1)

        # 12. Usage errors exit 2, not 0/1.
        result = subprocess.run([str(binary)], capture_output=True, text=True)
        check("missing argument exits 2", result.returncode == 2)
        result = run_tool(binary, workdir / "does_not_exist.log")
        check("unreadable transcript exits 2", result.returncode == 2)

        # 13. Full-chain fixture (adversarial tamper matrix + evidence
        # trail) verifies, and the JSON reports the new layers and
        # bindings.
        full_text = FULL_CHAIN_FIXTURE.read_text()
        json_path = workdir / "full_chain.json"
        result = run_tool(binary, FULL_CHAIN_FIXTURE,
                          "--json", str(json_path))
        check("full-chain transcript verifies", result.returncode == 0,
              result.stdout + result.stderr)
        summary = json.loads(json_path.read_text())
        check("json reports tamper matrix replayed",
              summary["tamper_matrix"]["markers"] == 1
              and summary["tamper_matrix"]["passed"] is True
              and summary["tamper_matrix"]["coverage_permille"] == 1000
              and summary["tamper_matrix"]["missed"] == 0)
        check("json reports trail replayed",
              summary["trail"]["markers"] == 6
              and summary["trail"]["passed"] is True
              and summary["trail"]["entries"] == 5)
        check("json reports wave-11 bindings",
              summary["bindings"]["passport_to_tamper"] is True
              and summary["bindings"]["trail_identity"] is True)

        # 14. Tampering with one trail entry digest breaks the link chain.
        idx = full_text.find(
            "PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ENTRY schema=1 seq=2")
        idx = full_text.find("digest=", idx) + len("digest=")
        flipped = "0" if full_text[idx] != "0" else "1"
        tampered = write_variant(
            workdir, "trail_entry_tampered.log",
            full_text[:idx] + flipped + full_text[idx + 1:])
        result = run_tool(binary, tampered, "--quiet")
        check("tampered trail entry rejected", result.returncode == 1)

        # 15. Removing one trail entry breaks the head count.
        no_entry = write_variant(
            workdir, "trail_entry_dropped.log",
            "\n".join(line for line in full_text.splitlines()
                      if "TRAIL_ENTRY schema=1 seq=3" not in line) + "\n")
        result = run_tool(binary, no_entry, "--quiet")
        check("dropped trail entry rejected", result.returncode == 1)

        # 16. Forging the claimed detection coverage breaks the matrix
        # digest.
        forged = write_variant(
            workdir, "matrix_coverage_forged.log",
            full_text.replace("coverage_permille=1000",
                              "coverage_permille=970", 1))
        result = run_tool(binary, forged, "--quiet")
        check("forged tamper coverage rejected", result.returncode == 1)

        # 17. Older transcripts without the new layers must keep verifying
        # (covered by test 1) and stripping the new layers from a new
        # transcript must also keep the core chain verifiable.
        stripped = write_variant(
            workdir, "wave11_stripped.log",
            "\n".join(line for line in full_text.splitlines()
                      if not line.startswith((
                          "PQCP_DEPLOYMENT_TAMPER_",
                          "PQCP_DEPLOYMENT_EVIDENCE_TRAIL",
                          "PQCP_CAPABILITY_EXTENSION"))) + "\n")
        result = run_tool(binary, stripped, "--quiet")
        check("stripped wave-11 layers keep core chain verifiable",
              result.returncode == 0)


        # ------------------------------------------------------------
        # Single-check isolation and cross-run splices. Defense in depth
        # means ordinary tamper tests are caught by several checks at once
        # and would stay green if any ONE check were deleted. These cases
        # are built so exactly one check can catch the forgery; the
        # mutation runner (scripts/run_mutation_checks.py) proves it.
        # ------------------------------------------------------------
        def lines_with(text: str, *prefixes: str) -> list[str]:
            return [line for line in text.splitlines()
                    if line.startswith(prefixes)]

        VERDICT = ("PQCP_DEPLOYMENT_EVIDENCE_VERDICT ",)
        SEAL = ("PQCP_DEPLOYMENT_EVIDENCE_SEAL ",)
        PASSPORT = ("PQCP_DEPLOYMENT_ASSURANCE_PASSPORT ",)
        MATRIX = ("PQCP_DEPLOYMENT_TAMPER_CELL ",
                  "PQCP_DEPLOYMENT_TAMPER_MATRIX ")
        TRAIL = ("PQCP_DEPLOYMENT_EVIDENCE_TRAIL_ENTRY ",
                 "PQCP_DEPLOYMENT_EVIDENCE_TRAIL ")

        def lenient_rc(name: str, lines: list[str]) -> int:
            path = write_variant(workdir, name, "\n".join(lines) + "\n")
            return run_tool(binary, path, "--lenient", "--quiet").returncode

        def tamper_first(lines: list[str], index: int, old: str,
                         new: str) -> list[str]:
            assert old in lines[index], (old, lines[index][:120])
            changed = list(lines)
            changed[index] = lines[index].replace(old, new, 1)
            return changed

        # --- single-layer digest recomputation -----------------------
        verdict_a = lines_with(full_text, *VERDICT)
        seal_a = lines_with(full_text, *SEAL)
        check("control: verdict-only transcript verifies (lenient)",
              lenient_rc("v_ctrl.log", verdict_a) == 0)
        check("verdict digest alone rejects a covered-field forgery",
              lenient_rc("v_forged.log",
                         tamper_first(verdict_a, 0, " score=0 ",
                                      " score=1 ")) == 1)
        check("control: seal-only transcript verifies (lenient)",
              lenient_rc("s_ctrl.log", seal_a) == 0)
        check("seal digest alone rejects a covered-field forgery",
              lenient_rc("s_forged.log",
                         tamper_first(seal_a, 0, " score=0 ",
                                      " score=1 ")) == 1)

        trail_a = lines_with(full_text, *TRAIL)
        check("control: verdict+trail transcript verifies (lenient)",
              lenient_rc("t_ctrl.log", verdict_a + trail_a) == 0)
        entry_index = next(i for i, line in enumerate(trail_a)
                           if " seq=1 " in line)
        link_value = trail_a[entry_index].split(" link=")[1].split()[0]
        flipped_link = ("0" if link_value[0] != "0" else "1") + link_value[1:]
        check("hash-chain link check rejects a forged stored link",
              lenient_rc("t_forged.log", verdict_a + tamper_first(
                  trail_a, entry_index, " link=" + link_value,
                  " link=" + flipped_link)) == 1)

        matrix_a = lines_with(full_text, *MATRIX)
        passport_a = lines_with(full_text, *PASSPORT)
        check("control: passport+matrix transcript verifies (lenient)",
              lenient_rc("m_ctrl.log", passport_a + matrix_a) == 0)
        matrix_index = next(i for i, line in enumerate(matrix_a)
                            if line.startswith(MATRIX[1]))
        check("matrix digest alone rejects a covered-field forgery",
              lenient_rc("m_forged.log", passport_a + tamper_first(
                  matrix_a, matrix_index, " profile=product ",
                  " profile=partner ")) == 1)

        # --- cross-run splices: each layer valid on its own ----------
        verdict_b = lines_with(signed_text, *VERDICT)
        seal_b = lines_with(signed_text, *SEAL)
        passport_b = lines_with(signed_text, *PASSPORT)
        check("control: run-B verdict+seal verify together",
              lenient_rc("sp1_ctrl.log", verdict_b + seal_b) == 0)
        check("splice: verdict(A)+seal(B) is rejected by the binding",
              lenient_rc("sp1.log", verdict_a + seal_b) == 1)
        check("control: run-B seal+passport verify together",
              lenient_rc("sp2_ctrl.log", seal_b + passport_b) == 0)
        check("splice: seal(A)+passport(B) is rejected by the binding",
              lenient_rc("sp2.log", seal_a + passport_b) == 1)
        check("control: run-A passport+matrix verify together",
              lenient_rc("sp3_ctrl.log", passport_a + matrix_a) == 0)
        check("splice: passport(B)+matrix(A) is rejected by the binding",
              lenient_rc("sp3.log", passport_b + matrix_a) == 1)
        signature_b = lines_with(
            signed_text, "PQCP_DEPLOYMENT_PASSPORT_SIGNATURE ",
            "PQCP_DEPLOYMENT_PASSPORT_PK_CHUNK ",
            "PQCP_DEPLOYMENT_PASSPORT_SIG_CHUNK ")
        spliced_sig = write_variant(
            workdir, "sp4.log",
            "\n".join(passport_a + signature_b) + "\n")
        check("splice: passport(A)+signature(B) is rejected",
              run_tool(binary, spliced_sig, "--lenient",
                       "--require-signature", "--quiet").returncode == 1)

    if failures:
        print(f"\n{len(failures)} test(s) failed")
        return 1
    print("\nAll evidence verifier tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
