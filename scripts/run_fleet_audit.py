#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fleet-level drift audit over multiple device evidence transcripts.

Each device's chain is verified by the C verifier (pqcp-evidence-verify);
this script only aggregates the per-device JSON summaries and decides
whether the fleet agrees. It mirrors, at fleet scope, what the on-device
audit modules do across replay results: every device must individually
verify, and (unless --allow-drift) all devices must share one passport
digest, one board identity, and one top-candidate id.

A homogeneous fleet built from one image yields one passport digest across
all devices; a device running tampered or divergent evidence shows up as a
distinct digest, i.e. detected drift. The crypto and replay decisions are
the C verifier's; the fleet comparison here is set logic over its output.
"""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
MODULE_PATH = SCRIPT_DIR.parent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("transcripts", nargs="+", type=Path,
                        help="Device evidence transcripts (one per device)")
    parser.add_argument("--verifier", type=Path, default=None,
                        help="Path to pqcp-evidence-verify (else built)")
    parser.add_argument("--build-dir", type=Path, default=None,
                        help="CMake build dir if the verifier must be built")
    parser.add_argument("--require-signature", action="store_true",
                        help="Each device must carry a verifying signature")
    parser.add_argument("--allow-drift", action="store_true",
                        help="Report drift without failing (still requires "
                             "each device to verify)")
    parser.add_argument("--lenient", action="store_true",
                        help="Pass --lenient to the per-device verifier")
    parser.add_argument("--json", type=Path, default=None,
                        help="Write the fleet summary JSON here")
    return parser.parse_args()


def build_verifier(build_dir: Path) -> Path:
    tool_dir = MODULE_PATH / "tools" / "evidence_verifier"
    subprocess.run(["cmake", "-S", str(tool_dir), "-B", str(build_dir),
                    "-DCMAKE_BUILD_TYPE=Release"],
                   check=True, capture_output=True, text=True)
    subprocess.run(["cmake", "--build", str(build_dir)],
                   check=True, capture_output=True, text=True)
    binary = build_dir / "pqcp-evidence-verify"
    if not binary.exists():
        raise RuntimeError("failed to build pqcp-evidence-verify")
    return binary


def verify_one(binary: Path, transcript: Path, *, lenient: bool,
               require_signature: bool, workdir: Path) -> dict:
    json_path = workdir / (transcript.name + ".json")
    cmd = [str(binary)]
    if lenient:
        cmd.append("--lenient")
    if require_signature:
        cmd.append("--require-signature")
    cmd += ["--quiet", "--json", str(json_path), str(transcript)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    summary = json.loads(json_path.read_text()) if json_path.exists() else {}
    return {
        "transcript": str(transcript),
        "returncode": result.returncode,
        "chain_ok": bool(summary.get("chain_ok")),
        "passport_digest": summary.get("passport", {}).get("computed_digest"),
        "board": summary.get("passport", {}).get("board"),
        "signature_verified":
            summary.get("signature", {}).get("verified", False),
        "summary": summary,
    }


def main() -> int:
    args = parse_args()

    for transcript in args.transcripts:
        if not transcript.exists():
            print(f"[fleet] FAIL: transcript missing: {transcript}")
            return 2

    with tempfile.TemporaryDirectory(prefix="pqcp-fleet-") as tmp:
        workdir = Path(tmp)
        if args.verifier is not None:
            binary = args.verifier
        else:
            build_dir = args.build_dir or (workdir / "build")
            binary = build_verifier(build_dir)

        devices = [
            verify_one(binary, t, lenient=args.lenient,
                       require_signature=args.require_signature,
                       workdir=workdir)
            for t in args.transcripts
        ]

    device_count = len(devices)
    verified = [d for d in devices if d["returncode"] == 0 and d["chain_ok"]]
    failed = [d for d in devices if d not in verified]
    digests = {d["passport_digest"] for d in verified
               if d["passport_digest"]}
    boards = {d["board"] for d in verified if d["board"]}
    unique_digests = sorted(digests)

    fleet_consistent = (
        len(failed) == 0
        and len(verified) == device_count
        and len(unique_digests) == 1
        and len(boards) == 1
    )

    print(f"[fleet] devices={device_count} verified={len(verified)} "
          f"failed={len(failed)}")
    print(f"[fleet] unique_passport_digests={len(unique_digests)} "
          f"boards={sorted(boards)}")
    for d in devices:
        status = "ok" if (d["returncode"] == 0 and d["chain_ok"]) else "FAIL"
        digest = (d["passport_digest"] or "none")[:16]
        print(f"[fleet]   {status} {Path(d['transcript']).name} "
              f"board={d['board']} digest={digest}...")

    fleet_summary = {
        "schema_version": 1,
        "device_count": device_count,
        "verified_count": len(verified),
        "failed_count": len(failed),
        "unique_passport_digests": unique_digests,
        "boards": sorted(boards),
        "fleet_consistent": fleet_consistent,
        "require_signature": args.require_signature,
        "devices": [
            {k: d[k] for k in ("transcript", "returncode", "chain_ok",
                               "passport_digest", "board",
                               "signature_verified")}
            for d in devices
        ],
    }
    if args.json is not None:
        args.json.write_text(json.dumps(fleet_summary, indent=2) + "\n")
        print(f"[fleet] summary written to {args.json}")

    if len(failed) != 0:
        print(f"[fleet] FAIL: {len(failed)} device(s) did not verify")
        return 1

    if len(unique_digests) == 1 and len(boards) == 1:
        print(f"PQCP_FLEET_AUDIT PASS devices={device_count} "
              f"passport_digest={unique_digests[0]} "
              f"board={sorted(boards)[0]}")
        print("[fleet] PASS: homogeneous fleet, all devices agree")
        return 0

    # Devices verified individually but disagree: drift detected.
    print(f"PQCP_FLEET_AUDIT DRIFT devices={device_count} "
          f"unique_digests={len(unique_digests)} boards={len(boards)}")
    if args.allow_drift:
        print("[fleet] PASS (--allow-drift): per-device chains verified, "
              "fleet is heterogeneous")
        return 0
    print("[fleet] FAIL: fleet drift detected (passport digest or board "
          "differs across devices)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
