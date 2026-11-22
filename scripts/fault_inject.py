#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Proprietary-Collaborative-Evaluation
"""Instruction-level fault sites for an x86 Zephyr image, patched in a copy.

The SDK QEMU (plugin API v4) cannot write guest state, so faults are
injected by patching the bytes of a COPY of the loadable image before QEMU
runs it. Two models, both permanent (every execution of the instruction is
affected):

  SKIP     overwrite the instruction with NOPs (an instruction skip)
  JCC_INV  invert the condition of a conditional jump, cmov or setcc by
           flipping the low bit of its condition code (a branch inversion)

Pure stdlib. Disassembly comes from the SDK objdump; the byte arithmetic and
ELF address mapping live here and are unit tested.
"""

import re
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path

NOP = 0x90
PREFIXES = {0x66, 0x67, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65}


@dataclass(frozen=True)
class Insn:
    addr: int
    raw: bytes
    text: str


@dataclass(frozen=True)
class Fault:
    function: str
    addr: int
    model: str          # "SKIP" | "JCC_INV"
    old: bytes
    new: bytes
    text: str
    base: int = 0       # start address of the function

    @property
    def ident(self) -> str:
        """Stable across builds: function-relative offset, not an address."""
        return f"{self.function}+{self.addr - self.base:x}:{self.model}"


def jcc_offset(raw: bytes) -> int | None:
    """Index of the byte holding the condition code, or None."""
    i = 0
    while i < len(raw) and (raw[i] in PREFIXES or 0x40 <= raw[i] <= 0x4F):
        i += 1
    if i >= len(raw):
        return None
    b = raw[i]
    if 0x70 <= b <= 0x7F:                       # jcc rel8
        return i
    if b == 0x0F and i + 1 < len(raw):
        n = raw[i + 1]
        if 0x80 <= n <= 0x8F or 0x90 <= n <= 0x9F or 0x40 <= n <= 0x4F:
            return i + 1                        # jcc rel32, setcc, cmovcc
    return None


def invert_condition(raw: bytes) -> bytes | None:
    index = jcc_offset(raw)
    if index is None:
        return None
    out = bytearray(raw)
    out[index] ^= 0x01
    return bytes(out)


def faults_for(function: str, insns: list[Insn],
               base: int = 0) -> list[Fault]:
    faults = []
    for insn in insns:
        faults.append(Fault(function, insn.addr, "SKIP", insn.raw,
                            bytes([NOP]) * len(insn.raw), insn.text, base))
        inverted = invert_condition(insn.raw)
        if inverted is not None:
            faults.append(Fault(function, insn.addr, "JCC_INV", insn.raw,
                                inverted, insn.text, base))
    return faults


# --- tools -----------------------------------------------------------------

def function_range(nm: str, elf: Path, name: str) -> tuple[int, int]:
    out = subprocess.run([nm, "-S", str(elf)], capture_output=True,
                         text=True, check=True).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[3] == name and parts[2] in "Tt":
            start = int(parts[0], 16)
            return start, start + int(parts[1], 16)
    raise KeyError(f"function {name} not found in {elf}")


INSN_RE = re.compile(r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*\t?(.*)$")


def disassemble(objdump: str, elf: Path, start: int, end: int) -> list[Insn]:
    out = subprocess.run(
        [objdump, "-d", "-w", f"--start-address={start:#x}",
         f"--stop-address={end:#x}", str(elf)],
        capture_output=True, text=True, check=True).stdout
    insns = []
    for line in out.splitlines():
        m = INSN_RE.match(line)
        if m:
            raw = bytes.fromhex(m.group(2).replace(" ", ""))
            insns.append(Insn(int(m.group(1), 16), raw, m.group(3).strip()))
    return insns


# --- image patching --------------------------------------------------------

def load_segments(image: bytes) -> list[tuple[int, int, int]]:
    """(vaddr, file offset, file size) of every PT_LOAD of an ELF32/64."""
    if image[:4] != b"\x7fELF":
        raise ValueError("not an ELF image")
    is64 = image[4] == 2
    if is64:
        phoff, = struct.unpack_from("<Q", image, 0x20)
        phentsize, phnum = struct.unpack_from("<HH", image, 0x36)
    else:
        phoff, = struct.unpack_from("<I", image, 0x1C)
        phentsize, phnum = struct.unpack_from("<HH", image, 0x2A)
    segments = []
    for i in range(phnum):
        base = phoff + i * phentsize
        if is64:
            p_type, _, p_off, p_vaddr, _, p_filesz = struct.unpack_from(
                "<IIQQQQ", image, base)
        else:
            p_type, p_off, p_vaddr, _, p_filesz = struct.unpack_from(
                "<IIIII", image, base)
        if p_type == 1 and p_filesz:
            segments.append((p_vaddr, p_off, p_filesz))
    return segments


def file_offset(segments: list, vaddr: int, length: int = 1) -> int:
    for seg_vaddr, seg_off, seg_size in segments:
        if seg_vaddr <= vaddr and vaddr + length <= seg_vaddr + seg_size:
            return seg_off + (vaddr - seg_vaddr)
    raise ValueError(f"vaddr {vaddr:#x} not in a loadable segment")


def apply_fault(image: bytes, fault: Fault) -> bytes:
    """Return a patched copy; refuse if the bytes there are not what we expect."""
    segments = load_segments(image)
    offset = file_offset(segments, fault.addr, len(fault.old))
    if image[offset:offset + len(fault.old)] != fault.old:
        raise ValueError(
            f"image bytes at {fault.addr:#x} do not match the disassembly")
    patched = bytearray(image)
    patched[offset:offset + len(fault.new)] = fault.new
    return bytes(patched)
