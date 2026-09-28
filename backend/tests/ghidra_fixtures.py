"""Ghidra 静的解析教材のテスト用部品。実データ・実在の検体は使わない。

  * make_gzf     … Ghidra 12.1.4 の ItemSerializer と同じ並びのバイト列を作る。
                   中身（FOLDER_ITEM）は意味のない埋め草で、Ghidra では開けない。
  * facts_doc    … 抽出スクリプトの出力（schema zip2learn-ghidra-static/1）と同じ形の、
                   架空の小さなゲームを模した静的事実。
"""

from __future__ import annotations

import copy
import json
import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import gzf  # noqa: E402

PROGRAM_SHA = "ab" * 32


def _utf(text: str) -> bytes:
    raw = text.encode()
    return struct.pack(">H", len(raw)) + raw


def make_gzf(content: bytes = b"\x00" * 4096 + bytes(range(256)) * 16, *,
             content_type: str = "Program", name: str = "demo",
             declared: int | None = None, version: int = 1, magic: int = gzf.MAGIC,
             crc: int | None = None, descriptor: bool = True) -> bytes:
    block = (struct.pack(">Q", magic) + struct.pack(">i", version) + _utf(name)
             + _utf(content_type)
             + struct.pack(">iq", 0, len(content) if declared is None else declared))
    head = b"\xac\xed\x00\x05" + bytes([0x77, len(block)]) + block
    comp = zlib.compressobj(6, zlib.DEFLATED, -15)
    data = comp.compress(content) + comp.flush()
    local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0x8, 8, 0, 0, 0, 0, 0,
                        len(b"FOLDER_ITEM"), 0) + b"FOLDER_ITEM"
    tail = b""
    if descriptor:
        tail = struct.pack("<IIII", 0x08074B50,
                           zlib.crc32(content) if crc is None else crc,
                           len(data), len(content))
    return head + local + data + tail


def _a(off: int, space: str = "ram") -> str:
    return f"{space}:{off:016x}"


def _fn(off: int, name: str, thunk_target: str | None = None) -> dict:
    return {"id": "fn:" + _a(off), "name": name, "entry": _a(off),
            "thunk": thunk_target is not None, "thunkTarget": thunk_target}


def _ext(off: int, name: str, lib: str | None) -> dict:
    return {"id": "ext:" + _a(off, "EXTERNAL"), "name": name, "library": lib,
            "address": _a(off, "EXTERNAL")}


def _str(off: int, value: str) -> dict:
    return {"id": "str:" + _a(off), "address": _a(off), "length": len(value),
            "value": value, "clipped": False}


def _ref(frm: int, fn: int, s: int) -> dict:
    return {"from": _a(frm), "function": "fn:" + _a(fn), "string": "str:" + _a(s),
            "instruction": f"LEA RDI,[0x{s:08x}]", "refType": "DATA"}


def _call(frm: int, fn: int, target: str, target_addr: str, resolved=None) -> dict:
    return {"from": _a(frm), "function": "fn:" + _a(fn), "mnemonic": "CALL",
            "instruction": f"CALL 0x{int(target_addr.rsplit(':', 1)[1], 16):08x}",
            "target": target, "targetAddress": target_addr, "resolvedTarget": resolved}


BASE = {
    "schemaVersion": "zip2learn-ghidra-static/1",
    "input": {"sha256": PROGRAM_SHA, "bytes": 12345},
    "tool": {"ghidraVersion": "12.1.4", "scriptVersion": "1.0.0"},
    "program": {
        "name": "minigame", "languageId": "x86:LE:64:default", "compilerSpecId": "gcc",
        "executableFormat": "Executable and Linking Format (ELF)",
        "storedExecutableSha256": "cd" * 32, "imageBase": _a(0x100000), "analyzed": True,
    },
    "functions": [
        _fn(0x101000, "_init"),
        _fn(0x101030, "printf", "ext:" + _a(0x10, "EXTERNAL")),
        _fn(0x101100, "init_board"),
        _fn(0x101150, "place_mines"),
        _fn(0x101180, "print_usage"),
        _fn(0x101190, "draw"),
        _fn(0x101200, "main"),
    ],
    "externals": [
        _ext(0x10, "printf", "libc.so.6"),
        _ext(0x18, "rand", "libc.so.6"),
        _ext(0x20, "initscr", "libncursesw.so.6"),
    ],
    "strings": [
        _str(0x102000, "Usage: %s"),
        _str(0x102010, "Game over"),
        _str(0x102020, "Board ready"),
        _str(0x102030, "Usage: %s"),      # 同じ中身の別の文字列
        _str(0x102040, "You win!"),
        _str(0x102050, "Mines left: %d"),
        _str(0x102060, "Cheat mode"),
    ],
    "stringRefs": [
        _ref(0x101110, 0x101100, 0x102020),
        _ref(0x101185, 0x101180, 0x102030),
        _ref(0x101195, 0x101190, 0x102050),
        _ref(0x101210, 0x101200, 0x102000),
        _ref(0x101230, 0x101200, 0x102010),
    ],
    "calls": [
        _call(0x101120, 0x101100, "fn:" + _a(0x101150), _a(0x101150)),
        _call(0x1011A0, 0x101190, "fn:" + _a(0x101180), _a(0x101180)),
        _call(0x101220, 0x101200, "fn:" + _a(0x101100), _a(0x101100)),
        _call(0x101240, 0x101200, "fn:" + _a(0x101030), _a(0x101030),
              "ext:" + _a(0x10, "EXTERNAL")),
    ],
    "callStats": {"indirect": 2, "unresolved": 1},
    "truncated": [],
    "end": "zip2learn-ghidra-static-end",
}


def facts_doc(sha: str = PROGRAM_SHA, **overrides) -> dict:
    doc = copy.deepcopy(BASE)
    doc["input"]["sha256"] = sha
    for k, v in overrides.items():
        doc[k] = v
    return doc


def facts_bytes(sha: str = PROGRAM_SHA, **overrides) -> bytes:
    return json.dumps(facts_doc(sha, **overrides)).encode()


#: 画面テスト（test_ui_static.mjs）が読む、ビルダーの出力そのもの。
LESSON_FIXTURE = "fixtures/ghidra/static-lesson.json"


def static_lesson() -> dict:
    """架空のゲームの静的事実から、実際のビルダーで作った教材。"""
    import static_facts
    import static_lesson as builder

    facts = static_facts.parse(facts_bytes(), expected_sha256=PROGRAM_SHA,
                               expected_ghidra="12.1.4", expected_script="1.0.0")
    return builder.build(
        facts,
        image={"imageRef": "zip2learn-ghidra-static:12.1.4-test", "imageId": "sha256:" + "4" * 64,
               "arch": "arm64", "scriptSha256": "5" * 64},
        origin={"kind": "upload", "name": "minigame.gzf"},
    )


if __name__ == "__main__":
    # python3 backend/tests/ghidra_fixtures.py で固定データを作り直す。
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, LESSON_FIXTURE), "w", encoding="utf-8") as fh:
        json.dump(static_lesson(), fh, ensure_ascii=False, indent=1, sort_keys=True)
        fh.write("\n")
