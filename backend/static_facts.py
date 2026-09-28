"""static_facts.py — 抽出 JSON（schema zip2learn-ghidra-static/1）を検証して静的事実にする。

コンテナの出力も信用しない。ここを通らなかったものは、教材にも画面にも
出さない。確かめること:

  * 大きさ・型・長さ・件数。未知の項目や未知のスキーマは断る。
  * 途中で切れていないこと（末尾の印）。
  * 入力 GZF の SHA-256 が、アプリがコピー時に計算した値と一致すること。
    元の実行ファイルについて DB に保存されたハッシュとは別の項目として扱う。
  * Ghidra と抽出スクリプトの版が、固定したものと一致すること。
  * ID の重複が無く、ID とアドレスが対応していること。
  * 参照・呼び出しの参照先が、同じ出力の中に実在すること。

文字列の長さは、抽出側（Java の String.length()）に合わせて **UTF-16 の単位**で
数える。Python の len() はコードポイント単位なので、絵文字など BMP 外の文字を
含むと値がずれる。`length`・上限・切り詰めの判定は、すべて `utf16_len` で行う。

静的事実は、ログ由来の `NormalizedEvent` とは別のモデルにする。時刻・
ホスト名・実行イベントは持たない（持たせると、実行されたかのように見える）。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

SCHEMA = "zip2learn-ghidra-static/1"
END_MARK = "zip2learn-ghidra-static-end"
MAX_JSON_BYTES = 32 * 1024**2

MAX_FUNCTIONS = 5000
MAX_EXTERNALS = 2000
MAX_STRINGS = 5000
MAX_STRING_REFS = 10000
MAX_CALLS = 20000
MAX_NAME = 256
MAX_STRING_VALUE = 512
MAX_INSTRUCTION = 160
TRUNCATABLE = {"functions", "externals", "strings", "stringRefs", "calls"}

_SPACE = r"[A-Za-z0-9_.-]{1,64}"
ADDRESS = re.compile(rf"{_SPACE}:[0-9a-f]{{16}}")
FN_ID = re.compile(rf"fn:{_SPACE}:[0-9a-f]{{16}}")
EXT_ID = re.compile(rf"ext:{_SPACE}:[0-9a-f]{{16}}")
STR_ID = re.compile(rf"str:{_SPACE}:[0-9a-f]{{16}}")
SHA256 = re.compile(r"[0-9a-f]{64}")


def utf16_len(text: str) -> int:
    """Java の String.length() と同じ数え方（UTF-16 の単位）。

    切り詰めで対になっていないサロゲートが混ざっても数えられるよう、
    surrogatepass で符号化する。
    """
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


class FactsInvalid(Exception):
    """抽出結果を採用できない。`code` は画面へ出す固定の符号。"""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code


@dataclass
class StaticFacts:
    input_sha256: str
    input_bytes: int
    ghidra_version: str
    script_version: str
    program: dict
    functions: dict            # id -> {id, name, entry, thunk, thunkTarget}
    externals: dict            # id -> {id, name, library, address}
    strings: dict              # id -> {id, address, value, length, clipped}
    string_refs: list          # [{from, function, string, instruction, refType}]
    calls: list                # [{from, function, mnemonic, instruction, target, targetAddress, resolvedTarget}]
    call_stats: dict
    truncated: list = field(default_factory=list)

    def name_of(self, ident: str) -> str:
        rec = self.functions.get(ident) or self.externals.get(ident)
        return rec["name"] if rec else ident

    def counts(self) -> dict:
        return {
            "functions": len(self.functions),
            "externals": len(self.externals),
            "strings": len(self.strings),
            "stringRefs": len(self.string_refs),
            "calls": len(self.calls),
            "indirectCalls": self.call_stats["indirect"],
            "unresolvedCalls": self.call_stats["unresolved"],
        }


def _fail(detail: str, code: str = "output-invalid"):
    raise FactsInvalid(code, detail)


def _obj(v, keys: set, where: str, optional: set = frozenset()) -> dict:
    if not isinstance(v, dict):
        _fail(f"{where}: not an object")
    extra = set(v) - keys - optional
    missing = keys - set(v)
    if extra:
        _fail(f"{where}: unknown keys {sorted(extra)[:3]}")
    if missing:
        _fail(f"{where}: missing keys {sorted(missing)[:3]}")
    return v


def _str(v, where: str, limit: int, *, nullable=False, pattern=None, empty=False) -> str | None:
    if v is None and nullable:
        return None
    if not isinstance(v, str):
        _fail(f"{where}: not a string")
    if len(v) > limit or (not empty and not v):
        _fail(f"{where}: bad length")
    if pattern is not None and not pattern.fullmatch(v):
        _fail(f"{where}: bad format")
    return v


def _int(v, where: str, lo: int = 0, hi: int = 2**53) -> int:
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        _fail(f"{where}: bad integer")
    return v


def _bool(v, where: str) -> bool:
    if not isinstance(v, bool):
        _fail(f"{where}: not a boolean")
    return v


def _list(v, where: str, limit: int) -> list:
    if not isinstance(v, list):
        _fail(f"{where}: not a list")
    if len(v) > limit:
        _fail(f"{where}: too many items")
    return v


def parse(raw: bytes, *, expected_sha256: str, expected_ghidra: str,
          expected_script: str) -> StaticFacts:
    """コンテナの標準出力をそのまま受け取り、検証済みの静的事実を返す。"""
    if not raw:
        _fail("empty output", "output-missing")
    if len(raw) > MAX_JSON_BYTES:
        _fail("too large", "output-too-large")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        # 途中で切れた出力もここに来る。
        _fail("not json", "output-invalid")
    if not isinstance(doc, dict):
        _fail("top level is not an object")
    if doc.get("schemaVersion") != SCHEMA:
        _fail("unknown schema", "schema-unsupported")
    if doc.get("end") != END_MARK:
        _fail("no end mark", "output-incomplete")
    top = {"schemaVersion", "input", "tool", "program", "functions", "externals",
           "strings", "stringRefs", "calls", "callStats", "truncated", "end"}
    _obj(doc, top, "top")

    inp = _obj(doc["input"], {"sha256", "bytes"}, "input")
    sha = _str(inp["sha256"], "input.sha256", 64, pattern=SHA256)
    if sha != expected_sha256:
        _fail("input hash differs", "hash-mismatch")
    size = _int(inp["bytes"], "input.bytes", 1)

    tool = _obj(doc["tool"], {"ghidraVersion", "scriptVersion"}, "tool")
    gver = _str(tool["ghidraVersion"], "tool.ghidraVersion", 32)
    sver = _str(tool["scriptVersion"], "tool.scriptVersion", 32)
    if gver != expected_ghidra or sver != expected_script:
        _fail("tool version differs", "tool-mismatch")

    prog = _obj(doc["program"], {"name", "languageId", "compilerSpecId", "executableFormat",
                                 "storedExecutableSha256", "imageBase", "analyzed"}, "program")
    program = {
        "name": _str(prog["name"], "program.name", MAX_NAME),
        "languageId": _str(prog["languageId"], "program.languageId", 128),
        "compilerSpecId": _str(prog["compilerSpecId"], "program.compilerSpecId", 64),
        "executableFormat": _str(prog["executableFormat"], "program.executableFormat",
                                 MAX_NAME, nullable=True, empty=True),
        "storedExecutableSha256": _str(prog["storedExecutableSha256"],
                                       "program.storedExecutableSha256", 64,
                                       nullable=True, empty=True),
        "imageBase": _str(prog["imageBase"], "program.imageBase", 96, pattern=ADDRESS),
        "analyzed": _bool(prog["analyzed"], "program.analyzed"),
    }
    stored = program["storedExecutableSha256"]
    if stored and not SHA256.fullmatch(stored.lower()):
        program["storedExecutableSha256"] = None

    functions: dict = {}
    for i, f in enumerate(_list(doc["functions"], "functions", MAX_FUNCTIONS)):
        w = f"functions[{i}]"
        _obj(f, {"id", "name", "entry", "thunk", "thunkTarget"}, w)
        fid = _str(f["id"], w + ".id", 96, pattern=FN_ID)
        entry = _str(f["entry"], w + ".entry", 96, pattern=ADDRESS)
        if fid != "fn:" + entry:
            _fail(f"{w}: id does not match entry")
        if fid in functions:
            _fail(f"{w}: duplicate id")
        functions[fid] = {
            "id": fid,
            "name": _str(f["name"], w + ".name", MAX_NAME),
            "entry": entry,
            "thunk": _bool(f["thunk"], w + ".thunk"),
            "thunkTarget": _str(f["thunkTarget"], w + ".thunkTarget", 96, nullable=True),
        }

    externals: dict = {}
    for i, e in enumerate(_list(doc["externals"], "externals", MAX_EXTERNALS)):
        w = f"externals[{i}]"
        _obj(e, {"id", "name", "library", "address"}, w)
        eid = _str(e["id"], w + ".id", 96, pattern=EXT_ID)
        address = _str(e["address"], w + ".address", 96, pattern=ADDRESS)
        if eid != "ext:" + address:
            _fail(f"{w}: id does not match address")
        if eid in externals:
            _fail(f"{w}: duplicate id")
        externals[eid] = {
            "id": eid,
            "name": _str(e["name"], w + ".name", MAX_NAME),
            "library": _str(e["library"], w + ".library", MAX_NAME, nullable=True, empty=True),
            "address": address,
        }

    for fid, f in functions.items():
        t = f["thunkTarget"]
        if t is not None and t not in functions and t not in externals:
            _fail(f"{fid}: thunk target missing")
        if t is not None and not f["thunk"]:
            _fail(f"{fid}: thunk target on non-thunk")

    strings: dict = {}
    for i, s in enumerate(_list(doc["strings"], "strings", MAX_STRINGS)):
        w = f"strings[{i}]"
        _obj(s, {"id", "address", "length", "value", "clipped"}, w)
        sid = _str(s["id"], w + ".id", 96, pattern=STR_ID)
        address = _str(s["address"], w + ".address", 96, pattern=ADDRESS)
        if sid != "str:" + address:
            _fail(f"{w}: id does not match address")
        if sid in strings:
            _fail(f"{w}: duplicate id")
        value = _str(s["value"], w + ".value", MAX_STRING_VALUE, empty=True)
        length = _int(s["length"], w + ".length", 0, 2**31)
        clipped = _bool(s["clipped"], w + ".clipped")
        units = utf16_len(value)
        if units > MAX_STRING_VALUE:
            _fail(f"{w}: value longer than the limit")
        if length < units or clipped != (length > units):
            _fail(f"{w}: length disagrees with value")
        strings[sid] = {"id": sid, "address": address, "value": value,
                        "length": length, "clipped": clipped}

    refs = []
    for i, r in enumerate(_list(doc["stringRefs"], "stringRefs", MAX_STRING_REFS)):
        w = f"stringRefs[{i}]"
        _obj(r, {"from", "function", "string", "instruction", "refType"}, w)
        rec = {
            "from": _str(r["from"], w + ".from", 96, pattern=ADDRESS),
            "function": _str(r["function"], w + ".function", 96, pattern=FN_ID),
            "string": _str(r["string"], w + ".string", 96, pattern=STR_ID),
            "instruction": _str(r["instruction"], w + ".instruction", MAX_INSTRUCTION),
            "refType": _str(r["refType"], w + ".refType", 32),
        }
        if rec["function"] not in functions:
            _fail(f"{w}: function missing")
        if rec["string"] not in strings:
            _fail(f"{w}: string missing")
        refs.append(rec)

    calls = []
    for i, c in enumerate(_list(doc["calls"], "calls", MAX_CALLS)):
        w = f"calls[{i}]"
        _obj(c, {"from", "function", "mnemonic", "instruction", "target",
                 "targetAddress", "resolvedTarget"}, w)
        rec = {
            "from": _str(c["from"], w + ".from", 96, pattern=ADDRESS),
            "function": _str(c["function"], w + ".function", 96, pattern=FN_ID),
            "mnemonic": _str(c["mnemonic"], w + ".mnemonic", 32),
            "instruction": _str(c["instruction"], w + ".instruction", MAX_INSTRUCTION),
            "target": _str(c["target"], w + ".target", 96),
            "targetAddress": _str(c["targetAddress"], w + ".targetAddress", 96, pattern=ADDRESS),
            "resolvedTarget": _str(c["resolvedTarget"], w + ".resolvedTarget", 96, nullable=True),
        }
        if rec["function"] not in functions:
            _fail(f"{w}: caller missing")
        target = functions.get(rec["target"]) or externals.get(rec["target"])
        if target is None:
            _fail(f"{w}: target missing")
        if (target.get("entry") or target.get("address")) != rec["targetAddress"]:
            _fail(f"{w}: target address disagrees with target")
        rt = rec["resolvedTarget"]
        if rt is not None:
            if rt not in functions and rt not in externals:
                _fail(f"{w}: resolved target missing")
            if functions.get(rec["target"], {}).get("thunkTarget") != rt:
                _fail(f"{w}: resolved target disagrees with thunk")
        calls.append(rec)

    stats = _obj(doc["callStats"], {"indirect", "unresolved"}, "callStats")
    call_stats = {"indirect": _int(stats["indirect"], "callStats.indirect"),
                  "unresolved": _int(stats["unresolved"], "callStats.unresolved")}

    truncated = _list(doc["truncated"], "truncated", len(TRUNCATABLE))
    if any(t not in TRUNCATABLE for t in truncated) or len(set(truncated)) != len(truncated):
        _fail("truncated: unknown entry")

    return StaticFacts(
        input_sha256=sha, input_bytes=size, ghidra_version=gver, script_version=sver,
        program=program, functions=functions, externals=externals, strings=strings,
        string_refs=refs, calls=calls, call_stats=call_stats, truncated=list(truncated),
    )
