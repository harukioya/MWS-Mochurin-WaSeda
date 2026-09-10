"""identify.py — classify a file by its bytes, never by its name.

Answers the question the learner actually needs (BUILD-CONTRACT, teaching goal
1a): *can the operating system run this, and what is it?*

Two invariants govern everything here:

  1. DEFAULT-DENY. Anything unrecognised, unreadable, or unsupported returns
     Verdict.UNKNOWN, which gates exactly as strictly as a native executable.
     A classifier that guesses "probably fine" is worse than no classifier.
  2. EXTENSION IS NEVER EVIDENCE. A file named `program.dll.gzf` can be
     (a Ghidra database, not a DLL) and `__MACOSX` entries named `*.zip` that
     are AppleDouble headers. Names are display data; bytes decide.

Nothing in this module opens a file, writes a file, or executes anything. It is
a pure function over a bounded prefix of bytes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

# How much of a file we need to classify it. Callers must not read more than
# this just to identify — an unbounded read is how identification becomes the
# decompression bomb it was meant to detect.
HEAD_BYTES = 4096


class Verdict(str, Enum):
    """Gating category. Only INERT_DATA is ever materializable."""

    INERT_DATA = "inert-data"
    CONTAINER = "container"
    SCRIPT = "script"
    DOCUMENT_ACTIVE = "document-with-active-content"
    SHORTCUT_LAUNCHER = "shortcut-or-launcher"
    NATIVE_EXECUTABLE = "native-executable"
    BYTECODE_ARCHIVE = "bytecode-archive"
    SAMPLE_BEARING = "sample-bearing"
    FORENSIC_IMAGE = "forensic-image"
    OPAQUE_ENCRYPTED = "opaque-encrypted"
    UNSUPPORTED_CONTAINER = "unsupported-container"
    DOCUMENT_PASSIVE = "document-passive"
    METADATA_SIDECAR = "metadata-sidecar"
    UNKNOWN = "unknown"


#: The ONLY verdict that may be written to disk. Allowlist, never denylist —
#: a denylist of "dangerous" types loses to the first format nobody listed.
MATERIALIZABLE = frozenset({Verdict.INERT_DATA})

#: Verdicts whose bytes can become a running program on some OS, with however
#: much deliberate effort. Drives the UI's "can this run?" answer.
RUNNABLE = frozenset(
    {
        Verdict.NATIVE_EXECUTABLE,
        Verdict.SCRIPT,
        Verdict.BYTECODE_ARCHIVE,
        Verdict.DOCUMENT_ACTIVE,
        Verdict.SHORTCUT_LAUNCHER,
        Verdict.SAMPLE_BEARING,
        Verdict.DOCUMENT_PASSIVE,
        Verdict.METADATA_SIDECAR,
        Verdict.UNKNOWN,  # default-deny: assume the worst about the unrecognised
    }
)


@dataclass(frozen=True)
class Identification:
    kind: str  # human-readable format name
    verdict: Verdict
    why: str  # the evidence, shown to the learner
    caveat: str = ""  # what the headline classification hides
    #: True when only a prefix of the file was examined. The classification is
    #: still the best available answer and is worth showing -- an MP4 header is
    #: an MP4 header -- but it is not a statement about the whole file, so it
    #: can never authorize a write. Keeping this separate from `verdict` means
    #: a lecture video still reads as "video" instead of being flattened to
    #: "unknown" along with everything else we could not fully read.
    provisional: bool = False

    @property
    def materializable(self) -> bool:
        return self.verdict in MATERIALIZABLE and not self.provisional

    @property
    def runnable(self) -> bool:
        return self.verdict in RUNNABLE


# ---------------------------------------------------------------------------
# Signature table. Longest prefix wins, so order within the list is irrelevant;
# `_match` sorts by descending magic length before testing.
# ---------------------------------------------------------------------------

_SIGNATURES: list[tuple[bytes, str, Verdict, str]] = [
    # --- native executables -------------------------------------------------
    (b"MZ", "PE 実行ファイル（Windows）", Verdict.NATIVE_EXECUTABLE,
     "先頭が DOS ヘッダ MZ です"),
    (b"\x7fELF", "ELF 実行ファイル（Linux/Unix）", Verdict.NATIVE_EXECUTABLE,
     "先頭が ELF の識別子です"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64ビット（macOS）", Verdict.NATIVE_EXECUTABLE,
     "先頭が Mach-O 64ビットの識別子です"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32ビット（macOS）", Verdict.NATIVE_EXECUTABLE,
     "先頭が Mach-O 32ビットの識別子です"),
    (b"\xbe\xba\xfe\xca", "Mach-O 統合バイナリ（macOS）", Verdict.NATIVE_EXECUTABLE,
     "先頭が Mach-O 統合形式の識別子です"),
    # --- bytecode / archive-that-runs --------------------------------------
    (b"dex\n", "Android DEX 中間コード", Verdict.BYTECODE_ARCHIVE,
     "先頭が DEX の識別子です"),
    # --- containers ---------------------------------------------------------
    (b"PK\x03\x04", "ZIP ファイル", Verdict.CONTAINER,
     "先頭が ZIP のファイルヘッダです"),
    (b"PK\x05\x06", "ZIP ファイル（空）", Verdict.CONTAINER,
     "先頭が ZIP の終端レコードです"),
    (b"PK\x07\x08", "ZIP ファイル（分割）", Verdict.CONTAINER,
     "先頭が ZIP の分割圧縮ファイルの印です"),
    (b"\x1f\x8b", "gzip 圧縮データ", Verdict.CONTAINER, "先頭が gzip の識別子です"),
    # --- containers we cannot currently enumerate: hard block ---------------
    (b"7z\xbc\xaf\x27\x1c", "7-Zip ファイル", Verdict.UNSUPPORTED_CONTAINER,
     "先頭が 7-Zip の識別子です"),
    (b"\xfd7zXZ\x00", "xz 圧縮データ", Verdict.UNSUPPORTED_CONTAINER,
     "先頭が xz の識別子です"),
    (b"BZh", "bzip2 圧縮データ", Verdict.UNSUPPORTED_CONTAINER,
     "先頭が bzip2 の識別子です"),
    (b"\x28\xb5\x2f\xfd", "zstd 圧縮データ", Verdict.UNSUPPORTED_CONTAINER,
     "先頭が zstd の識別子です"),
    (b"Rar!\x1a\x07", "RAR ファイル", Verdict.UNSUPPORTED_CONTAINER,
     "先頭が RAR の識別子です"),
    (b"MSCF", "Microsoft Cabinet ファイル", Verdict.UNSUPPORTED_CONTAINER,
     "先頭が CAB の識別子です"),
    # --- documents that can carry executable content -----------------------
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE 複合文書（旧 Office 形式）",
     Verdict.DOCUMENT_ACTIVE, "先頭が OLE 複合文書の識別子です"),
    # --- launchers ----------------------------------------------------------
    (b"L\x00\x00\x00\x01\x14\x02\x00", "Windows ショートカット（.lnk）",
     Verdict.SHORTCUT_LAUNCHER, "先頭が Windows ショートカットのヘッダです"),
    # --- sample-bearing analysis databases ----------------------------------
    (b"\xac\xed\x00\x05", "Java 直列化データ", Verdict.SAMPLE_BEARING,
     "先頭が Java 直列化の識別子（0xACED0005）です"),
    # --- forensic images ----------------------------------------------------
    (b"EVF\x09\x0d\x0a\xff\x00", "EnCase/EWF 保全イメージ", Verdict.FORENSIC_IMAGE,
     "先頭が EWF の識別子です"),
    (b"AFF", "AFF 保全イメージ", Verdict.FORENSIC_IMAGE,
     "先頭が AFF の識別子です"),
    # --- inert -------------------------------------------------------------
    # PDF is NOT inert: /Launch, /JavaScript and /EmbeddedFile are part of the
    # format, and BUILD-CONTRACT rule 5 does not list it in the inert allowlist.
    (b"%PDF", "PDF 文書", Verdict.DOCUMENT_ACTIVE,
     "先頭が PDF の識別子です。PDF は /Launch や /JavaScript の動作を持てます"),
    (b"\x89PNG\r\n\x1a\n", "PNG 画像", Verdict.INERT_DATA,
     "先頭が PNG の識別子です"),
    (b"\xff\xd8\xff", "JPEG 画像", Verdict.INERT_DATA, "先頭が JPEG の識別子です"),
    (b"GIF87a", "GIF 画像", Verdict.INERT_DATA, "先頭が GIF の識別子です"),
    (b"GIF89a", "GIF 画像", Verdict.INERT_DATA, "先頭が GIF の識別子です"),
    # A capture of a malware download carries the sample verbatim in its
    # payload -- recoverable with Wireshark's "Export Objects". Same reasoning
    # that makes a Ghidra .gzf sample-bearing rather than inert.
    (b"\xd4\xc3\xb2\xa1", "pcap 通信記録", Verdict.SAMPLE_BEARING,
     "先頭が pcap の識別子です"),
    (b"\xa1\xb2\xc3\xd4", "pcap 通信記録（ビッグエンディアン）", Verdict.SAMPLE_BEARING,
     "先頭が pcap の識別子です"),
    (b"\x0a\x0d\x0d\x0a", "pcapng 通信記録", Verdict.SAMPLE_BEARING,
     "先頭が pcapng のブロックヘッダです"),
    (b"\x00\x05\x16\x07", "macOS の付随情報（AppleDouble）", Verdict.METADATA_SIDECAR,
     "先頭が AppleDouble の識別子です"),
]

# Sorted once: longest magic first, so `PK\x05\x06` cannot be shadowed by a
# shorter prefix and `GIF89a` wins over a hypothetical `GIF`.
_SIGNATURES_BY_LENGTH = sorted(_SIGNATURES, key=lambda s: -len(s[0]))

# ---------------------------------------------------------------------------
# Ordering of evidence
#
# Severity ranking exists so that several independent signals can be combined
# by taking the WORST, rather than by whichever check happened to run first.
# The original version returned as soon as a signature matched, which meant a
# file whose bytes 4-8 read `ftyp` was called an inert video even when it was
# named `x.sh` and its first line was a shell comment followed by live code.
# ---------------------------------------------------------------------------

_SEVERITY: dict[Verdict, int] = {
    Verdict.INERT_DATA: 0,
    Verdict.CONTAINER: 1,
    Verdict.FORENSIC_IMAGE: 2,
    # UNKNOWN means "not ruled out". It must outrank the benign verdicts, but
    # it must LOSE to any positive identification: knowing a file is a script
    # is strictly more useful to the learner than knowing nothing about it, and
    # both are equally non-materializable, so gating is unaffected either way.
    Verdict.DOCUMENT_PASSIVE: 2,
    Verdict.METADATA_SIDECAR: 2,
    Verdict.UNKNOWN: 3,
    Verdict.OPAQUE_ENCRYPTED: 4,
    Verdict.UNSUPPORTED_CONTAINER: 4,
    Verdict.DOCUMENT_ACTIVE: 5,
    Verdict.SAMPLE_BEARING: 6,
    Verdict.SHORTCUT_LAUNCHER: 6,
    Verdict.BYTECODE_ARCHIVE: 7,
    Verdict.SCRIPT: 7,
    Verdict.NATIVE_EXECUTABLE: 8,
}

#: PDF が実際に「動作あり」かどうかを分ける印。形式として持てることと、その
#: ファイルが実際に持っていることは別。全件を「動作あり」にすると、講義資料の
#: PDF まで警告対象になり、警告そのものが読み飛ばされるようになる。
_PDF_ACTIVE = [
    (b"/JavaScript", "JavaScript"),
    (b"/JS", "JavaScript"),
    (b"/Launch", "外部プログラムの起動指定"),
    (b"/OpenAction", "開いた時に動く指定"),
    (b"/AA", "自動実行の指定"),
    (b"/EmbeddedFile", "埋め込まれたファイル"),
    (b"/RichMedia", "埋め込まれた動画・音声"),
]


# A shebang settles the question before any signature is consulted.
_SHEBANG = re.compile(rb"^#!\s*\S")

# Signatures searched for ANYWHERE in the data, not just at offset 0. The
# search starts at offset 1, not at len(magic): a 7-Zip magic sitting at
# offset 4 of a PDF was previously invisible because the scan began at 6.
_EMBEDDED = [
    (b"PK\x05\x06", "ZIP の終端レコード"),
    (b"PK\x03\x04", "ZIP のファイルヘッダ"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip ファイル"),
    (b"\xfd7zXZ\x00", "xz 圧縮データ"),
    (b"Rar!\x1a\x07", "RAR ファイル"),
    (b"MZ\x90\x00", "PE 実行ファイルのヘッダ"),
    (b"\x7fELF", "ELF 実行ファイルのヘッダ"),
]

# Formats whose magic does not sit at offset 0. Each carries a validator,
# because "these four bytes appear here" is not evidence on its own — the
# surrounding container framing has to agree.
def _valid_ftyp(head: bytes) -> bool:
    # ISO base media: a 4-byte big-endian box length, then 'ftyp'. A real box
    # is at least 8 bytes and does not span the whole address space.
    if len(head) < 12:
        return False
    size = int.from_bytes(head[:4], "big")
    return 8 <= size <= 4096 and head[8:12].isalnum()


def _valid_riff(head: bytes) -> bool:
    return head[:4] == b"RIFF"


_OFFSET_SIGNATURES = [
    (4, b"ftyp", "MP4/QuickTime 動画", Verdict.INERT_DATA,
     "4バイト目に ISO 基本メディアの ftyp 領域があります", _valid_ftyp),
    (8, b"WAVE", "WAV 音声", Verdict.INERT_DATA,
     "RIFF 形式で WAVE を宣言しています", _valid_riff),
    (8, b"AVI ", "AVI 動画", Verdict.INERT_DATA,
     "RIFF 形式で AVI を宣言しています", _valid_riff),
]

# Extensions that make a file runnable somewhere WITHOUT an execute bit.
# Matching these can only RAISE severity, never lower it.
_SCRIPT_EXT = {
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".sh", ".zsh", ".bash", ".ksh",
    ".rb", ".pl", ".pm", ".php", ".ps1", ".psm1", ".lua", ".jl", ".tcl",
    ".awk", ".r", ".groovy", ".vbs", ".vbe", ".wsf", ".wsh", ".bat", ".cmd",
    ".scpt", ".applescript", ".osascript",
}
_LAUNCHER_EXT = {
    ".command", ".hta", ".lnk", ".url", ".webloc", ".desktop", ".service",
    ".plist", ".reg", ".inf", ".scf", ".workflow", ".app", ".pkg", ".dmg",
}
_BYTECODE_EXT = {".jar", ".apk", ".war", ".ear", ".class", ".pyc"}
_MACRO_DOC_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".xll"}

# The ONLY extensions whose text content may be called inert. A positive
# allowlist: `sh notes.txt` runs notes.txt, so "it is text" is not safety.
_INERT_TEXT_EXT = {
    ".txt", ".log", ".md", ".rst", ".csv", ".tsv", ".json", ".jsonl",
    ".ndjson", ".yaml", ".yml", ".ini", ".cfg", ".conf", ".toml", ".diff",
    ".patch", ".srt", ".vtt",
}

# Text that betrays executable intent regardless of its extension.
_ACTIVE_MARKERS = [
    (b"@echo off", "Windows のバッチ命令"),
    (b"<?php", "PHP のソース"),
    (b"CreateObject(", "VBScript の自動実行呼び出し"),
    (b"do shell script", "AppleScript からのシェル呼び出し"),
    (b"<plist", "設定ファイル形式。自動起動の登録に使われ、実行権限がなくても動きます"),
    (b"Invoke-Expression", "PowerShell の動的実行呼び出し"),
    (b"IEX(", "PowerShell の動的実行呼び出し"),
    (b"<script", "埋め込まれたスクリプト記述"),
]


def _match(head: bytes) -> tuple[str, Verdict, str] | None:
    for magic, kind, verdict, why in _SIGNATURES_BY_LENGTH:
        if head.startswith(magic):
            return kind, verdict, why
    for off, magic, kind, verdict, why, validator in _OFFSET_SIGNATURES:
        if head[off : off + len(magic)] == magic and validator(head):
            return kind, verdict, why
    return None


def _looks_like_utf8_text(data: bytes) -> bool:
    """True only for data that is unambiguously inert text.

    A NUL byte disqualifies it outright: that is the classic way to smuggle
    binary content past a naive text check. The final 1-3 bytes are ignored so
    that a multi-byte character straddling the read boundary does not make a
    perfectly ordinary Japanese log file look like a binary.
    """
    if not data or b"\x00" in data:
        return False
    trimmed = data
    for _ in range(3):
        try:
            trimmed.decode("utf-8")
            break
        except UnicodeDecodeError as exc:
            if exc.start >= len(trimmed) - 3:
                trimmed = trimmed[: exc.start]  # truncated final character
                continue
            return False
    else:
        return False
    return not any(b < 0x09 or 0x0E <= b < 0x20 for b in trimmed)


def _worse(a: Identification, b: Identification) -> Identification:
    """Combine two independent readings by keeping the more severe."""
    return b if _SEVERITY[b.verdict] > _SEVERITY[a.verdict] else a


def _polyglot(head: bytes) -> str | None:
    """Report a container signature embedded past offset 0."""
    for sig, desc in _EMBEDDED:
        if head.find(sig, 1) > 0:
            return desc
    return None


def _from_name(ext: str) -> Identification | None:
    """A reading based only on the name. May escalate, never soften."""
    if ext in _LAUNCHER_EXT:
        return Identification(
            f"起動用ファイル（{ext}）", Verdict.SHORTCUT_LAUNCHER,
            f"拡張子が {ext} で、基本ソフトが起動対象として扱う形式です",
            "実行権限は不要です。開くだけで動作します。",
        )
    if ext in _SCRIPT_EXT:
        return Identification(
            f"スクリプト（{ext}）", Verdict.SCRIPT,
            f"拡張子が {ext} で、解釈実行される形式です",
            "実行権限は不要です。`python3 ファイル` や `sh ファイル` で動きます。",
        )
    if ext in _BYTECODE_EXT:
        return Identification(
            f"実行可能な圧縮ファイル（{ext}）", Verdict.BYTECODE_ARCHIVE,
            f"拡張子が {ext} で、実行環境が動かす形式です",
            "`java -jar` などの実行環境で動きます。",
        )
    if ext in _MACRO_DOC_EXT:
        return Identification(
            f"マクロ付き文書（{ext}）", Verdict.DOCUMENT_ACTIVE,
            f"拡張子が {ext} で、マクロを含められる Office 形式です",
        )
    return None


def identify(head: bytes, name: str = "", size: int | None = None) -> Identification:
    """Classify a file from a bounded prefix of its bytes.

    `head` is the first HEAD_BYTES of the file. `size` is the file's true
    length when known: if we only saw a prefix, nothing may be called inert,
    because the payload can simply live past the window we read.
    """
    if not head:
        return Identification(
            "空のファイル", Verdict.UNKNOWN, "内容がないため判定できません",
            "場所取りの空ファイルか、取り出しが途中で切れた可能性があります。",
        )

    lowered = name.lower()
    dot = lowered.rfind(".")
    ext = lowered[dot:] if dot > 0 else ""
    truncated = size is not None and size > len(head)

    # (1) A shebang outranks everything. It is an explicit declaration by the
    #     file itself that an interpreter should run it.
    if _SHEBANG.match(head):
        interp = head.split(b"\n", 1)[0].decode("utf-8", "replace").lstrip("#!").strip()
        result = Identification(
            "実行指定付きスクリプト", Verdict.SCRIPT,
            f"先頭の #! で解釈実行の対象 {interp!r} を指定しています",
            "実行権限は不要です。指定された処理系がデータとして読み込んで動かします。",
        )
    else:
        # (2) What the bytes say.
        hit = _match(head)
        if hit is not None:
            kind, verdict, why = hit
            caveat = ""
            if verdict is Verdict.SAMPLE_BEARING:
                if lowered.endswith(".gzf") or b"Program" in head:
                    kind = "Ghidra 解析データベース（.gzf）"
                    caveat = (
                        "Ghidra の Export Program → Original File で、元の検体そのものを"
                        "取り出せます。この形式のままでは基本ソフトは実行できませんが、"
                        "検体を内包していると考えてください。"
                    )
                else:
                    caveat = (
                        "Java の直列化データは任意の内容を含められます。信頼できない"
                        "データの復元処理そのものに危険があります。"
                    )
            elif kind == "PDF 文書":
                found = [d for m, d in _PDF_ACTIVE if m in head]
                if found:
                    caveat = f"この PDF には{found[0]}が含まれています。"
                else:
                    # 読み取った範囲に見当たらないだけで、無いとは限らない。
                    verdict = Verdict.DOCUMENT_PASSIVE
                    caveat = (
                        "読み取った範囲には、開いた時に動作する指定は見当たりません"
                        "でした。"
                    )
            elif verdict is Verdict.UNSUPPORTED_CONTAINER:
                caveat = (
                    "この圧縮形式はまだ一覧できないため、中身を確認できていません。"
                    "安全とみなさず、取り出しを禁止しています。"
                )
            result = Identification(kind, verdict, why, caveat)
        elif _looks_like_utf8_text(head):
            # (3) Text is inert ONLY for an allowlisted extension. "It is text"
            #     is not safety: `sh notes.txt` executes notes.txt.
            if ext in _INERT_TEXT_EXT:
                result = Identification(
                    "文字データ（UTF-8）", Verdict.INERT_DATA,
                    "正しい UTF-8 で、動作を伴わない拡張子です",
                )
            else:
                result = Identification(
                    "文字データ（拡張子が対象外）", Verdict.UNKNOWN,
                    f"正しい UTF-8 ですが、拡張子 {ext or 'なし'} は安全と確認できていません",
                    "文字データでも安全とは限りません。処理系に渡せば実行権限なしで動きます。",
                )
        else:
            result = Identification(
                "判別できない内容", Verdict.UNKNOWN,
                "既知のどの形式にも一致せず、文字データでもありません",
                "安全と確認できないため、実行ファイルと同じ扱いにしています。",
            )

    # (4) 名前による格上げ。ただし macOS の付随ファイル（`._` で始まる、または
    #     __MACOSX/ の下）の拡張子は、隣にある本体のものであって、この
    #     ファイル自身の中身を表さない。
    base = lowered.rsplit("/", 1)[-1]
    is_sidecar = base.startswith("._") or lowered.startswith("__macosx/")
    from_name = None if is_sidecar else _from_name(ext)
    if from_name is not None:
        result = _worse(result, from_name)

    # (5) Content markers, likewise on every branch.
    for marker, desc in _ACTIVE_MARKERS:
        if marker in head:
            result = _worse(
                result,
                Identification(
                    result.kind, Verdict.SCRIPT,
                    f"{desc}を含んでいます",
                    "実行権限がなくても動きます。",
                ),
            )
            break

    # (6) A container signature past offset 0 means another tool may read this
    #     file as something else entirely.
    embedded = _polyglot(head)
    if embedded is not None and result.verdict is not Verdict.CONTAINER:
        note = (
            f"途中の位置に{embedded}も含まれています。別のソフトはこのファイルを"
            "そちらとして読む可能性があります。"
        )
        # 重大度が上がるときだけ差し替える。UNKNOWN は「確かめられていない」と
        # いう意味なので、確定した判定に上書きすると、分かっていることまで
        # 「判別できません」と言ってしまう。
        if _SEVERITY[Verdict.UNKNOWN] > _SEVERITY[result.verdict]:
            result = Identification(result.kind, Verdict.UNKNOWN, result.why, note)
        else:
            result = Identification(
                result.kind, result.verdict, result.why,
                (note + " " + result.caveat).strip(),
            )

    # (7) We only saw a prefix. Keep the classification -- it is the most
    #     useful thing we can tell the learner -- but mark it provisional so it
    #     can never authorize a write: a payload can live past the window.
    if truncated:
        unread = size - len(head)
        extra = (
            f"先頭 {len(head)} バイトのみを確認しており、{unread} バイトは未確認です。"
            "この判定はファイル全体についてのものではありません。"
        )
        result = Identification(
            result.kind, result.verdict, result.why,
            (result.caveat + " " + extra).strip(),
            provisional=True,
        )

    return result
