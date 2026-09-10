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
    (b"MZ", "PE executable (Windows)", Verdict.NATIVE_EXECUTABLE,
     "starts with the DOS header 'MZ'"),
    (b"\x7fELF", "ELF executable (Linux/Unix)", Verdict.NATIVE_EXECUTABLE,
     "starts with the ELF magic"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit (macOS)", Verdict.NATIVE_EXECUTABLE,
     "starts with the Mach-O 64-bit magic"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit (macOS)", Verdict.NATIVE_EXECUTABLE,
     "starts with the Mach-O 32-bit magic"),
    (b"\xbe\xba\xfe\xca", "Mach-O fat binary (macOS)", Verdict.NATIVE_EXECUTABLE,
     "starts with the Mach-O fat magic"),
    # --- bytecode / archive-that-runs --------------------------------------
    (b"dex\n", "Android DEX bytecode", Verdict.BYTECODE_ARCHIVE,
     "starts with the DEX magic"),
    # --- containers ---------------------------------------------------------
    (b"PK\x03\x04", "ZIP archive", Verdict.CONTAINER,
     "starts with the ZIP local-file header"),
    (b"PK\x05\x06", "ZIP archive (empty)", Verdict.CONTAINER,
     "starts with the ZIP end-of-central-directory record"),
    (b"PK\x07\x08", "ZIP archive (spanned)", Verdict.CONTAINER,
     "starts with the ZIP spanned-archive marker"),
    (b"\x1f\x8b", "gzip stream", Verdict.CONTAINER, "starts with the gzip magic"),
    # --- containers we cannot currently enumerate: hard block ---------------
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", Verdict.UNSUPPORTED_CONTAINER,
     "starts with the 7-Zip magic"),
    (b"\xfd7zXZ\x00", "xz stream", Verdict.UNSUPPORTED_CONTAINER,
     "starts with the xz magic"),
    (b"BZh", "bzip2 stream", Verdict.UNSUPPORTED_CONTAINER,
     "starts with the bzip2 magic"),
    (b"\x28\xb5\x2f\xfd", "zstd stream", Verdict.UNSUPPORTED_CONTAINER,
     "starts with the zstd magic"),
    (b"Rar!\x1a\x07", "RAR archive", Verdict.UNSUPPORTED_CONTAINER,
     "starts with the RAR magic"),
    (b"MSCF", "Microsoft Cabinet", Verdict.UNSUPPORTED_CONTAINER,
     "starts with the CAB magic"),
    # --- documents that can carry executable content -----------------------
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound document (legacy Office)",
     Verdict.DOCUMENT_ACTIVE, "starts with the OLE compound-file magic"),
    # --- launchers ----------------------------------------------------------
    (b"L\x00\x00\x00\x01\x14\x02\x00", "Windows shortcut (.lnk)",
     Verdict.SHORTCUT_LAUNCHER, "starts with the Windows shell-link header"),
    # --- sample-bearing analysis databases ----------------------------------
    (b"\xac\xed\x00\x05", "Java serialized object stream", Verdict.SAMPLE_BEARING,
     "starts with the Java serialization magic (0xACED0005)"),
    # --- forensic images ----------------------------------------------------
    (b"EVF\x09\x0d\x0a\xff\x00", "EnCase/EWF forensic image", Verdict.FORENSIC_IMAGE,
     "starts with the EWF magic"),
    (b"AFF", "AFF forensic image", Verdict.FORENSIC_IMAGE,
     "starts with the AFF magic"),
    # --- inert -------------------------------------------------------------
    # PDF is NOT inert: /Launch, /JavaScript and /EmbeddedFile are part of the
    # format, and BUILD-CONTRACT rule 5 does not list it in the inert allowlist.
    (b"%PDF", "PDF document", Verdict.DOCUMENT_ACTIVE,
     "starts with the PDF magic — PDFs can carry /Launch and /JavaScript actions"),
    (b"\x89PNG\r\n\x1a\n", "PNG image", Verdict.INERT_DATA,
     "starts with the PNG magic"),
    (b"\xff\xd8\xff", "JPEG image", Verdict.INERT_DATA, "starts with the JPEG magic"),
    (b"GIF87a", "GIF image", Verdict.INERT_DATA, "starts with the GIF magic"),
    (b"GIF89a", "GIF image", Verdict.INERT_DATA, "starts with the GIF magic"),
    # A capture of a malware download carries the sample verbatim in its
    # payload -- recoverable with Wireshark's "Export Objects". Same reasoning
    # that makes a Ghidra .gzf sample-bearing rather than inert.
    (b"\xd4\xc3\xb2\xa1", "pcap capture", Verdict.SAMPLE_BEARING,
     "starts with the pcap magic"),
    (b"\xa1\xb2\xc3\xd4", "pcap capture (big-endian)", Verdict.SAMPLE_BEARING,
     "starts with the pcap magic"),
    (b"\x0a\x0d\x0d\x0a", "pcapng capture", Verdict.SAMPLE_BEARING,
     "starts with the pcapng block header"),
    (b"\x00\x05\x16\x07", "AppleDouble resource header", Verdict.UNKNOWN,
     "starts with the AppleDouble magic — carries xattrs and resource forks"),
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

# A shebang settles the question before any signature is consulted.
_SHEBANG = re.compile(rb"^#!\s*\S")

# Signatures searched for ANYWHERE in the data, not just at offset 0. The
# search starts at offset 1, not at len(magic): a 7-Zip magic sitting at
# offset 4 of a PDF was previously invisible because the scan began at 6.
_EMBEDDED = [
    (b"PK\x05\x06", "a ZIP end-of-central-directory record"),
    (b"PK\x03\x04", "a ZIP local-file header"),
    (b"7z\xbc\xaf\x27\x1c", "a 7-Zip archive"),
    (b"\xfd7zXZ\x00", "an xz stream"),
    (b"Rar!\x1a\x07", "a RAR archive"),
    (b"MZ\x90\x00", "a PE executable header"),
    (b"\x7fELF", "an ELF executable header"),
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
    (4, b"ftyp", "MP4/QuickTime video", Verdict.INERT_DATA,
     "carries a valid ISO base-media 'ftyp' box at offset 4", _valid_ftyp),
    (8, b"WAVE", "WAV audio", Verdict.INERT_DATA,
     "is a RIFF container declaring WAVE", _valid_riff),
    (8, b"AVI ", "AVI video", Verdict.INERT_DATA,
     "is a RIFF container declaring AVI", _valid_riff),
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
    (b"@echo off", "a Windows batch script"),
    (b"<?php", "PHP source"),
    (b"CreateObject(", "VBScript automation"),
    (b"do shell script", "an AppleScript shell invocation"),
    (b"<plist", "a property list — LaunchAgents run these with no execute bit"),
    (b"Invoke-Expression", "a PowerShell dynamic-execution call"),
    (b"IEX(", "a PowerShell dynamic-execution call"),
    (b"<script", "embedded script markup"),
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
            f"launcher ({ext})", Verdict.SHORTCUT_LAUNCHER,
            f"the name ends in {ext}, which the operating system treats as "
            "something to launch",
            "Needs no execute bit: opening it is enough.",
        )
    if ext in _SCRIPT_EXT:
        return Identification(
            f"script ({ext})", Verdict.SCRIPT,
            f"the name ends in {ext}, which an interpreter will run",
            "Runs without an execute bit, e.g. `python3 file` or `sh file`.",
        )
    if ext in _BYTECODE_EXT:
        return Identification(
            f"bytecode archive ({ext})", Verdict.BYTECODE_ARCHIVE,
            f"the name ends in {ext}, which a runtime will execute",
            "Runs with `java -jar` or an equivalent runtime.",
        )
    if ext in _MACRO_DOC_EXT:
        return Identification(
            f"macro-enabled document ({ext})", Verdict.DOCUMENT_ACTIVE,
            f"the name ends in {ext}, a macro-enabled Office format",
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
            "empty", Verdict.UNKNOWN, "the file has no content to classify",
            "An empty member may be a placeholder, or a truncated extraction.",
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
            "script with a shebang", Verdict.SCRIPT,
            f"starts with '#!' naming the interpreter {interp!r}",
            "Runs without an execute bit: an interpreter reads it as data.",
        )
    else:
        # (2) What the bytes say.
        hit = _match(head)
        if hit is not None:
            kind, verdict, why = hit
            caveat = ""
            if verdict is Verdict.SAMPLE_BEARING:
                if lowered.endswith(".gzf") or b"Program" in head:
                    kind = "Ghidra packed program database (.gzf)"
                    caveat = (
                        "The original sample's bytes are recoverable from this file "
                        "with Ghidra (Export Program -> Original File). The operating "
                        "system cannot run it as it stands, but it is not a derived "
                        "artifact — treat it as carrying the sample itself."
                    )
                else:
                    caveat = (
                        "A Java object stream can carry arbitrary embedded data, and "
                        "deserializing an untrusted stream is itself an execution risk."
                    )
            elif verdict is Verdict.UNSUPPORTED_CONTAINER:
                caveat = (
                    "This container cannot be enumerated yet, so its contents are "
                    "unverified. It is blocked rather than assumed safe."
                )
            result = Identification(kind, verdict, why, caveat)
        elif _looks_like_utf8_text(head):
            # (3) Text is inert ONLY for an allowlisted extension. "It is text"
            #     is not safety: `sh notes.txt` executes notes.txt.
            if ext in _INERT_TEXT_EXT:
                result = Identification(
                    "plain UTF-8 text", Verdict.INERT_DATA,
                    "is valid UTF-8 with no NUL bytes, and carries an extension "
                    "on the inert allowlist",
                )
            else:
                result = Identification(
                    "text with an unrecognised extension", Verdict.UNKNOWN,
                    f"is valid UTF-8 text, but {ext or 'no extension'} is not on "
                    "the inert allowlist",
                    "Text is not automatically safe — an interpreter will run it "
                    "if asked, with no execute bit required.",
                )
        else:
            result = Identification(
                "unrecognised binary", Verdict.UNKNOWN,
                "matches no known signature and is not valid UTF-8 text",
                "Treated as strictly as an executable, because it has not been "
                "ruled out.",
            )

    # (4) The name is consulted on EVERY branch, and can only escalate.
    from_name = _from_name(ext)
    if from_name is not None:
        result = _worse(result, from_name)

    # (5) Content markers, likewise on every branch.
    for marker, desc in _ACTIVE_MARKERS:
        if marker in head:
            result = _worse(
                result,
                Identification(
                    result.kind, Verdict.SCRIPT,
                    f"contains {desc}",
                    "Runs without an execute bit.",
                ),
            )
            break

    # (6) A container signature past offset 0 means another tool may read this
    #     file as something else entirely.
    embedded = _polyglot(head)
    if embedded is not None and result.verdict is not Verdict.CONTAINER:
        result = Identification(
            result.kind, Verdict.UNKNOWN, result.why,
            f"Also contains {embedded} at a non-zero offset — this file is a "
            "polyglot and a different tool may read it as that instead. "
            + result.caveat,
        )

    # (7) We only saw a prefix. Keep the classification -- it is the most
    #     useful thing we can tell the learner -- but mark it provisional so it
    #     can never authorize a write: a payload can live past the window.
    if truncated:
        unread = size - len(head)
        extra = (
            f"Only the first {len(head)} bytes were examined; {unread} bytes were "
            "not read, so this describes the header, not the whole file."
        )
        result = Identification(
            result.kind, result.verdict, result.why,
            (result.caveat + " " + extra).strip(),
            provisional=True,
        )

    return result
