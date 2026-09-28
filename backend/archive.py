"""archive.py — enumerate what is inside an archive WITHOUT extracting it.

The single best decision in this design is that inspection never writes a file.
We read the central directory for metadata and a bounded prefix of each member
for its magic bytes. Nothing is expanded to disk, ever.

Three classes of hazard are handled here:

  * BOMBS — a flat bomb points many directory entries at one overlapping blob,
    so per-entry ratios look ordinary while the total explodes. We budget the
    whole tree, cap the entry count, and detect duplicate header offsets.
  * NAMES — a CP932 (Shift_JIS) trail byte may be 0x5C ('\\'), so a validator
    that checks the DECODED string sees one character where a byte-level
    extractor on Windows sees a path separator. We check both views and report
    the disagreement. (Measured on the real archives used for validation during
    development: all 236 entries were in fact UTF-8 with the language flag
    CLEAR, so they take the UTF-8 path and this scan does not fire on them. It
    is kept for archives that are CP932.)
  * FAIL-OPEN — an encrypted, malformed, or unsupported member must never land
    on the benign side of the fence. Every failure path returns a blocking
    verdict, never `inert`.

Note that traversal cannot actually escape via this tool, because storage is
content-addressed and no member name ever becomes a path component
(the storage rule: names come from the content hash, never from the archive).
The name checks here exist to WARN the learner about
what a third-party extractor would do with the same archive.
"""

from __future__ import annotations

import hashlib
import io
import os
import stat
import struct
import zipfile
from dataclasses import dataclass, field

from identify import (
    _EMBEDDED,
    _SEVERITY,
    HEAD_BYTES,
    Identification,
    Verdict,
    _looks_like_utf8_text,
    identify,
)

# --- budgets ---------------------------------------------------------------
MAX_ENTRIES = 10_000
MAX_TOTAL_UNCOMPRESSED = 2 * 1024**3  # 2 GiB across the whole tree
MAX_RATIO = 200  # per-entry compression ratio
MAX_DEPTH = 3  # archives inside archives
MAX_ARCHIVE_BYTES = 8 * 1024**3  # refuse to even open something larger
MAX_NESTED_BYTES = 64 * 1024**2  # only recurse into a nested archive below this
MAX_FULL_SCAN_BYTES = 256 * 1024**2  # cap on a whole-stream verification read
_CHUNK = 1024 * 1024

# CP932 lead-byte ranges. A byte in these ranges consumes the following byte.
_CP932_LEAD = [(0x81, 0x9F), (0xE0, 0xFC)]


def _is_lead(b: int) -> bool:
    return any(lo <= b <= hi for lo, hi in _CP932_LEAD)


@dataclass
class Member:
    """One entry in an archive. `name` is display data and never a path."""

    index: int
    name: str
    size: int
    compressed: int
    encrypted: bool
    ident: Identification
    warnings: list[str] = field(default_factory=list)
    #: Empty for a top-level member. For a member found inside a nested
    #: archive, the name of the archive it came from -- such a member has no
    #: top-level index, so it cannot be previewed directly.
    container: str = ""

    @property
    def verdict(self) -> Verdict:
        return self.ident.verdict

    @property
    def materializable(self) -> bool:
        # A member with any structural warning is never materializable, even if
        # its bytes look inert. Defence in depth over the identify() verdict.
        return self.ident.materializable and not self.warnings


@dataclass
class Listing:
    path: str
    members: list[Member]
    warnings: list[str] = field(default_factory=list)
    truncated: bool = False


def raw_name_bytes(info: zipfile.ZipInfo) -> bytes:
    """Recover the on-disk bytes of a member name.

    Python decodes names as UTF-8 when the language-encoding flag is set and as
    CP437 otherwise. CP437 is a single-byte codec covering 0x00-0xFF, so it
    round-trips the original bytes exactly — verified lossless against an
    independent parse of the central directory for all 236 real entries.
    """
    if info.flag_bits & 0x800:
        return info.orig_filename.encode("utf-8", "surrogateescape")
    try:
        return info.orig_filename.encode("cp437")
    except UnicodeEncodeError:
        return info.orig_filename.encode("utf-8", "surrogateescape")


def decode_name(raw: bytes, utf8_flag: bool) -> tuple[str, str]:
    """Best-effort display name, plus the encoding that actually worked.

    Real-world archives often store UTF-8 bytes but leave the language-encoding flag
    CLEAR, so the flag cannot be trusted either way — we try decoders in order
    and report which one succeeded. The caller needs that answer, because the
    Shift_JIS separator hazard exists only for genuinely CP932 names.
    """
    if utf8_flag:
        return raw.decode("utf-8", "replace"), "utf-8"
    # UTF-8 first: it is self-synchronising, so a successful UTF-8 decode is
    # strong evidence. CP932 would happily decode the same bytes as mojibake.
    for enc in ("utf-8", "cp932"):
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return raw.decode("cp437", "replace"), "cp437"


def inspect_name(raw: bytes, decoded: str, encoding: str = "cp932") -> list[str]:
    """Compare the byte view and the decoded view of a member name.

    Returns human-readable warnings. Disagreement between the two views is the
    Shift_JIS traversal pattern and is reported even though this tool cannot be
    escaped by it.
    """
    warnings: list[str] = []

    # Byte-level view: what a naive extractor sees.
    byte_seps = {i for i, b in enumerate(raw) if b in (0x2F, 0x5C)}

    # Decoder-aware view: which of those bytes are really trail bytes of a
    # two-byte CP932 character, and therefore NOT separators.
    #
    # This applies ONLY to CP932. In UTF-8 a continuation byte is always
    # 0x80-0xBF and can never be 0x2F or 0x5C, so a UTF-8 name has no such
    # ambiguity. Running the CP932 model over UTF-8 bytes mis-frames them
    # (0xE6 and 0x90 both look like CP932 lead bytes) and reports every real
    # directory separator as suspicious.
    trail_positions: set[int] = set()
    if encoding == "cp932":
        i = 0
        while i < len(raw):
            if _is_lead(raw[i]) and i + 1 < len(raw):
                trail_positions.add(i + 1)
                i += 2
            else:
                i += 1

    ambiguous = sorted(byte_seps & trail_positions)
    if ambiguous:
        warnings.append(
            "名前の解釈が一致しません。バイト位置 "
            + ", ".join(str(o) for o in ambiguous[:4])
            + " は日本語一文字の一部ですが、バイト単位で扱うソフトは"
            "区切り文字として読みます（Shift_JIS を悪用した位置ずらしの手口）。"
        )

    if decoded.startswith("/") or (len(decoded) > 1 and decoded[1] == ":"):
        warnings.append("名前が絶対パスです。取り出し先を無視するソフトがあります。")

    parts = decoded.replace("\\", "/").split("/")
    if ".." in parts:
        warnings.append("名前に .. が含まれます。別のソフトで取り出すと想定外の場所に書かれます。")

    if any(ord(c) < 0x20 for c in decoded):
        warnings.append("名前に制御文字が含まれます。")

    # Right-to-left override and friends reverse how a name renders, so
    # `photo_gpj.exe` can display as `photo_exe.jpg`.
    if any(c in decoded for c in "‪‫‬‭‮⁦⁧⁨⁩"):
        warnings.append(
            "名前に表示順を反転させる文字が含まれます。見えている並びは"
            "実際の並びと異なります。"
        )

    return warnings


def scan_stream_full(fh, name: str, declared_size: int):
    """Read a member END TO END and return (Identification, sha256, bytes read).

    `identify()` sees only the first HEAD_BYTES. That is fine for *display* but
    must never authorize a write, for two independent reasons:

      * a payload can simply live past the 4 KB window; and
      * a ZIP is located by its END-of-central-directory record, so a
        PDF/ZIP polyglot is invisible to a prefix scan by construction.

    This is the check that has to pass before anything reaches disk. Returns
    None if the member exceeds the scan budget -- in which case it is refused,
    not assumed safe.
    """
    digest = hashlib.sha256()
    head = b""
    total = 0
    text_ok = True
    embedded: str | None = None
    carry = b""
    max_sig = max(len(sig) for sig, _ in _EMBEDDED)

    while True:
        chunk = fh.read(_CHUNK)
        if not chunk:
            break
        if total + len(chunk) > MAX_FULL_SCAN_BYTES:
            return None  # too large to verify -> refused, never assumed inert
        digest.update(chunk)
        if not head:
            head = chunk[:HEAD_BYTES]
        if text_ok and not _looks_like_utf8_text(chunk):
            text_ok = False
        if embedded is None:
            window = carry + chunk
            base = total - len(carry)
            for sig, desc in _EMBEDDED:
                pos = window.find(sig)
                # A match at absolute offset 0 is the file's own magic.
                while pos != -1:
                    if base + pos > 0:
                        embedded = desc
                        break
                    pos = window.find(sig, pos + 1)
                if embedded:
                    break
            carry = window[-max_sig:]
        total += len(chunk)

    # size=None, not size=total: we are handing identify() everything it is
    # being asked to judge, so it must not add its "only a prefix was read"
    # caveat -- we read the whole stream right here.
    ident = identify(head, name, size=None)

    if embedded is not None and ident.verdict is not Verdict.CONTAINER:
        # Escalate, never replace. UNKNOWN means "not ruled out", so applying
        # it over a positive identification would tell the learner LESS than
        # the tool already knows -- a .gzf would stop saying "Ghidra database,
        # sample recoverable" and start saying "unrecognised". Both block a
        # write either way, so there is nothing to gain by flattening it.
        note = (
            f"ファイル全体の走査で、途中の位置に{embedded}が見つかりました。"
            "別のソフトはこのファイルをそちらとして読む可能性があります。"
        )
        if _SEVERITY[Verdict.UNKNOWN] > _SEVERITY[ident.verdict]:
            ident = Identification(ident.kind, Verdict.UNKNOWN, ident.why, note)
        else:
            ident = Identification(
                ident.kind, ident.verdict, ident.why,
                (ident.caveat + " " + note).strip(),
            )
    elif ident.verdict is Verdict.INERT_DATA and not text_ok and total > len(head):
        # The header looked like text but the body is not.
        ident = Identification(
            ident.kind, Verdict.UNKNOWN, ident.why,
            "先頭は無害に見えますが、残りの部分は正しい文字データではありません。",
        )
    return ident, digest.hexdigest(), total


def enumerate_zip(path: str, depth: int = 0) -> Listing:
    """Open a ZIP from disk and enumerate it. Extracts nothing."""
    listing = Listing(path=path, members=[])

    # Anything that is not a regular file can block forever: a FIFO named
    # `x.zip` makes open() wait for a writer, and a symlink to /dev/zero makes
    # hashing loop without end. Both would hang inside the caller's lock.
    try:
        st = os.lstat(path)
    except OSError as exc:
        listing.warnings.append(f"情報を取得できません: {exc}")
        return listing
    if not stat.S_ISREG(st.st_mode):
        listing.warnings.append(
            "通常のファイルではありません（連結・特殊ファイル）。読まずに拒否しました。"
        )
        return listing
    if st.st_size > MAX_ARCHIVE_BYTES:
        listing.warnings.append(
            f"ファイルの大きさ {st.st_size} バイトが上限 {MAX_ARCHIVE_BYTES} を超えています。"
        )
        return listing

    # A hostile name can raise UnicodeDecodeError from ZipFile's own strict
    # decode. Catching only BadZipFile/OSError let that escape and abort the
    # whole directory scan, which is the tool-level fail-open this module
    # exists to prevent.
    try:
        zf = zipfile.ZipFile(path)
    except (
        zipfile.BadZipFile, OSError, ValueError, EOFError,
        NotImplementedError, RuntimeError, struct.error,
    ) as exc:
        listing.warnings.append(f"ZIPファイルとして開けません: {exc}")
        return listing

    with zf:
        inner = _enumerate_open(zf, depth)
    listing.members = inner.members
    listing.warnings.extend(inner.warnings)
    listing.truncated = inner.truncated
    return listing


def _enumerate_open(zf: zipfile.ZipFile, depth: int = 0) -> Listing:
    """Enumerate an already-open archive. Never touches the filesystem."""
    listing = Listing(path=getattr(zf, "filename", "") or "<nested>", members=[])

    infos = zf.infolist()
    if len(infos) > MAX_ENTRIES:
        listing.warnings.append(
            f"この圧縮ファイルは {len(infos)} 件を宣言しています。先頭 "
            f"{MAX_ENTRIES} 件のみ確認しました。"
        )
        infos = infos[:MAX_ENTRIES]
        listing.truncated = True

    # A flat bomb reuses one compressed blob across many entries.
    offsets: dict[int, int] = {}
    for info in infos:
        offsets[info.header_offset] = offsets.get(info.header_offset, 0) + 1
    repeated = {off: n for off, n in offsets.items() if n > 1}
    if repeated:
        listing.warnings.append(
            f"{sum(repeated.values())} 件が {len(repeated)} 個の同じ位置を"
            "指しています。展開すると膨張する細工の特徴です。"
        )

    total = 0
    for index, info in enumerate(infos):
        # is_dir() is only `filename.endswith('/')`. An entry with a
        # trailing slash AND content was being dropped silently -- no row,
        # no warning -- while a byte-level extractor would still write it.
        if info.is_dir():
            if not (info.file_size or info.compress_size):
                continue
            warn_dir = True
        else:
            warn_dir = False

        raw = raw_name_bytes(info)
        name, encoding = decode_name(raw, bool(info.flag_bits & 0x800))
        warnings = inspect_name(raw, name, encoding)
        if warn_dir:
            warnings.append(
                '名前が区切り文字で終わっていますが中身があります。実際には入れ物ではありません。'
            )

        encrypted = bool(info.flag_bits & 0x1)
        total += info.file_size
        if total > MAX_TOTAL_UNCOMPRESSED:
            listing.warnings.append(
                "展開後の合計が上限を超えたため、"
                "確認を途中で打ち切りました。"
            )
            listing.truncated = True
            break

        # No `and info.compress_size` guard: a declared compress_size of 0
        # is falsy and previously skipped this check altogether.
        if info.file_size / max(info.compress_size, 1) > MAX_RATIO:
            warnings.append(
                f"圧縮率が {info.file_size // max(info.compress_size, 1)}:1 です。"
                "展開すると膨張する細工の可能性があります。"
            )

        # AppleDouble sidecars carry xattrs, resource forks and exec bits.
        # A resource fork can hold a whole second payload that a data-fork
        # hash never sees, so they are called out rather than ignored.
        # 付随情報であることは identify() が判定として返すので、ここで警告を
        # 重ねない。警告を付けると画面上「注意が必要」に入り、60 件を超える
        # macOS の付随ファイルが、本当に注意すべき数件を埋もれさせる。
        base = name.rsplit("/", 1)[-1]

        if encrypted:
            # Fail closed. This is exactly where a live sample hides, and
            # we cannot see a single byte of it.
            ident = Identification(
                "暗号化された項目",
                Verdict.OPAQUE_ENCRYPTED,
                "ZIP の暗号化指定があり、内容を読めません",
                "パスワード付きの圧縮ファイルはマルウェアの一般的な配布形式です。"
                "判定できないため取り出しを禁止しています。",
            )
        else:
            try:
                with zf.open(info) as fh:
                    head = fh.read(HEAD_BYTES)
                ident = identify(head, name, info.file_size)
            except (RuntimeError, zipfile.BadZipFile, OSError, NotImplementedError) as exc:
                # Includes "compression method not supported" and the
                # local-vs-central header mismatch check. Never inert.
                ident = Identification(
                    "読み取れない項目",
                    Verdict.UNKNOWN,
                    f"この項目を読めませんでした: {exc}",
                    "危険と判明したためではなく、"
                    "判定できないため禁止しています。",
                )

        listing.members.append(
            Member(
                index=index,
                name=name,
                size=info.file_size,
                compressed=info.compress_size,
                encrypted=encrypted,
                ident=ident,
                warnings=warnings,
            )
        )

    # --- nested archives ------------------------------------------------
    # Without this, a student is told "an archive -- look inside before
    # trusting it" with no way to look inside, and the encrypted members
    # (which in the real dataset live one level down) are never seen at all.
    if depth < MAX_DEPTH:
        for parent in list(listing.members):
            if parent.verdict is not Verdict.CONTAINER or parent.container:
                continue
            if not (0 < parent.size <= MAX_NESTED_BYTES):
                if parent.size > MAX_NESTED_BYTES:
                    parent.warnings.append(
                        f"入れ子の圧縮ファイルが {parent.size} バイトで上限 "
                        f"{MAX_NESTED_BYTES} を超えるため、"
                        "中身を確認していません。"
                    )
                continue
            try:
                with zf.open(zf.infolist()[parent.index]) as fh:
                    blob = fh.read(MAX_NESTED_BYTES + 1)
            except Exception as exc:  # noqa: BLE001 - fail closed
                parent.warnings.append(f"入れ子の圧縮ファイルを読めません: {exc}")
                continue
            if len(blob) > MAX_NESTED_BYTES:
                parent.warnings.append("入れ子の圧縮ファイルが上限を超えました。")
                continue
            try:
                inner = zipfile.ZipFile(io.BytesIO(blob))
            except Exception as exc:  # noqa: BLE001 - fail closed
                parent.warnings.append(f"入れ子の圧縮ファイルを開けません: {exc}")
                continue
            with inner:
                sub = _enumerate_open(inner, depth + 1)
            for m in sub.members:
                m.container = parent.name
                m.name = f"{parent.name} :: {m.name}"
                listing.members.append(m)
            for w in sub.warnings:
                parent.warnings.append(f"この圧縮ファイルの中: {w}")

    # An archive-level warning -- a flat bomb, a truncated listing -- is a
    # statement about every member in it. Without this, a member of an archive
    # positively identified as a zip bomb was still materializable.
    if listing.warnings:
        note = "圧縮ファイル全体の警告: " + listing.warnings[0]
        for m in listing.members:
            m.warnings.append(note)

    return listing


def summarise(listing: Listing) -> dict[str, int]:
    """Count members by verdict — the headline the inventory screen shows."""
    counts: dict[str, int] = {}
    for m in listing.members:
        counts[m.verdict.value] = counts.get(m.verdict.value, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))
