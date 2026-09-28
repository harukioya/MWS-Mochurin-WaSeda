"""gzf.py — Ghidra の packed file（.gzf）であることを、中身から確かめる。

拡張子もブラウザの `accept` も証拠にならない。Ghidra の `GzfLoader` は
拡張子に加えて先頭のマジック番号を見るが、アプリ側でも同じ確認と、それより
一歩踏み込んだ確認を、コンテナを起動する前に行う。

Ghidra 12.1.4 の `ItemSerializer.outputItem` が書く形式（Java の直列化ストリーム）:

    AC ED 00 05                 ObjectOutputStream の頭
    77 <len:1>                  TC_BLOCKDATA（短いブロック）
      <magic:8>                 0x2e30212634e92c20
      <formatVersion:4>         1
      <itemName:UTF>            2 バイト長 + 修正 UTF-8
      <contentType:UTF>         "Program" 等
      <fileType:4>
      <length:8>                展開後の中身の大きさ
    ZIP ストリーム（1 項目 "FOLDER_ITEM"）

`Program` 以外（データ型アーカイブ等）はこの教材の対象ではないので断る。
展開後の大きさは宣言値と、実際に展開した量の両方で上限を確かめる。コンテナ内の
作業領域は容量制限付きなので、そこで溢れる前にここで止める。

ファイルは読むだけで、何も実行しない。ZIP 部分はメモリ上で数えながら展開するだけで、
ディスクへは書かない。
"""

from __future__ import annotations

import stat
import struct
import zlib
from dataclasses import dataclass

MAGIC = 0x2E30212634E92C20
FORMAT_VERSION = 1
PROGRAM_CONTENT_TYPE = "Program"
ENTRY_NAME = "FOLDER_ITEM"

#: 受け付ける GZF の大きさ（圧縮された状態）。
MAX_GZF_BYTES = 64 * 1024**2
#: 展開後のデータベースの大きさ。コンテナの /tmp（1.5 GiB）に、作業用の
#: 複製と Ghidra の一時ファイルを置いても収まる値にする。
MAX_UNPACKED_BYTES = 512 * 1024**2
#: 展開後 / 圧縮後の比率。Ghidra の DB はよく縮むが、極端な値は爆弾の特徴。
MAX_RATIO = 200
#: 先頭の確認に読む量。ヘッダーはこれより十分短い。
HEAD_BYTES = 4096


class NotGzf(Exception):
    """Ghidra の packed file として読めない。`code` は画面へ出す固定の符号。"""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code


@dataclass(frozen=True)
class GzfHeader:
    item_name: str
    content_type: str
    file_type: int
    declared_length: int
    zip_offset: int


def _utf(buf: bytes, pos: int) -> tuple[str, int]:
    if pos + 2 > len(buf):
        raise NotGzf("not-gzf", "truncated UTF length")
    (n,) = struct.unpack_from(">H", buf, pos)
    pos += 2
    if pos + n > len(buf):
        raise NotGzf("not-gzf", "truncated UTF body")
    raw = buf[pos : pos + n]
    # Java の修正 UTF-8。NUL が C0 80 になる以外は UTF-8 と同じ。表示に使う
    # だけなので、読めない並びは置き換えてよい。
    text = raw.replace(b"\xc0\x80", b"\x00").decode("utf-8", "replace")
    return text, pos + n


def parse_header(head: bytes) -> GzfHeader:
    """先頭のバイト列から、GZF の頭を読み取る。形が違えば NotGzf。"""
    if len(head) < 6 + 8 + 4:
        raise NotGzf("not-gzf", "too short")
    if head[:4] != b"\xac\xed\x00\x05":
        raise NotGzf("not-gzf", "no Java serialization header")
    if head[4] != 0x77:
        # Ghidra の isPackedFile は 6 バイト目から読むので、短いブロック以外は
        # Ghidra 自身も受け付けない。
        raise NotGzf("not-gzf", "unexpected block type")
    block_len = head[5]
    block_end = 6 + block_len
    if block_end > len(head):
        raise NotGzf("not-gzf", "truncated block")
    block = head[6:block_end]
    if len(block) < 8 + 4:
        raise NotGzf("not-gzf", "short block")
    (magic,) = struct.unpack_from(">Q", block, 0)
    if magic != MAGIC:
        raise NotGzf("not-gzf", "bad magic")
    (version,) = struct.unpack_from(">i", block, 8)
    if version != FORMAT_VERSION:
        raise NotGzf("version-unsupported", f"packed format {version}")
    pos = 12
    item_name, pos = _utf(block, pos)
    content_type, pos = _utf(block, pos)
    if pos + 12 != len(block):
        raise NotGzf("not-gzf", "block length mismatch")
    file_type, declared = struct.unpack_from(">iq", block, pos)
    if content_type != PROGRAM_CONTENT_TYPE:
        raise NotGzf("not-program", f"content type {content_type[:40]!r}")
    if declared < 0:
        raise NotGzf("not-gzf", "negative length")
    if declared > MAX_UNPACKED_BYTES:
        raise NotGzf("too-large-unpacked", f"declared {declared}")
    return GzfHeader(item_name, content_type, file_type, declared, block_end)


_LOCAL_HEADER = struct.Struct("<IHHHHHIIIHH")
_LOCAL_SIG = 0x04034B50
_DESCRIPTOR_SIG = 0x08074B50
_CHUNK = 256 * 1024


def inspect_file(fh, size: int) -> GzfHeader:
    """開いたファイルを GZF として確かめる。形が違えば必ず NotGzf を送出する。

    壊れた圧縮データでは zlib が zlib.error を、途中で切れたヘッダーでは
    struct が struct.error を出す。これらを呼び出し側へ漏らすと、受付処理が
    想定外の例外で抜けて処理枠と一時ファイルが残る。中身の形の問題はすべて
    「GZF として読めない」に揃える。
    """
    try:
        return _inspect(fh, size)
    except NotGzf:
        raise
    except (zlib.error, struct.error, ValueError, OverflowError, EOFError, MemoryError) as exc:
        raise NotGzf("not-gzf", type(exc).__name__) from None


def _inspect(fh, size: int) -> GzfHeader:
    """inspect_file の本体。ディスクへは何も書かない。

    Ghidra の書き出しは ZIP の目録（central directory）を書かずに閉じるので、
    標準の `zipfile` では開けない。ローカルヘッダーを読み、中身をメモリ上で
    少しずつ展開しながら、宣言された大きさを超えないこと、大きさと CRC が
    末尾の記述子と一致することを確かめる。展開したデータは捨てる。

    `fh` は呼び出し側が O_NOFOLLOW で開いた通常ファイル。読み終えたら先頭へ戻す。
    """
    if size <= 0:
        raise NotGzf("empty", "empty file")
    if size > MAX_GZF_BYTES:
        raise NotGzf("too-large", f"{size} bytes")
    fh.seek(0)
    header = parse_header(fh.read(HEAD_BYTES))

    fh.seek(header.zip_offset)
    raw = fh.read(_LOCAL_HEADER.size)
    if len(raw) != _LOCAL_HEADER.size:
        raise NotGzf("not-gzf", "truncated zip header")
    (sig, _ver, flags, method, _t, _d, crc, csize, usize,
     name_len, extra_len) = _LOCAL_HEADER.unpack(raw)
    if sig != _LOCAL_SIG:
        raise NotGzf("not-gzf", "no zip local header")
    if flags & 0x1:
        raise NotGzf("not-gzf", "encrypted entry")
    if method != 8:
        raise NotGzf("not-gzf", f"method {method}")
    name = fh.read(name_len)
    if name != ENTRY_NAME.encode():
        raise NotGzf("not-gzf", "unexpected entry name")
    fh.seek(extra_len, 1)
    data_start = header.zip_offset + _LOCAL_HEADER.size + name_len + extra_len
    compressed_room = size - data_start
    if compressed_room <= 0:
        raise NotGzf("not-gzf", "no data")
    if header.declared_length / compressed_room > MAX_RATIO:
        raise NotGzf("ratio", "extreme compression ratio")

    dec = zlib.decompressobj(-15)
    produced = 0
    running = 0
    while not dec.eof:
        chunk = fh.read(_CHUNK)
        if not chunk:
            raise NotGzf("not-gzf", "truncated deflate stream")
        data = dec.decompress(chunk, _CHUNK * 4)
        while True:
            produced += len(data)
            if produced > header.declared_length:
                raise NotGzf("not-gzf", "content longer than declared")
            running = zlib.crc32(data, running)
            if not dec.unconsumed_tail or dec.eof:
                break
            data = dec.decompress(dec.unconsumed_tail, _CHUNK * 4)
    if produced != header.declared_length:
        raise NotGzf("not-gzf", "content shorter than declared")

    # 展開し終えた位置の直後に、大きさと CRC が来る（flags の bit 3）。
    # ローカルヘッダーに値が入っている場合はそちらと照合する。
    consumed = fh.tell() - data_start - len(dec.unused_data)
    if flags & 0x8:
        tail = dec.unused_data + fh.read(24)
        if tail[:4] == struct.pack("<I", _DESCRIPTOR_SIG):
            tail = tail[4:]
        if len(tail) < 12:
            raise NotGzf("not-gzf", "missing data descriptor")
        d_crc, d_csize, d_usize = struct.unpack_from("<III", tail, 0)
    else:
        d_crc, d_csize, d_usize = crc, csize, usize
    if d_crc != running or d_usize != (produced & 0xFFFFFFFF):
        raise NotGzf("crc", "size or CRC mismatch")
    if d_csize != (consumed & 0xFFFFFFFF):
        raise NotGzf("not-gzf", "compressed size mismatch")
    fh.seek(0)
    return header


def is_regular(st) -> bool:
    return stat.S_ISREG(st.st_mode)
