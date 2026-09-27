"""ghidra_intake.py — GZF を 1 件だけ、ジョブ専用の場所へ上限付きで写す。

入口は二つ。どちらも書き出し先の名前はアプリが決めた固定名
（`<job>/input/input.gzf`）で、利用者やアーカイブ由来の名前はパスに使わない。

  * ブラウザからの送信（`receive_upload`）。宣言された長さ・実際に読んだ量・
    受信時間に上限を置き、全体をメモリへは載せない。
  * 登録済み ZIP の 1 メンバー（`copy_member`）。`extractall` は使わず、
    manifest に記録した位置のメンバーだけを開く。入れ子は 1 段まで。
    暗号化（ZipCrypto）はメモリ内のパスワードで読み、AES は断る。CRC は
    最後まで読んだ時点で `zipfile` が照合する。外側・内側を合わせた読み取り
    量は共有の予算で縛る。

既存の `h_materialize` の保管庫（中身が安全と判定できたものだけを書く場所）
とは別の、GZF 専用の隔離領域である。ここに書いたものは抽出が終われば消える。
"""

from __future__ import annotations

import errno
import hashlib
import io
import os
import stat
import time
import zipfile

import gzf
from archive import decode_name, raw_name_bytes

CHUNK = 64 * 1024
#: ブラウザからの受信にかけてよい時間。
RECEIVE_SECONDS = 120
#: ZIP から取り出すときに読んでよい合計（外側の入れ子 ZIP を含む）。
ARCHIVE_BUDGET = 192 * 1024**2
#: メモリへ載せる入れ子 ZIP の大きさ。
MAX_NESTED_BYTES = 64 * 1024**2
MAX_PASSWORD = 256
_AES = 99


class IntakeError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _create(dest: str) -> int:
    # 既存のものを上書きしない。途中にリンクを置かれても辿らない。
    return os.open(dest, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        try:
            n = os.write(fd, view)
        except OSError as exc:
            if exc.errno == errno.ENOSPC:
                raise IntakeError("disk-full") from None
            raise
        view = view[n:]


def receive_upload(rfile, length: int, dest: str, *, cancel, deadline: float,
                   clock=time.monotonic, set_timeout=None) -> tuple[str, int]:
    """要求本文をちょうど `length` バイト読み、dest へ書く。(sha256, 大きさ)。

    受信時間の上限とキャンセルは、読み取りの途中でも効かせる。

      * `read1` を使う。`read(n)` は n バイトそろうまで受信を繰り返すので、
        少しずつ送られると、1 回の呼び出しがいつまでも戻らない（接続の
        タイムアウトは 1 回の受信ごとにしか効かない）。`read1` は届いた分
        だけで戻るので、そのたびに期限とキャンセルを確かめられる。
      * `set_timeout` があれば、読む前に接続のタイムアウトを残り時間に
        合わせる。何も届かないまま待ち続けても、総期限で必ず戻る。
      * キャンセルは、呼び出し側が接続の受信を止める（shutdown）ことで、
        待っている読み取りを終わらせる。ここでは終わった理由を見分ける。
    """
    if not 0 < length <= gzf.MAX_GZF_BYTES:
        raise IntakeError("too-large" if length > 0 else "empty")
    read = getattr(rfile, "read1", None) or rfile.read
    digest = hashlib.sha256()
    fd = _create(dest)
    got = 0
    try:
        while got < length:
            if cancel.is_set():
                raise IntakeError("cancelled")
            remaining = deadline - clock()
            if remaining <= 0:
                raise IntakeError("upload-timeout")
            if set_timeout is not None:
                set_timeout(remaining)
            try:
                chunk = read(min(CHUNK, length - got))
            except (TimeoutError, OSError, ValueError):
                if cancel.is_set():
                    raise IntakeError("cancelled") from None
                if clock() >= deadline:
                    raise IntakeError("upload-timeout") from None
                raise IntakeError("upload-incomplete") from None
            if not chunk:
                if cancel.is_set():
                    raise IntakeError("cancelled")
                raise IntakeError("upload-incomplete")
            digest.update(chunk)
            _write_all(fd, chunk)
            got += len(chunk)
    finally:
        os.close(fd)
    return digest.hexdigest(), got


def check_copy(path: str) -> gzf.GzfHeader:
    """写し終えたファイルを、GZF として中身から確かめる。"""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise gzf.NotGzf("not-gzf", "not a regular file")
        header = gzf.inspect_file(fh, st.st_size)
    # コンテナからは読み取り専用で渡す。こちらでも書き込み権を外しておく。
    os.chmod(path, 0o400)
    return header


# ---------------------------------------------------------------------------
# ZIP の 1 メンバー
# ---------------------------------------------------------------------------

def _name(info: zipfile.ZipInfo) -> str:
    return decode_name(raw_name_bytes(info), bool(info.flag_bits & 0x800))[0]


def _unsafe_name(name: str) -> bool:
    if name.startswith("/") or name.startswith("\\") or (len(name) > 1 and name[1] == ":"):
        return True
    if ".." in name.replace("\\", "/").split("/"):
        return True
    return any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in name) or any(
        c in name for c in "‪‫‬‭‮⁦⁧⁨⁩"
    )


def _check_info(info: zipfile.ZipInfo, name: str, limit: int) -> None:
    if info.is_dir():
        raise IntakeError("zip-member-missing")
    mode = (info.external_attr >> 16) & 0o170000
    if mode == stat.S_IFLNK:
        raise IntakeError("zip-symlink")
    if mode not in (0, stat.S_IFREG):
        raise IntakeError("zip-unsafe-name")
    if _unsafe_name(name):
        raise IntakeError("zip-unsafe-name")
    if info.compress_type == _AES:
        raise IntakeError("zip-aes")
    if info.file_size > limit:
        raise IntakeError("too-large")
    if info.file_size / max(info.compress_size, 1) > gzf.MAX_RATIO:
        raise IntakeError("ratio")


class _Budget:
    def __init__(self, total: int):
        self.left = total

    def take(self, n: int) -> None:
        self.left -= n
        if self.left < 0:
            raise IntakeError("budget")


def _stream(zf: zipfile.ZipFile, info: zipfile.ZipInfo, password: bytes | None,
            budget: _Budget, limit: int, cancel, sink) -> int:
    """1 メンバーを最後まで読み、sink へ渡す。CRC は最後の読み取りで照合される。"""
    encrypted = bool(info.flag_bits & 0x1)
    if encrypted and not password:
        raise IntakeError("password-required")
    total = 0
    try:
        with zf.open(info, pwd=password if encrypted else None) as src:
            while True:
                if cancel.is_set():
                    raise IntakeError("cancelled")
                chunk = src.read(CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit or total > info.file_size:
                    raise IntakeError("too-large")
                budget.take(len(chunk))
                sink(chunk)
    except IntakeError:
        raise
    except RuntimeError:
        # zipfile は、パスワードの照合バイトが合わないと RuntimeError を出す。
        raise IntakeError("password-rejected" if encrypted else "zip-damaged") from None
    except (zipfile.BadZipFile, EOFError, OSError, ValueError, NotImplementedError) as exc:
        text = str(exc)
        if "CRC" in text:
            # 暗号化されていると、照合バイトが偶然合った誤ったパスワードでも
            # ここに来る。区別できないので、パスワードの誤りとして案内する。
            raise IntakeError("password-rejected" if encrypted else "crc") from None
        raise IntakeError("password-rejected" if encrypted else "zip-damaged") from None
    except Exception:  # noqa: BLE001 - zlib.error など。展開できないものは断る
        raise IntakeError("password-rejected" if encrypted else "zip-damaged") from None
    if total != info.file_size:
        raise IntakeError("zip-damaged")
    return total


def locate(zf: zipfile.ZipFile, member: dict) -> tuple[zipfile.ZipInfo | None, str, str]:
    """manifest の 1 行から、外側の ZipInfo を探す。

    戻り値は (外側の info, 外側で見つかった名前, 内側の名前)。入れ子でない
    メンバーでは内側の名前は空。
    """
    name = member.get("name") or ""
    container = member.get("container") or ""
    infos = zf.infolist()
    if not container:
        try:
            info = infos[int(member["idx"])]
        except (IndexError, KeyError, ValueError, TypeError):
            raise IntakeError("zip-member-missing") from None
        if _name(info) != name:
            raise IntakeError("zip-member-changed")
        return info, name, ""
    # 入れ子は 1 段まで。記録上の名前は「外側 :: 内側」の形。
    if name.count(" :: ") != 1 or not name.startswith(container + " :: "):
        raise IntakeError("zip-nested-too-deep")
    inner = name[len(container) + 4:]
    matches = [i for i in infos if not i.is_dir() and _name(i) == container]
    if len(matches) != 1:
        # 同名の入れ子 ZIP が複数あると、どれの中身か決められない。
        raise IntakeError("zip-ambiguous")
    return matches[0], container, inner


def copy_member(archive_fh, member: dict, dest: str, *, password: str | None,
                cancel) -> tuple[str, int]:
    """登録済み ZIP の 1 メンバー（入れ子 1 段まで）を dest へ写す。(sha256, 大きさ)。

    `archive_fh` は呼び出し側がハッシュを照合済みの記述子。パスワードは
    この呼び出しの間だけ使い、保存も記録もしない。
    """
    pwd = password.encode("utf-8") if password else None
    if pwd is not None and len(pwd) > MAX_PASSWORD:
        raise IntakeError("password-rejected")
    budget = _Budget(ARCHIVE_BUDGET)
    try:
        outer = zipfile.ZipFile(archive_fh)
    except (zipfile.BadZipFile, OSError, ValueError, EOFError) as exc:
        raise IntakeError("zip-damaged") from exc
    with outer:
        info, outer_name, inner_name = locate(outer, member)
        if not inner_name:
            _check_info(info, outer_name, gzf.MAX_GZF_BYTES)
            return _copy_to(outer, info, dest, pwd, budget, cancel)

        _check_info(info, outer_name, MAX_NESTED_BYTES)
        blob = bytearray()
        _stream(outer, info, pwd, budget, MAX_NESTED_BYTES, cancel, blob.extend)
        try:
            inner_zf = zipfile.ZipFile(io.BytesIO(bytes(blob)))
        except (zipfile.BadZipFile, OSError, ValueError, EOFError) as exc:
            raise IntakeError("zip-damaged") from exc
        with inner_zf:
            infos = inner_zf.infolist()
            try:
                inner = infos[int(member["idx"])]
            except (IndexError, KeyError, ValueError, TypeError):
                raise IntakeError("zip-member-missing") from None
            if _name(inner) != inner_name:
                raise IntakeError("zip-member-changed")
            _check_info(inner, inner_name, gzf.MAX_GZF_BYTES)
            return _copy_to(inner_zf, inner, dest, pwd, budget, cancel)


def _copy_to(zf, info, dest, pwd, budget, cancel) -> tuple[str, int]:
    digest = hashlib.sha256()
    fd = _create(dest)
    try:
        def sink(chunk: bytes) -> None:
            digest.update(chunk)
            _write_all(fd, chunk)
        size = _stream(zf, info, pwd, budget, gzf.MAX_GZF_BYTES, cancel, sink)
    finally:
        os.close(fd)
    return digest.hexdigest(), size
