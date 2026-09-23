"""dataset.py — 配布ZIPを「教材としてどう使うか」で解釈する層。

`archive.py` と `identify.py` が答えるのは「このファイルは安全か」であり、
ここが答えるのは「このファイルは教材の何にあたるか」である。この二つは
別物なので混ぜない。`challenge`（本番の問題ログ）は役割であって、危険度の
判定ではない。実際、問題ログの安全性判定は `opaque-encrypted` になる。

責務は四つ。

  1. 年度プロファイルの読み込み（`data/profiles/*.json`）
  2. メンバー名から年度を推定し、役割を割り当てる
  3. 同梱の案内文からパスワード候補を見つける（値は外へ出さない）
  4. 利用者の明示操作後に、暗号化された問題ログをメモリ上で読む

パスワードに関する不変条件（仕様書 12 章）:

  * 候補を見つけても自動では復号しない。呼び出し側の明示操作が要る。
  * 候補の値を返り値・API・DB・ログ・例外メッセージへ載せない。
  * 復号した内容をディスクへ書かない。パーサーへはメモリ上で渡す。
"""

from __future__ import annotations

import contextlib
import fnmatch
import io
import json
import os
import zipfile
import zlib
from dataclasses import dataclass, field

PROFILE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "profiles"
)

#: 教材上の役割。安全性の判定とは無関係。
ROLES = (
    "challenge",   # 本番の問題ログ
    "baseline",    # 平常時・サンプルログ
    "narrative",   # 問題文、説明、解説
    "tool",        # 同梱ツールとそのサンプル
    "artifact",    # 静的解析対象
    "unrelated",   # DFIR 以外
    "unknown",     # 判定不能
    "ignore",      # __MACOSX、AppleDouble など
)

#: 役割を当てる順序。先に当たったものを採用する。
#:
#: 順序そのものが仕様である。`tools/README.md` は `*/case/tools/*` にも
#: `*/case/*.md` にも当たるので、`tool` を `narrative` より先に見ないと
#: 同梱ツールの説明書が問題文として扱われる。同じ理由で `challenge` は
#: `narrative` より先、`ignore` はすべてより先に置く。
ROLE_PRECEDENCE = (
    "ignore",
    "tool",
    "challenge",
    "baseline",
    "artifact",
    "narrative",
    "unrelated",
)

#: 任意パターンのうちこれだけ当たらなければ、その年度と断定しない。
#: 必須パターンだけでは 別の版の ZIP も `*/case/*` に当たってしまう。
MIN_OPTIONAL_RATIO = 0.5

# ---- 読み取りの上限（仕様書 13.2） ---------------------------------------
MAX_LINE_BYTES = 64 * 1024          # 1 行
MAX_LOG_BYTES = 32 * 1024**2        # 1 ログの非圧縮読み取り量
MAX_TOTAL_BYTES = 128 * 1024**2     # 1 回の生成で読む合計
MAX_RECORDS = 500_000               # 1 ログの行数
MAX_CONTAINER_BYTES = 64 * 1024**2  # メモリへ載せる内側 ZIP の大きさ
MAX_HINT_BYTES = 100 * 1024         # パスワード案内として読むファイルの大きさ
MAX_PASSWORD_CANDIDATES = 8         # 総当たりにならないよう候補数を絞る
_READ_BLOCK = 64 * 1024             # 一度にメモリへ載せるバイト数


class DatasetError(Exception):
    """利用者へそのまま見せてよい、原因の分かる失敗。"""


class PasswordRequired(DatasetError):
    """暗号化されているが、使える鍵が渡されていない。"""


class PasswordRejected(DatasetError):
    """渡された候補がどれも合わなかった。値は決して含めない。"""


class UnsupportedEncryption(DatasetError):
    """AES など、標準ライブラリで読めない方式。"""


class ArchiveDamaged(DatasetError):
    """壊れている、または途中で読めなくなった。"""


class LimitExceeded(DatasetError):
    """上限に達したので読み切らずに止めた。"""


@dataclass
class Profile:
    id: str
    year: int
    label: str
    required: list[str]
    optional: list[str]
    roles: dict[str, list[str]]
    password_hints: list[str]
    parsers: list[str]

    @classmethod
    def from_json(cls, raw: dict) -> "Profile":
        match = raw.get("match") or {}
        return cls(
            id=str(raw["id"]),
            year=int(raw["year"]),
            label=str(raw.get("label") or raw["id"]),
            required=list(match.get("requiredPathPatterns") or []),
            optional=list(match.get("optionalNamePatterns") or []),
            roles={k: list(v) for k, v in (raw.get("roles") or {}).items()},
            password_hints=list(raw.get("passwordHintPatterns") or []),
            parsers=list(raw.get("parsers") or []),
        )


@dataclass
class Dataset:
    """1 つの ZIP を 教材として見た結果。"""

    profile: Profile | None
    year: int | None
    confidence: float
    #: メンバー名 -> 役割
    roles: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def generic(self) -> bool:
        """年度を断定できなかった（汎用 DFIR モード）。"""
        return self.profile is None

    def named(self, role: str) -> list[str]:
        """その役割を持つメンバー名を、名前順で返す。"""
        return sorted(n for n, r in self.roles.items() if r == role)


def load_profiles(directory: str = PROFILE_DIR) -> list[Profile]:
    """`data/profiles/*.json` を読む。壊れた 1 件で全体を止めない。"""
    out: list[Profile] = []
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return out
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(directory, name), encoding="utf-8") as fh:
                out.append(Profile.from_json(json.load(fh)))
        except (OSError, ValueError, KeyError):
            continue
    return out


def _matches_any(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, p) for p in patterns)


def _score(names: list[str], profile: Profile) -> float:
    """このプロファイルらしさ。必須が 1 つでも外れたら 0。"""
    for pattern in profile.required:
        if not any(fnmatch.fnmatchcase(n, pattern) for n in names):
            return 0.0
    if not profile.optional:
        return 1.0
    hit = sum(
        1 for p in profile.optional if any(fnmatch.fnmatchcase(n, p) for n in names)
    )
    return hit / len(profile.optional)


def classify(names: list[str], profile: Profile) -> dict[str, str]:
    """メンバー名へ役割を割り当てる。当たらないものは `unknown`。"""
    out: dict[str, str] = {}
    for name in names:
        role = "unknown"
        for candidate in ROLE_PRECEDENCE:
            if _matches_any(name, profile.roles.get(candidate, [])):
                role = candidate
                break
        out[name] = role
    return out


def _generic_roles(names: list[str]) -> dict[str, str]:
    """年度が分からないときの最小限の仕分け。

    問題ログを言い当てられないので `challenge` は付けない。当てずっぽうで
    `challenge` を付けると、まさに今回直している「平常時ログを本番ログとして
    教材化する」不具合に戻る。
    """
    out: dict[str, str] = {}
    for name in names:
        low = name.lower()
        if "__macosx" in low or "/._" in name or name.startswith("._"):
            out[name] = "ignore"
        elif low.endswith((".md", ".pdf", ".txt")):
            out[name] = "narrative"
        else:
            out[name] = "unknown"
    return out


class UnknownProfile(DatasetError):
    """利用者が指定したプロファイルが存在しない。"""


def detect(
    names: list[str],
    profiles: list[Profile] | None = None,
    force_id: str | None = None,
) -> Dataset:
    """メンバー名の一覧から年度と役割を決める。

    一致が弱ければ年度を断定せず、汎用モードとして返す。仕様書 11.2。

    `force_id` を渡すと自動判定を上書きする（仕様書 11.2「自動判定結果は
    利用者が変更できる」）。指定されたプロファイルは一致度に関わらず適用し、
    一致が弱いことは警告として添える。存在しない id は黙って自動判定へ
    落とさず、`UnknownProfile` として突き返す。取り違えたまま別の年度の規則
    で分類されるより、指定が通らなかったと分かるほうがよい。
    """
    profiles = load_profiles() if profiles is None else profiles

    if force_id and force_id != "auto":
        chosen = next((p for p in profiles if p.id == force_id), None)
        if chosen is None:
            raise UnknownProfile(f"指定されたプロファイル '{force_id}' は存在しません。")
        score = _score(names, chosen)
        warnings: list[str] = []
        if score < MIN_OPTIONAL_RATIO:
            warnings.append(
                f"{chosen.label} を指定されましたが、このZIPとの一致は弱いままです。"
            )
        roles = classify(names, chosen)
        if not any(r == "challenge" for r in roles.values()):
            warnings.append("本番の問題ログにあたるファイルが見つかりませんでした。")
        return Dataset(
            profile=chosen, year=chosen.year, confidence=score,
            roles=roles, warnings=warnings,
        )

    best: Profile | None = None
    best_score = 0.0
    for profile in profiles:
        score = _score(names, profile)
        if score > best_score:
            best, best_score = profile, score

    warnings: list[str] = []
    if best is None or best_score < MIN_OPTIONAL_RATIO:
        if best is not None:
            warnings.append(
                f"{best.label} の特徴が十分に揃っていないため、年度を断定しませんでした。"
            )
        return Dataset(
            profile=None, year=None, confidence=best_score,
            roles=_generic_roles(names), warnings=warnings,
        )

    roles = classify(names, best)
    if not any(r == "challenge" for r in roles.values()):
        warnings.append("本番の問題ログにあたるファイルが見つかりませんでした。")
    return Dataset(
        profile=best, year=best.year, confidence=best_score,
        roles=roles, warnings=warnings,
    )


# ---------------------------------------------------------------------------
# パスワード案内
# ---------------------------------------------------------------------------

_KEYWORDS = ("パスワード", "password")

#: コード表記・引用表記。案内文はこのいずれかで鍵を囲んでいる。
_QUOTE_PAIRS = (("`", "`"), ('"', '"'), ("'", "'"), ("「", "」"), ("“", "”"))


def _quoted_tokens(line: str) -> list[str]:
    """1 行から引用された短い字句を取り出す。"""
    out: list[str] = []
    for opener, closer in _QUOTE_PAIRS:
        start = 0
        while True:
            i = line.find(opener, start)
            if i < 0:
                break
            j = line.find(closer, i + len(opener))
            if j < 0:
                break
            token = line[i + len(opener):j]
            start = j + len(closer)
            if 3 < len(token) <= 128 and not any(c.isspace() for c in token):
                out.append(token)
    return out


def password_candidates_from_text(text: str) -> list[str]:
    """案内文からパスワード候補を拾う。重複は除き、出現順を保つ。

    同じ行に見出し語と引用表記の両方があることを求める。片方だけで拾うと、
    「ユーザ名edenのパスワードを答えよ」のような設問文や、その近くにある
    「フォーマット: `...`」を鍵と取り違える。
    """
    out: list[str] = []
    for line in text.splitlines():
        low = line.lower()
        if not any(k in low for k in _KEYWORDS):
            continue
        for token in _quoted_tokens(line):
            if token.lower() in _KEYWORDS:
                continue
            if token not in out:
                out.append(token)
    return out[:MAX_PASSWORD_CANDIDATES]


def _hint_patterns(dataset: Dataset) -> list[str]:
    if dataset.profile and dataset.profile.password_hints:
        return dataset.profile.password_hints
    return ["*.md", "*.txt", "*/*.md", "*/*.txt"]


def find_password_candidates(archive, dataset: Dataset) -> list[str]:
    """同梱の案内文から鍵の候補を集める。

    戻り値はメモリ上だけで扱うこと。API 応答・DB・ログへ載せてはならない。
    呼び出し側は「候補があるか」だけを外へ出す。
    """
    out: list[str] = []
    try:
        with _open_archive(archive) as zf:
            for info in zf.infolist():
                if info.is_dir() or info.file_size > MAX_HINT_BYTES:
                    continue
                name = _decoded_name(info)
                low = name.lower()
                if not low.endswith((".md", ".txt")):
                    continue
                if not _matches_any(name, _hint_patterns(dataset)):
                    continue
                if info.flag_bits & 0x1:
                    continue  # 案内文自体が暗号化されていることは想定しない
                try:
                    raw = zf.open(info).read(MAX_HINT_BYTES)
                except (OSError, RuntimeError, zipfile.BadZipFile, ValueError,
                        zlib.error, EOFError):
                    continue
                for cand in password_candidates_from_text(
                    raw.decode("utf-8", "replace")
                ):
                    if cand not in out:
                        out.append(cand)
    except (OSError, zipfile.BadZipFile):
        return out
    return out[:MAX_PASSWORD_CANDIDATES]


# ---------------------------------------------------------------------------
# 暗号化されたログの読み取り
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _open_archive(archive):
    """パスでも、開いてあるファイルでも同じように扱う。

    API 側は「ハッシュ照合した記述子」をそのまま渡してくる。照合したパスを
    閉じてから開き直すと、その隙に差し替えられる余地が残るため。ZipFile は
    渡されたファイルを自分では閉じないので、ここでも閉じない。
    """
    if isinstance(archive, zipfile.ZipFile):
        yield archive
        return
    if isinstance(archive, str):
        with zipfile.ZipFile(archive) as zf:
            yield zf
        return
    archive.seek(0)
    with zipfile.ZipFile(archive) as zf:
        yield zf


def _decoded_name(info: zipfile.ZipInfo) -> str:
    # archive.py と同じ復号規則を使う。info.filename をそのまま使うと
    # CP932 の名前が cp437 で文字化けし、パターンが当たらなくなる。
    from archive import decode_name, raw_name_bytes

    name, _enc = decode_name(raw_name_bytes(info), bool(info.flag_bits & 0x800))
    return name


def _is_aes(info: zipfile.ZipInfo) -> bool:
    """AES 暗号化（WinZip 仕様）か。標準ライブラリでは読めない。"""
    if info.compress_type == 99:
        return True
    extra = info.extra or b""
    i = 0
    while i + 4 <= len(extra):
        header = int.from_bytes(extra[i:i + 2], "little")
        size = int.from_bytes(extra[i + 2:i + 4], "little")
        if header == 0x9901:
            return True
        i += 4 + size
    return False


@dataclass
class LogSource:
    """読み取れた 1 本のログ。"""

    name: str        # 表示用のメンバー名（親 :: 子）
    text: str
    lines: int
    truncated: bool


@dataclass
class ReadResult:
    sources: list[LogSource] = field(default_factory=list)
    failures: list[dict] = field(default_factory=list)
    truncated: bool = False

    @property
    def as_mapping(self) -> dict[str, str]:
        """`explain.build_lesson` が受け取る形。名前順で決定的に並べる。"""
        return {s.name: s.text for s in sorted(self.sources, key=lambda s: s.name)}


@dataclass
class _Read:
    """`_read_stream` の結果。

    `kept` と `consumed` は別物である。上限は「返した量」ではなく「実際に
    展開した量」に掛けなければならない。読み捨てたバイトも CPU と伸長を
    消費しているし、ZIP Bomb が狙うのはまさにそこだから。
    """

    text: str
    lines: int
    truncated: bool
    consumed: int   # 実際に展開したバイト数（読み捨てた分を含む）
    eof: bool       # メンバーの終端まで読み切ったか


class _Budget:
    """1 リクエストで展開してよい総量。

    数える対象は「採用した分」ではなく「展開した分すべて」である。誤った鍵で
    途中まで伸長した分、CRC を確かめられずに捨てた分、壊れていて読めなかった
    分も、CPU と伸長を実際に使っている。成功した読み取りだけを引いていた頃は、
    読めない問題ログを並べるだけで合計上限をいくらでも超えられた。鍵の候補数
    には上限があるが、問題ログの本数には無いので、候補を絞るだけでは保証に
    ならない。

    引き方は「先に予約し、余りを戻す」である。読む前に 1 ブロック分を `take`
    し、読み終えてから実際に読まなかった分を `refund` する。`fh.read()` の中
    で復号と伸長が起きるため、読んだ「あと」に引く書き方では、そこで
    zlib.error などが飛んだときに費やした処理が誰にも数えられないまま次の鍵
    候補へ進んでしまう。実際の消費量は取れないので、多めに取って成功時に戻す
    ほうを選んでいる。例外が飛んだ場合は予約したまま返さない。

    上限の効き方は「1 リクエストにつき、予算＋最大 1 ブロック（64 KB）」で
    ある。予約は読み取りの直前に行い、次のブロックへ進む前に残量を見るので、
    超過し得るのは進行中の 1 ブロックだけになる。なお、これは 1 リクエストの
    中での保証である。HTTP リクエストを同時に処理した場合、プロセス全体の
    消費量はリクエストごとの予算の合計になる。
    """

    __slots__ = ("remaining",)

    def __init__(self, total: int):
        self.remaining = total

    def take(self, n: int) -> None:
        self.remaining -= n

    def refund(self, n: int) -> None:
        """予約したが使わなかった分を戻す。"""
        self.remaining += n

    @property
    def exhausted(self) -> bool:
        return self.remaining <= 0


def _read_stream(fh, budget: int, shared: "_Budget | None" = None) -> _Read:
    """メンバーを読む。ディスクへ書かず、メモリも上限内に収める。

    バイト列を固定長の塊で取り出し、自分で改行を探す。`TextIOWrapper` を
    行単位で回す書き方では上限が守れない。改行の無い入力に対しては、切り詰め
    る前に行全体をメモリへ載せてしまうためで、実測でも予算 1 バイトに対して
    改行なし 5 MB の入力でピーク約 10.5 MB になった。MAX_LINE_BYTES を超えた
    分はここで読み捨て、次の改行まで飛ばす。

    抱えるのは「現在の行の先頭 MAX_LINE_BYTES まで」と「読み取り塊 1 個」
    だけなので、ピークは入力の大きさに関係なく一定になる。

    総量については、最初の 1 行だけ予算を超えても返す。ここで空を返すと、
    呼び出し側の「復号できたのに中身が空＝鍵違い」という判定が誤作動し、
    正しいパスワードを不一致として突き返してしまうため。1 行は
    MAX_LINE_BYTES で頭打ちなので、超過はそれ以下に限られる。

    `budget` はこのメンバー 1 本に許す量、`shared` はリクエスト全体で共有する
    `_Budget`。`shared` へは、1 ブロック読む前に `_READ_BLOCK` を予約し、
    読み終えてから読まなかった分を戻す。読んだ「あと」に引くと、`fh.read()`
    の中の復号・伸長で例外が飛んだときに消費が記録されないまま抜けてしまう。
    """
    out: list[str] = []
    lines = 0
    total = 0
    truncated = False
    pending = bytearray()   # 現在の行の、まだ改行が来ていない部分
    dropping = False        # この行は長すぎる。次の改行まで読み捨てる

    def flush() -> bool:
        """pending を 1 行として確定する。読み続けてよければ True。"""
        nonlocal lines, total, truncated
        raw = bytes(pending)
        pending.clear()
        if lines >= MAX_RECORDS:
            truncated = True
            return False
        if total and total + len(raw) > budget:
            truncated = True
            return False
        out.append(raw.decode("utf-8", "replace"))
        total += len(raw)
        lines += 1
        return True

    consumed = 0
    eof = False
    while True:
        # 実際に展開した量で止める。読み捨てた分を数えないと、改行の無い
        # 巨大メンバーを最後まで伸張してしまい、メモリは一定でも CPU と
        # 展開量が青天井になる（ZIP Bomb が狙うのはここ）。
        if consumed >= budget or (shared is not None and shared.exhausted):
            truncated = True
            break
        # 1 ブロック分を「先に」予約してから読む。fh.read() の中で復号と伸長
        # が起きるので、そこで zlib.error などが飛ぶと、費やした処理は誰にも
        # 数えられないまま次の鍵候補へ進んでしまう。実際の消費量は取れない
        # ので、多めに取って成功時に戻す。安全側に倒すほうを選ぶ。
        if shared is not None:
            shared.take(_READ_BLOCK)
        block = fh.read(_READ_BLOCK)
        if shared is not None:
            shared.refund(_READ_BLOCK - len(block))
        if not block:
            eof = True
            break
        consumed += len(block)
        pos = 0
        while pos < len(block):
            nl = block.find(b"\n", pos)
            end = len(block) if nl < 0 else nl + 1
            segment = block[pos:end]
            pos = end
            if not dropping:
                room = MAX_LINE_BYTES - len(pending)
                if len(segment) > room:
                    pending += segment[:room]
                    dropping = True
                    truncated = True
                else:
                    pending += segment
            if nl >= 0:
                if dropping:
                    # 切り詰めた分と一緒に行末の改行まで捨ててしまうと、この行
                    # と次の行が地続きになり、パーサーが 1 行として読む。境界
                    # だけは戻す。MAX_LINE_BYTES は中身に対する上限とする。
                    pending += b"\n"
                dropping = False
                if not flush():
                    return _Read("".join(out), lines, True, consumed, eof)

    if pending:
        flush()
    return _Read("".join(out), lines, truncated, consumed, eof)


def read_logs(
    archive,
    dataset: Dataset,
    role: str,
    passwords: list[str] | None = None,
) -> ReadResult:
    """その役割のログを読む。復号した内容はメモリ上にしか置かない。

    `passwords` は候補の並び。暗号化メンバーごとに順に試し、最初に通った
    ものを以降でも使う。候補は同梱の案内文か利用者の手入力から来た数個で、
    総当たりではない。失敗しても値は記録しない。
    """
    wanted = set(dataset.named(role))
    if not wanted:
        return ReadResult()

    # 親 ZIP 名 -> その中で読みたい子の名前
    containers: dict[str, set[str]] = {}
    direct: set[str] = set()
    for name in wanted:
        if " :: " in name:
            parent, child = name.split(" :: ", 1)
            containers.setdefault(parent, set()).add(child)
        elif name.lower().endswith(".zip"):
            # 役割としては問題ログだが、それ自体は入れ物。子が列挙できて
            # いれば上の枝で登録される。列挙に失敗した（壊れている、上限を
            # 超えた）場合はここだけが残るので、黙って飛ばさず開きにいく。
            # 空集合は「中の .log をすべて」を意味する。
            containers.setdefault(name, set())
        else:
            direct.add(name)

    result = ReadResult()
    budget = _Budget(MAX_TOTAL_BYTES)
    tried = list(passwords or [])
    working: bytes | None = None

    try:
        opener = _open_archive(archive)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ArchiveDamaged("ZIPファイルを開けませんでした。") from exc

    with opener as outer:
        by_name = {_decoded_name(i): i for i in outer.infolist() if not i.is_dir()}

        # 直下のログ（暗号化されていない年度向け）
        for name in sorted(direct):
            info = by_name.get(name)
            if info is None or not name.lower().endswith(".log"):
                continue
            working = _read_one(outer, info, name, result, budget, tried, working)

        # 内側 ZIP の中のログ
        for parent in sorted(containers):
            info = by_name.get(parent)
            if info is None:
                continue
            if info.file_size > MAX_CONTAINER_BYTES:
                result.failures.append(
                    {"name": parent, "reason": "container-too-large",
                     "detail": "内側の圧縮ファイルが大きすぎるため読み取りませんでした。"}
                )
                result.truncated = True
                continue

            # 予算の確認は、読む「前」に済ませる。
            #
            # 内側 ZIP は中央ディレクトリが末尾にあるため、部分読みでは
            # ZipFile として使えない。つまり全体を載せるか、載せないかの二択
            # になる。以前は読み終えてから引いていたので、1 バイトしか残って
            # いなくても 1 個まるごと読めてしまい、しかも次の入れ物へ進んで
            # いた。実測では予算 1 に対して 100 KB の内側 ZIP を 2 個読み、
            # 残量が -200,215 まで落ちた。入れ物を並べるだけで上限を何倍にも
            # できる状態だったので、残りに収まらないものは読まずに断る。
            if budget.exhausted:
                result.failures.append(
                    {"name": parent, "reason": "budget",
                     "detail": "合計の読み取り上限に達しました。"}
                )
                result.truncated = True
                continue
            if info.file_size > budget.remaining:
                result.failures.append(
                    {"name": parent, "reason": "limit-exceeded",
                     "detail": "残りの読み取り上限に収まらないため読み取りませんでした。"}
                )
                result.truncated = True
                continue

            try:
                # 先に予約してから読む。読み取り中に例外が飛んでも、消費した
                # 分が無かったことにならないようにする。
                budget.take(info.file_size)
                blob = outer.open(info).read(MAX_CONTAINER_BYTES + 1)
                budget.refund(max(0, info.file_size - len(blob)))
                inner = zipfile.ZipFile(io.BytesIO(blob))
            except (OSError, RuntimeError, zipfile.BadZipFile, ValueError,
                    zlib.error, EOFError):
                # 理由は固定文にする。例外文をそのまま返すと、鍵に由来する
                # 文字列が紛れ込む余地を残してしまう。
                result.failures.append(
                    {"name": parent, "reason": "damaged",
                     "detail": "圧縮ファイルを読み取れませんでした。"}
                )
                continue
            with inner:
                inner_by_name = {
                    _decoded_name(i): i for i in inner.infolist() if not i.is_dir()
                }
                children = containers[parent]
                if not children:
                    children = {
                        n for n in inner_by_name if n.lower().endswith(".log")
                    }
                for child in sorted(children):
                    child_info = inner_by_name.get(child)
                    display = f"{parent} :: {child}"
                    if child_info is None:
                        continue
                    working = _read_one(
                        inner, child_info, display, result, budget, tried, working
                    )
    return result


def _read_one(zf, info, display, result, budget, candidates, working):
    """1 メンバーを読む。「通った鍵」を返す。

    `budget` はリクエスト全体で共有する `_Budget`。ここで試した読み取りは、
    採用したかどうかに関わらずすべてそこから引かれる。引くのは `_read_stream`
    側で、1 ブロック読む前に予約し、読み終えてから余りを戻す方式による。
    途中で例外が飛んだ試行も、予約した分は消費したままになる。

    例外文へ鍵を載せないため、失敗理由は固定の文言だけを積む。
    """
    if budget.exhausted:
        result.failures.append(
            {"name": display, "reason": "budget",
             "detail": "合計の読み取り上限に達しました。"}
        )
        result.truncated = True
        return working

    if _is_aes(info):
        result.failures.append(
            {"name": display, "reason": "unsupported-encryption",
             "detail": "AES 方式で暗号化されているため、この環境では読み取れません。"}
        )
        return working

    encrypted = bool(info.flag_bits & 0x1)
    if encrypted and not candidates and working is None:
        result.failures.append(
            {"name": display, "reason": "password-required",
             "detail": "暗号化されています。パスワードが必要です。"}
        )
        return working

    # 通った鍵を先に試す。毎回すべての候補を試し直さないため。
    order: list[bytes | None] = []
    if not encrypted:
        order = [None]
    else:
        if working is not None:
            order.append(working)
        order += [c.encode("utf-8") for c in candidates if c.encode("utf-8") != working]

    unverifiable = False
    for pwd in order:
        if budget.exhausted:
            # 候補を試すたびに展開している。残りが無くなったらそこで止める。
            result.failures.append(
                {"name": display, "reason": "budget",
                 "detail": "合計の読み取り上限に達しました。"}
            )
            result.truncated = True
            return working
        # 1 ログの上限と、リクエスト全体の残りの小さいほう。
        limit = max(0, min(budget.remaining, MAX_LOG_BYTES))
        try:
            with zf.open(info, pwd=pwd) as fh:
                got = _read_stream(fh, limit, budget)
        except RuntimeError:
            # 鍵違い。値は記録しない。
            continue
        except (zipfile.BadZipFile, OSError, ValueError, EOFError, zlib.error):
            # ここが鍵の本当の検査になる。ZipCrypto のヘッダ検査は 1 バイト
            # しか見ないので誤った鍵でも 256 回に 1 回ほど通るが、終端まで
            # 読めば zipfile が CRC-32 を照合し BadZipFile を投げる。伸長を
            # 伴う場合は zlib が先に音を上げる。値は記録しない。
            #
            # ここまでに展開した分は `_read_stream` が共有予算から引き済み。
            continue

        if encrypted and not got.eof:
            # 終端まで読めなかった＝ CRC を照合できていない。ZipCrypto の
            # 検査バイトを偶然通った誤鍵は、ここで非空のゴミを返す。それを
            # 採用すると、復号に失敗したバイト列を「本番の問題ログ」として
            # 教材化してしまう。読めないほうがまだ安全なので採用しない。
            unverifiable = True
            break

        if encrypted and not _looks_like_text(got.text):
            # CRC を通ったうえでの保険。まともな鍵なら通る。
            continue

        result.sources.append(
            LogSource(
                name=display, text=got.text, lines=got.lines, truncated=got.truncated
            )
        )
        if got.truncated:
            result.truncated = True
        return pwd if encrypted else working

    if unverifiable:
        result.failures.append(
            {"name": display, "reason": "limit-exceeded",
             "detail": "上限内では最後まで読めず、内容の正しさを確認できませんでした。"}
        )
        result.truncated = True
        return working

    result.failures.append(
        {"name": display,
         "reason": "password-rejected" if encrypted else "damaged",
         "detail": ("パスワードが合いませんでした。" if encrypted
                    else "読み取れませんでした。")}
    )
    return working


def _looks_like_text(text: str) -> bool:
    """復号結果が文字として読めるか。CRC 照合に続く二段目の確認。

    誤った鍵の出力はバイト列として無作為なので、UTF-8 として解釈すると
    置換文字だらけになる。閾値は緩くしてある（本物のログにも文字化けは
    混ざりうる）が、ゴミを弾くには十分。
    """
    if not text.strip():
        return False
    sample = text[:4096]
    bad = sample.count("�") + sum(
        1 for c in sample if c < " " and c not in "\t\r\n"
    )
    return bad <= len(sample) * 0.15


def summarise(dataset: Dataset, member_rows: list[dict]) -> dict:
    """API へ出す形。パスワード候補の値は決して含めない。"""
    counts: dict[str, int] = {r: 0 for r in ROLES}
    encrypted_challenge = 0
    by_role: dict[str, list[dict]] = {r: [] for r in ROLES}
    for row in member_rows:
        name = row.get("name", "")
        role = dataset.roles.get(name, "unknown")
        counts[role] = counts.get(role, 0) + 1
        if role == "ignore":
            continue
        entry = {
            "name": name,
            "size": row.get("size", 0),
            "verdict": row.get("verdict", ""),
            "encrypted": row.get("verdict") == "opaque-encrypted",
        }
        if entry["encrypted"] and role == "challenge":
            encrypted_challenge += 1
        by_role[role].append(entry)
    return {
        "year": dataset.year,
        "profile": (dataset.profile.id if dataset.profile else None),
        "label": (dataset.profile.label if dataset.profile else "年度不明（汎用DFIRモード）"),
        "confidence": round(dataset.confidence, 3),
        "generic": dataset.generic,
        "parsers": (dataset.profile.parsers if dataset.profile else []),
        "counts": counts,
        "members": by_role,
        "encryptedChallenge": encrypted_challenge,
        "warnings": list(dataset.warnings),
    }
