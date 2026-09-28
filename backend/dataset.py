"""dataset.py — 読み込んだ ZIP を「教材としてどう使うか」で解釈する層。

`archive.py` と `identify.py` が答えるのは「このファイルは安全か」であり、
ここが答えるのは「このファイルは教材の何にあたるか」である。この二つは
別物なので混ぜない。`challenge`（本番の問題ログ）は役割であって、危険度の
判定ではない。実際、暗号化された問題ログの安全性判定は `opaque-encrypted`
になる。

責務は四つ。

  1. データセット形式のプロファイルの読み込みと検証
     （標準の `data/profiles/` と、起動時に指定された外部フォルダ）
  2. メンバー名からプロファイルを推定し、役割を割り当てる
  3. 同梱の案内文からパスワード候補を見つける（値は外へ出さない）
  4. 利用者の明示操作後に、暗号化された問題ログをメモリ上で読む

特定のデータセットの名前や ZIP の構造は、このファイルに書かない。それは
プロファイル（JSON）が宣言する。プロファイルが 1 件も無くても、汎用解析
（プロファイル未特定）として動く。

パスワードに関する不変条件:

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
import re
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass, field

import parsers
from evidence import visible

#: 標準で読み込むプロファイルのフォルダ。公開版は空で配布する。
BUILTIN_PROFILE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "profiles"
)

#: 教材上の役割。安全性の判定とは無関係。
ROLES = (
    "challenge",   # 本番の問題ログ
    "baseline",    # 平常時・サンプルログ
    "narrative",   # 問題文、説明、解説
    "tool",        # 同梱ツールとそのサンプル
    "artifact",    # 静的解析対象
    "unrelated",   # 教材の対象外
    "unknown",     # 判定不能
    "ignore",      # __MACOSX、AppleDouble など
)

#: 役割を当てる順序。先に当たったものを採用する。
#:
#: 順序そのものが仕様である。`tools/README.md` は `*/tools/*` にも `*/*.md`
#: にも当たりうるので、`tool` を `narrative` より先に見ないと同梱ツールの
#: 説明書が問題文として扱われる。同じ理由で `challenge` は `narrative` より
#: 先、`ignore` はすべてより先に置く。
ROLE_PRECEDENCE = (
    "ignore",
    "tool",
    "challenge",
    "baseline",
    "artifact",
    "narrative",
    "unrelated",
)

#: 任意パターンのうちこれだけ当たらなければ、そのプロファイルと断定しない。
#: 構造の似たデータセットは必須パターンだけなら互いに当たってしまうので、
#: 固有の名前（任意パターン）がどれだけ揃うかで絞る。
MIN_OPTIONAL_RATIO = 0.5

#: 首位が 2 つ以上並んだとき、どれか 1 つを選ぶために必要な差。
#:
#: 複数のプロファイルを同時に読み込むと「同点の首位」が起こりうる。以前の
#: 実装は `score > best_score` だったので、同点ならファイル名の若いほうが
#: 黙って勝っていた。プロファイルの取り違えをファイル名の並びで決めるのは、
#: 当たっているときでも理由が説明できない。同点は「どちらとも断定しない」
#: = 汎用解析として扱い、候補名を警告に出す。
MIN_LEAD = 1e-9

#: 多重 ZIP をいくつまで潜るか。`archive.MAX_DEPTH` と同じ値にする。
#: ここを緩めると走査側と読み取り側で見える範囲が食い違う。
MAX_CONTAINER_DEPTH = 3

#: 丸ごと 1 個がパスワードそのものである案内ファイルの上限。
#: この形の案内は、ふつう数十バイト程度の 1 行である。
MAX_PASSWORD_FILE_BYTES = 1024

#: パスワード案内を探すために開いてよい内側 ZIP の個数。
#: 案内文が 1 階層内側にあるデータセットのための経路で、
#: 「見つからないから手当たり次第に開く」にならないよう数で止める。
MAX_HINT_CONTAINERS = 4

#: プロファイル JSON 1 件の大きさの上限。パターンと役割しか書かないので、
#: これを超えるものは誤って別のファイルを置いたと見なす。
MAX_PROFILE_BYTES = 256 * 1024

#: プロファイル ID の形。API の `profileId` と同じにする。これ以外の ID は
#: 画面から指定できないので、読み込みの時点で拒否する。
PROFILE_ID = r"[A-Za-z0-9_-]{1,64}"

#: プロファイルが特定できなかったときの表示名。
GENERIC_LABEL = "プロファイル未特定（汎用解析）"

# ---- 読み取りの上限。達したら truncated として教材と画面に明示する ----------
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


class ProfileError(DatasetError):
    """読み込めない・不正なプロファイル。黙って捨てず、理由を添えて報告する。

    `source` はファイル名（またはフォルダ名）だけにする。中身を引用しない。
    プロファイルの値は利用者のものだが、API 応答や画面に原文を流すと、
    壊れた JSON の断片まで表に出ることになる。
    """

    def __init__(self, source: str, reason: str) -> None:
        super().__init__(f"{source}: {reason}")
        self.source = source
        self.reason = reason

    def as_json(self) -> dict:
        return {"source": self.source, "reason": self.reason}


class _Invalid(ValueError):
    """プロファイルの中身が契約に合わない。読み込み側でファイル名を添える。"""


_PROFILE_ID = re.compile(PROFILE_ID)

#: プロファイルに書いてよい項目。これ以外は拒否する。綴りを間違えた項目を
#: 黙って無視すると、「書いたのに効かない」が起きて原因が分からない。
_PROFILE_FIELDS = frozenset({
    "id", "label", "edition", "metadata", "order",
    "match", "roles", "parsers", "unsupportedFormats",
    "passwordHintPatterns", "passwordFilePatterns", "passwordHintContainerPatterns",
})
_MATCH_FIELDS = frozenset({"requiredPathPatterns", "optionalNamePatterns"})
_UNSUPPORTED_FIELDS = frozenset({"label", "detail", "patterns"})
#: プロファイルが割り当てられる役割。`unknown` は「当たらなかった」ときの
#: 既定値なので、宣言するものではない。
_ASSIGNABLE_ROLES = tuple(r for r in ROLES if r != "unknown")

_MAX_TEXT = 200
_MAX_PATTERNS = 200
_MAX_PATTERN = 300
_MAX_METADATA = 16
_MAX_META_KEY = 64
_MAX_META_VALUE = 500


def _keys(names) -> str:
    """未知の項目名を、表示してよい形で並べる。値は決して含めない。

    項目名は利用者のファイルから来るので、制御文字や表示順を入れ替える
    文字が入りうる。端末と画面へ出る前に、見える形へ置き換える。
    """
    return ", ".join(visible(str(n)[:40], 40) for n in list(names)[:5])


def _text(raw: dict, key: str, required: bool = False, limit: int = _MAX_TEXT) -> str:
    value = raw.get(key)
    if value is None:
        if required:
            raise _Invalid(f"'{key}' は必須です。")
        return ""
    if not isinstance(value, str):
        raise _Invalid(f"'{key}' は文字列で書きます。")
    value = value.strip()
    if required and not value:
        raise _Invalid(f"'{key}' が空です。")
    if len(value) > limit:
        raise _Invalid(f"'{key}' が長すぎます（{limit} 文字まで）。")
    return value


def _patterns(value, where: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise _Invalid(f"'{where}' はパターンの配列で書きます。")
    if len(value) > _MAX_PATTERNS:
        raise _Invalid(f"'{where}' のパターンが多すぎます（{_MAX_PATTERNS} 個まで）。")
    out = []
    for item in value:
        if not isinstance(item, str) or not item or len(item) > _MAX_PATTERN:
            raise _Invalid(
                f"'{where}' の各パターンは 1〜{_MAX_PATTERN} 文字の文字列で書きます。"
            )
        out.append(item)
    return out


@dataclass
class Unsupported:
    """分類はできたが、専用の解析を持っていないログ形式。

    「無視した」とも「読めなかった」とも違う、三つめの状態である。役割と
    しては `challenge` のままにし、教材の材料からは外し、理由を添えて利用者へ
    見せる。黙って落とすと、9 本あるはずの問題ログが 7 本で「完成」した
    ように見える。
    """

    label: str        # 「Web サーバーのアクセスログ」など
    detail: str       # なぜ教材にできないか
    patterns: list[str]

    @classmethod
    def from_json(cls, raw) -> "Unsupported":
        if not isinstance(raw, dict):
            raise _Invalid("'unsupportedFormats' の各要素はオブジェクトで書きます。")
        extra = sorted(set(raw) - _UNSUPPORTED_FIELDS)
        if extra:
            raise _Invalid(f"'unsupportedFormats' に未知の項目があります: {_keys(extra)}")
        patterns = _patterns(raw.get("patterns"), "unsupportedFormats.patterns")
        if not patterns:
            raise _Invalid("'unsupportedFormats' の各要素には patterns が必要です。")
        return cls(
            label=_text(raw, "label") or "未対応のログ形式",
            detail=_text(raw, "detail", limit=1000) or "専用の解析に対応していません。",
            patterns=patterns,
        )


@dataclass
class Profile:
    """データセット形式 1 つぶんの規則。パスのパターンと役割だけを持つ。

    実データ、正解、パスワードは書かない。年度のような特別な型も持たない。
    版・時期・回を区別したいときは、任意の文字列 `edition` に書く。
    """

    id: str
    label: str
    required: list[str]
    optional: list[str]
    roles: dict[str, list[str]]
    edition: str = ""
    metadata: dict[str, str] = field(default_factory=dict)
    #: 選択肢の並び順。小さいほど先。無ければ label、id の順で後ろに並ぶ。
    order: int | None = None
    password_hints: list[str] = field(default_factory=list)
    #: 中身そのものがパスワードである案内ファイル（`*password*.txt` など）。
    password_files: list[str] = field(default_factory=list)
    #: パスワード案内を探すために開いてよい内側 ZIP。
    password_hint_containers: list[str] = field(default_factory=list)
    #: 使うパーサーの ID。None は「自動判定に参加するパーサーで判定する」。
    parsers: list[str] | None = None
    unsupported: list[Unsupported] = field(default_factory=list)
    #: `parsers` のうち、読み込んだ時点で登録されていなかった ID。
    unknown_parsers: list[str] = field(default_factory=list)

    @property
    def display_label(self) -> str:
        """画面に出す名前。edition が無ければ括弧を付けない。"""
        return f"{self.label}（{self.edition}）" if self.edition else self.label

    def sort_key(self) -> tuple:
        return (self.order is None, self.order or 0, self.label, self.id)

    @classmethod
    def from_json(cls, raw, known_parsers=None) -> "Profile":
        """JSON の値からプロファイルを作る。契約に合わなければ `_Invalid`。

        `known_parsers` は登録済みのパーサー ID。省略すると既定の登録簿を見る。
        """
        if not isinstance(raw, dict):
            raise _Invalid("プロファイルは JSON のオブジェクトで書きます。")
        if "year" in raw:
            # 年度を特別扱いしない。版や回の区別は edition（任意の文字列）で。
            raise _Invalid(
                "'year' は使えません。版・時期・回を区別するには 'edition' を使ってください。"
            )
        extra = sorted(set(raw) - _PROFILE_FIELDS)
        if extra:
            raise _Invalid(f"未知の項目があります: {_keys(extra)}")

        ident = raw.get("id")
        if not isinstance(ident, str) or not _PROFILE_ID.fullmatch(ident):
            raise _Invalid("'id' は英数字・ハイフン・下線で 1〜64 文字にします。")
        label = _text(raw, "label", required=True)
        edition = _text(raw, "edition")

        metadata_raw = raw.get("metadata")
        metadata: dict[str, str] = {}
        if metadata_raw is not None:
            if not isinstance(metadata_raw, dict) or len(metadata_raw) > _MAX_METADATA:
                raise _Invalid(f"'metadata' は {_MAX_METADATA} 項目までのオブジェクトで書きます。")
            for key, value in metadata_raw.items():
                if (not isinstance(key, str) or not key or len(key) > _MAX_META_KEY
                        or not isinstance(value, str) or len(value) > _MAX_META_VALUE):
                    raise _Invalid("'metadata' のキーと値は短い文字列で書きます。")
                metadata[key] = value

        order = raw.get("order")
        if order is not None and (not isinstance(order, int) or isinstance(order, bool)):
            raise _Invalid("'order' は整数で書きます。")

        match = raw.get("match")
        if not isinstance(match, dict):
            raise _Invalid("'match' が必要です（requiredPathPatterns を含むオブジェクト）。")
        extra = sorted(set(match) - _MATCH_FIELDS)
        if extra:
            raise _Invalid(f"'match' に未知の項目があります: {_keys(extra)}")
        required = _patterns(match.get("requiredPathPatterns"), "match.requiredPathPatterns")
        if not required:
            # 必須パターンの無いプロファイルは、どの ZIP にも満点で当たる。
            # 自動判定に参加させると、無関係な ZIP まで自分のものだと主張する。
            raise _Invalid("'match.requiredPathPatterns' に 1 つ以上のパターンが必要です。")
        optional = _patterns(match.get("optionalNamePatterns"), "match.optionalNamePatterns")

        roles_raw = raw.get("roles") or {}
        if not isinstance(roles_raw, dict):
            raise _Invalid("'roles' は役割ごとのパターン配列を持つオブジェクトで書きます。")
        roles: dict[str, list[str]] = {}
        for role, pats in roles_raw.items():
            if role not in _ASSIGNABLE_ROLES:
                raise _Invalid(
                    f"'roles' に未知の役割があります。使えるのは {', '.join(_ASSIGNABLE_ROLES)} です。"
                )
            roles[role] = _patterns(pats, f"roles.{role}")

        parser_ids = raw.get("parsers")
        if parser_ids is not None:
            if (not isinstance(parser_ids, list) or not parser_ids
                    or not all(isinstance(i, str) and i for i in parser_ids)):
                raise _Invalid("'parsers' はパーサー ID の空でない配列で書きます。")
            parser_ids = sorted(set(parser_ids))
        if known_parsers is None:
            known_parsers = parsers.REGISTRY.ids()
        known = set(known_parsers)
        unknown = [i for i in (parser_ids or []) if i not in known]

        unsupported_raw = raw.get("unsupportedFormats") or []
        if not isinstance(unsupported_raw, list):
            raise _Invalid("'unsupportedFormats' は配列で書きます。")

        return cls(
            id=ident,
            label=label,
            edition=edition,
            metadata=metadata,
            order=order,
            required=required,
            optional=optional,
            roles=roles,
            password_hints=_patterns(raw.get("passwordHintPatterns"), "passwordHintPatterns"),
            password_files=_patterns(raw.get("passwordFilePatterns"), "passwordFilePatterns"),
            password_hint_containers=_patterns(
                raw.get("passwordHintContainerPatterns"), "passwordHintContainerPatterns"
            ),
            parsers=parser_ids,
            unsupported=[Unsupported.from_json(u) for u in unsupported_raw],
            unknown_parsers=unknown,
        )


@dataclass
class Dataset:
    """1 つの ZIP を教材として見た結果。"""

    profile: Profile | None
    confidence: float
    #: メンバー名 -> 役割
    roles: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    #: 利用者がプロファイルを明示指定したか（自動判定ではないか）。
    forced: bool = False
    #: メンバー名 -> {"label", "detail"}。分類はできたが専用解析が無いもの。
    unsupported: dict[str, dict] = field(default_factory=dict)

    @property
    def generic(self) -> bool:
        """プロファイルを特定できなかった（汎用解析）。"""
        return self.profile is None

    @property
    def label(self) -> str:
        return self.profile.label if self.profile else GENERIC_LABEL

    @property
    def edition(self) -> str:
        return self.profile.edition if self.profile else ""

    @property
    def parser_ids(self) -> list[str] | None:
        """解析に使うパーサー。None は自動判定に参加するパーサー（AUTO_DETECT）で判定する。"""
        return self.profile.parsers if self.profile else None

    def named(self, role: str) -> list[str]:
        """その役割を持つメンバー名を、名前順で返す。"""
        return sorted(n for n, r in self.roles.items() if r == role)

    def unsupported_rows(self) -> list[dict]:
        """未対応形式の一覧。名前順で決定的に返す。"""
        return [
            {"name": n, **self.unsupported[n]} for n in sorted(self.unsupported)
        ]


@dataclass
class ProfileCatalog:
    """読み込んだプロファイルと、読み込めなかったものの理由。"""

    profiles: list[Profile] = field(default_factory=list)
    errors: list[ProfileError] = field(default_factory=list)

    def get(self, profile_id: str) -> Profile | None:
        return next((p for p in self.profiles if p.id == profile_id), None)

    def choices(self) -> list[dict]:
        """利用者が指定できるプロファイルの一覧。表示順、label、id の順。"""
        return [
            {"id": p.id, "label": p.label, "edition": p.edition}
            for p in sorted(self.profiles, key=Profile.sort_key)
        ]

    def errors_json(self) -> list[dict]:
        return [e.as_json() for e in self.errors]


def load_profile_dir(directory: str, known_parsers=None,
                     required: bool = False) -> tuple[list[Profile], list[ProfileError]]:
    """1 つのフォルダから `*.json` を読む。壊れたものは理由付きで返す。

    `required` は、利用者が明示的に指定したフォルダかどうか。標準のフォルダ
    が無いのは正常（プロファイル 0 件）だが、指定したフォルダが無いのは
    設定の誤りなので報告する。
    """
    label = os.path.basename(os.path.normpath(directory)) or directory
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        if required:
            return [], [ProfileError(label, "プロファイルのフォルダを開けませんでした。")]
        return [], []
    profiles: list[Profile] = []
    errors: list[ProfileError] = []
    for name in names:
        if not name.endswith(".json"):
            continue
        path = os.path.join(directory, name)
        try:
            if os.path.getsize(path) > MAX_PROFILE_BYTES:
                raise _Invalid("ファイルが大きすぎます。")
            with open(path, encoding="utf-8") as fh:
                raw = json.load(fh)
            profiles.append(Profile.from_json(raw, known_parsers))
        except _Invalid as exc:
            errors.append(ProfileError(name, str(exc)))
        except (OSError, UnicodeDecodeError):
            errors.append(ProfileError(name, "ファイルを読めませんでした。"))
        except ValueError:
            # json.JSONDecodeError を含む。位置や断片は載せない。
            errors.append(ProfileError(name, "JSON として読めませんでした。"))
    return profiles, errors


def load_catalog(directories=(), known_parsers=None,
                 include_builtin: bool = False) -> ProfileCatalog:
    """複数のフォルダからプロファイルを集める。ID の重複はすべて拒否する。

    同じ ID が二つあると、どちらの規則で分類されたのかが分からなくなる。
    どちらかを先勝ちで採ると、ファイルの並びで結果が変わる。だから重複した
    ID は、どのコピーも読み込まず、それぞれ理由を付けて報告する。
    """
    loaded: list[tuple[str, Profile]] = []
    errors: list[ProfileError] = []
    sources = ([(BUILTIN_PROFILE_DIR, False)] if include_builtin else []) + [
        (d, True) for d in directories
    ]
    for directory, required in sources:
        found, bad = load_profile_dir(directory, known_parsers, required)
        errors.extend(bad)
        loaded.extend((directory, p) for p in found)
    counts: dict[str, int] = {}
    for _dir, profile in loaded:
        counts[profile.id] = counts.get(profile.id, 0) + 1
    profiles: list[Profile] = []
    for directory, profile in loaded:
        if counts[profile.id] > 1:
            label = os.path.basename(os.path.normpath(directory)) or directory
            errors.append(ProfileError(
                label, f"プロファイル ID '{profile.id}' が重複しているため、どのコピーも読み込みませんでした。"
            ))
            continue
        profiles.append(profile)
    profiles.sort(key=Profile.sort_key)
    return ProfileCatalog(profiles=profiles, errors=errors)


#: サーバーが起動時に作る一覧。`configure_profiles()` で差し替える。
_CATALOG: ProfileCatalog | None = None


def configure_profiles(external_dirs=(), known_parsers=None) -> ProfileCatalog:
    """標準のフォルダと、起動時に指定された外部フォルダから読み込む。

    外部フォルダは起動時の設定（環境変数 `DATASET_PROFILE_DIR`）からだけ
    受け取る。HTTP リクエストから任意のフォルダを指定させない。
    """
    global _CATALOG
    _CATALOG = load_catalog(external_dirs, known_parsers, include_builtin=True)
    return _CATALOG


def profile_catalog() -> ProfileCatalog:
    """現在の一覧。まだ設定されていなければ、標準のフォルダだけを読む。"""
    if _CATALOG is None:
        return configure_profiles()
    return _CATALOG


def _nfc(text: str) -> str:
    """照合用に Unicode 正規化する。

    macOS が作った ZIP の名前は NFD で入っていることがある。`平常時ログ.zip`
    の「グ」は NFD では「ク」＋濁点の 2 符号位置になるので、エディタで
    ふつうに（NFC で）書いたパターンとは一文字も一致しない。

    正規化するのは照合のときだけで、表示名と保存名は原文のまま扱う。
    ASCII と既に NFC の名前に対しては何も変えない。
    """
    return unicodedata.normalize("NFC", text)


def _matches_any(name: str, patterns: list[str]) -> bool:
    name = _nfc(name)
    return any(fnmatch.fnmatchcase(name, _nfc(p)) for p in patterns)


def _score(names: list[str], profile: Profile) -> float:
    """このプロファイルらしさ。必須が 1 つでも外れたら 0。"""
    normalised = [_nfc(n) for n in names]
    for pattern in profile.required:
        pattern = _nfc(pattern)
        if not any(fnmatch.fnmatchcase(n, pattern) for n in normalised):
            return 0.0
    if not profile.optional:
        return 1.0
    hit = sum(
        1 for p in profile.optional
        if any(fnmatch.fnmatchcase(n, _nfc(p)) for n in normalised)
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


def unsupported_for(names: list[str], profile: Profile) -> dict[str, dict]:
    """「分類はできたが専用解析が無い」メンバーを拾う。

    役割は変えない。問題ログ（`challenge`）のままで、ただし教材の材料には
    せず、理由付きで一覧に出す。先に当たった宣言を採用するので、同じ名前が
    二つの宣言に当たっても結果は決定的になる。
    """
    out: dict[str, dict] = {}
    for name in names:
        for decl in profile.unsupported:
            if _matches_any(name, decl.patterns):
                out[name] = {"label": decl.label, "detail": decl.detail}
                break
    return out


def _generic_roles(names: list[str]) -> dict[str, str]:
    """プロファイルが分からないときの最小限の仕分け。

    問題ログを言い当てられないので `challenge` は付けない。当てずっぽうで
    `challenge` を付けると、「平常時ログや同梱のサンプルを本番の問題ログ
    として教材化する」不具合に戻る。
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


def _profile_warnings(profile: Profile) -> list[str]:
    """プロファイル自体の不備。分類はできても、解析で何かが欠けるもの。"""
    if not profile.unknown_parsers:
        return []
    return [
        f"このプロファイルが指定したパーサー（{', '.join(profile.unknown_parsers)}）は"
        "登録されていません。その形式のログは解析されません。"
    ]


def detect(
    names: list[str],
    profiles: list[Profile] | None = None,
    force_id: str | None = None,
) -> Dataset:
    """メンバー名の一覧からプロファイルと役割を決める。

    一致が弱ければ断定せず、汎用解析として返す。プロファイルが 1 件も無い
    のも正常で、そのときも汎用解析になる。

    `force_id` を渡すと自動判定を上書きする（自動判定の結果は、利用者が
    いつでも変更できなければならない）。指定されたプロファイルは一致度に関わらず適用し、
    一致が弱いことは警告として添える。存在しない id は黙って自動判定へ
    落とさず、`UnknownProfile` として突き返す。取り違えたまま別の規則で
    分類されるより、指定が通らなかったと分かるほうがよい。
    """
    profiles = profile_catalog().profiles if profiles is None else profiles

    if force_id and force_id != "auto":
        chosen = next((p for p in profiles if p.id == force_id), None)
        if chosen is None:
            raise UnknownProfile(f"指定されたプロファイル '{force_id}' は存在しません。")
        score = _score(names, chosen)
        warnings: list[str] = []
        if score < MIN_OPTIONAL_RATIO:
            warnings.append(
                f"{chosen.display_label} を指定されましたが、このZIPとの一致は弱いままです。"
            )
        warnings += _profile_warnings(chosen)
        roles = classify(names, chosen)
        if not any(r == "challenge" for r in roles.values()):
            warnings.append("本番の問題ログにあたるファイルが見つかりませんでした。")
        return Dataset(
            profile=chosen, confidence=score,
            roles=roles, warnings=warnings, forced=True,
            unsupported=unsupported_for(names, chosen),
        )

    # 全プロファイルを採点してから決める。1 パスで `>` 比較しながら首位を
    # 更新する書き方だと、同点のときにファイル名の若いほうが黙って勝つ。
    scored = sorted(
        ((_score(names, p), p) for p in profiles),
        key=lambda sp: (-sp[0], sp[1].id),
    )

    warnings: list[str] = []
    best_score = scored[0][0] if scored else 0.0
    best = scored[0][1] if scored else None

    if best is None or best_score < MIN_OPTIONAL_RATIO:
        if best is not None and best_score > 0:
            warnings.append(
                f"{best.display_label} の特徴が十分に揃っていないため、"
                "データセット形式を断定しませんでした。"
            )
        return Dataset(
            profile=None, confidence=best_score,
            roles=_generic_roles(names), warnings=warnings,
        )

    tied = [p for s, p in scored if best_score - s <= MIN_LEAD]
    if len(tied) > 1:
        # 差が付かなかった。どれかを選ぶ理由が無いので選ばない。
        warnings.append(
            "データセット形式の候補が同じ一致度で並びました（"
            + "、".join(p.display_label for p in tied)
            + "）。取り違えを避けるため断定せず、汎用解析にしました。"
            "画面からデータセット形式を指定すると、そのプロファイルの規則で分類します。"
        )
        return Dataset(
            profile=None, confidence=best_score,
            roles=_generic_roles(names), warnings=warnings,
        )

    roles = classify(names, best)
    warnings += _profile_warnings(best)
    if not any(r == "challenge" for r in roles.values()):
        warnings.append("本番の問題ログにあたるファイルが見つかりませんでした。")
    return Dataset(
        profile=best, confidence=best_score,
        roles=roles, warnings=warnings,
        unsupported=unsupported_for(names, best),
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


def password_from_password_file(text: str) -> str | None:
    """丸ごと 1 個がパスワードである案内ファイルを読む。

    データセットによっては、鍵が `*password*.txt` のようなファイルに
    「見出しも引用符も無い 1 語」として置かれている。散文用の検出
    （同じ行に見出し語と引用表記の両方を求める）はここでは何も拾えない。

    だからといって「小さい .txt の中身は鍵かもしれない」と一般化はしない。
    それでは README の 1 行やライセンスの断片まで鍵の候補になる。適用する
    のは、プロファイルが `passwordFilePatterns` として名指ししたパスに
    限る。どのファイルが案内なのかは、推測ではなくプロファイルの宣言で決める。

    条件は「空白を含まない 1 語であること」だけにしてある。鍵の中身に
    ついての仮定（長さの上限以外）は置かない。
    """
    token = text.strip()
    if not token or any(c.isspace() for c in token):
        return None
    if not 3 < len(token) <= 128:
        return None
    return token


def _hint_patterns(dataset: Dataset) -> list[str]:
    if dataset.profile and dataset.profile.password_hints:
        return dataset.profile.password_hints
    return ["*.md", "*.txt", "*/*.md", "*/*.txt"]


def _hint_from_member(zf, info, name: str, dataset: Dataset, out: list[str]) -> None:
    """1 メンバーを案内文として読み、候補を `out` へ足す。値は返さない。"""
    if info.is_dir() or info.flag_bits & 0x1:
        return  # 案内文自体が暗号化されていることは想定しない
    if not name.lower().endswith((".md", ".txt")):
        return
    profile = dataset.profile
    whole = bool(profile and _matches_any(name, profile.password_files))
    cap = MAX_PASSWORD_FILE_BYTES if whole else MAX_HINT_BYTES
    if info.file_size > cap:
        return
    if not whole and not _matches_any(name, _hint_patterns(dataset)):
        return
    try:
        raw = zf.open(info).read(cap)
    except (OSError, RuntimeError, zipfile.BadZipFile, ValueError,
            zlib.error, EOFError):
        return
    text = raw.decode("utf-8", "replace")
    found = list(password_candidates_from_text(text))
    if whole:
        token = password_from_password_file(text)
        # 丸ごと 1 語のほうを先に試す。名指しされた案内ファイルなので、
        # 散文から拾った候補より確からしい。
        if token:
            found.insert(0, token)
    for cand in found:
        if cand not in out:
            out.append(cand)


def find_password_candidates(archive, dataset: Dataset) -> list[str]:
    """同梱の案内文から鍵の候補を集める。

    戻り値はメモリ上だけで扱うこと。API 応答・DB・ログへ載せてはならない。
    呼び出し側は「候補があるか」だけを外へ出す。

    データセットによっては案内文が内側 ZIP の中にある。
    そのため、プロファイルが `passwordHintContainerPatterns` で名指しした
    入れ物だけは開く。手当たり次第には開かない。名指しされていても、
    大きさ（`MAX_CONTAINER_BYTES`）と個数（`MAX_HINT_CONTAINERS`）で
    止まるようにしてある。
    """
    out: list[str] = []
    profile = dataset.profile
    containers = list(profile.password_hint_containers) if profile else []
    opened = 0
    try:
        with _open_archive(archive) as zf:
            for info in zf.infolist():
                name = _decoded_name(info)
                _hint_from_member(zf, info, name, dataset, out)
                if (
                    containers
                    and opened < MAX_HINT_CONTAINERS
                    and not info.is_dir()
                    and not (info.flag_bits & 0x1)
                    and 0 < info.file_size <= MAX_CONTAINER_BYTES
                    and _matches_any(name, containers)
                ):
                    opened += 1
                    try:
                        blob = zf.open(info).read(MAX_CONTAINER_BYTES + 1)
                        inner = zipfile.ZipFile(io.BytesIO(blob))
                    except (OSError, RuntimeError, zipfile.BadZipFile, ValueError,
                            zlib.error, EOFError):
                        continue
                    with inner:
                        for child in inner.infolist():
                            _hint_from_member(
                                inner, child,
                                f"{name} :: {_decoded_name(child)}", dataset, out,
                            )
    except (OSError, zipfile.BadZipFile, ArchiveDamaged):
        return out[:MAX_PASSWORD_CANDIDATES]
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

    開けなかったとき（外側の ZIP が壊れている、読めない）は、ここで
    `ArchiveDamaged` に変換する。これは contextmanager なので、ZIP を実際に
    開くのは呼び出した時点ではなく `with` に入った時点である。呼び出しだけを
    try で囲む書き方では何も捕まえられず、`BadZipFile` が API の外まで
    漏れていた。変換をここに置けば、呼び出し側の書き方に左右されない。

    変換するのは開く処理だけで、`with` の本体で起きた例外には触れない。
    """
    if isinstance(archive, zipfile.ZipFile):
        yield archive
        return
    try:
        if isinstance(archive, str):
            zf = zipfile.ZipFile(archive)
        else:
            archive.seek(0)
            zf = zipfile.ZipFile(archive)
    except (OSError, zipfile.BadZipFile, ValueError, EOFError) as exc:
        raise ArchiveDamaged("ZIPファイルを開けませんでした。") from exc
    with zf:
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
    #: 分類はできたが専用の解析が無いため材料にしなかったログ。
    #: `failures` とは別に持つ。「読めなかった」と「読む仕組みが無い」は
    #: 利用者にとって意味が違い、直し方も違う。
    unsupported: list[dict] = field(default_factory=list)

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


class _Plan:
    """読みたいメンバーを、入れ物の入れ子どおりの木にしたもの。

    走査側（`archive.py`）はメンバー名を `親 :: 子 :: 孫` の形で記録する。
    問題ログが `bundle.zip :: case/logs.zip :: host/a.log` のように二重の
    入れ物の奥にあると、区切りが二つある。名前を一度しか分けない読み方
    では、`case/logs.zip :: host/a.log` という名前の子を外側 ZIP の中に
    探しに行くことになり、当然見つからない。だから木にして順に潜る。

    深さは `MAX_CONTAINER_DEPTH`（= `archive.MAX_DEPTH`）で止める。走査側
    が見えている範囲と同じにしてあり、ここを広げるつもりはない。
    """

    __slots__ = ("logs", "children")

    def __init__(self) -> None:
        self.logs: set[str] = set()
        self.children: dict[str, "_Plan"] = {}

    @property
    def empty(self) -> bool:
        return not self.logs and not self.children

    @classmethod
    def build(cls, names: set[str]) -> "_Plan":
        root = cls()
        for name in names:
            segments = name.split(" :: ")
            node = root
            for segment in segments[:-1]:
                node = node.children.setdefault(segment, cls())
            leaf = segments[-1]
            if leaf.lower().endswith(".zip"):
                # 役割としては問題ログだが、それ自体は入れ物。中身が列挙
                # できていれば別の名前が子として登録される。列挙に失敗した
                # （壊れている、上限を超えた）場合はここだけが残るので、
                # 黙って飛ばさず開きにいく。
                node.children.setdefault(leaf, cls())
            else:
                node.logs.add(leaf)
        return root


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

    分類はできたが専用の解析が無い形式（プロファイルが `unsupportedFormats`
    で宣言したもの）は、ここでは読まず、`result.unsupported` へ理由付きで
    積む。たとえば Web サーバーのアクセスログは、プロキシのログと行の形が
    ほぼ同じなので、読めばプロキシのパーサーが黙って通してしまい、サーバー
    への要求をプロキシの通信として教材化することになる。当たっていない
    より、当たっているように見えるほうが危ない。
    """
    wanted = set(dataset.named(role))
    if not wanted:
        return ReadResult()

    result = ReadResult()
    for name in sorted(wanted):
        note = dataset.unsupported.get(name)
        if note is not None:
            result.unsupported.append({"name": name, **note})
    wanted -= set(dataset.unsupported)
    if not wanted:
        return result

    plan = _Plan.build(wanted)
    budget = _Budget(MAX_TOTAL_BYTES)
    tried = list(passwords or [])

    # 開けなければ `_open_archive` が ArchiveDamaged を投げる。
    with _open_archive(archive) as outer:
        _read_plan(outer, plan, "", dataset, result, budget, tried, None, 0)
    return result


def _read_plan(zf, node, prefix, dataset, result, budget, candidates, working, depth):
    """`_Plan` の 1 階層を読む。「通った鍵」を返す。

    `prefix` は表示名の先頭（空文字列か `親 :: `）。予算・上限の扱いは一段
    だけだった頃とまったく同じで、階層が増えても入れ物 1 個ごとに同じ
    順番で確かめる。
    """
    by_name = {_decoded_name(i): i for i in zf.infolist() if not i.is_dir()}

    for child in sorted(node.logs):
        display = prefix + child
        info = by_name.get(child)
        if info is None or not child.lower().endswith(".log"):
            continue
        working = _read_one(zf, info, display, result, budget, candidates, working)

    for child in sorted(node.children):
        display = prefix + child
        info = by_name.get(child)
        if info is None:
            continue
        # 予算の確認は、読む「前」に済ませる（`_open_container`）。
        #
        # 内側 ZIP は中央ディレクトリが末尾にあるため、部分読みでは
        # ZipFile として使えない。つまり全体を載せるか、載せないかの二択
        # になる。以前は読み終えてから引いていたので、1 バイトしか残って
        # いなくても 1 個まるごと読めてしまい、しかも次の入れ物へ進んで
        # いた。残りに収まらないものは読まずに断る。
        inner = _open_container(zf, info, display, result, budget, depth)
        if inner is None:
            continue

        sub = node.children[child]
        with inner:
            if sub.empty:
                sub = _fallback_plan(inner, display + " :: ", dataset)
            working = _read_plan(
                inner, sub, display + " :: ", dataset,
                result, budget, candidates, working, depth + 1,
            )
    return working


def _open_container(zf, info, display, result, budget, depth,
                    max_depth: int = MAX_CONTAINER_DEPTH):
    """内側 ZIP を、予算を先に予約してから開く。開けなければ理由を積んで None。

    プロファイル経路（`_read_plan`）と汎用解析（`read_all_logs`）で共通。
    """
    if depth >= max_depth:
        result.failures.append(
            {"name": display, "reason": "too-deep",
             "detail": "圧縮ファイルの入れ子が深すぎるため、これ以上は開きませんでした。"}
        )
        result.truncated = True
        return None
    if info.file_size > MAX_CONTAINER_BYTES:
        result.failures.append(
            {"name": display, "reason": "container-too-large",
             "detail": "内側の圧縮ファイルが大きすぎるため読み取りませんでした。"}
        )
        result.truncated = True
        return None
    if budget.exhausted:
        result.failures.append(
            {"name": display, "reason": "budget",
             "detail": "合計の読み取り上限に達しました。"}
        )
        result.truncated = True
        return None
    if info.file_size > budget.remaining:
        result.failures.append(
            {"name": display, "reason": "limit-exceeded",
             "detail": "残りの読み取り上限に収まらないため読み取りませんでした。"}
        )
        result.truncated = True
        return None
    try:
        budget.take(info.file_size)
        blob = zf.open(info).read(MAX_CONTAINER_BYTES + 1)
        budget.refund(max(0, info.file_size - len(blob)))
        return zipfile.ZipFile(io.BytesIO(blob))
    except (OSError, RuntimeError, zipfile.BadZipFile, ValueError,
            zlib.error, EOFError):
        result.failures.append(
            {"name": display, "reason": "damaged",
             "detail": "圧縮ファイルを読み取れませんでした。"}
        )
        return None


#: 汎用解析（プロファイル未特定）の読み取り上限。プロファイル経路より小さい。
#: 役割が分からないまま「読めるものをすべて」読むので、量を絞っておく。
GENERIC_TOTAL_BYTES = 24 * 1024**2
GENERIC_LOG_BYTES = 4 * 1024**2
#: 汎用解析で潜る入れ子の深さ（外側の中の 2 階層まで）。
GENERIC_CONTAINER_DEPTH = 2


def read_all_logs(archive) -> ReadResult:
    """汎用解析：暗号化されていない `.log` をすべて読む。

    プロファイル経路と同じ部品で読む。共有予算は読む「前」に予約し、内側
    ZIP も予約してから開く。1 ログの上限で切った・合計の上限で読めなかった・
    暗号化されていた・壊れていた、はすべて `failures` と `truncated` に残し、
    教材の導入と最終レポートまで伝える。黙って読み飛ばすと、欠けた証拠から
    作った教材が完全なものに見える。

    パスワードは使わない（汎用解析では、どの案内が何の鍵かを決められない）。
    暗号化されたログは `password-required` として報告する。
    """
    result = ReadResult()
    budget = _Budget(GENERIC_TOTAL_BYTES)
    # 開けなければ `_open_archive` が ArchiveDamaged を投げる。
    with _open_archive(archive) as outer:
        _read_everything(outer, "", result, budget, 0)
    return result


def _read_everything(zf, prefix, result, budget, depth) -> None:
    infos = sorted((i for i in zf.infolist() if not i.is_dir()), key=_decoded_name)
    for info in infos:
        name = _decoded_name(info)
        low = name.lower()
        display = prefix + name
        if low.endswith(".log") and info.file_size:
            # 1 ログの上限で切れば、`_read_stream` が truncated を立てる。
            _read_one(zf, info, display, result, budget, [], None,
                      per_log=GENERIC_LOG_BYTES)
        elif low.endswith(".zip"):
            if info.flag_bits & 0x1:
                # 鍵を使わないので開けない。黙って飛ばさず報告する。
                result.failures.append(
                    {"name": display, "reason": "password-required",
                     "detail": "暗号化されています。パスワードが必要です。"}
                )
                continue
            inner = _open_container(zf, info, display, result, budget, depth,
                                    GENERIC_CONTAINER_DEPTH)
            if inner is None:
                continue
            with inner:
                _read_everything(inner, display + " :: ", result, budget, depth + 1)


def _fallback_plan(inner, prefix, dataset: Dataset) -> _Plan:
    """入れ物の中身を走査時に列挙できていなかった場合の受け皿。

    「中の `.log` をぜんぶ」では戻りすぎる。問題ログと同じ入れ物に同梱
    ツールの動作確認用サンプル（`tools/sample.log` のようなもの）が入って
    いると、それを拾えば、この層がまさに直した「同梱ツールのサンプルを
    本番の問題ログとして教材化する」不具合に戻る。

    そこで、組み立てた表示名をプロファイル自身にもう一度分類させ、
    `challenge` と言われたものだけを読む。判断の根拠は最初から最後まで
    プロファイル 1 か所にある。
    """
    plan = _Plan()
    profile = dataset.profile
    for info in inner.infolist():
        if info.is_dir():
            continue
        name = _decoded_name(info)
        if not name.lower().endswith(".log"):
            continue
        display = prefix + name
        if dataset.unsupported.get(display):
            continue
        if profile is not None:
            if classify([display], profile).get(display) != "challenge":
                continue
        plan.logs.add(name)
    return plan


def _read_one(zf, info, display, result, budget, candidates, working,
              per_log: int | None = None):
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
        # 既定は呼び出し時の MAX_LOG_BYTES（定義時に固定しない）。
        cap = MAX_LOG_BYTES if per_log is None else per_log
        limit = max(0, min(budget.remaining, cap))
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


def dataset_info(dataset: Dataset, registry=None) -> dict:
    """判定したデータセット形式の要約。データセット画面・教材・API で共通。

    年度のような特別な項目は持たない。`edition` は任意の文字列で、無ければ
    空文字。画面はこれを見て括弧を付けるかどうかを決める。
    """
    registry = registry if registry is not None else parsers.REGISTRY
    wanted = dataset.parser_ids
    usable, _unknown = registry.resolve(wanted)
    profile = dataset.profile
    return {
        "profileId": profile.id if profile else None,
        "label": dataset.label,
        "edition": dataset.edition,
        "metadata": dict(profile.metadata) if profile else {},
        "forced": dataset.forced,
        "confidence": round(dataset.confidence, 3),
        "generic": dataset.generic,
        # 解析に使うパーサー。プロファイルが指定しないときは、自動判定に
        # 参加するもの（AUTO_DETECT）で各ログの形式を判定する。
        "parsers": [p.id for p in usable],
        "parserLabels": [p.label for p in usable],
        # 登録はあるが、プロファイルで明示されたときだけ使う形式（内容だけ
        # では形式を言い切れないもの）。今回は使わないことを画面で伝える。
        "explicitOnlyLabels": [p.label for p in registry.explicit_only(wanted)],
        "unknownParsers": list(profile.unknown_parsers) if profile else [],
    }


def summarise(dataset: Dataset, member_rows: list[dict],
              catalog: "ProfileCatalog | None" = None, registry=None) -> dict:
    """API へ出す形。パスワード候補の値は決して含めない。"""
    catalog = catalog if catalog is not None else profile_catalog()
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
        note = dataset.unsupported.get(name)
        if note is not None:
            # 役割は変えない。「問題ログだが専用解析は無い」と両方を言う。
            entry["unsupported"] = note["label"]
        if entry["encrypted"] and role == "challenge":
            encrypted_challenge += 1
        by_role[role].append(entry)
    return {
        **dataset_info(dataset, registry),
        "counts": counts,
        "members": by_role,
        "encryptedChallenge": encrypted_challenge,
        "unsupported": dataset.unsupported_rows(),
        "profiles": catalog.choices(),
        "profileErrors": catalog.errors_json(),
        "warnings": list(dataset.warnings),
    }
