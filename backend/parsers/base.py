"""parsers/base.py — パーサーの契約と、正規化イベント。

教材生成（`explain.py`）は、ログの形式を知らない。知っているのは、ここで
定義する共通の形だけである。

    アーカイブ読み取り（dataset.py）
        ↓  {論理パス: 本文}
    入力ソース（InputSource）
        ↓
    パーサーレジストリ（registry.py）
        ↓
    正規化イベント（NormalizedEvent）＋ EvidenceStore
        ↓
    教材生成（explain.py）

新しいログ形式に対応するときに書くのは `Parser` の派生クラス 1 つで、
レジストリへ登録すれば教材生成まで届く。教材生成側は変更しない。

形式の知識は、次の三つの形でだけパーサーから外へ出る。

  * `NormalizedEvent` … 1 行を種別・時刻・端末・要約・属性へ直したもの
  * `reread()`         … 保存済みの抜粋から、事実を「どの項目か」付きで読み直す
  * 表現の辞書         … 設問の解説や段階の導入で、その形式を説明する文

生成側が形式ごとに分岐しない（`if parser_id == "itm2"` を書かない）ための
仕組みがこの三つである。
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Mapping

import evidence
import timeline

#: 教材生成が段階を組み立てられる種別。これ以外の種別を出してもよいが、
#: 段階には載らない（件数の集計にだけ使う）。
KNOWN_KINDS = ("process", "file", "registry", "network")

#: 種別ごとに必ず持たせる属性。値は空文字でもよいが、キーは省略できない。
#: 教材生成はこのキーを前提に読むので、ここで欠けを止める。
REQUIRED_ATTRIBUTES: dict[str, tuple[str, ...]] = {
    "process": ("program", "program_name"),
    "file": ("path", "name"),
    "registry": ("path",),
    "network": ("client", "method", "target"),
}

#: 教材生成が `reread()` で尋ねる事実。パーサーが答えられないものは
#: None を返せばよく、その事実を使う設問は作られない。
FACTS: dict[str, tuple[str, ...]] = {
    "process": ("program_name", "command_line", "host"),
    "file": ("path", "host"),
    "registry": ("path",),
    "network": ("client", "target"),
}

_KIND = re.compile(r"[a-z][a-z0-9_]{0,31}")
_PARSER_ID = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_EVIDENCE_ID = re.compile(r"ev-[0-9a-f]{%d}" % evidence.ID_HEX)

#: 1 ログから読む最大行数。読み取り層の上限（`dataset.MAX_RECORDS`）とは
#: 別に、パーサーが 1 回に抱える量の上限として持つ。
MAX_LINES = 200_000

#: 端末の照合キーとして採用しない値。
#:
#: `?` と空文字は「読めなかった」を表す代用で、端末を指していない。ループ
#: バックと未指定アドレスはどの端末にも存在するので、一致しても同じ端末で
#: あることを示さない。いずれも、一致を根拠に「同一端末」と言えない。
NOT_A_HOST = frozenset({
    "", "?", "-", "unknown", "n/a",
    "127.0.0.1", "::1", "localhost",
    "0.0.0.0", "::",
})


class ContractError(ValueError):
    """パーサーが契約を守っていない。登録時か、解析結果の検査で投げる。"""


def clean_host_keys(values) -> frozenset:
    """端末の照合に使える呼び名だけを残す。"""
    out = set()
    for value in values or ():
        value = str(value).strip()
        if value.lower() not in NOT_A_HOST:
            out.add(value)
    return frozenset(out)


def source_of(name: str, line_no: int, line: str) -> evidence.Source:
    """1 行の出典を組み立てる。

    `name` は `親 ZIP :: 子` の形の論理パス。同じ `a.log` が別の内側 ZIP に
    あっても取り違えないよう、`archive_path` には全体を、`member` には
    最後の区切りの後ろだけを持つ。

    抜粋は原文のまま持つ。保存用の切り詰めと不可視文字の置き換えは
    `evidence.Source.as_json()` が一か所で行う。
    """
    member = name.split(" :: ")[-1] if " :: " in name else name
    return evidence.Source(archive_path=name, member=member, line=line_no, excerpt=line)


@dataclass(frozen=True, slots=True)
class InputSource:
    """読み取り済みのログ 1 本。`name` は論理パス、`text` は本文。"""

    name: str
    text: str

    def lines(self, limit: int = MAX_LINES) -> list[str]:
        """行へ分ける。行番号は元のファイルの位置に合わせて 1 から数える。

        空行や読めない行も数に入れる。飛ばすと「12345 行目」がずれ、
        ログを開いて確かめる人が別の行に着く。
        """
        return self.text.split("\n")[:limit]


@dataclass(frozen=True, slots=True)
class FactReading:
    """保存済みの抜粋から読み直した 1 つの事実。

    `field` は、原文のどの項目から読んだか（`psPath` など）。設問の解説や
    ATT&CK の理由は、この名前で「この 1 行のどこに書いてあるか」を示す。
    読み取りが代替の項目へ落ちたときは、その項目の名前が入る。
    """

    value: str
    field: str


@dataclass(frozen=True, slots=True)
class FactText:
    """ある形式で、ある事実がどこに書かれるかの説明。

    `where` は設問の解説の書き出しになる。`{field}` は実際に読んだ項目名で
    置き換わる。`next` を空にすると、教材生成側の既定の文言を使う。
    """

    where: str
    next: str = ""


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    """教材生成が受け取る、形式に依らない 1 件の記録。

    必須項目と、その検査（`validate_event`）:

      kind            小文字の種別名。`KNOWN_KINDS` 以外も可（段階には載らない）。
      action          その種別の中での動作（start / create / request など）。
      timestamp       `timeline.Stamp`。読めなければ `timeline.UNKNOWN`。
      host            表示用の端末名。読めなければ `?` などの代用。
      summary         1 行の要約。`KNOWN_KINDS` では空にできない。
      source          `evidence.Source`。出典・行番号・原文。
      parser_id       この記録を作ったパーサーの ID。
      attributes      種別ごとの属性。`REQUIRED_ATTRIBUTES` のキーは必須。
      correlation_keys 端末を照合する呼び名の集合。代用値は入れない。
      evidence_id     出典と種別から決まる証拠 ID（自動で計算する）。

    `evidence_id` を引数で受け取らないのは、出典と食い違う ID を作れない
    ようにするため。計算は `EvidenceStore.add()` と同じ関数で行うので、
    教材へ登録したときの ID と必ず一致する。

    証拠を `EvidenceStore` へ登録するのはここではない。教材に載るのは
    一部の行だけなので、全行を登録するとメモリが行数に比例して膨らむ。
    登録は教材生成側が、画面に出す行と相関に採用した行についてだけ行う。
    """

    kind: str
    action: str
    timestamp: timeline.Stamp
    host: str
    summary: str
    source: evidence.Source
    parser_id: str
    attributes: Mapping[str, str]
    correlation_keys: frozenset
    evidence_id: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "evidence_id", evidence.evidence_id(self.source, self.kind)
        )


def validate_event(event, parser_id: str) -> None:
    """1 件の正規化イベントが契約を満たすか。満たさなければ ContractError。

    パーサーは外から足される部品なので、出してきたものを信用しない。教材
    生成は、ここを通ったものだけを受け取る。
    """
    if not isinstance(event, NormalizedEvent):
        raise ContractError("正規化イベントではない値が返されました。")
    if event.parser_id != parser_id:
        raise ContractError("別のパーサーの ID を名乗るイベントがあります。")
    if not isinstance(event.kind, str) or not _KIND.fullmatch(event.kind):
        raise ContractError("種別（kind）の形式が不正です。")
    if not isinstance(event.action, str):
        raise ContractError("動作（action）が文字列ではありません。")
    if not isinstance(event.timestamp, timeline.Stamp):
        raise ContractError("時刻（timestamp）が timeline.Stamp ではありません。")
    if not isinstance(event.host, str):
        raise ContractError("端末（host）が文字列ではありません。")
    if not isinstance(event.summary, str):
        raise ContractError("要約（summary）が文字列ではありません。")
    known = event.kind in KNOWN_KINDS
    if known and (not event.summary or not event.action):
        raise ContractError("教材に載る種別で、要約か動作が空です。")
    src = event.source
    if not isinstance(src, evidence.Source):
        raise ContractError("出典（source）が evidence.Source ではありません。")
    if not isinstance(src.line, int) or isinstance(src.line, bool) or src.line < 1:
        raise ContractError("行番号は 1 以上の整数でなければなりません。")
    if not isinstance(src.excerpt, str) or not isinstance(src.archive_path, str):
        raise ContractError("出典の原文か論理パスが文字列ではありません。")
    attrs = event.attributes
    if not isinstance(attrs, Mapping):
        raise ContractError("属性（attributes）が辞書ではありません。")
    for key, value in attrs.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ContractError("属性のキーと値は文字列でなければなりません。")
    for key in REQUIRED_ATTRIBUTES.get(event.kind, ()):
        if key not in attrs:
            raise ContractError(f"種別 {event.kind} に必須の属性 {key} がありません。")
    keys = event.correlation_keys
    if not isinstance(keys, frozenset):
        raise ContractError("照合キー（correlation_keys）が frozenset ではありません。")
    for key in keys:
        if not isinstance(key, str) or key.strip().lower() in NOT_A_HOST:
            raise ContractError("照合キーに、端末を特定しない代用値が入っています。")
    if not isinstance(event.evidence_id, str) or not _EVIDENCE_ID.fullmatch(event.evidence_id):
        raise ContractError("証拠 ID（evidence_id）がありません。")


def detect_score(value) -> float:
    """`detect()` の戻り値を 0〜1 の数へ。範囲外や非数は契約違反。"""
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if not isinstance(value, (int, float)):
        raise ContractError("detect() は数値か真偽値を返さなければなりません。")
    value = float(value)
    if math.isnan(value) or not 0.0 <= value <= 1.0:
        raise ContractError("detect() の値は 0 以上 1 以下でなければなりません。")
    return value


class Parser:
    """ログ形式 1 つぶんの読み方。これを派生させてレジストリへ登録する。

    必須:
      id       小文字の識別子（例: "itm2"）。プロファイルの `parsers` で使う。
      label    利用者に見せる名前。
      detect() その入力を読めるか（0〜1）。0 なら parse() は呼ばれない。
      parse()  正規化イベントの並び。

    任意（既定のままでも教材生成まで届く）:
      AUTO_DETECT   自動判定（プロファイルが `parsers` を指定しないとき）の
                    候補に入れるか。内容だけでは形式を言い切れない形式は
                    False にし、プロファイルで明示されたときだけ使わせる。
      reread()      保存済み抜粋から事実を読み直す。答えられなければ None。
      FACT_TEXTS    (種別, 事実) → FactText。設問の解説の書き出し。
      RECORD_NOUNS  種別 → この形式の記録の呼び名（段階の導入文に使う）。
      ABOUTS        種別 → この形式の記録が何を残すかの一文。
    """

    id: str = ""
    label: str = ""
    AUTO_DETECT: bool = True

    FACT_TEXTS: Mapping[tuple[str, str], FactText] = {}
    RECORD_NOUNS: Mapping[str, str] = {}
    ABOUTS: Mapping[str, str] = {}

    def detect(self, source: InputSource) -> float:
        raise NotImplementedError

    def parse(self, source: InputSource,
              evidence_store: "evidence.EvidenceStore | None" = None,
              ) -> list[NormalizedEvent]:
        """正規化イベントを返す。

        `evidence_store` は契約上受け取るが、全行を登録してはならない
        （`NormalizedEvent` の説明を参照）。組み込みのパーサーは触らない。
        """
        raise NotImplementedError

    def reread(self, kind: str, fact: str, excerpt: str) -> FactReading | None:
        """保存済みの抜粋から事実を読み直す。既定は「答えられない」。"""
        return None

    def fact_text(self, kind: str, fact: str) -> FactText | None:
        return self.FACT_TEXTS.get((kind, fact))

    def record_noun(self, kind: str) -> str:
        return self.RECORD_NOUNS.get(kind, "")

    def about(self, kind: str) -> str:
        return self.ABOUTS.get(kind, "")


def check_parser(parser) -> None:
    """登録してよいパーサーか。形の不備は登録の時点で止める。"""
    if not isinstance(parser, Parser):
        raise ContractError("parsers.Parser を継承していません。")
    if not isinstance(parser.id, str) or not _PARSER_ID.fullmatch(parser.id):
        raise ContractError("パーサー ID は小文字の英数字・ハイフン・下線で書きます。")
    if not isinstance(parser.label, str) or not parser.label.strip():
        raise ContractError("パーサーには表示名（label）が必要です。")
    if not isinstance(parser.AUTO_DETECT, bool):
        raise ContractError("AUTO_DETECT は True か False で書きます。")
    for name in ("detect", "parse"):
        method = getattr(type(parser), name, None)
        if method is None or method is getattr(Parser, name):
            raise ContractError(f"{name}() が実装されていません。")
