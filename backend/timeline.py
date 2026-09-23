"""timeline.py — ログの時刻を、並べ替えられる形で保つ。

フェーズ2までは各行の出典を保持したが、時刻は表示用の文字列としてしか
残っていなかった。「どの順で記録されたか」を言うには、比較できる値が要る。

方針が二つある。

1. 元の文字列をそのまま残す。ログに書いてある時刻はその現場の時刻であり、
   こちらで別のタイムゾーンへ直すと、原文と画面が食い違う。並べ替えのために
   数値へ直すが、表示は常に原文のままにする。
2. 読めない時刻を捨てない。形式が想定と違う、欄が空、という行も調査対象で
   ありうる。捨てると「無かったこと」になるので、`時刻不明` として残し、
   並べ替えでは末尾へ送る。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone

#: InfoTrace Mark II の行頭。`10/05/2022 14:00:27.738 +0900`
_ITM2_TS = re.compile(
    r"^(?P<mon>\d{2})/(?P<day>\d{2})/(?P<year>\d{4})\s+"
    r"(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})(?:\.(?P<frac>\d{1,6}))?"
    r"(?:\s*(?P<tz>[+-]\d{4}))?"
)

#: Squid/Apache 形式。`[05/Oct/2022:14:00:07 +0900]`
_PROXY_TS = re.compile(
    r"^(?P<day>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):"
    r"(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})"
    r"(?:\s*(?P<tz>[+-]\d{4}))?"
)

_MONTHS = {
    m: i + 1
    for i, m in enumerate(
        "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
    )
}

#: 時刻が読めなかったことを表す並べ替え値。数値より必ず後ろへ来る。
UNKNOWN_SORT = float("inf")

#: 画面に出す文言。値そのものではなく状態なので、ここに置いて揃える。
UNKNOWN_LABEL = "時刻不明"


@dataclass(frozen=True)
class Stamp:
    """1 件の時刻。

    `display` は必ず原文のまま。`sort` は比較用の実時刻（UTC 秒）で、
    タイムゾーンの指定がある行はその分を戻す。指定が無い行は現場時刻を
    そのまま秒へ直す。

    `basis` は「どの基準で測った時刻か」を表す札である。真偽値では足りない。
    タイムゾーンの無い 2 行を「どちらも基準不明だから比較できる」と扱うと、
    別々の端末の、別々にずれた時計を並べて前後を論じることになる。

      "utc"          … タイムゾーンが書かれている。どのログの記録とも比べられる。
      "local:<出典>" … 書かれていない。同じログの中でだけ比べられる。
      ""             … 時刻そのものが読めなかった。何とも比べられない。

    `comparable` は `basis == "utc"` の言い換え。画面が「基準不明」の印を
    出すかどうかに使う。
    """

    display: str
    sort: float
    comparable: bool
    basis: str = ""

    @property
    def known(self) -> bool:
        return self.sort != UNKNOWN_SORT

    def as_json(self) -> dict:
        return {
            "display": self.display if self.known else UNKNOWN_LABEL,
            "known": self.known,
            "comparable": self.comparable,
            "basis": self.basis,
        }


UNKNOWN = Stamp(display=UNKNOWN_LABEL, sort=UNKNOWN_SORT, comparable=False,
                basis="")


def _plausible(mon, day, hh, mm, ss) -> bool:
    """暦として成り立つ値か。

    正規表現は桁数しか見ないので、`13/45/2022 99:99:99` も通ってしまう。
    そのまま数値へ直すと、ありえない時刻が並べ替えの中へ紛れ込み、「読めた
    時刻」として扱われる。読めなかったものは読めなかったと言う。
    """
    return (
        1 <= mon <= 12
        and 1 <= day <= 31
        and 0 <= hh <= 23
        and 0 <= mm <= 59
        and 0 <= ss <= 60  # 閏秒を拒まない
    )


def _seconds(year, mon, day, hh, mm, ss, frac, tz) -> float | None:
    """暦の値を、実際の経過秒へ。暦として存在しない日なら None。

    以前は `((year*12+mon)*31+day)*24*3600` という便宜的な写像を使っていた。
    順序を決めるだけなら足りるが、差が実際の秒数にならない。月をまたぐ 2 件の
    差が 1 か月分ずれ、日をまたぐと 1 日分ずれる。「同一端末で 34 秒以内」と
    いう相関理由を出すには、差そのものが正しくなければならない。

    閏秒（ss=60）は暦の側で受け付けられないので、59 秒 + 1 秒として写す。
    表示は原文のままなので、画面には 60 秒と出る。
    """
    extra = 0.0
    if ss == 60:
        ss, extra = 59, 1.0
    try:
        base = datetime(year, mon, day, hh, mm, ss, tzinfo=timezone.utc)
    except ValueError:
        # 2 月 31 日のような、桁数は正しいが存在しない日。読めなかったと言う。
        return None
    total = base.timestamp() + (frac or 0) + extra
    if tz:
        sign = -1 if tz[0] == "-" else 1
        offset = sign * (int(tz[1:3]) * 3600 + int(tz[3:5]) * 60)
        total -= offset
    return float(total)


def _basis(tz: str | None, source: str) -> str:
    """この時刻をどの基準で測ったか。詳しくは `Stamp` の説明を参照。

    タイムゾーンが無く、出典も分からない行は、何とも比べられない。出典が
    分かれば、少なくとも同じログの中では同じ時計で測られていると言える。
    """
    if tz:
        return "utc"
    return f"local:{source}" if source else ""


def parse_itm2(line: str, source: str = "") -> Stamp:
    """InfoTrace Mark II の行頭から時刻を読む。

    `source` はその行の出どころ（ログの論理パス）。タイムゾーンが書かれて
    いない行の比較基準を決めるのに使う。
    """
    m = _ITM2_TS.match(line or "")
    if not m:
        return UNKNOWN
    g = m.groupdict()
    mon, day = int(g["mon"]), int(g["day"])
    hh, mm_, ss = int(g["hh"]), int(g["mm"]), int(g["ss"])
    if not _plausible(mon, day, hh, mm_, ss):
        return UNKNOWN
    frac = float(f"0.{g['frac']}") if g.get("frac") else 0.0
    sort = _seconds(
        int(g["year"]), mon, day, hh, mm_, ss, frac, g.get("tz"),
    )
    if sort is None:
        return UNKNOWN
    return Stamp(
        display=m.group(0).strip(),
        sort=sort,
        comparable=bool(g.get("tz")),
        basis=_basis(g.get("tz"), source),
    )


def parse_proxy(stamp: str, source: str = "") -> Stamp:
    """`[...]` の中身として取り出された時刻文字列を読む。"""
    m = _PROXY_TS.match((stamp or "").strip())
    if not m:
        return UNKNOWN
    g = m.groupdict()
    mon = _MONTHS.get(g["mon"].title())
    if mon is None:
        return UNKNOWN
    if not _plausible(mon, int(g["day"]), int(g["hh"]), int(g["mm"]), int(g["ss"])):
        return UNKNOWN
    sort = _seconds(
        int(g["year"]), mon, int(g["day"]),
        int(g["hh"]), int(g["mm"]), int(g["ss"]), 0.0, g.get("tz"),
    )
    if sort is None:
        return UNKNOWN
    return Stamp(
        display=m.group(0).strip(),
        sort=sort,
        comparable=bool(g.get("tz")),
        basis=_basis(g.get("tz"), source),
    )


def order_key(entry: dict) -> tuple:
    """時系列の並べ替えキー。

    時刻だけでは足りない。同じ秒に複数の記録が並ぶことは普通にあり、そこで
    順序が入力順に依存すると、同じ ZIP から作り直すたびに教材が変わる。
    出典・行番号・証拠 ID を二次キーにして、入力の並びに関わらず同じ結果に
    なるようにする。時刻不明は末尾へ。
    """
    stamp = entry.get("_stamp") or UNKNOWN
    return (
        0 if stamp.known else 1,
        stamp.sort if stamp.known else 0.0,
        entry.get("member", ""),
        entry.get("line", 0),
        entry.get("evidenceId", ""),
    )
