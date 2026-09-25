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

ログ形式ごとの時刻の書き方（正規表現）はここに置かない。各パーサーが自分の
形式から年・月・日・時刻・タイムゾーンを取り出し、`stamp()` で `Stamp` に
する。ここが持つのは、形式に依らない「暦として正しいか」「実際の秒数」
「比較の基準」の三つだけである。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

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


def stamp(year: int, mon: int, day: int, hh: int, mm: int, ss: int,
          frac: float, tz: str | None, display: str, source: str = "") -> Stamp:
    """パーサーが取り出した暦の値から `Stamp` を作る。

    `display` はログに書かれていたとおりの表記。`tz` は `+0900` のような
    オフセットで、書かれていなければ None。`source` はその行の論理パスで、
    タイムゾーンの無い行の比較基準に使う。

    暦として成り立たない値（13 月、2 月 31 日など）は読めなかったことにする。
    桁数の揃った数字であっても、存在しない時刻を並べ替えへ紛れ込ませない。
    """
    if not _plausible(mon, day, hh, mm, ss):
        return UNKNOWN
    sort = _seconds(year, mon, day, hh, mm, ss, frac, tz)
    if sort is None:
        return UNKNOWN
    return Stamp(
        display=display,
        sort=sort,
        comparable=bool(tz),
        basis=_basis(tz, source),
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
