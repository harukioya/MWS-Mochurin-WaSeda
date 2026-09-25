"""parsers/itm2.py — InfoTrace Mark II クライアントログ。

1 行が 1 件の記録で、空白区切りの `key=value`（値は引用符で囲まれることが
ある）が並ぶ。

    10/14/2022 16:45:10.750 +0900 ... evt=ps subEvt=start com="WS01"
    psPath="C:\\Windows\\System32\\cmd.exe" cmd="cmd.exe /c ..."

この形式の知識（項目名、時刻の書き方、どの `evt`/`subEvt` が何を意味するか、
項目名を使った解説文）は、すべてこのファイルに置く。教材生成は、ここが
返す正規化イベントと、`reread()` の答えしか見ない。

項目の意味:

  com        記録を残した端末の名前
  ip         その端末のアドレス（カンマ区切りで複数のことがある）
  evt/subEvt 記録の種類。ps/start はプロセス開始、file/create・write は
             ファイルの作成と書き込み、reg はレジストリ
  psPath     起動したプロセスの実行ファイル。親は parentPath
  path       ファイル・レジストリの対象。起動記録では psPath が空のとき
             の代わりに使う
  cmd        起動時に渡された引数列
"""

from __future__ import annotations

import re

import timeline

from .base import (
    MAX_LINES,
    FactReading,
    FactText,
    InputSource,
    NormalizedEvent,
    Parser,
    clean_host_keys,
    source_of,
)

ID = "itm2"

#: この形式の行に必ず現れる印。検出と解析の両方でこれを見る。
MARKER = "type=ITM2"

#: key=value。値は "引用" か、空白までの素の並び。
_KV = re.compile(r'(\w+)=("([^"]*)"|[^\s]*)')

#: 行頭の時刻。`10/05/2022 14:00:27.738 +0900`
_TS = re.compile(
    r"^(?P<mon>\d{2})/(?P<day>\d{2})/(?P<year>\d{4})\s+"
    r"(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})(?:\.(?P<frac>\d{1,6}))?"
    r"(?:\s*(?P<tz>[+-]\d{4}))?"
)

#: 事象として取り出す種類。`(evt, subEvt の集合)` から正規化の種別へ。
#: None は subEvt を問わない。ここに当たらない行は種別 `other` になり、
#: 件数と端末の集計にだけ使われる。
_KINDS = (
    ("ps", ("start",), "process"),
    ("file", ("create", "write"), "file"),
    ("reg", None, "registry"),
)

#: 種別ごとの要約の作り方。表示・設問・相関で同じ文言になるよう、ここ
#: 一か所で作る。
_SUMMARY = {
    "process": "{host}: {target} を起動",
    "file": "{host}: {target} に書き込み",
    "registry": "{host}: {target} を設定",
}

_NO_ATTRIBUTES: dict[str, str] = {}


def parse_timestamp(line: str, source: str = "") -> timeline.Stamp:
    """行頭から時刻を読む。原文の表記はそのまま表示に使う。

    `source` はその行の論理パス。タイムゾーンが書かれていない行の比較
    基準（同じログの中でだけ比べられる）を決めるのに使う。
    """
    m = _TS.match(line or "")
    if not m:
        return timeline.UNKNOWN
    g = m.groupdict()
    return timeline.stamp(
        year=int(g["year"]), mon=int(g["mon"]), day=int(g["day"]),
        hh=int(g["hh"]), mm=int(g["mm"]), ss=int(g["ss"]),
        frac=float(f"0.{g['frac']}") if g.get("frac") else 0.0,
        tz=g.get("tz"), display=m.group(0).strip(), source=source,
    )


def field_in(text: str, key: str) -> str:
    """key=value 形式の 1 行から、その項目の値を読む。無ければ空。"""
    for m in _KV.finditer(text or ""):
        if m.group(1) == key:
            return (m.group(3) if m.group(3) is not None else m.group(2)) or ""
    return ""


def _basename(path: str) -> str:
    return path.rsplit("\\", 1)[-1] if path else ""


def program_reading(excerpt: str) -> FactReading | None:
    """抜粋が示す「起動したプロセス」の実行ファイル名と、読んだ項目。

    表示（要約）と同じ順序で読む。psPath、無ければ path。表示・設問・
    根拠・ATT&CK の四つが同じ項目を見ていなければ、示した記録が主張を
    裏付けているとは言えない。
    """
    for key in ("psPath", "path"):
        raw = field_in(excerpt, key)
        if raw:
            return FactReading(value=_basename(raw), field=key)
    return None


def program_name(excerpt: str) -> str:
    """`program_reading` の値だけ。読めなければ空文字。"""
    reading = program_reading(excerpt)
    return reading.value if reading else ""


def _kind_of(rec: dict) -> str:
    evt, sub = rec.get("evt", ""), rec.get("subEvt", "")
    for want_evt, subs, kind in _KINDS:
        if evt == want_evt and (subs is None or sub in subs):
            return kind
    return "other"


class Itm2Parser(Parser):
    id = ID
    label = "InfoTrace Mark II（端末の記録）"

    ABOUTS = {
        "process": (
            "これは端末で起きたことを逐一書き留めた記録で、プログラムが起動する"
            "たびに、実行ファイルの場所と起動元が残ります。"
        ),
    }

    FACT_TEXTS = {
        ("process", "program_name"): FactText(
            where="プロセスの起動記録には、実行ファイルの完全なパスが `{field}` として残ります。",
            next="この行の `cmd` に渡された引数と、`rcCom` の接続元を確かめる",
        ),
        ("process", "host"): FactText(
            where="`{field}` が、その記録を残した端末の名前です。",
        ),
        ("file", "path"): FactText(
            where="`{field}` に、書き込まれたファイルの完全なパスが残ります。",
        ),
        ("file", "host"): FactText(
            where="端末名は `{field}` にあります。",
        ),
    }

    def detect(self, source: InputSource) -> float:
        # 解析と同じ印を見る。印の無い入力からは 1 件も取り出せないので、
        # ここで 0 を返しても取りこぼしは起きない。
        return 1.0 if MARKER in source.text else 0.0

    def parse(self, source: InputSource, evidence_store=None) -> list[NormalizedEvent]:
        out: list[NormalizedEvent] = []
        # 端末キーの集合は端末ごとに使い回す。ログに出てくる端末は数台なので、
        # 行ごとに新しい集合を作ると、その分だけ無駄に積み上がる。
        memo: dict[tuple[str, str], frozenset] = {}
        name = source.name
        for line_no, line in enumerate(source.lines(MAX_LINES), 1):
            if MARKER not in line:
                continue
            rec: dict[str, str] = {}
            for m in _KV.finditer(line):
                rec[m.group(1)] = m.group(3) if m.group(3) is not None else m.group(2)
            if not rec:
                continue
            kind = _kind_of(rec)
            host = rec.get("com", "?")
            com, ip = rec.get("com", ""), rec.get("ip") or ""
            keys = memo.get((com, ip))
            if keys is None:
                keys = memo[(com, ip)] = clean_host_keys([com] + ip.split(","))
            # 原文のまま保つ。タイムゾーンを勝手に直すと、画面と原文が食い違う。
            stamp = parse_timestamp(line, name)
            src = source_of(name, line_no, line)

            if kind == "process":
                # 起動したプロセスは psPath。親は parentPath で別に記録される。
                # 両方が埋まっている記録で path を先に読むと、表示と設問が
                # 別の値を指す。ここが起動プロセスの唯一の出所。
                program = rec.get("psPath") or rec.get("path") or ""
                attrs = {
                    "program": program,
                    "program_name": _basename(program),
                    "command_line": rec.get("cmd", ""),
                    "parent": rec.get("parentPath", ""),
                }
                action, target = "start", program
            elif kind in ("file", "registry"):
                target = rec.get("path", "")
                attrs = {"path": target}
                if kind == "file":
                    attrs["name"] = _basename(target)
                action = rec.get("subEvt", "") or kind
            else:
                out.append(NormalizedEvent(
                    kind="other", action=rec.get("subEvt", ""), timestamp=stamp,
                    host=host, summary="", source=src, parser_id=ID,
                    attributes=_NO_ATTRIBUTES, correlation_keys=keys,
                ))
                continue

            out.append(NormalizedEvent(
                kind=kind, action=action, timestamp=stamp, host=host,
                summary=_SUMMARY[kind].format(host=host, target=target),
                source=src, parser_id=ID, attributes=attrs,
                correlation_keys=keys,
            ))
        return out

    def reread(self, kind: str, fact: str, excerpt: str) -> FactReading | None:
        """保存済みの抜粋から読み直す。抜粋に無い項目は「読めない」と答える。

        解析済みの属性ではなく抜粋から読むのが要点。属性は行全体から作って
        いるので、長い行では抜粋の外にある項目まで持っている。そちらを根拠に
        すると、示した抜粋に書かれていないことを「この 1 行に書いてある」と
        言うことになる。
        """
        if kind == "process" and fact == "program_name":
            return program_reading(excerpt)
        if fact == "command_line" and kind == "process":
            key = "cmd"
        elif fact == "host" and kind in ("process", "file", "registry"):
            key = "com"
        elif fact == "path" and kind in ("file", "registry"):
            key = "path"
        else:
            return None
        value = field_in(excerpt, key)
        return FactReading(value=value, field=key) if value else None


PARSER = Itm2Parser()
