"""parsers/proxy.py — Squid 形式のプロキシアクセスログ。

    192.0.2.10 - - [14/Oct/2022:16:45:10 +0900] "CONNECT host:443 HTTP/1.1" 200 1588

行頭が要求元のアドレス、`[...]` が時刻、引用符の中が要求（方式と宛先）、
その後ろが応答の番号。この形式の知識はこのファイルに置く。

なお、Web サーバーのアクセスログ（Apache の combined 形式など）も行の形は
ほぼ同じで、`_LINE` に当たってしまう。ただし意味は逆で、行頭は「サーバーへ
要求してきた相手」であり、端末から外部への通信ではない。プロキシの記録と
して教材化すると、サーバーへのアクセスを「外部へ出ていった通信」と教えて
しまう。

行の形では区別できないので、要求の書き方で区別する。プロキシへの要求は
宛先を丸ごと書く（`GET http://host/path`、`CONNECT host:443`）。Web
サーバーへの要求はパスだけを書く（`GET /index.html`）。

  * 検出（`detect`）は、プロキシ形の要求が 1 行以上あり、パスだけの要求が
    1 行も無いときに限って「読める」と答える。混ざっていれば、どちらとも
    断定せず 0 を返す（入力ソースは「形式を判別できなかったログ」として
    報告される）。Web サーバーのログには、開いたプロキシを探す走査が
    `GET http://...` を送ってくることがあるので、「1 行でもプロキシ形が
    あれば」では足りない。
  * 解析（`parse`）も、プロキシ形の要求の行だけをイベントにする。

ただし、宛先を丸ごと書いた要求（absolute-form）も、プロキシの証明には
ならない。HTTP の仕様は、通常の Web サーバーにも absolute-form の要求を
受け付けることを求めている（RFC 9112 §3.2.2）。`GET http://web.example/`
だけから成る Web サーバーのログは、上の検査をすべて通る。この形式の 1 行
からは、通信の向き（端末から外へ出たのか、外からサーバーへ来たのか）を
決められない。

そこで、このパーサーは自動判定に参加しない（`AUTO_DETECT = False`）。
プロファイルが `parsers` に `proxy` を書いたとき、つまり「このデータセット
のこのログはプロキシの記録だ」と人が明示したときだけ使う。プロファイル
0 件の標準構成では使われず、読めそうだったログは「通信の向きを断定
できないログ」として報告される（`ParsedSources.explicit_only`）。
上の書き方の検査は、明示されたときの防御として残す。
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

ID = "proxy"

_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\w+) (?P<target>\S+)[^"]*" '
    r'(?P<status>\d{3})'
)

#: 検出用。行ごとに `_LINE` を当てるのと同じ条件を、本文全体への 1 回の
#: 検索で見る。`[^\]]` と `[^"]` は改行をまたげるので誤検出は起こりうるが、
#: 取りこぼし（1 行でも当たる本文で 0 を返すこと）は起こらない。誤検出は
#: 解析で 0 件になるだけで害が無い。
_DETECT = re.compile(
    r'^\S+ \S+ \S+ \[[^\]]+\] "\w+ \S+[^"]*" \d{3}', re.M
)

#: `[05/Oct/2022:14:00:07 +0900]` の中身。
_TS = re.compile(
    r"^(?P<day>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):"
    r"(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})"
    r"(?:\s*(?P<tz>[+-]\d{4}))?"
)

_MONTHS = {
    m: i + 1
    for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())
}


#: 宛先を丸ごと書いた要求（absolute-form）。`http://…`、`ftp://…` など。
_ABSOLUTE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://\S")
#: CONNECT の宛先（authority-form）。`host:443`、`[2001:db8::1]:443`。
_AUTHORITY = re.compile(r"^(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):\d{1,5}$")


def request_form(method: str, dest: str) -> str:
    """要求の書き方。"proxy"（プロキシ宛て）、"origin"（Web サーバー宛て）、"other"。"""
    if method.upper() == "CONNECT":
        return "proxy" if _AUTHORITY.match(dest) else "other"
    if _ABSOLUTE.match(dest):
        return "proxy"
    if dest.startswith("/") or dest == "*":
        return "origin"
    return "other"


def parse_timestamp(stamp: str, source: str = "") -> timeline.Stamp:
    """`[...]` の中身として取り出された時刻文字列を読む。"""
    m = _TS.match((stamp or "").strip())
    if not m:
        return timeline.UNKNOWN
    g = m.groupdict()
    mon = _MONTHS.get(g["mon"].title())
    if mon is None:
        return timeline.UNKNOWN
    return timeline.stamp(
        year=int(g["year"]), mon=mon, day=int(g["day"]),
        hh=int(g["hh"]), mm=int(g["mm"]), ss=int(g["ss"]),
        frac=0.0, tz=g.get("tz"), display=m.group(0).strip(), source=source,
    )


def client(excerpt: str) -> str:
    """行が示す要求元。行頭の 1 語。"""
    return excerpt.split(" ", 1)[0] if excerpt else ""


def target(excerpt: str) -> str:
    """行が示す宛先。要求元を除いた、宛先らしい最初の語。

    抜粋の末尾が切り詰められていると宛先が残らないことがある。その場合は
    空を返し、呼び出し側は「読めない」として扱う。
    """
    if " " not in (excerpt or ""):
        return ""
    who = client(excerpt)
    for token in excerpt.split():
        if "://" in token or token.count(".") >= 2:
            if token != who:
                return token
    return ""


class ProxyParser(Parser):
    id = ID
    label = "Proxy（通信の記録）"
    # 内容だけではプロキシの記録と言い切れない。プロファイルでの明示が要る。
    AUTO_DETECT = False

    RECORD_NOUNS = {"network": "プロキシの記録"}
    ABOUTS = {
        "network": "プロキシは端末と外部の間に立つため、どの端末がどこへ繋いだかが残ります。",
    }
    FACT_TEXTS = {
        ("network", "client"): FactText(
            where="プロキシの記録は、行の先頭に要求元のアドレスを書きます。",
        ),
    }

    def detect(self, source: InputSource) -> float:
        """プロキシのログだと言い切れるときだけ 1。曖昧なら 0。"""
        if not _DETECT.search(source.text):
            return 0.0   # 1 行も当たらない本文は、行ごとに見るまでもない
        proxy_form = False
        for line in source.lines(MAX_LINES):
            m = _LINE.match(line)
            if not m:
                continue
            form = request_form(m.group("method"), m.group("target"))
            if form == "origin":
                # Web サーバーが受けた要求。1 行でもあれば断定しない。
                return 0.0
            proxy_form = proxy_form or form == "proxy"
        return 1.0 if proxy_form else 0.0

    def parse(self, source: InputSource, evidence_store=None) -> list[NormalizedEvent]:
        out: list[NormalizedEvent] = []
        memo: dict[str, frozenset] = {}
        name = source.name
        for line_no, line in enumerate(source.lines(MAX_LINES), 1):
            m = _LINE.match(line)
            if not m:
                continue
            ip, method, dest = m.group("ip"), m.group("method"), m.group("target")
            if request_form(method, dest) != "proxy":
                continue   # プロキシ宛ての要求と言えない行は、通信として扱わない
            keys = memo.get(ip)
            if keys is None:
                keys = memo[ip] = clean_host_keys([ip])
            out.append(NormalizedEvent(
                kind="network", action="request",
                timestamp=parse_timestamp(m.group("ts"), name),
                host=ip, summary=f"{ip} -> {method} {dest}",
                source=source_of(name, line_no, line), parser_id=ID,
                attributes={
                    "client": ip, "method": method, "target": dest,
                    "status": m.group("status"),
                },
                correlation_keys=keys,
            ))
        return out

    def reread(self, kind: str, fact: str, excerpt: str) -> FactReading | None:
        if kind != "network":
            return None
        if fact == "client":
            value = client(excerpt)
        elif fact == "target":
            value = target(excerpt)
        else:
            return None
        return FactReading(value=value, field="行頭の要求元" if fact == "client" else "要求の宛先") \
            if value else None


PARSER = ProxyParser()
