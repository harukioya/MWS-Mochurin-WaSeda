"""explain.py — turn real MWS artifacts into lessons the existing player renders.

The teaching layer already works: `js/player.js` walks stages, `js/quiz.js`
gates each one, `js/recap.js` draws the kill chain. All this module has to do
is produce the same JSON shape from real data instead of hand-written examples.

Two log formats appear in the MWS Cup DFIR sets:

  * INFOTRACE MARK II (ITM2) endpoint logs -- space-separated `key=value`
    pairs with quoted values, one event per line:
        10/14/2022 16:45:10.750 +0900 ... evt=file subEvt=close com="DC01"
        psPath="C:\\Windows\\system32\\svchost.exe" path="C:\\..."
  * SQUID-style proxy logs -- Apache-ish combined format:
        172.16.1.102 - - [14/Oct/2022:16:45:10 +0900] "CONNECT host:443 ..." 200

HONESTY RULE (BUILD-CONTRACT rule 8). An ATT&CK technique is attached only
where the evidence is unambiguous on its face -- a PowerShell process start is
T1059.001 because that is what the field says. Everything else is left untagged
rather than guessed at. A generated lesson is a DRAFT for an instructor to
check, and says so in its own metadata; a confidently wrong technique tag in a
teaching tool is worse than no tag.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter

# key=value, value either "quoted" or bare-until-space
_KV = re.compile(r'(\w+)=("([^"]*)"|[^\s]*)')
_PROXY = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\w+) (?P<target>\S+)[^"]*" '
    r'(?P<status>\d{3})'
)

#: Only patterns whose mapping is unambiguous from the field itself.
_PROCESS_ATTCK = {
    "powershell.exe": ("T1059.001", "Command and Scripting Interpreter: PowerShell"),
    "pwsh.exe": ("T1059.001", "Command and Scripting Interpreter: PowerShell"),
    "cmd.exe": ("T1059.003", "Command and Scripting Interpreter: Windows Command Shell"),
    "wscript.exe": ("T1059.005", "Command and Scripting Interpreter: Visual Basic"),
    "cscript.exe": ("T1059.005", "Command and Scripting Interpreter: Visual Basic"),
    "mshta.exe": ("T1218.005", "System Binary Proxy Execution: Mshta"),
    "rundll32.exe": ("T1218.011", "System Binary Proxy Execution: Rundll32"),
    "regsvr32.exe": ("T1218.010", "System Binary Proxy Execution: Regsvr32"),
    "certutil.exe": ("T1140", "Deobfuscate/Decode Files or Information"),
    "vssadmin.exe": ("T1490", "Inhibit System Recovery"),
    "bcdedit.exe": ("T1490", "Inhibit System Recovery"),
    "net.exe": ("T1087", "Account Discovery"),
    "whoami.exe": ("T1033", "System Owner/User Discovery"),
    "systeminfo.exe": ("T1082", "System Information Discovery"),
    "schtasks.exe": ("T1053.005", "Scheduled Task/Job: Scheduled Task"),
}


def parse_itm2(text: str, limit: int = 200_000) -> list[dict]:
    """Parse InfoTrace Mark II lines into dicts. Unparseable lines are skipped."""
    out = []
    for line in text.split("\n")[:limit]:
        if "type=ITM2" not in line:
            continue
        rec = {}
        for m in _KV.finditer(line):
            rec[m.group(1)] = m.group(3) if m.group(3) is not None else m.group(2)
        if rec:
            rec["_ts"] = line[:23]
            out.append(rec)
    return out


def parse_proxy(text: str, limit: int = 200_000) -> list[dict]:
    out = []
    for line in text.split("\n")[:limit]:
        m = _PROXY.match(line)
        if m:
            out.append(m.groupdict())
    return out


def _is_external(host: str) -> bool:
    """True for a routable address. Private/loopback targets are lateral, not exfil."""
    host = host.split(":")[0]
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return True  # a hostname; treat as external
    return not (addr.is_private or addr.is_loopback or addr.is_link_local)


def _event(kind: str, detail: str, attck: tuple[str, str] | None = None) -> dict:
    ev = {"type": kind, "detail": detail[:400]}
    if attck:
        ev["attck"] = {"id": attck[0], "name": attck[1]}
    return ev


#: 1 段階に載せる事象の数。
STAGE_EVENTS = 8


def _pick(events: list[dict], limit: int = STAGE_EVENTS) -> list[dict]:
    """段階に載せる事象を選ぶ。根拠の付いたものを先に取る。

    単純な先頭 n 件だと、実データでは起動直後のシステムプロセス
    （smss.exe、csrss.exe、winlogon.exe …）だけで埋まる。本番の問題ログは
    時系列で始まるため、調査対象になる事象は必ず後ろにあり、先頭を切り取る
    と教材から丸ごと抜け落ちる。

    ATT&CK の対応が付いた事象は「根拠を説明できる」と判断済みのものなので、
    それを優先する。各群の中では元の時系列を保つので、同じ入力からは同じ
    並びになる。
    """
    tagged = [e for e in events if "attck" in e]
    rest = [e for e in events if "attck" not in e]
    return (tagged + rest)[:limit]


def events_from_itm2(records: list[dict]) -> list[dict]:
    """Turn parsed records into lesson events, most interesting first."""
    events: list[dict] = []
    seen: set[str] = set()
    for r in records:
        evt, sub = r.get("evt", ""), r.get("subEvt", "")
        host = r.get("com", "?")
        if evt == "ps" and sub == "start":
            path = r.get("path") or r.get("psPath") or ""
            exe = path.rsplit("\\", 1)[-1].lower()
            key = f"ps:{host}:{exe}"
            if key in seen:
                continue
            seen.add(key)
            events.append(
                _event("process", f"{host}: {path} を起動", _PROCESS_ATTCK.get(exe))
            )
        elif evt == "file" and sub in ("create", "write"):
            path = r.get("path", "")
            key = f"file:{host}:{path.rsplit(chr(92), 1)[-1]}"
            if key in seen or not path:
                continue
            seen.add(key)
            events.append(_event("file", f"{host}: {path} に書き込み"))
        elif evt == "reg":
            path = r.get("path", "")
            if not path or f"reg:{path}" in seen:
                continue
            seen.add(f"reg:{path}")
            attck = None
            if "CurrentVersion\\Run" in path:
                attck = ("T1547.001", "Boot or Logon Autostart: Registry Run Keys")
            events.append(_event("registry", f"{host}: {path} を設定", attck))
    return events


def events_from_proxy(records: list[dict]) -> list[dict]:
    events, seen = [], set()
    external = [r for r in records if _is_external(r["target"])]
    for r in external:
        target = r["target"]
        base = target.split("/")[0] if "//" not in target else target.split("/")[2]
        if base in seen:
            continue
        seen.add(base)
        # DELIBERATELY UNTAGGED. An earlier version mapped POST/PUT to T1041
        # (Exfiltration Over C2) and GET/CONNECT to T1071.001, which labelled
        # `POST http://go.microsoft.com/fwlink/?` as exfiltration. The HTTP
        # method carries no intent, and tagging every external request as
        # "application layer protocol" tags ordinary browsing. Deciding which
        # of these destinations matters IS the analytical work, so the lesson
        # presents the observations and asks, rather than pre-answering wrongly.
        events.append(_event("network", f'{r["ip"]} -> {r["method"]} {target}'))
    return events


def _exe_of(event: dict) -> str:
    """事象の説明文から実行ファイル名だけを取り出す。設問に埋め込むため。"""
    return event["detail"].rsplit(" を起動", 1)[0].rsplit("\\", 1)[-1]


def _stage_endpoint(itm2: list[dict], procs: list[dict], hosts: Counter) -> dict:
    """段階1：端末で何が動いたか。

    設問は、一覧に実際に出ているものを指して問う。「最も有力な手がかりはどれ
    か」のような抽象的な問い方だと、何と何を比べればよいのかが示されないため。
    """
    tagged = [e for e in procs if "attck" in e]
    if tagged:
        exe = _exe_of(tagged[0])
        quiz = {
            "q": (
                f"上の一覧には、Windows が普段から動かしているプログラムが並んでいます。"
                f"その中で {exe} だけに印が付いているのはなぜでしょうか。"
            ),
            "options": [
                "このプログラムは Windows の標準構成には含まれておらず、攻撃者が持ち込んだものだから",
                "正規のプログラムだが、他のプログラムを呼び出して動かせるため、"
                "攻撃者が実行ファイルを持ち込まずに済ませる手段になるから",
                "他のプログラムより新しく、まだ十分に検証されていないから",
                "起動した回数が他より多く、負荷の原因になっているから",
            ],
            "correct": 1,
            "explain": (
                f"{exe} は Windows に最初から入っている正規のプログラムです。"
                "攻撃者にとっての価値は、まさにそこにあります。"
                "自前の実行ファイルを置けば見つかりやすくなりますが、"
                "元からあるものを使えば、記録の上では普段の動作に紛れます。"
                "この手口は「環境にあるもので済ませる（living off the land）」と"
                "呼ばれ、対策製品を避ける定番の方法です。\n\n"
                f"したがって、{exe} が起動したこと自体は異常ではありません。"
                "問うべきは「何を実行させたか」と「誰が起動したか」で、"
                "そのためには次の段階以降で、書き込まれたファイルや通信を"
                "突き合わせる必要があります。"
            ),
        }
    else:
        quiz = {
            "q": (
                "この一覧には、監視エージェントが起動を記録したプログラムが並んでいます。"
                "調査を進めるとき、ここから何が得られるでしょうか。"
            ),
            "options": [
                "どのプログラムが危険かの判定結果",
                "端末で起きたことの時系列の骨組み。書き込みや通信は、"
                "そのとき動いていたプロセスに結び付けて読む",
                "各プログラムが使ったメモリ量の比較",
                "利用者がどの操作を意図して行ったかの記録",
            ],
            "correct": 1,
            "explain": (
                "プロセスの起動記録は、端末の時系列の骨組みです。"
                "ファイルが書き込まれた、レジストリが変更された、通信が発生した——"
                "これらはいずれも、そのとき動いていた何かの結果です。"
                "起動記録があって初めて、後の事象を「誰がやったか」に結び付けられます。\n\n"
                "この一覧自体は危険かどうかの判定ではありません。"
                "普段どおりのものが大半で、そこから外れるものを見つけるのが分析です。"
            ),
        }

    return {
        "id": "endpoint",
        "name": "端末 — 何が実行されたか",
        "intro": (
            f"監視下の {len(hosts)} 台から、{len(itm2)} 件の記録が集まっています。"
            "これは端末で起きたことを逐一書き留めた記録で、プログラムが起動する"
            "たびに、実行ファイルの場所と起動元が残ります。\n\n"
            "ただし、正常に動いている Windows でも記録は絶えず増えます。"
            "以下は重複を除いた「起動したプログラムの種類」の一覧です。"
            "大半は Windows 自身が動かすもので、その中から注意すべきものを"
            "見分けるのがここでの課題です。"
        ),
        "events": _pick(procs),
        "quiz": quiz,
    }


def _stage_files(files: list[dict]) -> dict:
    """段階2：ディスク上で何が変わったか。"""
    sample = files[0]["detail"].rsplit(" に書き込み", 1)[0].split(": ", 1)[-1]
    return {
        "id": "files",
        "name": "ファイル — ディスク上で何が変わったか",
        "intro": (
            "同じ記録には、ファイルの作成と書き込みも残ります。"
            "ここで見るべきなのは中身ではなく、置かれた場所です。"
            "内容が同じファイルでも、どこに置かれたかによって意味が変わるためです。\n\n"
            "たとえば一時フォルダにあれば、何かの準備のために置かれた可能性があります。"
            "自動起動の設定に関わる場所にあれば、再起動後も動き続けるための仕込みです。"
            "システムの中枢にあれば、それを書き込めた権限そのものが問題になります。"
        ),
        "events": _pick(files),
        "quiz": {
            "q": (
                f"たとえば {sample[:60]} のような記録から、"
                "分析者はまず何を読み取ろうとするでしょうか。"
            ),
            "options": [
                "ファイルの大きさから、中身がどれだけ重要かを見積もる",
                "置かれた場所から、その書き込みが何を意図したものかを推し量る",
                "ファイル名の文字数から、自動生成されたものかを判別する",
                "拡張子から、安全なファイルかどうかを確定させる",
            ],
            "correct": 1,
            "explain": (
                "場所が意図を語ります。一時フォルダは準備段階、"
                "自動起動に関わる場所は常駐化、システムディレクトリは権限の問題——"
                "同じ内容でも、置かれた場所で読み方が変わります。\n\n"
                "拡張子で確定させないでください。名前は書き手が自由に付けられるもので、"
                "中身を保証しません。この道具が拡張子ではなく先頭のデータで種別を"
                "判定しているのも、同じ理由です。"
            ),
        },
    }


def _stage_network(proxy: list[dict], network: list[dict]) -> dict:
    """段階3：外部へ何が出ていったか。"""
    return {
        "id": "network",
        "name": "通信 — 外部へ何が出ていったか",
        "intro": (
            f"プロキシの記録 {len(proxy)} 件から、外部の宛先 {len(network)} 箇所を"
            "取り出しました。プロキシは端末と外部の間に立つため、"
            "どの端末がどこへ繋いだかが残ります。\n\n"
            "ただし通信の中身は分かりません。暗号化されていれば、"
            "プロキシに見えるのは「いつ・どこへ・どれだけ」だけです。"
            "以下の一覧に印を付けていないのは、そのためです。"
            "この中のどれが業務上の通常の通信で、どれがそうでないかは、"
            "一行ずつ見ても決まりません。"
        ),
        "events": _pick(network),
        "quiz": {
            "q": (
                "上の宛先のうち、どれが調査に値するかを判断したいとします。"
                "一行だけを見て決められないのはなぜでしょうか。"
            ),
            "options": [
                "プロキシの記録には宛先が書かれていないから",
                "一度の通信は、それ単体では普通の通信と区別が付かない。"
                "手がかりになるのは、同じ宛先への通信が一定の間隔で繰り返される"
                "といった、複数行にまたがる形のほう",
                "暗号化された通信はプロキシの記録に一切残らないから",
                "外部の宛先はすべて等しく危険であり、区別する意味がないから",
            ],
            "correct": 1,
            "explain": (
                "取引先への POST が情報の持ち出しとは限らず、"
                "配信網への接続が指令通信とも限りません。"
                "一行だけでは、ほぼ何も決まりません。\n\n"
                "外部との定期的なやり取りを見分ける手がかりになるのは、繰り返しの形です。"
                "決まった間隔、単一の宛先、その端末の普段の動きと合わない時間帯——"
                "中身が読めなくても、こうした形は残ります。"
                "だからこそ、内容を記録できない場合でも接続の記録は取られます。\n\n"
                "この演習が各行に判定を付けていないのは、"
                "どれが問題かを決めること自体が、ここで身に付ける作業だからです。"
            ),
        },
    }


def build_lesson(name: str, sources: dict[str, str], lesson_id: str) -> dict | None:
    """Build a draft lesson from {member name: text} of one or more logs."""
    itm2: list[dict] = []
    proxy: list[dict] = []
    for text in sources.values():
        itm2 += parse_itm2(text)
        proxy += parse_proxy(text)
    if not itm2 and not proxy:
        return None

    stages = []
    endpoint = events_from_itm2(itm2)
    network = events_from_proxy(proxy)
    hosts = Counter(r.get("com", "?") for r in itm2)

    procs = [e for e in endpoint if e["type"] == "process"]
    if procs:
        stages.append(_stage_endpoint(itm2, procs, hosts))
    files = [e for e in endpoint if e["type"] == "file"]
    if files:
        stages.append(_stage_files(files))
    if network:
        stages.append(_stage_network(proxy, network))

    if not stages:
        return None

    return {
        "id": lesson_id,
        "title": name,
        "tagline": "MWS Cup のログから自動生成しました。使用前に内容を確認してください。",
        "difficulty": "中級",
        "family": "DFIR",
        "source": {
            "type": "generated",
            "note": "MWS データセットのログから自動生成した演習です。内容を確認のうえ使用してください。",
            "inputs": sorted(sources),
        },
        "recap": {
            "summary": (
                "実際の事案を、端末で何が実行されたか、ディスク上で何が変わったか、"
                "ネットワークへ何が出ていったかの順に読み解きました。"
            ),
            "chain": [
                {
                    "stage": s["name"].split(" — ")[0],
                    "name": s["name"].split(" — ")[-1],
                    "desc": f"観測事象 {len(s['events'])} 件。",
                    "attck": [e["attck"] for e in s["events"] if "attck" in e][:3],
                }
                for s in stages
            ],
        },
        "stages": stages,
    }
