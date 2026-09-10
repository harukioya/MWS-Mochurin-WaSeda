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
    if endpoint:
        procs = [e for e in endpoint if e["type"] == "process"]
        tagged = [e for e in procs if "attck" in e]
        if procs:
            stages.append({
                "id": "endpoint",
                "name": "端末 — 何が実行されたか",
                "intro": (
                    f"端末ログ {len(itm2)} 件、対象ホスト {len(hosts)} 台。"
                    "監視エージェントが起動を記録したプログラムの一覧です。"
                ),
                "events": procs[:8],
                "quiz": {
                    "q": "これらの観測のうち、分析者にとって最も有力な手がかりはどれですか。",
                    "options": [
                        "報告しているホストの台数",
                        (
                            f"スクリプト実行環境の起動（{tagged[0]['detail'].rsplit(' を起動', 1)[0].rsplit(chr(92), 1)[-1]}）"
                            if tagged else "署名付きのシステムプログラムの起動"
                        ),
                        "時刻表記が +0900 であること",
                        "ログの書式が ITM2 であること",
                    ],
                    "correct": 1,
                    "explain": (
                        "スクリプト実行環境や代理実行に使われるシステムプログラムは、"
                        "攻撃者が実行ファイルを持ち込まずにコードを動かす手段です。"
                        "Windows では日常的に動くものだからこそ追う価値があり、"
                        "問うべきは「動いたか」ではなく「何を実行し、誰が起動したか」です。"
                    ) if tagged else (
                        "プロセスの起動は端末の時系列の背骨です。ファイルの書き込み、"
                        "レジストリの設定、通信の確立はいずれも、そのとき動いていた"
                        "プロセスに紐づきます。"
                    ),
                },
            })
        files = [e for e in endpoint if e["type"] == "file"]
        if files:
            stages.append({
                "id": "files",
                "name": "ファイル — ディスク上で何が変わったか",
                "intro": "監視エージェントが作成または書き込みを記録したファイルです。",
                "events": files[:8],
                "quiz": {
                    "q": "分析者が「書き込まれたか」だけでなく「どこに書き込まれたか」を気にするのはなぜですか。",
                    "options": [
                        "深い階層のパスは読むのに時間がかかるから",
                        "場所が意図を示すから。スタートアップフォルダやシステムディレクトリなら常駐化や権限、一時フォルダなら準備段階を意味する",
                        "Windows はファイルをパス順に並べるから",
                        "パスがファイルの大きさを決めるから",
                    ],
                    "correct": 1,
                    "explain": (
                        "同じ内容のファイルでも、置かれた場所によって意味が変わります。"
                        "%TEMP% にあれば準備段階、Run キーやスタートアップフォルダに"
                        "あれば常駐化、System32 にあれば権限の問題です。"
                        "パスは意図を示す証拠です。"
                    ),
                },
            })

    if network:
        ext = network[:8]
        stages.append({
            "id": "network",
            "name": "ネットワーク — 外部へ何が出ていったか",
            "intro": (
                f"プロキシログ {len(proxy)} 件、外部宛先 {len(network)} 箇所。"
                "多くは通常の通信です。どれが怪しいかを見分けるのがこの段階の課題です。"
            ),
            "events": ext,
            "quiz": {
                "q": "怪しい宛先と通常の通信を分けるものは何ですか。",
                "options": [
                    "HTTP メソッド。POST ならデータが外に出ている",
                    "1 行だけでは判断できない。繰り返し、間隔、そのホストの普段の挙動に合うかといった、複数行にわたる傾向で判断する",
                    "内部ネットワーク以外の宛先はすべて怪しい",
                    "プロキシが中身を読めない HTTPS は怪しい",
                ],
                "correct": 1,
                "explain": (
                    "製品の利用状況送信先への POST は情報の持ち出しではなく、"
                    "CDN への CONNECT は指令通信（C2）ではありません。"
                    "1 行だけで判断できることはほとんどありません。"
                    "定期通信の手がかりは傾向にあります。一定の間隔、単一の宛先、"
                    "そのホストの普段の通信と合わない動きです。"
                ),
            },
        })

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
            "note": "MWS データセットのログから自動生成した課です。内容を確認のうえ使用してください。",
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
