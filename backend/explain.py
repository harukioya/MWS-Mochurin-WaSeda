"""explain.py — turn real artifacts into lessons the existing player renders.

The teaching layer already works: `js/player.js` walks stages, `js/quiz.js`
gates each one, `js/recap.js` draws the kill chain. All this module has to do
is produce the same JSON shape from real data instead of hand-written examples.

Two log formats appear in the DFIR sets:

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
                _event("process", f'{host}: started {path}', _PROCESS_ATTCK.get(exe))
            )
        elif evt == "file" and sub in ("create", "write"):
            path = r.get("path", "")
            key = f"file:{host}:{path.rsplit(chr(92), 1)[-1]}"
            if key in seen or not path:
                continue
            seen.add(key)
            events.append(_event("file", f"{host}: wrote {path}"))
        elif evt == "reg":
            path = r.get("path", "")
            if not path or f"reg:{path}" in seen:
                continue
            seen.add(f"reg:{path}")
            attck = None
            if "CurrentVersion\\Run" in path:
                attck = ("T1547.001", "Boot or Logon Autostart: Registry Run Keys")
            events.append(_event("registry", f"{host}: set {path}", attck))
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
                "name": "Endpoint — what ran",
                "intro": (
                    f"{len(itm2)} endpoint records across "
                    f"{len(hosts)} host(s). These are the distinct programs the "
                    "monitoring agent saw start."
                ),
                "events": procs[:8],
                "quiz": {
                    "q": "Which of these observations is the strongest lead for an analyst?",
                    "options": [
                        "The number of hosts reporting",
                        (
                            f"A scripting interpreter starting ({tagged[0]['detail'].split('started ')[-1].rsplit(chr(92),1)[-1]})"
                            if tagged else "A signed system binary starting"
                        ),
                        "The timestamps being in +0900",
                        "The log format being ITM2",
                    ],
                    "correct": 1,
                    "explain": (
                        "Interpreters and proxy-execution binaries are how attackers "
                        "run code without shipping an executable. They are normal on a "
                        "Windows host, which is exactly why they are worth following: "
                        "the question is never 'did it run' but 'what did it run, and "
                        "who started it'."
                    ) if tagged else (
                        "Process starts are the spine of a host timeline: everything "
                        "else — files written, keys set, connections made — hangs off "
                        "some process that was running at the time."
                    ),
                },
            })
        files = [e for e in endpoint if e["type"] == "file"]
        if files:
            stages.append({
                "id": "files",
                "name": "Files — what changed on disk",
                "intro": "Files the agent recorded being created or written.",
                "events": files[:8],
                "quiz": {
                    "q": "Why does an analyst care where a file was written, not just that it was?",
                    "options": [
                        "Deeper paths take longer to read",
                        "Location implies intent: a startup folder or a system directory means persistence or privilege, a temp directory means staging",
                        "Windows sorts files by path",
                        "The path determines the file's size",
                    ],
                    "correct": 1,
                    "explain": (
                        "The same bytes mean different things in different places. In "
                        "%TEMP% they are probably staging; under a Run key or a startup "
                        "folder they are persistence; in System32 they are a privilege "
                        "problem. Path is evidence of intent."
                    ),
                },
            })

    if network:
        ext = network[:8]
        stages.append({
            "id": "network",
            "name": "Network — what left the host",
            "intro": (
                f"{len(proxy)} proxy records; {len(network)} distinct external "
                "destinations. These are deliberately shown WITHOUT technique "
                "tags — most of them are ordinary traffic, and telling which is "
                "which is the analytical work this stage is about."
            ),
            "events": ext,
            "quiz": {
                "q": "None of these destinations is labelled. What actually separates a suspicious one from ordinary traffic here?",
                "options": [
                    "The HTTP method — POST means data is leaving",
                    "Nothing in a single line does; it takes the pattern across many lines — repetition, timing, and whether the destination fits this host's normal behaviour",
                    "Any address outside the local network is suspicious",
                    "HTTPS is suspicious because the proxy cannot read it",
                ],
                "correct": 1,
                "explain": (
                    "A POST to a vendor telemetry endpoint is not exfiltration, and a "
                    "CONNECT to a CDN is not command-and-control. One line is almost "
                    "never enough. What gives beaconing away is the pattern — regular "
                    "intervals, one destination, traffic that does not match what this "
                    "host does the rest of the time. A tool that labelled each line for "
                    "you would be guessing, and would teach you to trust the guess."
                ),
            },
        })

    if not stages:
        return None

    return {
        "id": lesson_id,
        "title": name,
        "tagline": "Generated from real log data — review before teaching.",
        "difficulty": "Intermediate",
        "family": "DFIR",
        "source": {
            "type": "generated",
            "note": (
                "Built automatically from log records in the dataset. ATT&CK "
                "tags are attached only where the log field says so outright; "
                "anything less certain is left untagged. Treat this as a draft to "
                "review, not as ground truth."
            ),
            "inputs": sorted(sources),
        },
        "recap": {
            "summary": (
                "You read a real incident the way an analyst does: what ran on the "
                "endpoints, what changed on disk, and what left the network. No "
                "sample was executed to produce any of it — every observation here "
                "came from logs that were already recorded."
            ),
            "chain": [
                {
                    "stage": s["name"].split(" — ")[0],
                    "name": s["name"].split(" — ")[-1],
                    "desc": f"{len(s['events'])} observed events.",
                    "attck": [e["attck"] for e in s["events"] if "attck" in e][:3],
                }
                for s in stages
            ],
        },
        "stages": stages,
    }
