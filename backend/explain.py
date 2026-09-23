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
from bisect import bisect_left, bisect_right
from collections import Counter, namedtuple

from typing import Callable  # noqa: E402

import timeline  # noqa: E402
from evidence import EvidenceStore, Source, pick_index  # noqa: E402

# key=value, value either "quoted" or bare-until-space
_KV = re.compile(r'(\w+)=("([^"]*)"|[^\s]*)')
_PROXY = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\w+) (?P<target>\S+)[^"]*" '
    r'(?P<status>\d{3})'
)

#: 対応規則の版。教材に残すことで、後から「どの規則で付けたタグか」を
#: 追える。規則を足し引きしたら上げる。
ATTCK_RULE_VERSION = "2026-09-mws-3"


def _tokens(cmd: str) -> list[str]:
    r"""コマンド行を語へ分ける。引用符は外し、中の空白は区切りにしない。

    部分一致で判定していた頃は、次のような行を取り違えていた。

      net.exe use Z: \\user-files.example\share
        → 共有の接続なのに "user" を含むので「アカウントの列挙」

      certutil.exe -hashfile C:\temp\-decode.txt SHA256
        → ハッシュ計算なのに、ファイル名に "-decode" を含むので「復号」

    どちらも、行を文字の並びとしてしか見ていないために起きる。語へ分けて、
    「どの位置の語か」「スイッチなのか値なのか」を見れば起きない。
    """
    out: list[str] = []
    cur: list[str] = []
    quote = ""
    for ch in cmd or "":
        if quote:
            if ch == quote:
                quote = ""
            else:
                cur.append(ch)
        elif ch in "\"'":
            quote = ch
        elif ch.isspace():
            if cur:
                out.append("".join(cur))
                cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    return out


def _switches(tokens: list[str]) -> set[str]:
    r"""`-decode` `/create` のようなスイッチだけを、記号を外して集める。

    `C:\temp\-decode.txt` は `-` で始まらないのでスイッチにならない。ここが
    値とスイッチの境目で、部分一致との違いでもある。
    """
    out = set()
    for t in tokens[1:]:
        if t[:1] in "-/" and len(t) > 1:
            out.add(t[1:].split(":", 1)[0].lower())
    return out


def _values(tokens: list[str]) -> list[str]:
    """スイッチでない語（引数の値）。小文字で返す。"""
    return [t.lower() for t in tokens[1:] if t[:1] not in "-/"]


def _is_url(token: str) -> bool:
    return token.lower().startswith(("http://", "https://", "ftp://"))


# --- 規則ごとの照合関数 -----------------------------------------------------
#
# 実行ファイル 1 つに Technique 1 つを割り当てるのをやめた。同じプログラムでも
# 引数によって別の手法になる（`net user` は列挙、`net user /add` は作成）。
# 引数列を見て、確実に言えるものだけを返す。

def _net(tokens):
    r"""`net` の下位命令。列挙と断定できる形だけを列挙として扱う。

    変更系のスイッチを並べて除外する書き方をやめた。`net user` のスイッチは
    `/fullname:` `/comment:` `/homedir:` `/profilepath:` `/scriptpath:`
    `/workstations:` `/passwordreq:` など多数あり、数え落としたものが
    そのまま「列挙」として通ってしまう。実際 `/fullname:` や `/comment:`
    での変更が T1087 Account Discovery になっていた。

    そこで向きを逆にする。列挙だと言い切れる形を許可リストで持ち、それ以外は
    無タグにする。許すのは次の三つだけ。

        net <sub>
        net <sub> <名前>
        上のどちらかに /domain が付いたもの

    `/add` だけは別扱い。作成であることが引数から一意に決まるため。
    """
    vals = _values(tokens)
    sub = vals[0] if vals else ""
    if sub not in ("user", "group", "localgroup"):
        return None  # use / share / view / start などは対象外

    sw = _switches(tokens)
    # /domain は「どこのアカウントか」を切り替える。`net group` は
    # ドメインコントローラー上の命令なので、書かれていなくてもドメイン側。
    domain = "domain" in sw or sub == "group"
    # 下位命令のあとに続く値。`net user alice newpassword` なら 2 つ。
    args = vals[1:]

    if "add" in sw:
        if sub != "user":
            # グループの作成か、メンバーの追加か、この 1 行では決まらない。
            return None
        if domain:
            return ("T1136.002", "Create Account: Domain Account",
                    "net.exe に user と /add と /domain が渡されています。"
                    "ドメインのアカウントを作成する指定です。")
        return ("T1136.001", "Create Account: Local Account",
                "net.exe に user と /add が渡されています。これは端末の"
                "アカウントを作成する指定であって、一覧の取得ではありません。")

    # ここから先は列挙の判定。許可リストから外れたら無タグ。
    if sw - {"domain"}:
        # /domain 以外のスイッチが付いている。`net user alice /fullname:X` の
        # ように、表示ではなく変更である可能性がある。
        return None
    if len(args) > 1:
        # `net user alice newpassword` はパスワードの変更。表示ではない。
        return None

    if sub == "user":
        if domain:
            return ("T1087.002", "Account Discovery: Domain Account",
                    "net.exe に user と /domain だけが渡されています。"
                    "ドメインのアカウントを一覧するものです。")
        return ("T1087.001", "Account Discovery: Local Account",
                "net.exe に user だけが渡されています。端末のアカウントを"
                "一覧するものです。")

    # group / localgroup はグループの列挙。アカウントの列挙とは別の Technique。
    if domain:
        return ("T1069.002", "Permission Groups Discovery: Domain Groups",
                "net.exe に group が渡されています。ドメインのグループを"
                "一覧するものです。")
    return ("T1069.001", "Permission Groups Discovery: Local Groups",
            "net.exe に localgroup だけが渡されています。端末のグループを"
            "一覧するものです。")


def _certutil(tokens):
    """`certutil` は復号・デコードのときだけ T1140。

    `-encode` は符号化であって復号ではない。`-urlcache` は取得であって
    復号ではない（内容によっては T1105 だが、この 1 行では決まらない）。
    どちらも T1140 の定義と合わないので、付けない。
    """
    sw = _switches(tokens)
    if sw & {"decode", "decodehex"}:
        return ("T1140", "Deobfuscate/Decode Files or Information",
                "certutil.exe に decode が渡されています。符号化された内容を"
                "元へ戻す指定です。")
    return None


def _vssadmin(tokens):
    vals = _values(tokens)
    if vals[:2] == ["delete", "shadows"]:
        return ("T1490", "Inhibit System Recovery",
                "vssadmin.exe に delete shadows が渡されています。復元用の"
                "控えを削除する指定で、一覧表示ではありません。")
    # `resize shadowstorage` は付けない。
    #
    # Microsoft の定義でも、これは保存領域の最大容量を変更する命令であって、
    # 控えが消えるのは「起こり得る」結果に過ぎない。`/maxsize=100GB` が
    # 縮小なのか拡大なのかは、変更前の割り当てが分からなければ決まらない。
    # この 1 行から縮小を示せない以上、復元の妨害と断定しない。
    return None


def _bcdedit(tokens):
    """回復機能を止める指定だけを見る。

    `/deletevalue` は何を消すかで意味が変わる汎用の指定なので付けない。
    `bcdedit /deletevalue {current} safeboot` は、むしろ回復の妨害ではない。
    """
    vals = _values(tokens)
    for a, b, what in (
        ("recoveryenabled", ("no", "off"), "回復環境を無効にする"),
        ("bootstatuspolicy", ("ignoreallfailures",), "起動失敗時の回復を止める"),
    ):
        if a in vals:
            at = vals.index(a)
            if at + 1 < len(vals) and vals[at + 1] in b:
                return ("T1490", "Inhibit System Recovery",
                        f"bcdedit.exe に {a} {vals[at + 1]} が渡されています。"
                        f"{what}指定です。")
    return None


def _schtasks(tokens):
    sw = _switches(tokens)
    if "create" in sw:
        return ("T1053.005", "Scheduled Task/Job: Scheduled Task",
                "schtasks.exe に /create が渡されています。予定実行を新しく"
                "登録する指定で、確認や一覧ではありません。")
    return None


def _rundll32(tokens):
    for t in tokens[1:]:
        low = t.lower()
        if ".dll," in low or low.startswith("javascript:"):
            return ("T1218.011", "System Binary Proxy Execution: Rundll32",
                    "rundll32.exe に、読み込む DLL と呼び出し先が 1 つの語と"
                    "して渡されています。正規のプログラムを介して別のコードを"
                    "動かす形です。")
    return None


def _regsvr32(tokens):
    for t in tokens[1:]:
        low = t.lower()
        if low.startswith(("/i:", "-i:")) or low == "scrobj.dll" or _is_url(t):
            return ("T1218.010", "System Binary Proxy Execution: Regsvr32",
                    "regsvr32.exe に、登録処理を経由して別のコードを呼び出す"
                    "引数が渡されています。")
    return None


def _mshta(tokens):
    for t in tokens[1:]:
        low = t.lower()
        if _is_url(t) or low.endswith(".hta") or low.startswith(("javascript:", "vbscript:")):
            return ("T1218.005", "System Binary Proxy Execution: Mshta",
                    "mshta.exe に、外部の場所またはスクリプトを指す引数が"
                    "渡されています。")
    return None


#: ATT&CK 規則。
#:
#: 値は (起動だけで足りるか, 規則) の組。
#:
#:   (False, (ID, 名前, 理由))  … そのプログラムが起動したこと自体が手法に
#:                                あたる。解釈系と、用途が一つしかない照会系。
#:   (True,  照合関数)          … 引数列を見て決める。関数は (ID, 名前, 理由)
#:                                か None を返す。同じプログラムでも引数に
#:                                よって別の手法になるので、実行ファイルごとに
#:                                Technique を 1 つ決め打ちにはしない。
#:
#: どちらの場合も、判定に使った項目が保存済みの抜粋に残っていなければ付けない。
#: 抜粋を読んでも確かめられない対応は、根拠付きとは言えないため。
_PROCESS_ATTCK: dict[str, tuple[bool, object]] = {
    # --- 起動そのものが手法にあたるもの ---
    "powershell.exe": (False, (
        "T1059.001", "Command and Scripting Interpreter: PowerShell",
        "起動したプログラムが PowerShell 本体であることが、"
        "この 1 行の psPath に書かれています。")),
    "pwsh.exe": (False, (
        "T1059.001", "Command and Scripting Interpreter: PowerShell",
        "起動したプログラムが PowerShell 本体であることが、"
        "この 1 行の psPath に書かれています。")),
    "cmd.exe": (False, (
        "T1059.003", "Command and Scripting Interpreter: Windows Command Shell",
        "起動したプログラムが Windows のコマンドシェルであることが、"
        "この 1 行の psPath に書かれています。")),
    "wscript.exe": (False, (
        "T1059.005", "Command and Scripting Interpreter: Visual Basic",
        "スクリプト実行系が起動したことが、この 1 行の psPath に"
        "書かれています。")),
    "cscript.exe": (False, (
        "T1059.005", "Command and Scripting Interpreter: Visual Basic",
        "スクリプト実行系が起動したことが、この 1 行の psPath に"
        "書かれています。")),
    "whoami.exe": (False, (
        "T1033", "System Owner/User Discovery",
        "whoami.exe は現在の利用者を表示する以外の用途を持ちません。"
        "起動したこと自体が、その確認が行われたことを示します。")),
    "systeminfo.exe": (False, (
        "T1082", "System Information Discovery",
        "systeminfo.exe は端末の構成を列挙する以外の用途を持ちません。"
        "起動したこと自体が、その列挙が行われたことを示します。")),

    # --- 引数列を見て決めるもの ---
    "net.exe": (True, _net),
    "certutil.exe": (True, _certutil),
    "vssadmin.exe": (True, _vssadmin),
    "bcdedit.exe": (True, _bcdedit),
    "schtasks.exe": (True, _schtasks),
    "rundll32.exe": (True, _rundll32),
    "regsvr32.exe": (True, _regsvr32),
    "mshta.exe": (True, _mshta),
}

#: レジストリ規則。パスに対する明示的な一致だけを持つ。
_REGISTRY_ATTCK = (
    ("CurrentVersion\\Run",
     "T1547.001", "Boot or Logon Autostart: Registry Run Keys",
     "この 1 行の path が、ログオン時に自動実行される場所を指しています。"),
)


def _attck(ident: str, name: str, reason: str, evidence_ids: list[str]) -> dict:
    """ATT&CK の対応。理由と根拠が無いものは作れない形にしておく。

    `status` は `observed` 固定。ここで付けるのは、保存した 1 行の抜粋から
    直接読み取れるものだけだから。複数行を突き合わせた対応は `correlated` に
    なるが、このフェーズではその規則を持たない。
    """
    return {
        "id": ident,
        "name": name,
        "reason": reason,
        "evidenceIds": list(evidence_ids),
        "ruleVersion": ATTCK_RULE_VERSION,
        "confidence": "high",
        "status": "observed",
    }


def _attck_for_process(excerpt: str, evidence_ids: list[str]) -> dict | None:
    """保存済みの抜粋だけを見て、プロセス起動へ対応を付ける。

    解析済みレコードではなく抜粋から読み直すのが要点。レコードには行全体が
    入っているので、判定に使った項目が抜粋の外にあっても対応が付いてしまう。
    そうなると「この 1 行の psPath に書かれています」と言いながら、示した
    抜粋に psPath が無い、という状態になる。
    """
    if not excerpt or not evidence_ids:
        return None
    raw = _field_in(excerpt, "psPath") or _field_in(excerpt, "path")
    if not raw:
        return None  # 起動対象が抜粋から読めない
    entry = _PROCESS_ATTCK.get(raw.rsplit("\\", 1)[-1].lower())
    if not entry:
        return None
    needs_arg, rule = entry
    if not needs_arg:
        return _attck(rule[0], rule[1], rule[2], evidence_ids)
    cmd = _field_in(excerpt, "cmd")
    if not cmd:
        return None  # 引数が抜粋に無い。起動しただけでは手法を決められない。
    found = rule(_tokens(cmd))
    if not found:
        return None
    return _attck(found[0], found[1], found[2], evidence_ids)


#: 学習カテゴリ（仕様書 15.3）。最終レポートのカテゴリ別得点に使う。
#:
#: 「読む」「根拠を出す」だけでは、調査の練習として足りない。観測から手法へ
#: 対応させる練習と、逆に「ここからは言えない」と線を引く練習を別建てにする。
#: 後者が無いと、1 行から読み取れる以上のことを断定する癖がつく。
CATEGORY_LABEL = {
    "log-reading": "ログの意味を読む",
    "evidence": "根拠を特定する",
    "correlation": "二つの証拠を関連付ける",
    "attck": "観測を手法に対応させる",
    "limits": "断定できない理由を説明する",
}


def _source_of(name: str, line_no: int, line: str) -> Source:
    """1 行の出典を組み立てる。

    `name` は `dataset/case/logs.zip :: logs/ws02.log` の形。内側 ZIP まで
    含んだ論理パスなので、同じ `ws02.log` が別の ZIP にあっても取り違えない。

    抜粋は原文のまま持つ。ここで `MAX_EXCERPT` へ切る案を試したが、二つの
    理由でやめた。行の文字列は `text.split()` の結果として生き続けるので、
    切っても複製が増えるだけでメモリは減らない（測ると逆に増えた）。また
    `visible()` は切り詰めたときだけ末尾に「…」を付けるので、先に切ると
    「この行はまだ続いている」という表示が消える。
    """
    member = name.split(" :: ")[-1] if " :: " in name else name
    return Source(archive_path=name, member=member, line=line_no, excerpt=line)


def parse_itm2(text: str, limit: int = 200_000, name: str = "") -> list[dict]:
    """Parse InfoTrace Mark II lines into dicts. Unparseable lines are skipped.

    Each record carries `_src`: where the line came from, with a 1-based line
    number. The number counts lines in the original file, so blank and
    unparseable lines still advance it -- otherwise "line 12345" would point at
    a different line than the one the person opens the log to check.
    """
    out = []
    for line_no, line in enumerate(text.split("\n")[:limit], 1):
        if "type=ITM2" not in line:
            continue
        rec = {}
        for m in _KV.finditer(line):
            rec[m.group(1)] = m.group(3) if m.group(3) is not None else m.group(2)
        if rec:
            rec["_ts"] = line[:23]
            # 原文のまま保つ。タイムゾーンを勝手に直すと、画面と原文が食い違う。
            rec["_stamp"] = timeline.parse_itm2(line, name)
            rec["_src"] = _source_of(name, line_no, line)
            out.append(rec)
    return out


def parse_proxy(text: str, limit: int = 200_000, name: str = "") -> list[dict]:
    """Parse Squid-style proxy lines. Line numbers are 1-based as above."""
    out = []
    for line_no, line in enumerate(text.split("\n")[:limit], 1):
        m = _PROXY.match(line)
        if m:
            rec = m.groupdict()
            rec["_stamp"] = timeline.parse_proxy(rec.get("ts", ""), name)
            rec["_src"] = _source_of(name, line_no, line)
            out.append(rec)
    return out


def _is_external(host: str) -> bool:
    """True for a routable address. Private/loopback targets are lateral, not exfil."""
    host = host.split(":")[0]
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return True  # a hostname; treat as external
    return not (addr.is_private or addr.is_loopback or addr.is_link_local)


def _event(kind: str, detail: str, attck: dict | None = None,
           evidence_ids: list[str] | None = None,
           stamp: "timeline.Stamp | None" = None,
           host: str = "", keys: "set[str] | None" = None) -> dict:
    ev = {"type": kind, "detail": detail[:400]}
    if attck:
        ev["attck"] = attck
    if evidence_ids:
        ev["evidenceIds"] = list(evidence_ids)
    if host:
        ev["host"] = host
    # 端末を指す呼び名。ログの種類ごとに違う名前で同じ端末を指すため、
    # 表示用の `host` とは別に、照合用の集合を持つ。端末ログは com（端末名）
    # と ip= の各アドレス、プロキシは要求元アドレス。ここが重なれば同じ端末と
    # 言える。名前の文字列比較だけでは、端末ログと通信ログは永遠に繋がらない。
    #
    # 呼び出し側が「調べたが何も無かった」と空集合を渡したときに、`host` へ
    # 戻してはいけない。`host` は表示用で、端末名の読めない行には `?` が
    # 入る。戻すと `?` どうしが一致し、端末の分からない 2 行が「同一端末で
    # 10 秒以内」として相関された。`keys is None`（渡されなかった）と
    # 空集合（渡したが空）を区別する。
    ev["_keys"] = _clean_keys(keys) if keys is not None else _clean_keys({host})
    # 時刻は必ず持たせる。読めなかった行も「時刻不明」として残し、捨てない。
    st = stamp or timeline.UNKNOWN
    ev["time"] = st.as_json()
    ev["_stamp"] = st
    return ev


#: 端末の照合キーとして採用しない値。
#:
#: `?` と空文字は「読めなかった」を表す代用で、端末を指していない。ループ
#: バックと未指定アドレスはどの端末にも存在するので、一致しても同じ端末で
#: あることを示さない。いずれも、一致を根拠に「同一端末」と言えない。
_NOT_A_HOST = frozenset({
    "", "?", "-", "unknown", "n/a",
    "127.0.0.1", "::1", "localhost",
    "0.0.0.0", "::",
})


def _clean_keys(keys) -> set[str]:
    """端末の照合に使える呼び名だけを残す。"""
    out = set()
    for k in keys or ():
        k = str(k).strip()
        if k.lower() not in _NOT_A_HOST:
            out.add(k)
    return out


def _host_keys(rec: dict) -> set[str]:
    """端末ログ 1 行が指す端末の呼び名。端末名と、記録されている IP。

    何も読めなければ空集合を返す。呼び出し側はこれをそのまま持たせる。
    表示用の `host` で埋め戻さない（`_event` の説明を参照）。
    """
    return _clean_keys(
        [rec.get("com", "")] + (rec.get("ip") or "").split(",")
    )


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



def _publish(event: dict) -> dict:
    """教材 JSON へ載せる形。内部だけで使うキーを落とす。

    `_stamp` は並べ替えのために持つ `Stamp` で、JSON にできない。表示と状態は
    `time` に写してあるので、ここで外す。元の辞書は壊さない。
    """
    return {k: v for k, v in event.items() if not k.startswith("_")}


def _record_evidence(store: EvidenceStore | None, rec: dict, kind: str) -> list[str]:
    """その 1 行を証拠として登録し、ID を返す。

    出典を持たないレコード（旧来の呼び出しや、パーサーへ名前を渡さなかった
    場合）では空を返す。証拠が無い事象は、あとで設問の根拠にも使わない。
    """
    src = rec.get("_src")
    if store is None or not isinstance(src, Source):
        return []
    return [store.add(src, kind)]


def _stored_excerpt(store: EvidenceStore | None, ids: list[str]) -> str:
    """登録済み証拠の抜粋。保存された長さで切られた、画面に出るのと同じ文字列。"""
    if store is None or not ids:
        return ""
    item = store.get(ids[0])
    return item["source"]["excerpt"] if item else ""


#: 事象として取り出す端末ログの種類。`(evt, subEvt の集合)` から種別名へ。
_ITM2_KINDS = (
    ("ps", ("start",), "process"),
    ("file", ("create", "write"), "file"),
    ("reg", None, "registry"),  # None は subEvt を問わない
)


def _itm2_kind(rec: dict) -> str:
    """端末ログ 1 行の事象種別。取り出さない行は空文字。"""
    evt, sub = rec.get("evt", ""), rec.get("subEvt", "")
    for want_evt, subs, kind in _ITM2_KINDS:
        if evt == want_evt and (subs is None or sub in subs):
            return kind
    return ""


def _target_of(kind: str, rec: dict) -> str:
    """その行が指している対象。表示にも、一覧の間引きにも使う。"""
    if kind == "process":
        # 起動したプロセスは `psPath`。親は `parentPath` で別に記録される。
        #
        # 以前は `path` を優先していた。ITM2 の起動記録では
        # `path` が常に空でフォールバックが効いていたため露見しなかったが、
        # 両方が埋まっている記録では表示と設問が別の値を指す。表示が
        # 「cmd.exe を起動」なのに設問の正解が親の explorer.exe になる、
        # という食い違いが実際に出た。ここが起動プロセスの唯一の出所。
        return rec.get("psPath") or rec.get("path") or ""
    if kind in ("file", "registry"):
        return rec.get("path", "")
    if kind == "network":
        return rec.get("target", "")
    return ""


#: 種別ごとの説明文の作り方。`detail` は一箇所で作る。表示・設問・相関で
#: 別々に組み立てると、同じ行が画面の場所ごとに違う文言になる。
_DETAIL = {
    "process": "{host}: {target} を起動",
    "file": "{host}: {target} に書き込み",
    "registry": "{host}: {target} を設定",
}


def _event_for(kind: str, rec: dict, store: EvidenceStore | None) -> dict | None:
    """1 レコードから事象を 1 件作る。証拠もここで登録する。

    一覧を作るときと、相関に採用した 2 件を作るときの、どちらもここを通す。
    二箇所で組み立てると、同じ行が場所によって違う文言や違うタグになる。
    """
    if kind == "network":
        ids = _record_evidence(store, rec, "network")
        # DELIBERATELY UNTAGGED. An earlier version mapped POST/PUT to T1041
        # (Exfiltration Over C2) and GET/CONNECT to T1071.001, which labelled
        # `POST http://go.microsoft.com/fwlink/?` as exfiltration. The HTTP
        # method carries no intent, and tagging every external request as
        # "application layer protocol" tags ordinary browsing. Deciding which
        # of these destinations matters IS the analytical work, so the lesson
        # presents the observations and asks, rather than pre-answering wrongly.
        # ここは意図的に無タグ。外部宛であること、POST であること、拡張子が
        # .exe であることは、いずれも手法を決める根拠にならない。どれが問題か
        # を決めること自体が、この演習で身に付ける作業である。
        return _event(
            "network", f'{rec["ip"]} -> {rec["method"]} {rec["target"]}', None,
            ids, rec.get("_stamp"), rec.get("ip", ""),
            _clean_keys([rec.get("ip", "")]),
        )

    host = rec.get("com", "?")
    target = _target_of(kind, rec)
    if kind != "process" and not target:
        return None
    ids = _record_evidence(store, rec, kind)
    attck = None
    if kind == "process":
        # 対応は「保存した抜粋」から付け直す。解析済みレコードには行全体が
        # 入っているので、そちらで判定すると、抜粋に写っていない項目を
        # 根拠として示すことになる。
        attck = _attck_for_process(_stored_excerpt(store, ids), ids)
    elif kind == "registry":
        # ここも抜粋から読み直す。長い行では path が抜粋の外に出ることが
        # あり、その場合「この 1 行の path が」という理由が嘘になる。
        kept = _field_in(_stored_excerpt(store, ids), "path")
        for needle, tid, tname, why in _REGISTRY_ATTCK:
            if ids and kept and needle in kept:
                attck = _attck(tid, tname, why, ids)
                break
    return _event(kind, _DETAIL[kind].format(host=host, target=target), attck,
                  ids, rec.get("_stamp"), host, _host_keys(rec))


def events_from_itm2(records: list[dict], store: EvidenceStore | None = None,
                     ) -> list[dict]:
    """Turn parsed records into lesson events, most interesting first.

    同じ端末で同じ実行ファイルが何度起動しても、一覧に何行も並べる意味は
    薄いので、最初の 1 件だけを残す。相関の探索はこの一覧からは行わない
    （`_correlation_candidates` を参照）。
    """
    events: list[dict] = []
    seen: set[str] = set()
    for r in records:
        kind = _itm2_kind(r)
        if not kind:
            continue
        host = r.get("com", "?")
        target = _target_of(kind, r)
        if kind == "process":
            key = f"ps:{host}:{target.rsplit(chr(92), 1)[-1].lower()}"
        elif kind == "file":
            if not target:
                continue
            key = f"file:{host}:{target.rsplit(chr(92), 1)[-1]}"
        else:
            if not target:
                continue
            key = f"reg:{target}"
        if key in seen:
            continue
        seen.add(key)
        event = _event_for(kind, r, store)
        if event:
            events.append(event)
    return events


def events_from_proxy(records: list[dict], store: EvidenceStore | None = None,
                      ) -> list[dict]:
    """外部宛の通信を事象にする。同じ宛先は 1 件へ間引く。"""
    events, seen = [], set()
    for r in records:
        if not _is_external(r["target"]):
            continue
        target = r["target"]
        base = target.split("/")[0] if "//" not in target else target.split("/")[2]
        if base in seen:
            continue
        seen.add(base)
        event = _event_for("network", r, store)
        if event:
            events.append(event)
    return events


#: 相関を探すための軽い候補。
#:
#: 完全な事象を作ると、1 件ごとに説明文・ATT&CK 判定・最大 1000 文字の抜粋・
#: 証拠表への登録が発生する。2 万行の合成ログで測ると、生成中のピークが
#: 76 MiB まで上がり、最終的に教材へ残る証拠は 8 件だった。パーサーは 1 ログ
#: 20 万行まで、読み取り予算は合計 128 MB まで許すので、想定内の入力でも
#: 数百 MB に届きうる。
#:
#: 探索に要るのは、種別・時刻・比較基準・端末キー・出典の五つだけ。ここでは
#: それだけを持ち、採用した 2 件だけを `_event_for` で事象にする。`rec` は
#: 解析済みレコードへの参照で、新しく複製はしない。
_Candidate = namedtuple("_Candidate", "kind stamp keys rec")


def _correlation_candidates(itm2_records: list[dict],
                            proxy_records: list[dict] | None = None,
                            ) -> list[_Candidate]:
    """相関の探索対象。間引かず、証拠も登録しない。"""
    # 端末キーの集合は端末ごとに使い回す。ログに出てくる端末は数台なので、
    # 行ごとに新しい集合を作ると、その分だけ無駄に積み上がる。
    memo: dict[tuple, frozenset] = {}

    def keys_for(com: str, ip: str) -> frozenset:
        at = (com, ip)
        if at not in memo:
            memo[at] = frozenset(_clean_keys([com] + ip.split(",")))
        return memo[at]

    out: list[_Candidate] = []
    for r in itm2_records:
        kind = _itm2_kind(r)
        if kind not in ("process", "file"):
            continue  # レジストリは仕様書 14.2 の相関対象に無い
        if kind == "file" and not _target_of(kind, r):
            continue
        stamp = r.get("_stamp") or timeline.UNKNOWN
        if not stamp.known or not stamp.basis:
            continue
        keys = keys_for(r.get("com", ""), r.get("ip") or "")
        if not keys or not isinstance(r.get("_src"), Source):
            continue
        out.append(_Candidate(kind, stamp, keys, r))

    for r in proxy_records or ():
        if not _is_external(r["target"]):
            continue
        stamp = r.get("_stamp") or timeline.UNKNOWN
        if not stamp.known or not stamp.basis:
            continue
        keys = keys_for("", r.get("ip", ""))
        if not keys or not isinstance(r.get("_src"), Source):
            continue
        out.append(_Candidate("network", stamp, keys, r))
    return out


def _ids_of(events: list[dict]) -> list[str]:
    """一覧に載っている事象の証拠 ID を、順序を保って重複なく集める。"""
    out: list[str] = []
    for e in events:
        for i in e.get("evidenceIds", []):
            if i not in out:
                out.append(i)
    return out


def _summarise(store: EvidenceStore, ident: str) -> str:
    """証拠を選択肢へ出すときの短い見出し。

    出典と行番号だけにする。原文をそのまま並べると、長さや見た目の派手さで
    正解が透けるうえ、細工された文字列を選択肢に持ち込むことになる。
    """
    item = store.get(ident) or {}
    src = item.get("source", {})
    return f"{src.get('member', '?')} の {src.get('line', '?')} 行目"


def _evidence_pick(store: EvidenceStore, correct_event: dict,
                   pool: list[dict], qid: str, objective: str,
                   claim: str, prompt_for: "Callable[[str], str]",
                   explain: str, nxt: str,
                   proves: "Callable[[str], str]" = lambda ex: "") -> dict | None:
    """根拠を選ばせる設問。作れないときは None を返す。

    誤答の選択肢も実在する証拠から取る。もっともらしい偽の出典を作ると、
    「根拠を確かめる」という練習そのものが嘘になるため。

    `claim` は問い文が主張する値（実行ファイル名や要求元アドレス）。`proves` は
    抜粋から「その主張を裏付ける項目」を読み出す関数で、読んだ結果が `claim`
    と一致しない限り設問を作らない。

    単に「抜粋のどこかに同じ文字列がある」では足りない。`cmd="cmd.exe --x"`
    や `parentPath="...\\cmd.exe"` にも同じ語は現れるので、起動対象を示す
    `psPath` が抜粋の外にあっても検査を通ってしまう。それでは「cmd.exe が
    起動した」の根拠として示した行を読んでも、コマンド文字列に名前が書かれて
    いることしか確かめられない。見るべき項目を名指しする。
    """
    right = (correct_event.get("evidenceIds") or [None])[0]
    if not right:
        return None

    item = store.get(right)
    if not item or not claim:
        return None
    if proves(item["source"]["excerpt"]) != claim:
        return None
    prompt = prompt_for(claim)
    others = [i for i in _ids_of(pool) if i != right][:3]
    if not others:
        return None  # 比べる相手がなければ設問にならない

    at = pick_index(qid + right, len(others) + 1)
    ids = others[:at] + [right] + others[at:]
    return {
        "id": qid,
        "type": "evidence_pick",
        "category": "evidence",
        "learningObjective": objective,
        "q": prompt,
        "prompt": prompt,
        "options": [
            {"label": _summarise(store, i), "evidenceId": i} for i in ids
        ],
        "correct": at,
        "explain": explain,
        "explanation": explain,
        "evidenceIds": [right],
        "nextInvestigation": nxt,
    }



def _field_in(text: str, key: str) -> str:
    """key=value 形式の 1 行から、その項目の値を読む。無ければ空。"""
    for m in _KV.finditer(text or ""):
        if m.group(1) == key:
            return (m.group(3) if m.group(3) is not None else m.group(2)) or ""
    return ""


def _excerpt_of(event: dict, store: EvidenceStore) -> str:
    """事象が指す証拠の、保存済み抜粋。"""
    ident = (event.get("evidenceIds") or [None])[0]
    item = store.get(ident) if ident else None
    return item["source"]["excerpt"] if item else ""


def _field_of(event: dict, store: EvidenceStore, key: str) -> str:
    """事象に紐づく証拠の原文から、1 つの項目を読み直す。

    設問の正解は、引用する行そのものに書かれていなければならない。説明文
    （`detail`）から取ると、こちらで組み立てた言葉に依存してしまう。
    """
    return _field_in(_excerpt_of(event, store), key)


def _started_program(excerpt: str) -> str:
    """抜粋が示す「起動したプロセス」の実行ファイル名。

    `events_from_itm2` と同じ順序で読む。表示・設問・根拠の三つが同じ項目を
    見ていなければ、示した記録が主張を裏付けているとは言えない。
    """
    raw = _field_in(excerpt, "psPath") or _field_in(excerpt, "path")
    return raw.rsplit("\\", 1)[-1] if raw else ""


def _proxy_client(excerpt: str) -> str:
    """Squid 形式の行が示す要求元。行頭の 1 語。"""
    return excerpt.split(" ", 1)[0] if excerpt else ""


def _grounded_choice(store: EvidenceStore, anchor: dict, pool: list[dict],
                     qid: str, objective: str, key: str, ask: str,
                     why: str, nxt: str, transform=lambda v: v) -> dict | None:
    """引用した 1 行を読めば答えられる設問を作る。

    正解も誤答も、同じ一覧に実在するログ行の同じ項目から取る。誤答をこちらで
    考え出すと、その選択肢だけ出典が無くなり「根拠を確かめる」という練習が
    成り立たない。値が足りず選択肢を作れないときは、無理に作らず None を返す。
    """
    right = transform(_field_of(anchor, store, key))
    if not right:
        return None

    wrong: list[str] = []
    for other in pool:
        if other is anchor:
            continue
        value = transform(_field_of(other, store, key))
        if value and value != right and value not in wrong:
            wrong.append(value)
        if len(wrong) == 3:
            break
    if not wrong:
        return None

    at = pick_index(qid + right, len(wrong) + 1)
    options = wrong[:at] + [right] + wrong[at:]
    src = (store.get(anchor["evidenceIds"][0]) or {}).get("source", {})
    return {
        "id": qid,
        "type": "single_choice",
        "category": "log-reading",
        "learningObjective": objective,
        "q": f"{src.get('member', '')} の {src.get('line', '')} 行目 について。{ask}",
        "prompt": f"{src.get('member', '')} の {src.get('line', '')} 行目 について。{ask}",
        "options": options,
        "correct": at,
        "explain": why,
        "explanation": why,
        "evidenceIds": list(anchor.get("evidenceIds") or []),
        "nextInvestigation": nxt,
    }


def _exe_of(event: dict) -> str:
    """事象の説明文から実行ファイル名だけを取り出す。設問に埋め込むため。"""
    return event["detail"].rsplit(" を起動", 1)[0].rsplit("\\", 1)[-1]


def _stage_endpoint(itm2: list[dict], procs: list[dict], hosts: Counter,
                    store: EvidenceStore) -> dict:
    """段階1：端末で何が動いたか。

    設問は、引用した 1 行を読めば答えられるものにする。以前はここで「その
    プログラムが攻撃に使える理由」を一般論として尋ねており、紐づけたログ行が
    示すのは「起動した」ことだけだった。根拠として示せない問いは、根拠を
    添えても根拠付きにはならない。しかも一覧では複数の実行ファイルに印が付く
    ため、「これだけに印が付いているのはなぜか」という問い自体が事実と
    食い違っていた。
    """
    shown = _pick(procs)
    anchor = next((e for e in shown if "attck" in e), shown[0] if shown else None)

    quizzes = []
    if anchor is not None:
        which = _grounded_choice(
            store, anchor, shown, "q-endpoint-01",
            "ログ 1 行から、起動したプログラムを読み取る",
            "psPath",
            "この行が起動を記録しているのは、どのプログラムですか。",
            ("プロセスの起動記録には、実行ファイルの完全なパスが `psPath` として"
             "残ります。答えはこの 1 行の中にあり、推測する余地はありません。\n\n"
             "分析でまず確かめるのはここです。名前だけでは同名の別物と区別が"
             "付かないため、どこに置かれた実行ファイルなのかまで見ます。"),
            "この行の `cmd` に渡された引数と、`rcCom` の接続元を確かめる",
            transform=lambda v: v.rsplit("\\", 1)[-1] if v else "",
        )
        if which:
            quizzes.append(which)

        where = _grounded_choice(
            store, anchor, shown, "q-endpoint-02",
            "ログ 1 行から、どの端末の記録かを読み取る",
            "com",
            "この起動が記録されたのは、どの端末ですか。",
            ("`com` が、その記録を残した端末の名前です。複数の端末のログを"
             "まとめて読むときは、まずどの端末の話かを押さえないと、別々の"
             "端末で起きたことを 1 つの流れとして誤読します。"),
            "同じ時刻帯に、他の端末で何が記録されているかを見比べる",
        )
        if where:
            quizzes.append(where)

        pick = _evidence_pick(
            store, anchor, shown, "q-endpoint-evidence",
            "主張の根拠となるログ行を特定する",
            _exe_of(anchor),
            lambda v: f"「{v} が起動した」と言えるのは、どの記録があるからですか。",
            ("設問の主張を支えるのは、その起動そのものを書き留めた 1 行です。"
             "同じ一覧に並んでいても、別のプログラムの記録はこの主張の根拠には"
             "なりません。根拠を示すとは、この 1 行を指せるということです。"),
            "この行の前後を見て、何が起動元になっているかを確かめる",
            proves=_started_program,
        )
        if pick:
            quizzes.append(pick)

    return {
        "id": "endpoint",
        "name": "端末 — 何が実行されたか",
        "intro": (
            f"監視下の {len(hosts)} 台から、{len(itm2)} 件の記録が集まっています。"
            "これは端末で起きたことを逐一書き留めた記録で、プログラムが起動する"
            "たびに、実行ファイルの場所と起動元が残ります。\n\n"
            "以下は重複を除いた「起動したプログラムの種類」の一覧です。"
            "各行の下に、元になったログの出典と行番号を示しています。"
            "設問は、その原文を読めば答えられるようにしてあります。"
        ),
        "events": shown,
        "quizzes": quizzes,
    }


def _stage_files(files: list[dict], store: EvidenceStore) -> dict:
    """段階2：ディスク上で何が変わったか。"""
    shown = _pick(files)
    anchor = shown[0]
    quizzes = []

    where = _grounded_choice(
        store, anchor, shown, "q-files-01",
        "ログ 1 行から、書き込まれた場所を読み取る",
        "path",
        "この行が記録しているのは、どのファイルへの書き込みですか。",
        ("`path` に、書き込まれたファイルの完全なパスが残ります。\n\n"
         "見るべきは中身ではなく置かれた場所です。一時フォルダなら何かの準備、"
         "自動起動に関わる場所なら再起動後も動き続けるための仕込み、システムの"
         "中枢ならそこへ書けた権限そのものが問題になります。同じ内容でも、"
         "どこに置かれたかで意味が変わります。"),
        "このファイルを書き込んだプロセスが、直前に何を起動したかを確かめる",
    )
    if where:
        quizzes.append(where)

    host = _grounded_choice(
        store, anchor, shown, "q-files-02",
        "ログ 1 行から、どの端末の記録かを読み取る",
        "com",
        "この書き込みが記録されたのは、どの端末ですか。",
        ("端末名は `com` にあります。どの端末で起きたかが決まらないと、"
         "この書き込みを、同じ時間帯の起動記録や通信記録と結び付けられません。"),
        "同じ端末の起動記録から、この時刻の前後に何が動いていたかを見る",
    )
    if host:
        quizzes.append(host)

    return {
        "id": "files",
        "name": "ファイル — ディスク上で何が変わったか",
        "intro": (
            "同じ記録には、ファイルの作成と書き込みも残ります。"
            "各行の下に出典と行番号を示しているので、設問はその原文を"
            "読んで答えてください。"
        ),
        "events": shown,
        "quizzes": quizzes,
    }


def _stage_network(proxy: list[dict], network: list[dict],
                   store: EvidenceStore) -> dict:
    """段階3：外部へ何が出ていったか。

    プロキシの記録は key=value ではないので、`_grounded_choice` は使えない。
    代わりに、この段階の事象そのもの（実在する宛先）を選択肢にする。
    """
    shown = _pick(network)
    anchor = shown[0]
    quizzes = []

    ident = (anchor.get("evidenceIds") or [None])[0]
    item = store.get(ident) if ident else None
    if item:
        src = item["source"]
        # `ip -> METHOD target` の形。原文にそのまま現れる値だけを使う。
        right = anchor["detail"].split(" -> ", 1)[0]
        wrong = []
        for other in shown:
            value = other["detail"].split(" -> ", 1)[0]
            if value != right and value not in wrong:
                wrong.append(value)
            if len(wrong) == 3:
                break
        if wrong:
            at = pick_index("q-network-01" + right, len(wrong) + 1)
            options = wrong[:at] + [right] + wrong[at:]
            quizzes.append({
                "id": "q-network-01",
                "type": "single_choice",
                "category": "log-reading",
                "learningObjective": "ログ 1 行から、通信の要求元を読み取る",
                "q": (f"{src['member']} の {src['line']} 行目 について。"
                      "この通信を出したのは、どの端末ですか。"),
                "prompt": (f"{src['member']} の {src['line']} 行目 について。"
                           "この通信を出したのは、どの端末ですか。"),
                "options": options,
                "correct": at,
                "explain": (
                    "プロキシの記録は、行の先頭に要求元のアドレスを書きます。"
                    "通信の中身は暗号化されていれば分かりませんが、"
                    "「いつ・どこから・どこへ」は残ります。\n\n"
                    "一度の通信だけでは、普通の通信と区別は付きません。"
                    "手がかりになるのは、同じ宛先への繰り返しや、その端末の"
                    "普段の動きと合わない時間帯といった、複数行にまたがる形です。"
                ),
                "explanation": "",
                "evidenceIds": list(anchor.get("evidenceIds") or []),
                "nextInvestigation": "同じ宛先への通信が繰り返されていないか、時刻を並べて確かめる",
            })
            quizzes[-1]["explanation"] = quizzes[-1]["explain"]

        pick = _evidence_pick(
            store, anchor, shown, "q-network-evidence",
            "主張の根拠となるログ行を特定する",
            right,
            lambda v: f"「{v} が外部へ通信した」と言えるのは、どの記録があるからですか。",
            ("この主張を支えるのは、その通信を書き留めた 1 行です。"
             "同じ一覧の他の行は、別の端末や別の宛先の記録なので、"
             "この主張の根拠にはなりません。"),
            "この端末の起動記録と時刻を突き合わせ、何が通信したのかを絞る",
            proves=_proxy_client,
        )
        if pick:
            quizzes.append(pick)

    return {
        "id": "network",
        "name": "通信 — 外部へ何が出ていったか",
        "intro": (
            f"プロキシの記録 {len(proxy)} 件から、外部の宛先 {len(network)} 箇所を"
            "取り出しました。プロキシは端末と外部の間に立つため、"
            "どの端末がどこへ繋いだかが残ります。\n\n"
            "通信の中身までは分かりません。一覧に印を付けていないのは、"
            "どれが業務上の通常の通信かは一行ずつ見ても決まらないためです。"
        ),
        "events": shown,
        "quizzes": quizzes,
    }




#: 相関とみなす時間幅（秒）。仕様書 14.2 の初期値は前後 60 秒。
#: プロファイルから差し替えられるよう、引数で上書きできる形にしてある。
CORRELATION_WINDOW_SECONDS = 60.0

#: 相関の対象にする種別の組（仕様書 14.2）。
#: 「プロセス開始とファイル操作」「プロセス開始と通信」の二つだけを持つ。
#: 起動どうし、ファイルどうしを結ぶ規則は仕様に無いので実装しない。
CORRELATION_PAIRS = (
    frozenset({"process", "file"}),
    frozenset({"process", "network"}),
)


def _basis_label(basis: str) -> str:
    """比較基準を、画面に出せる言い方へ。"""
    if basis == "utc":
        return "どちらもタイムゾーンつきで記録されている"
    if basis.startswith("local:"):
        return f"どちらも同じログ（{basis[len('local:'):].split(' :: ')[-1]}）の時計で記録されている"
    return ""


def _place(c: "_Candidate") -> tuple:
    """入力の並びに依らない二次キー。証拠 ID はまだ無いので出典で代える。"""
    src = c.rec["_src"]
    return (src.archive_path, src.member, src.line)


def _best_pair(candidates: "list[_Candidate]", window: float,
               ) -> "tuple[tuple | None, int]":
    """相関の条件を満たす組のうち、最も近いものを返す。比較回数も返す。

    総当たりにしない理由が二つある。

    ひとつは計算量。以前は時刻順に並べて「幅を越えたら内側を打ち切る」形に
    していたが、記録が幅の中に密集すると打ち切りが効かない。同時刻なら
    `gap == 0` で読み飛ばすだけなので、まったく効かない。実測では全件同時刻の
    とき、件数を 2 倍にすると時間が約 4 倍になった（2000 件 0.09 秒、
    4000 件 0.37 秒、8000 件 1.54 秒）。秒単位のプロキシログでは同時刻への
    集中は普通に起こるし、20 万行まで許している以上、現実的な時間で
    終わらなくなる。

    もうひとつは無駄。組になりうるのは「プロセス開始」と「ファイル操作 /
    通信」の間だけで（仕様書 14.2）、しかも同じ端末・同じ時計の基準どうしに
    限られる。総当たりは、その条件を満たさない組を大量に見てから捨てている。

    そこで (時計の基準, 端末キー) で仕切り、その中をプロセス側と非プロセス側の
    二つに分け、非プロセス側を時刻で索引する。あとはプロセス 1 件ごとに、
    「直前」と「直後」の時刻だけを二分探索で取ればよい。最も近い相手は必ず
    そのどちらかなので、間を見る必要がない。比較は 1 件あたり 2 回で済む。

    同時刻の扱いに注意が要る。前後が決まらないので同時刻は使えないが、
    「直前」「直後」を取るときに同時刻のものを掴んではいけない。二分探索の
    左右を使い分けて、厳密に前・厳密に後ろだけを見る。

    同時刻に複数の候補が並ぶときは、そのうち出典が最小のものだけを残す。
    選択の優先順位は (時間差, 先の時刻, 先の出典, 後の出典) なので、時刻が
    同じ候補の中では出典が最小のものしか選ばれない。残りを持っていても
    結果は変わらない。
    """
    comparisons = 0
    best: tuple | None = None

    def consider(a: "_Candidate", b: "_Candidate", shared: str) -> None:
        """組を 1 つ検討する。`shared` は二人が共有している端末の呼び名。

        共有キーはここで添える。選んだあとに集合の共通部分を取り直すと、
        仕切りを間違えたときに「共有していない 2 件」を選びながら気付かず、
        添字エラーで落ちる。どの呼び名で結んだかは選ぶ時点で分かっている。
        """
        nonlocal best, comparisons
        comparisons += 1
        first, other = (a, b) if a.stamp.sort < b.stamp.sort else (b, a)
        gap = other.stamp.sort - first.stamp.sort
        if gap <= 0 or gap > window:
            return
        if _place(first) == _place(other):
            return  # 同じ 1 行
        cand = (gap, first.stamp.sort, _place(first), _place(other),
                first, other, shared)
        if best is None or cand[:4] < best[:4]:
            best = cand

    # (時計の基準, 端末キー) ごとに、プロセス側と非プロセス側へ分ける。
    # 1 件が端末名と複数の IP を持つことがあるので、同じ候補が複数の仕切りへ
    # 入ることはある。端末の呼び名は 1 件あたりせいぜい数個なので、総量は
    # 件数に比例したままになる。
    groups: dict[tuple, tuple[list, list]] = {}
    for c in candidates:
        slot = 0 if c.kind == "process" else 1
        for key in c.keys:
            at = (c.stamp.basis, key)
            if at not in groups:
                groups[at] = ([], [])
            groups[at][slot].append(c)

    for at in sorted(groups):
        procs, others = groups[at]
        if not procs or not others:
            continue
        # 非プロセス側を時刻ごとに畳む。同時刻なら出典が最小の 1 件だけ残す。
        by_time: dict[float, "_Candidate"] = {}
        for c in others:
            have = by_time.get(c.stamp.sort)
            if have is None or _place(c) < _place(have):
                by_time[c.stamp.sort] = c
        times = sorted(by_time)
        reps = [by_time[t] for t in times]
        for p in procs:
            t = p.stamp.sort
            # 厳密に前（bisect_left の 1 つ手前）と、厳密に後ろ（bisect_right）。
            # 同時刻のものは、どちらの側にも入らない。
            for at_index in (bisect_left(times, t) - 1, bisect_right(times, t)):
                if 0 <= at_index < len(reps):
                    consider(p, reps[at_index], at[1])
    return best, comparisons


def _correlation_quiz(store: EvidenceStore, candidates: "list[_Candidate]",
                      qid: str,
                      window: float = CORRELATION_WINDOW_SECONDS,
                      ) -> tuple[dict | None, str, list[dict]]:
    """近接した二つの記録を突き合わせる設問。作れない理由と、使った 2 件も返す。

    仕様書 14.2 の関連付け規則のうち、MVP で持つ二つを実装する。

      * 同一ホストかつ近接時刻の「プロセス開始とファイル操作」
      * 同一ホストかつ近接時刻の「プロセス開始と通信」

    「近接」は既定で前後 60 秒。この幅と、実際の時間差（「同一端末で 34 秒
    以内」）を理由として出せることが、仕様の採用条件になっている。出せない
    組は自動相関として採用しない。

    以前は、同一ホストと「時刻が違うこと」しか見ていなかった。そのため
    24 時間離れたプロセス開始とファイル作成からも設問が出て、しかも
    `correlated` と名乗っていた。それは時系列を読む練習であって、二つの
    証拠を関連付ける練習ではない。

    比較の基準（`Stamp.basis`）は、両者で一致していなければならない。
    タイムゾーンの書かれていない行は、同じログの中でだけ比べられる。別々の
    ログの、別々にずれた時計を並べて前後を論じない。

    断定するのは「記録された順序」と「時間差」までで、因果は言わない。

    受け取るのは `_Candidate` の並び。完全な事象ではないのは、探索のためだけに
    全行分の説明文・タグ・抜粋を作ると、生成中のメモリがログの大きさに比例して
    膨らむため。証拠として登録するのは、採用した 2 件だけ。

    使った 2 件を返すのは、この設問を載せる段階に、その 2 件を根拠として
    並べるため。参照している記録が画面に無いと、「根拠ログを見る」の飛び先が
    存在しないボタンになる。
    """
    if len(candidates) < 2:
        return None, ("時刻と端末を読み取れた記録が二つ揃わなかったため、"
                      "関連付けの設問は作りませんでした。"), []

    best, _ = _best_pair(candidates, window)
    if best is None:
        return None, (
            f"同じ端末で {int(window)} 秒以内に記録された"
            "「プロセス開始とファイル操作」または「プロセス開始と通信」の組が"
            "見つからなかったため、関連付けの設問は作りませんでした。"
        ), []

    gap, _, _, _, pick_first, pick_other, shared = best
    # ここで初めて事象にする。証拠表へ入るのもこの 2 件だけ。
    first = _event_for(pick_first.kind, pick_first.rec, store)
    other = _event_for(pick_other.kind, pick_other.rec, store)
    if not first or not other or not first.get("evidenceIds") \
            or not other.get("evidenceIds"):
        return None, ("採用した二つの記録の出典を保存できなかったため、"
                      "関連付けの設問は作りませんでした。"), []
    ids = [first["evidenceIds"][0], other["evidenceIds"][0]]
    # 仕様書 14.2 が求める「同一端末で 34 秒以内」の形。これを出せない組は
    # 上で落としてある。
    reason_text = f"同一端末（{shared}）で {_gap_text(gap)}"
    gap_text = reason_text + "に"

    options = [
        f"{first['detail'][:60]} のほうが先に記録された",
        f"{other['detail'][:60]} のほうが先に記録された",
        "二つの記録は同じ時刻で、前後は決められない",
        "この二つの記録からは、どちらが先かは分からない",
    ]
    at = pick_index(qid + ids[0], 2)  # 正解は先頭 2 つのどちらか
    if at == 1:
        options[0], options[1] = options[1], options[0]
    correct = options.index(f"{first['detail'][:60]} のほうが先に記録された")
    prompt = (
        f"{gap_text}記録された二つの記録を見比べます。"
        "下に示した根拠の時刻から、どちらが先に記録されたと言えますか。"
    )
    return {
        "id": qid,
        "type": "single_choice",
        "category": "correlation",
        "learningObjective": "近接した二つの記録を突き合わせ、記録された順序を読む",
        "q": prompt,
        "prompt": prompt,
        "options": options,
        "correct": correct,
        "explain": (
            f"{first['time']['display']} と {other['time']['display']} を"
            f"見比べると、前者が先に記録されています（{reason_text}）。\n\n"
            f"この二つを並べてよい理由は、{reason_text}であり、"
            f"{_basis_label(first['_stamp'].basis)}ためです。\n\n"
            "ここで言えるのは記録の順序だけです。先に記録されたほうが"
            "後のほうを引き起こした、とは言えません。時計のずれ、書き込み"
            "の遅れ、そもそも記録されていない出来事があるためです。"
            "因果を言うには、親子関係や対象の一致など、別の根拠が要ります。"
        ),
        "explanation": "",
        "evidenceIds": ids,
        "correlation": {
            "reason": reason_text,
            "gapSeconds": round(gap, 3),
            "windowSeconds": window,
            "hostKey": shared,
            "basis": first["_stamp"].basis,
            "types": [first["type"], other["type"]],
        },
        "nextInvestigation": "この二つの記録の間に、同じ端末で他に何が記録されているかを見る",
        "status": "correlated",
    }, "", [first, other]


def _gap_text(gap: float) -> str:
    """時間差の言い方。仕様書の例「34 秒以内」に合わせる。"""
    if gap < 1:
        return "1 秒以内"
    return f"{int(gap) if gap == int(gap) else round(gap, 1)} 秒以内"


def _attck_quiz(store: EvidenceStore, stages: list[dict],
                qid: str) -> tuple[dict | None, int, str]:
    """観測を ATT&CK の手法へ対応させる設問。段階の位置と、作れない理由も返す。

    誤答は、同じ教材の中で実際に対応が付いた別の手法から取る。こちらで
    それらしい手法名を考え出すと、その選択肢だけ根拠が無くなる。教材に
    2 種類以上の対応が無ければ作らない。
    """
    tagged: list[tuple[int, dict, dict]] = []
    for at, stage in enumerate(stages):
        for event in stage["events"]:
            tag = event.get("attck")
            if tag and tag.get("id") and event.get("evidenceIds"):
                tagged.append((at, event, tag))
    labels = sorted({f'{t["id"]} · {t["name"]}' for _, _, t in tagged})
    if len(labels) < 3:
        return None, -1, ("対応の付いた手法が 3 種類に満たないため、"
                          "手法を選ぶ設問は作りませんでした。")

    at, event, tag = tagged[0]
    answer = f'{tag["id"]} · {tag["name"]}'
    others = [x for x in labels if x != answer][:3]
    options = [answer] + others
    pos = pick_index(qid + tag["id"], len(options))
    options[0], options[pos] = options[pos], options[0]
    prompt = (
        "下に示した記録は、どの手法にあたりますか。"
        "記録そのものに書かれていることだけから選んでください。"
    )
    return {
        "id": qid,
        "type": "single_choice",
        "category": "attck",
        "learningObjective": "観測された 1 行を、根拠を説明できる手法へ対応させる",
        "q": prompt,
        "prompt": prompt,
        "options": options,
        "correct": options.index(answer),
        "explain": (
            f'{tag["reason"]}\n\n'
            f'そのため、この記録は {answer} にあたります。'
            f'対応規則は {tag["ruleVersion"]} です。'
            "手法名から記録を推し量るのではなく、記録に書かれている項目から"
            "手法へたどるのが順序です。"
        ),
        "explanation": "",
        "evidenceIds": list(event["evidenceIds"]),
        "nextInvestigation": "同じ端末で、この手法に関わる他の記録が残っていないかを見る",
        "status": "observed",
    }, at, ""


def _limits_quiz(store: EvidenceStore, stages: list[dict],
                 qid: str) -> tuple[dict | None, int, str]:
    """1 行から「言えること」と「言えないこと」を分ける設問。

    通信の記録を使う。宛先と要求元は行に書いてあるが、中身、目的、利用者の
    関与は書いていない。ここを混ぜたまま先へ進むのが、調査でいちばん起きる
    間違いなので、独立した設問にする。
    """
    for at, stage in enumerate(stages):
        for event in stage["events"]:
            if event["type"] != "network" or not event.get("evidenceIds"):
                continue
            excerpt = _stored_excerpt(store, event["evidenceIds"])
            client = _proxy_client(excerpt)
            if not client or " " not in excerpt:
                continue
            # 宛先は抜粋の末尾側にあることがあるので、抜粋に残っている
            # ことを確かめてから使う。
            target = ""
            for token in excerpt.split():
                if "://" in token or token.count(".") >= 2:
                    if token != client:
                        target = token
                        break
            if not target:
                continue
            answer = f"{client} から {target} への要求が記録されたこと"
            options = [
                answer,
                "この通信で、端末内の情報が外部へ持ち出されたこと",
                "この宛先が、攻撃者の用意したものであること",
                "この通信が、利用者の操作によらず行われたこと",
            ]
            pos = pick_index(qid + event["evidenceIds"][0], len(options))
            options[0], options[pos] = options[pos], options[0]
            prompt = (
                "下に示したプロキシの記録 1 行だけから、確かに言えることは"
                "どれですか。"
            )
            return {
                "id": qid,
                "type": "single_choice",
                "category": "limits",
                "learningObjective": "1 行の記録から言えることと、言えないことを分ける",
                "q": prompt,
                "prompt": prompt,
                "options": options,
                "correct": options.index(answer),
                "explain": (
                    "この行に書いてあるのは、要求元と宛先、そして要求が"
                    "記録されたことだけです。\n\n"
                    "持ち出しの有無は、本文が暗号化されていれば残りません。"
                    "宛先の素性は、この行からは分かりません。利用者が操作した"
                    "のか、プログラムが勝手に出したのかも書かれていません。"
                    "これらを言うには、端末側の記録や宛先の調査など、"
                    "別の根拠が要ります。"
                ),
                "explanation": "",
                "evidenceIds": list(event["evidenceIds"]),
                "nextInvestigation": f"{target} への通信が、どのプロセスから出たのかを端末の記録で確かめる",
                "status": "observed",
            }, at, ""
    return None, -1, ("通信の記録から要求元と宛先を読み取れなかったため、"
                      "言えることを選ぶ設問は作りませんでした。")


# ---------------------------------------------------------------------------
# 時系列・ATT&CK・未確定事項（フェーズ3）
# ---------------------------------------------------------------------------

#: 確からしさの区別（仕様書 14.1）。色だけでなく文言でも出せるよう、表示名を
#: ここに持つ。生ログ 1 行の証拠は常に observed。複数行を突き合わせた「解釈」
#: を作っても、元の証拠自体は observed のまま書き換えない。
STATUS_LABEL = {
    "observed": "観測された事実",
    "correlated": "複数記録からの関連付け",
    "hypothesis": "未確定（追加調査が必要）",
}


def _timeline(stages: list[dict], store: EvidenceStore) -> list[dict]:
    """記録された順に並べた一覧。

    「攻撃がこの順で実行された」ではなく「ログにこの順で記録された」を言う。
    記録の順序と出来事の順序は同じとは限らない（時計のずれ、書き込みの遅れ、
    そもそも記録されていない出来事）。文言もデータもそこを混ぜない。
    """
    rows: list[dict] = []
    seen: set[str] = set()
    for stage in stages:
        for event in stage["events"]:
            ident = (event.get("evidenceIds") or [None])[0]
            if not ident or ident in seen:
                continue
            seen.add(ident)
            item = store.get(ident) or {}
            src = item.get("source", {})
            rows.append({
                "_stamp": event.get("_stamp") or timeline.UNKNOWN,
                "member": src.get("member", ""),
                "line": src.get("line", 0),
                "evidenceId": ident,
                "timestamp": (event.get("time") or {}).get("display",
                                                           timeline.UNKNOWN_LABEL),
                "timeKnown": bool((event.get("time") or {}).get("known")),
                # タイムゾーンが読めた行だけ、他の行と大小を比べられる。
                # 画面はこれを見て「基準不明」と添える。
                "timeComparable": bool(
                    (event.get("_stamp") or timeline.UNKNOWN).comparable
                ),
                # どの時計で測った時刻か。同じ札どうしだけが比べられる。
                "timeBasis": (event.get("_stamp") or timeline.UNKNOWN).basis,
                "title": event.get("detail", ""),
                "host": event.get("host", ""),
                "evidenceIds": [ident],
                "status": "observed",
                "stageId": stage.get("id", ""),
            })
    rows.sort(key=timeline.order_key)
    return [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows]


def _techniques(stages: list[dict]) -> list[dict]:
    """根拠付き ATT&CK の一覧。同じ手法は 1 件へまとめ、根拠は全部残す。

    まとめるのは ID と名前だけで、理由は束ねない。T1490 は `vssadmin` からも
    `bcdedit` からも付くが、その二つは「復元用の控えを消した」と「回復機能を
    無効化した」という別の観測である。先に見つかったほうの理由だけを残すと、
    vssadmin の話しか書いていない説明に bcdedit の行が根拠として並ぶ。示した
    記録と説明が食い違う状態は、根拠付きとは言えない。

    そこで `reasons` を「理由とその根拠」の組の並びにする。`reason` と
    `evidenceIds` は、旧形式の読み手のために残している。
    """
    merged: dict[str, dict] = {}
    for stage in stages:
        for event in stage["events"]:
            tag = event.get("attck")
            if not tag or not tag.get("id") or not tag.get("evidenceIds"):
                continue
            row = merged.setdefault(tag["id"], {
                "id": tag["id"], "name": tag["name"], "reason": tag["reason"],
                "reasons": [], "evidenceIds": [], "ruleVersion": tag["ruleVersion"],
                "confidence": tag["confidence"], "status": tag["status"],
            })
            slot = next((r for r in row["reasons"] if r["reason"] == tag["reason"]), None)
            if slot is None:
                slot = {"reason": tag["reason"], "evidenceIds": []}
                row["reasons"].append(slot)
            for ident in tag["evidenceIds"]:
                if ident not in slot["evidenceIds"]:
                    slot["evidenceIds"].append(ident)
                if ident not in row["evidenceIds"]:
                    row["evidenceIds"].append(ident)
    for row in merged.values():
        if len(row["reasons"]) > 1:
            # 旧形式の `reason` しか読まない相手にも、理由が複数あることは
            # 伝わるようにする。黙って 1 件目だけを見せない。
            row["reason"] = "／".join(r["reason"] for r in row["reasons"])
    return [merged[k] for k in sorted(merged)]


def _unknowns(stages: list[dict], techniques: list[dict],
              skipped: list[str]) -> list[dict]:
    """断定できなかったこと。教材の中身に応じて出す。

    いつも同じ注意書きを並べると読まれなくなるので、当てはまるものだけを
    積む。`dataset` 由来の打ち切りや未読ログは、呼び出し側が足す。
    """
    out: list[dict] = []
    out.append({
        "topic": "記録の順序と出来事の順序",
        "detail": ("時系列は「ログにこの順で記録された」ことを示します。"
                   "記録の前後は、一方が他方を引き起こしたことを意味しません。"),
    })
    if any(e["type"] == "network" for s in stages for e in s["events"]):
        out.append({
            "topic": "外部との通信",
            "detail": ("通信の記録だけでは、その通信が悪意あるものか、"
                       "情報を持ち出したのかは決まりません。中身は"
                       "暗号化されていれば残らず、宛先だけでは用途が"
                       "分かりません。"),
        })
    if not techniques:
        out.append({
            "topic": "ATT&CK の対応",
            "detail": ("この教材では、根拠を説明できる対応が見つかりません"
                       "でした。推測で手法を当てはめていません。"),
        })
    # タイムゾーンの有無が混ざっていると、一本の軸に並べた見た目ほどには
    # 前後が確かでない。並べること自体はやめない（同じログ内の相対順序は
    # 読めるため）が、混ざっている事実は必ず書く。
    known = [
        (e.get("_stamp") or timeline.UNKNOWN)
        for s in stages for e in s["events"]
        if (e.get("time") or {}).get("known")
    ]
    if len({st.basis for st in known}) > 1:
        out.append({
            "topic": "時刻の基準が揃っていない",
            "detail": ("タイムゾーンが書かれた記録と、書かれていない記録が"
                       "混ざっています。一覧は読み取った時刻の順に並べて"
                       "いますが、基準の違う記録どうしの前後は決められません。"
                       "「基準不明」と付いた行は、同じログの中でだけ前後を"
                       "比べられます。別のログの記録とは比較していません。"),
        })
    unknown_time = [
        r for s in stages for r in s["events"]
        if not (r.get("time") or {}).get("known")
    ]
    if unknown_time:
        out.append({
            "topic": "時刻を読めなかった記録",
            "detail": (f"{len(unknown_time)} 件は時刻の形式を解析できず、"
                       "「時刻不明」として末尾に置いています。"),
        })
    for note in skipped:
        out.append({"topic": "根拠が足りず作らなかった設問", "detail": note})
    return out


def _next_investigations(stages: list[dict]) -> list[str]:
    """推奨する追加調査。設問が示した観点を集める。"""
    out: list[str] = []
    for stage in stages:
        for quiz in stage.get("quizzes", []):
            nxt = quiz.get("nextInvestigation")
            if nxt and nxt not in out:
                out.append(nxt)
    return out


def _introduction(stages: list[dict], itm2: list[dict], proxy: list[dict],
                  hosts: Counter, sources: dict) -> dict:
    """調査導入。分からない項目は推測で埋めず、その旨を書く。"""
    log_types = []
    if itm2:
        log_types.append("InfoTrace Mark II（端末の記録）")
    if proxy:
        log_types.append("Proxy（通信の記録）")
    objectives = [
        "記録された事実と、そこから考えられることを区別して読む",
        "設問の答えを、どのログの何行目かで示せるようにする",
    ]
    if any(e.get("attck") for s in stages for e in s["events"]):
        objectives.append("観測された手法を、根拠付きで MITRE ATT&CK へ対応付ける")
    # 1 段階あたり数分の見積り。根拠のある数字ではないので、目安と明示する。
    minutes = max(5, 3 * len(stages))
    return {
        "scenario": ("実際に記録されたログを読み、何が起きたのかを段階を追って"
                     "確かめます。各段階の設問は、示された記録から答えられます。"),
        "logTypes": log_types or ["取得できませんでした"],
        "hosts": sorted(h for h in hosts if h and h != "?") or ["記録からは分かりません"],
        "objectives": objectives,
        "status": "draft",
        "estimatedMinutes": minutes,
        "inputs": sorted(sources),
    }


def build_lesson(name: str, sources: dict[str, str], lesson_id: str) -> dict | None:
    """Build a draft lesson from {member name: text} of one or more logs."""
    itm2: list[dict] = []
    proxy: list[dict] = []
    # 名前順に読む。証拠 ID は並び順を材料にしないが、同じ入力から同じ教材を
    # 作るには、事象の並びも決まっている必要がある。
    for member_name in sorted(sources):
        text = sources[member_name]
        itm2 += parse_itm2(text, name=member_name)
        proxy += parse_proxy(text, name=member_name)
    if not itm2 and not proxy:
        return None

    store = EvidenceStore()
    stages = []
    endpoint = events_from_itm2(itm2, store)
    network = events_from_proxy(proxy, store)
    hosts = Counter(r.get("com", "?") for r in itm2)

    procs = [e for e in endpoint if e["type"] == "process"]
    if procs:
        stages.append(_stage_endpoint(itm2, procs, hosts, store))
    files = [e for e in endpoint if e["type"] == "file"]
    if files:
        stages.append(_stage_files(files, store))
    if network:
        stages.append(_stage_network(proxy, network, store))

    if not stages:
        return None

    # 観測を手法へ対応させる設問と、1 行から言えることを分ける設問。
    # どちらも根拠の事象がある段階へ足す。別の段階へ置くと、その設問が
    # 指す記録が画面に無い段階になってしまう。
    correlation_notes: list[str] = []
    for maker, qid in ((_attck_quiz, "q-attck-01"), (_limits_quiz, "q-limits-01")):
        quiz, at, why = maker(store, stages, qid)
        if quiz:
            stages[at].setdefault("quizzes", []).append(quiz)
        elif why:
            correlation_notes.append(why)

    # 複数の証拠を突き合わせる設問。同じ端末で近接している組があるときだけ
    # 作る。作れなければ理由を残す。
    #
    # 探索は段階に載った事象からではなく、完全な事象集合から行う。段階の
    # 一覧は表示のために重複を間引き、`STAGE_EVENTS` 件で切ってあるので、
    # そこから探すと近接した組を見落とす（`events_from_itm2` の説明を参照）。
    #
    # これは独立した段階にする。二つの記録は別の段階から来ることがあり、
    # 既存の段階へ足すと、その段階には無い記録を根拠として指すことになる。
    # 突き合わせ自体が一つの作業なので、段階として分けるほうが筋も通る。
    corr, why, pair = _correlation_quiz(
        store, _correlation_candidates(itm2, proxy), "q-correlate-01"
    )
    if corr:
        stages.append({
            "id": "correlate",
            "name": "関連付け — 二つの記録を突き合わせる",
            "intro": (
                "ここまでは、ログを種類ごとに分けて読んできました。"
                "最後に、別々に見てきた記録を並べて突き合わせます。\n\n"
                "突き合わせて分かるのは、記録された順序までです。"
                "近い時刻に並んでいることは、一方が他方を引き起こした"
                "根拠にはなりません。"
            ),
            "events": [dict(e) for e in pair],
            "quizzes": [corr],
        })
    elif why:
        correlation_notes.append(why)

    # 根拠の無い設問は落とす。仕様書 15.1 の「根拠が不足する問題は生成しない」。
    # 一般論だけの設問が混ざると、根拠を示すという教材の約束が崩れる。
    for stage in stages:
        raw = stage.get("quizzes")
        if raw is None:
            # 段階によっては設問を 1 つしか作らない。ここで同じ形に揃える。
            raw = [stage["quiz"]] if stage.get("quiz") else []
        kept = [
            q for q in raw
            if q.get("evidenceIds") and all(store.get(i) for i in q["evidenceIds"])
        ]
        stage["quizzes"] = kept
        # `quiz` は旧形式の表示経路が読む。残った先頭を充てる。
        stage["quiz"] = kept[0] if kept else None
    if not stages:
        return None

    # 教材へ残す証拠は、実際に画面へ出る事象と設問が指しているものだけにする。
    # 解析中は 1 行ごとに登録するので実データでは千件を超えるが、そのすべてを
    # 教材 JSON に抱えると、DB にもブラウザにも読まれない抜粋が載り続ける。
    used: set[str] = set()
    for stage in stages:
        for event in stage["events"]:
            used.update(event.get("evidenceIds", []))
        for quiz in stage["quizzes"]:
            used.update(quiz.get("evidenceIds", []))
            for option in quiz.get("options", []):
                if isinstance(option, dict) and option.get("evidenceId"):
                    used.add(option["evidenceId"])
    evidence = {k: v for k, v in store.as_json().items() if k in used}

    # 段階から設問が全部落ちても、その段階を消さずに残す。観測できた事実は
    # 見せたうえで「根拠が足りず設問を作れなかった」と言うほうが、黙って
    # 段階ごと消すより手がかりが残る。
    for stage in stages:
        if not stage["quizzes"]:
            stage["note"] = "この段階では、問題を作るための根拠が不足しています。"
            correlation_notes.append(
                f"{stage['name']}: 根拠が足りず、設問を作れませんでした。"
            )

    return {
        "id": lesson_id,
        "title": name,
        "tagline": "ログから自動生成しました。使用前に内容を確認してください。",
        "difficulty": "中級",
        "family": "DFIR",
        "source": {
            "type": "generated",
            "note": "データセットのログから自動生成した演習です。内容を確認のうえ使用してください。",
            "inputs": sorted(sources),
        },
        "evidence": evidence,
        "introduction": _introduction(stages, itm2, proxy, hosts, sources),
        "report": {
            "timeline": _timeline(stages, store),
            "techniques": _techniques(stages),
            "unknowns": _unknowns(stages, _techniques(stages), correlation_notes),
            "nextInvestigations": _next_investigations(stages),
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
        "stages": [
            {**st, "events": [_publish(e) for e in st["events"]]} for st in stages
        ],
    }
