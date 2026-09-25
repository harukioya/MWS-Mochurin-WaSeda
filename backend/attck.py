"""attck.py — 観測を MITRE ATT&CK の手法へ対応させる規則。

ログの形式は知らない。受け取るのは、パーサーが保存済みの抜粋から読み直した
事実（`parsers.FactReading`）だけである。

  * プロセス開始: 起動した実行ファイルの名前と、渡された引数列
  * レジストリ:   設定された場所

事実には「原文のどの項目から読んだか」が付いてくるので、理由は
「この 1 行の psPath に書かれています」のように、示した抜粋のどこを見れば
確かめられるかまで言える。抜粋から読めなかった事実は None で届き、その
ときは対応を付けない。

HONESTY RULE. 付けるのは、1 行から疑いなく言えるものだけ。PowerShell の
起動は、そう書いてあるから T1059.001 である。それ以外は推測で埋めずに
無タグで残す。確信をもって誤ったタグは、タグが無いより悪い。外部宛て
である、POST である、`.exe` であるといった理由だけでは付けない。
"""

from __future__ import annotations

#: 対応規則の版。教材に残すことで、後から「どの規則で付けたタグか」を
#: 追える。規則を足し引きしたら上げる。
RULE_VERSION = "2026-09-mws-3"


def tokens(cmd: str) -> list[str]:
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


#: プロセス開始の規則。キーは起動した実行ファイルの名前（小文字）。
#:
#: 値は (起動だけで足りるか, 規則) の組。
#:
#:   (False, (ID, 名前, 理由))  … そのプログラムが起動したこと自体が手法に
#:                                あたる。解釈系と、用途が一つしかない照会系。
#:                                理由の `{field}` は、実行ファイル名を読んだ
#:                                原文の項目名に置き換わる。
#:   (True,  照合関数)          … 引数列を見て決める。関数は (ID, 名前, 理由)
#:                                か None を返す。同じプログラムでも引数に
#:                                よって別の手法になるので、実行ファイルごとに
#:                                Technique を 1 つ決め打ちにはしない。
#:
#: どちらの場合も、判定に使った事実が保存済みの抜粋から読めなければ付けない。
#: 抜粋を読んでも確かめられない対応は、根拠付きとは言えないため。
PROCESS_RULES: dict[str, tuple[bool, object]] = {
    # --- 起動そのものが手法にあたるもの ---
    "powershell.exe": (False, (
        "T1059.001", "Command and Scripting Interpreter: PowerShell",
        "起動したプログラムが PowerShell 本体であることが、"
        "この 1 行の {field} に書かれています。")),
    "pwsh.exe": (False, (
        "T1059.001", "Command and Scripting Interpreter: PowerShell",
        "起動したプログラムが PowerShell 本体であることが、"
        "この 1 行の {field} に書かれています。")),
    "cmd.exe": (False, (
        "T1059.003", "Command and Scripting Interpreter: Windows Command Shell",
        "起動したプログラムが Windows のコマンドシェルであることが、"
        "この 1 行の {field} に書かれています。")),
    "wscript.exe": (False, (
        "T1059.005", "Command and Scripting Interpreter: Visual Basic",
        "スクリプト実行系が起動したことが、この 1 行の {field} に"
        "書かれています。")),
    "cscript.exe": (False, (
        "T1059.005", "Command and Scripting Interpreter: Visual Basic",
        "スクリプト実行系が起動したことが、この 1 行の {field} に"
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

#: レジストリの規則。設定された場所に対する明示的な一致だけを持つ。
REGISTRY_RULES = (
    ("CurrentVersion\\Run",
     "T1547.001", "Boot or Logon Autostart: Registry Run Keys",
     "この 1 行の {field} が、ログオン時に自動実行される場所を指しています。"),
)


def tag(ident: str, name: str, reason: str, evidence_ids: list[str]) -> dict:
    """ATT&CK の対応。理由と根拠が無いものは作れない形にしておく。

    `status` は `observed` 固定。ここで付けるのは、保存した 1 行の抜粋から
    直接読み取れるものだけだから。
    """
    return {
        "id": ident,
        "name": name,
        "reason": reason,
        "evidenceIds": list(evidence_ids),
        "ruleVersion": RULE_VERSION,
        "confidence": "high",
        "status": "observed",
    }


def for_process(program, command_line, evidence_ids: list[str]) -> dict | None:
    """プロセス開始 1 件への対応。事実は保存済みの抜粋から読み直したもの。

    `program` と `command_line` は `parsers.FactReading` か None。解析済みの
    属性ではなく抜粋から読み直した値を受け取るのが要点で、属性には行全体の
    情報が入っているため、判定に使った項目が抜粋の外にあっても対応が付いて
    しまう。そうなると「この 1 行の psPath に書かれています」と言いながら、
    示した抜粋に psPath が無い、という状態になる。
    """
    if program is None or not program.value or not evidence_ids:
        return None
    entry = PROCESS_RULES.get(program.value.lower())
    if not entry:
        return None
    needs_arg, rule = entry
    if not needs_arg:
        return tag(rule[0], rule[1], rule[2].replace("{field}", program.field), evidence_ids)
    cmd = command_line.value if command_line is not None else ""
    if not cmd:
        return None  # 引数が抜粋に無い。起動しただけでは手法を決められない。
    found = rule(tokens(cmd))
    if not found:
        return None
    return tag(found[0], found[1], found[2], evidence_ids)


def for_registry(path, evidence_ids: list[str]) -> dict | None:
    """レジストリ設定 1 件への対応。`path` は抜粋から読み直した事実か None。"""
    kept = path.value if path is not None else ""
    for needle, tid, tname, why in REGISTRY_RULES:
        if evidence_ids and kept and needle in kept:
            return tag(tid, tname, why.replace("{field}", path.field), evidence_ids)
    return None
