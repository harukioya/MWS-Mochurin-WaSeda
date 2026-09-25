"""explain.py — 正規化イベントから、画面が描ける教材を作る。

画面側（`js/player.js` が段階を進め、`js/quiz.js` が設問を出し、
`js/recap.js` が最終レポートを描く）はすでにある。ここがするのは、同じ JSON
の形を、手書きの例ではなく実データから作ることである。

このモジュールはログの形式を知らない。受け取るのは `parsers` が作った
正規化イベント（`parsers.NormalizedEvent`）だけで、形式に固有のこと――
どの項目に何が書かれているか、その形式の記録を何と呼ぶか――は、イベントを
作ったパーサーに尋ねる。形式ごとの分岐（`if parser_id == ...`）は書かない。
新しい形式へ対応するときに、このファイルを変更する必要はない。

知っているのは、正規化イベントの語彙だけである。

  process   プロセスの開始。属性 program / program_name
  file      ファイルの作成・書き込み。属性 path / name
  registry  レジストリの設定。属性 path
  network   通信の要求。属性 client / method / target

HONESTY RULE. ATT&CK の対応は、保存した 1 行の抜粋から疑いなく言えるものに
だけ付ける（`attck.py`）。自動生成した教材は、教員が確かめるための下書き
であり、自らそう名乗る。確信をもって誤った対応は、対応が無いより悪い。
"""

from __future__ import annotations

import ipaddress
from bisect import bisect_left, bisect_right
from collections import Counter
from typing import Callable, Mapping

import attck
import parsers
import timeline
from evidence import EvidenceStore, pick_index
from parsers import FactReading, FactText, NormalizedEvent, ParsedSources, Parser

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

#: 1 段階に載せる事象の数。
STAGE_EVENTS = 8

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

#: 確からしさの区別（仕様書 14.1）。色だけでなく文言でも出せるよう、表示名を
#: ここに持つ。生ログ 1 行の証拠は常に observed。複数行を突き合わせた「解釈」
#: を作っても、元の証拠自体は observed のまま書き換えない。
STATUS_LABEL = {
    "observed": "観測された事実",
    "correlated": "複数記録からの関連付け",
    "hypothesis": "未確定（追加調査が必要）",
}

#: パーサーが事実の説明を持たないときの書き出し。`{field}` は、実際に値を
#: 読んだ原文の項目名。
DEFAULT_WHERE = "この 1 行の `{field}` に、その値が記録されています。"

#: パーサーが記録の呼び名を持たないときの呼び名（通信の段階と設問で使う）。
DEFAULT_NETWORK_NOUN = "通信の記録"


# ---------------------------------------------------------------------------
# パーサーへの問い合わせ
# ---------------------------------------------------------------------------

class _Readers:
    """事象を作ったパーサーへ、抜粋の読み直しと説明文を尋ねる窓口。

    教材生成が形式を知らずに済むのは、ここで「この事象を作ったパーサー」に
    尋ねているからである。解析に使ったパーサーの一覧を優先し、無ければ既定の
    登録簿を見る（内部関数を単体で呼ぶテストのため）。
    """

    def __init__(self, parsers_by_id: Mapping[str, Parser] | None = None) -> None:
        self._by_id = dict(parsers_by_id or {})

    def parser(self, parser_id: str) -> Parser | None:
        return self._by_id.get(parser_id) or parsers.REGISTRY.get(parser_id)

    def reread(self, nev: NormalizedEvent | None, fact: str,
               excerpt: str) -> FactReading | None:
        """保存済みの抜粋から事実を読み直す。読めなければ None。"""
        if nev is None or not excerpt:
            return None
        parser = self.parser(nev.parser_id)
        if parser is None:
            return None
        got = parser.reread(nev.kind, fact, excerpt)
        if not isinstance(got, FactReading) or not got.value:
            return None
        return got

    def text(self, nev: NormalizedEvent | None, fact: str) -> FactText | None:
        parser = self.parser(nev.parser_id) if nev is not None else None
        got = parser.fact_text(nev.kind, fact) if parser else None
        return got if isinstance(got, FactText) else None

    def nouns(self, parser_ids: list[str], kind: str) -> list[str]:
        out = []
        for pid in parser_ids:
            parser = self.parser(pid)
            noun = parser.record_noun(kind) if parser else ""
            if noun and noun not in out:
                out.append(noun)
        return out

    def abouts(self, parser_ids: list[str], kind: str) -> str:
        out = []
        for pid in parser_ids:
            parser = self.parser(pid)
            text = parser.about(kind) if parser else ""
            if text and text not in out:
                out.append(text)
        return "".join(out)

    def label(self, parser_id: str) -> str:
        parser = self.parser(parser_id)
        return parser.label if parser else parser_id


def _value(reading: FactReading | None) -> str:
    return reading.value if reading is not None else ""


def _producers(events: list[NormalizedEvent], kind: str) -> list[str]:
    """その種別の事象を出したパーサーの ID。ID 順で決定的に返す。"""
    return sorted({e.parser_id for e in events if e.kind == kind})


# ---------------------------------------------------------------------------
# 事象（画面に出す 1 件）
# ---------------------------------------------------------------------------

def _is_external(target: str) -> bool:
    """True for a routable address. Private/loopback targets are lateral, not exfil."""
    host = target.split(":")[0]
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return True  # a hostname; treat as external
    return not (addr.is_private or addr.is_loopback or addr.is_link_local)


def _destination(target: str) -> str:
    """宛先の要点。同じ宛先への繰り返しを 1 件へまとめるのに使う。"""
    return target.split("/")[0] if "//" not in target else target.split("/")[2]


def _event(kind: str, detail: str, attck_tag: dict | None = None,
           evidence_ids: list[str] | None = None,
           stamp: "timeline.Stamp | None" = None,
           host: str = "", nev: NormalizedEvent | None = None) -> dict:
    ev = {"type": kind, "detail": detail[:400]}
    if attck_tag:
        ev["attck"] = attck_tag
    if evidence_ids:
        ev["evidenceIds"] = list(evidence_ids)
    if host:
        ev["host"] = host
    # 時刻は必ず持たせる。読めなかった行も「時刻不明」として残し、捨てない。
    st = stamp or timeline.UNKNOWN
    ev["time"] = st.as_json()
    ev["_stamp"] = st
    # 元の正規化イベント。設問を作るときに、どのパーサーへ抜粋の読み直しを
    # 尋ねればよいかを知るために持つ。教材 JSON へは出さない。
    if nev is not None:
        ev["_nev"] = nev
    return ev


def _publish(event: dict) -> dict:
    """教材 JSON へ載せる形。内部だけで使うキーを落とす。

    `_stamp` は並べ替えのために持つ `Stamp` で、JSON にできない。表示と状態は
    `time` に写してある。`_nev` は正規化イベントへの参照。元の辞書は壊さない。
    """
    return {k: v for k, v in event.items() if not k.startswith("_")}


def _stored_excerpt(store: EvidenceStore | None, ids: list[str]) -> str:
    """登録済み証拠の抜粋。保存された長さで切られた、画面に出るのと同じ文字列。"""
    if store is None or not ids:
        return ""
    item = store.get(ids[0])
    return item["source"]["excerpt"] if item else ""


def _lesson_event(nev: NormalizedEvent, store: EvidenceStore,
                  readers: _Readers | None = None) -> dict:
    """正規化イベント 1 件から、画面に出す事象を 1 件作る。証拠もここで登録する。

    一覧を作るときと、相関に採用した 2 件を作るときの、どちらもここを通す。
    二箇所で組み立てると、同じ行が場所によって違う文言や違うタグになる。

    ATT&CK の対応は「保存した抜粋」から付け直す。正規化イベントの属性は行
    全体から作っているので、そちらで判定すると、抜粋に写っていない項目を
    根拠として示すことになる。読み直しはイベントを作ったパーサーに頼む。

    通信は意図的に無タグ。外部宛であること、POST であること、拡張子が
    .exe であることは、いずれも手法を決める根拠にならない。どれが問題かを
    決めること自体が、この演習で身に付ける作業である。
    """
    readers = readers or _Readers()
    ident = store.add(nev.source, nev.kind)
    tag = None
    if nev.kind in ("process", "registry"):
        excerpt = _stored_excerpt(store, [ident])
        if nev.kind == "process":
            tag = attck.for_process(
                readers.reread(nev, "program_name", excerpt),
                readers.reread(nev, "command_line", excerpt),
                [ident],
            )
        else:
            tag = attck.for_registry(readers.reread(nev, "path", excerpt), [ident])
    return _event(nev.kind, nev.summary, tag, [ident], nev.timestamp, nev.host, nev)


def display_events(events: list[NormalizedEvent], store: EvidenceStore,
                   readers: _Readers | None = None) -> list[dict]:
    """画面の一覧に載せる事象。入力の順を保ち、同じものは最初の 1 件だけ残す。

    同じ端末で同じ実行ファイルが何度起動しても、一覧に何行も並べる意味は
    薄い。通信は外部の宛先だけを、宛先ごとに 1 件へ間引く。相関の探索は
    この一覧からは行わない（`correlation_candidates` を参照）。
    """
    readers = readers or _Readers()
    out: list[dict] = []
    seen: set[tuple] = set()
    for nev in events:
        kind = nev.kind
        if kind == "process":
            key = ("process", nev.host, nev.attributes["program_name"].lower())
        elif kind == "file":
            if not nev.attributes["path"]:
                continue
            key = ("file", nev.host, nev.attributes["name"])
        elif kind == "registry":
            if not nev.attributes["path"]:
                continue
            key = ("registry", nev.attributes["path"])
        elif kind == "network":
            target = nev.attributes["target"]
            if not _is_external(target):
                continue
            key = ("network", _destination(target))
        else:
            continue
        if key in seen:
            continue
        seen.add(key)
        out.append(_lesson_event(nev, store, readers))
    return out


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


# ---------------------------------------------------------------------------
# 設問
# ---------------------------------------------------------------------------

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

    単に「抜粋のどこかに同じ文字列がある」では足りない。引数列や親プロセス
    の項目にも同じ語は現れるので、起動対象を示す項目が抜粋の外にあっても
    検査を通ってしまう。見るべき項目を名指しする（読み方はパーサーが知って
    いる）。
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
        "hint": (
            "選択肢のファイル名と行番号を、上の証拠カードと照合してください。"
            "同じ単語があるだけでなく、主張している対象と動作を直接記録した行を探します。"
        ),
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


def _excerpt_of(event: dict, store: EvidenceStore) -> str:
    """事象が指す証拠の、保存済み抜粋。"""
    ident = (event.get("evidenceIds") or [None])[0]
    item = store.get(ident) if ident else None
    return item["source"]["excerpt"] if item else ""


def _reread_event(event: dict, fact: str, store: EvidenceStore,
                  readers: _Readers) -> FactReading | None:
    """事象に紐づく証拠の原文から、1 つの事実を読み直す。

    設問の正解は、引用する行そのものに書かれていなければならない。説明文
    （`detail`）や解析済みの属性から取ると、こちらで組み立てた値に依存して
    しまう。
    """
    return readers.reread(event.get("_nev"), fact, _excerpt_of(event, store))


def _grounded_choice(store: EvidenceStore, anchor: dict, pool: list[dict],
                     qid: str, objective: str, fact: str, ask: str,
                     rest: str, nxt: str, readers: _Readers) -> dict | None:
    """引用した 1 行を読めば答えられる設問を作る。

    正解も誤答も、同じ一覧に実在するログ行の同じ事実から取る。誤答をこちらで
    考え出すと、その選択肢だけ出典が無くなり「根拠を確かめる」という練習が
    成り立たない。値が足りず選択肢を作れないときは、無理に作らず None を返す。

    解説の書き出し（その形式のどの項目に書かれるか）はパーサーが持つ。
    `rest` は、形式に依らない「なぜそこを見るのか」の部分。
    """
    reading = _reread_event(anchor, fact, store, readers)
    if reading is None:
        return None
    right = reading.value

    wrong: list[str] = []
    for other in pool:
        if other is anchor:
            continue
        value = _value(_reread_event(other, fact, store, readers))
        if value and value != right and value not in wrong:
            wrong.append(value)
        if len(wrong) == 3:
            break
    if not wrong:
        return None

    text = readers.text(anchor.get("_nev"), fact)
    where = (text.where if text else DEFAULT_WHERE).replace("{field}", reading.field)
    why = where + rest
    # 答えの値ではなく、その値を読んだ項目名と読み方だけを渡す。
    # 項目名はパーサーが返すため、新しい形式にも同じ処理を使える。
    hint = f"原文の「{reading.field}」を探してください。" + {
        "program_name": (
            "ここに起動したプログラムが記録されています。パスの場合は、"
            "最後の区切りより後ろのファイル名を読みます。親プロセスや起動時の引数とは区別します。"
        ),
        "host": "ここが記録を残した端末です。ユーザー名や接続先と取り違えないようにします。",
        "path": "操作対象のファイルの場所です。末尾の名前だけでなく、フォルダを含めて選択肢と比べます。",
        "client": "ここが通信の要求元です。通信先のアドレスとは区別して読みます。",
    }.get(fact, "その項目の値を、設問が尋ねている内容と照らし合わせてください。")
    if text and text.next:
        nxt = text.next

    at = pick_index(qid + right, len(wrong) + 1)
    options = wrong[:at] + [right] + wrong[at:]
    src = (store.get(anchor["evidenceIds"][0]) or {}).get("source", {})
    return {
        "id": qid,
        "type": "single_choice",
        "category": "log-reading",
        "learningObjective": objective,
        "hint": hint,
        "q": f"{src.get('member', '')} の {src.get('line', '')} 行目 について。{ask}",
        "prompt": f"{src.get('member', '')} の {src.get('line', '')} 行目 について。{ask}",
        "options": options,
        "correct": at,
        "explain": why,
        "explanation": why,
        "evidenceIds": list(anchor.get("evidenceIds") or []),
        # 問い文が名指ししている行。解答前でも画面がそこへ飛べるようにする。
        # 問い文にもう書いてある行なので、飛べても答えは漏れない。
        # `evidenceIds`（答えの根拠）とは意味が違うので別の項目にする。
        # 根拠を選ばせる設問では、根拠へ先に飛べると答えそのものになるため、
        # この項目を付けてはいけない。
        "subjectEvidenceIds": list(anchor.get("evidenceIds") or [])[:1],
        "nextInvestigation": nxt,
    }


def _stage_endpoint(records: int, procs: list[dict], hosts: Counter,
                    store: EvidenceStore, readers: _Readers,
                    producers: list[str]) -> dict:
    """段階1：端末で何が動いたか。

    設問は、引用した 1 行を読めば答えられるものにする。紐づけたログ行が
    示すのは「起動した」ことだけなので、「そのプログラムが攻撃に使える
    理由」のような一般論は尋ねない。根拠として示せない問いは、根拠を
    添えても根拠付きにはならない。
    """
    shown = _pick(procs)
    anchor = next((e for e in shown if "attck" in e), shown[0] if shown else None)

    quizzes = []
    if anchor is not None:
        which = _grounded_choice(
            store, anchor, shown, "q-endpoint-01",
            "ログ 1 行から、起動したプログラムを読み取る",
            "program_name",
            "この行が起動を記録しているのは、どのプログラムですか。",
            ("答えはこの 1 行の中にあり、推測する余地はありません。\n\n"
             "分析でまず確かめるのはここです。名前だけでは同名の別物と区別が"
             "付かないため、どこに置かれた実行ファイルなのかまで見ます。"),
            "この行に渡された引数と、起動元を確かめる",
            readers,
        )
        if which:
            quizzes.append(which)

        where = _grounded_choice(
            store, anchor, shown, "q-endpoint-02",
            "ログ 1 行から、どの端末の記録かを読み取る",
            "host",
            "この起動が記録されたのは、どの端末ですか。",
            ("複数の端末のログをまとめて読むときは、まずどの端末の話かを"
             "押さえないと、別々の端末で起きたことを 1 つの流れとして誤読します。"),
            "同じ時刻帯に、他の端末で何が記録されているかを見比べる",
            readers,
        )
        if where:
            quizzes.append(where)

        nev = anchor.get("_nev")
        pick = _evidence_pick(
            store, anchor, shown, "q-endpoint-evidence",
            "主張の根拠となるログ行を特定する",
            nev.attributes["program_name"] if nev is not None else "",
            lambda v: f"「{v} が起動した」と言えるのは、どの記録があるからですか。",
            ("設問の主張を支えるのは、その起動そのものを書き留めた 1 行です。"
             "同じ一覧に並んでいても、別のプログラムの記録はこの主張の根拠には"
             "なりません。根拠を示すとは、この 1 行を指せるということです。"),
            "この行の前後を見て、何が起動元になっているかを確かめる",
            proves=lambda ex: _value(readers.reread(nev, "program_name", ex)),
        )
        if pick:
            quizzes.append(pick)

    return {
        "id": "endpoint",
        "name": "端末 — 何が実行されたか",
        "intro": (
            f"監視下の {len(hosts)} 台から、{records} 件の記録が集まっています。"
            + readers.abouts(producers, "process")
            + "\n\n以下は重複を除いた「起動したプログラムの種類」の一覧です。"
            "各行の下に、元になったログの出典と行番号を示しています。"
            "設問は、その原文を読めば答えられるようにしてあります。"
        ),
        "events": shown,
        "quizzes": quizzes,
    }


def _stage_files(files: list[dict], store: EvidenceStore,
                 readers: _Readers | None = None) -> dict:
    """段階2：ディスク上で何が変わったか。"""
    readers = readers or _Readers()
    shown = _pick(files)
    anchor = shown[0]
    quizzes = []

    where = _grounded_choice(
        store, anchor, shown, "q-files-01",
        "ログ 1 行から、書き込まれた場所を読み取る",
        "path",
        "この行が記録しているのは、どのファイルへの書き込みですか。",
        ("\n\n見るべきは中身ではなく置かれた場所です。一時フォルダなら何かの準備、"
         "自動起動に関わる場所なら再起動後も動き続けるための仕込み、システムの"
         "中枢ならそこへ書けた権限そのものが問題になります。同じ内容でも、"
         "どこに置かれたかで意味が変わります。"),
        "このファイルを書き込んだプロセスが、直前に何を起動したかを確かめる",
        readers,
    )
    if where:
        quizzes.append(where)

    host = _grounded_choice(
        store, anchor, shown, "q-files-02",
        "ログ 1 行から、どの端末の記録かを読み取る",
        "host",
        "この書き込みが記録されたのは、どの端末ですか。",
        ("どの端末で起きたかが決まらないと、"
         "この書き込みを、同じ時間帯の起動記録や通信記録と結び付けられません。"),
        "同じ端末の起動記録から、この時刻の前後に何が動いていたかを見る",
        readers,
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


def _stage_network(records: int, network: list[dict], store: EvidenceStore,
                   readers: _Readers, producers: list[str]) -> dict:
    """段階3：外部へ何が出ていったか。

    要求元の設問も、ほかの段階と同じく、引用した 1 行から読み直せる値
    だけで作る。解析済みの属性（`attributes["client"]`）から正解を取ると、
    要求元が抜粋の切り詰めより後ろにある形式では、引用に書かれていない
    値が正解になる。「要求元は行頭にあるので切れない」はプロキシの形式の
    事情であって、教材生成が前提にしてよいことではない。
    """
    shown = _pick(network)
    anchor = shown[0]
    quizzes = []
    nev = anchor.get("_nev")

    ident = (anchor.get("evidenceIds") or [None])[0]
    item = store.get(ident) if ident else None
    if item and nev is not None:
        who = _grounded_choice(
            store, anchor, shown, "q-network-01",
            "ログ 1 行から、通信の要求元を読み取る",
            "client",
            "この通信を出したのは、どの端末ですか。",
            ("通信の中身は暗号化されていれば分かりませんが、"
             "「いつ・どこから・どこへ」は残ります。\n\n"
             "一度の通信だけでは、普通の通信と区別は付きません。"
             "手がかりになるのは、同じ宛先への繰り返しや、その端末の"
             "普段の動きと合わない時間帯といった、複数行にまたがる形です。"),
            "同じ宛先への通信が繰り返されていないか、時刻を並べて確かめる",
            readers,
        )
        if who:
            quizzes.append(who)

        # 根拠を選ぶ設問の主張も、引用から読み直せた要求元だけにする。
        right = _value(_reread_event(anchor, "client", store, readers))
        pick = _evidence_pick(
            store, anchor, shown, "q-network-evidence",
            "主張の根拠となるログ行を特定する",
            right,
            lambda v: f"「{v} が外部へ通信した」と言えるのは、どの記録があるからですか。",
            ("この主張を支えるのは、その通信を書き留めた 1 行です。"
             "同じ一覧の他の行は、別の端末や別の宛先の記録なので、"
             "この主張の根拠にはなりません。"),
            "この端末の起動記録と時刻を突き合わせ、何が通信したのかを絞る",
            proves=lambda ex: _value(readers.reread(nev, "client", ex)),
        )
        if pick:
            quizzes.append(pick)

    noun = "・".join(readers.nouns(producers, "network")) or DEFAULT_NETWORK_NOUN
    return {
        "id": "network",
        "name": "通信 — 外部へ何が出ていったか",
        "intro": (
            f"{noun} {records} 件から、外部の宛先 {len(network)} 箇所を"
            "取り出しました。"
            + readers.abouts(producers, "network")
            + "\n\n通信の中身までは分かりません。一覧に印を付けていないのは、"
            "どれが業務上の通常の通信かは一行ずつ見ても決まらないためです。"
        ),
        "events": shown,
        "quizzes": quizzes,
    }


# ---------------------------------------------------------------------------
# 相関（仕様書 14.2）
# ---------------------------------------------------------------------------

def correlation_candidates(events: list[NormalizedEvent]) -> list[NormalizedEvent]:
    """相関の探索対象。間引かず、証拠も登録しない。

    完全な事象を作ると、1 件ごとに説明文・ATT&CK 判定・最大 1000 文字の
    抜粋・証拠表への登録が発生する。探索に要るのは、種別・時刻・比較基準・
    端末キー・出典の五つだけで、正規化イベントはそれをすでに持っている。
    候補は正規化イベントそのもの（複製しない）で、採用した 2 件だけを
    `_lesson_event` で事象にする。
    """
    out: list[NormalizedEvent] = []
    for nev in events:
        kind = nev.kind
        if kind == "file":
            if not nev.attributes["path"]:
                continue
        elif kind == "network":
            if not _is_external(nev.attributes["target"]):
                continue
        elif kind != "process":
            continue  # レジストリは仕様書 14.2 の相関対象に無い
        stamp = nev.timestamp
        if not stamp.known or not stamp.basis:
            continue
        if not nev.correlation_keys:
            continue
        out.append(nev)
    return out


def _basis_label(basis: str) -> str:
    """比較基準を、画面に出せる言い方へ。"""
    if basis == "utc":
        return "どちらもタイムゾーンつきで記録されている"
    if basis.startswith("local:"):
        return f"どちらも同じログ（{basis[len('local:'):].split(' :: ')[-1]}）の時計で記録されている"
    return ""


def _place(c: NormalizedEvent) -> tuple:
    """入力の並びに依らない二次キー。証拠 ID はまだ登録していないので出典で代える。"""
    src = c.source
    return (src.archive_path, src.member, src.line)


def _best_pair(candidates: list[NormalizedEvent], window: float,
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

    def consider(a: NormalizedEvent, b: NormalizedEvent, shared: str) -> None:
        """組を 1 つ検討する。`shared` は二人が共有している端末の呼び名。

        共有キーはここで添える。選んだあとに集合の共通部分を取り直すと、
        仕切りを間違えたときに「共有していない 2 件」を選びながら気付かず、
        添字エラーで落ちる。どの呼び名で結んだかは選ぶ時点で分かっている。
        """
        nonlocal best, comparisons
        comparisons += 1
        first, other = (a, b) if a.timestamp.sort < b.timestamp.sort else (b, a)
        gap = other.timestamp.sort - first.timestamp.sort
        if gap <= 0 or gap > window:
            return
        if _place(first) == _place(other):
            return  # 同じ 1 行
        cand = (gap, first.timestamp.sort, _place(first), _place(other),
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
        for key in c.correlation_keys:
            at = (c.timestamp.basis, key)
            if at not in groups:
                groups[at] = ([], [])
            groups[at][slot].append(c)

    for at in sorted(groups):
        procs, others = groups[at]
        if not procs or not others:
            continue
        # 非プロセス側を時刻ごとに畳む。同時刻なら出典が最小の 1 件だけ残す。
        by_time: dict[float, NormalizedEvent] = {}
        for c in others:
            have = by_time.get(c.timestamp.sort)
            if have is None or _place(c) < _place(have):
                by_time[c.timestamp.sort] = c
        times = sorted(by_time)
        reps = [by_time[t] for t in times]
        for p in procs:
            t = p.timestamp.sort
            # 厳密に前（bisect_left の 1 つ手前）と、厳密に後ろ（bisect_right）。
            # 同時刻のものは、どちらの側にも入らない。
            for at_index in (bisect_left(times, t) - 1, bisect_right(times, t)):
                if 0 <= at_index < len(reps):
                    consider(p, reps[at_index], at[1])
    return best, comparisons


def _gap_text(gap: float) -> str:
    """時間差の言い方。仕様書の例「34 秒以内」に合わせる。"""
    if gap < 1:
        return "1 秒以内"
    return f"{int(gap) if gap == int(gap) else round(gap, 1)} 秒以内"


def _correlation_quiz(store: EvidenceStore, candidates: list[NormalizedEvent],
                      qid: str,
                      window: float = CORRELATION_WINDOW_SECONDS,
                      readers: _Readers | None = None,
                      ) -> tuple[dict | None, str, list[dict]]:
    """近接した二つの記録を突き合わせる設問。作れない理由と、使った 2 件も返す。

    仕様書 14.2 の関連付け規則のうち、MVP で持つ二つを実装する。

      * 同一ホストかつ近接時刻の「プロセス開始とファイル操作」
      * 同一ホストかつ近接時刻の「プロセス開始と通信」

    「近接」は既定で前後 60 秒。この幅と、実際の時間差（「同一端末で 34 秒
    以内」）を理由として出せることが、仕様の採用条件になっている。出せない
    組は自動相関として採用しない。

    比較の基準（`Stamp.basis`）は、両者で一致していなければならない。
    タイムゾーンの書かれていない行は、同じログの中でだけ比べられる。別々の
    ログの、別々にずれた時計を並べて前後を論じない。

    断定するのは「記録された順序」と「時間差」までで、因果は言わない。

    使った 2 件を返すのは、この設問を載せる段階に、その 2 件を根拠として
    並べるため。参照している記録が画面に無いと、「根拠ログを見る」の飛び先が
    存在しないボタンになる。
    """
    readers = readers or _Readers()
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
    first = _lesson_event(pick_first, store, readers)
    other = _lesson_event(pick_other, store, readers)
    if not first.get("evidenceIds") or not other.get("evidenceIds"):
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
        "hint": (
            "二つの証拠の日時とタイムゾーンを確認し、同じ時刻基準で前後を比べます。"
            "一覧での表示順ではなく記録された時刻を使い、因果関係とは区別してください。"
        ),
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
        # 問い文が「下に示した根拠」と言っている二つの記録。見比べる材料
        # なので、解答前から設問の下に出す。
        "subjectEvidenceIds": list(ids),
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


def _attck_quiz(store: EvidenceStore, stages: list[dict], qid: str,
                readers: _Readers | None = None) -> tuple[dict | None, int, str]:
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
        "hint": (
            "記録されたプログラムと引数、または設定された場所を確認し、"
            "実際に記録された動作を各手法の意味と照らし合わせます。攻撃の目的は推測で補いません。"
        ),
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
        # 問い文が「下に示した記録」と言っている行。手法を選ぶための材料
        # なので、解答前から設問の下に出す。
        "subjectEvidenceIds": list(event["evidenceIds"]),
        "nextInvestigation": "同じ端末で、この手法に関わる他の記録が残っていないかを見る",
        "status": "observed",
    }, at, ""


def _limits_quiz(store: EvidenceStore, stages: list[dict], qid: str,
                 readers: _Readers | None = None) -> tuple[dict | None, int, str]:
    """1 行から「言えること」と「言えないこと」を分ける設問。

    通信の記録を使う。宛先と要求元は行に書いてあるが、中身、目的、利用者の
    関与は書いていない。ここを混ぜたまま先へ進むのが、調査でいちばん起きる
    間違いなので、独立した設問にする。要求元と宛先は、保存済みの抜粋から
    （その形式を知るパーサーに）読み直す。抜粋に残っていなければ使わない。
    """
    readers = readers or _Readers()
    for at, stage in enumerate(stages):
        for event in stage["events"]:
            if event["type"] != "network" or not event.get("evidenceIds"):
                continue
            nev = event.get("_nev")
            excerpt = _stored_excerpt(store, event["evidenceIds"])
            client = _value(readers.reread(nev, "client", excerpt))
            target = _value(readers.reread(nev, "target", excerpt))
            if not client or not target:
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
            noun = ("・".join(readers.nouns([nev.parser_id], "network"))
                    if nev is not None else "") or DEFAULT_NETWORK_NOUN
            prompt = f"下に示した{noun} 1 行だけから、確かに言えることはどれですか。"
            return {
                "id": qid,
                "type": "single_choice",
                "category": "limits",
                "learningObjective": "1 行の記録から言えることと、言えないことを分ける",
                "hint": (
                    "選択肢ごとに、その内容を裏付ける項目が原文にあるか確認してください。"
                    "記録に書かれている事実と、目的や背景についての推測を分けます。"
                ),
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
                # 問い文が「下に示した 1 行」と言っている行。言えることを判断する
                # 材料なので、解答前から設問の下に出す。
                "subjectEvidenceIds": list(event["evidenceIds"]),
                "nextInvestigation": f"{target} への通信が、どのプロセスから出たのかを端末の記録で確かめる",
                "status": "observed",
            }, at, ""
    return None, -1, ("通信の記録から要求元と宛先を読み取れなかったため、"
                      "言えることを選ぶ設問は作りませんでした。")


# ---------------------------------------------------------------------------
# 時系列・ATT&CK・未確定事項
# ---------------------------------------------------------------------------

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
    積む。読み取り側の打ち切りや未読ログは、呼び出し側が足す。
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


def _introduction(stages: list[dict], events: list[NormalizedEvent],
                  hosts: Counter, sources: list[str], readers: _Readers) -> dict:
    """調査導入。分からない項目は推測で埋めず、その旨を書く。"""
    log_types = [readers.label(pid) for pid in sorted({e.parser_id for e in events})]
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


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def _require_normalized(events) -> None:
    """教材生成が受け取るのは正規化イベントだけ。生のレコードを通さない。"""
    for event in events:
        if not isinstance(event, NormalizedEvent):
            raise TypeError(
                "教材生成は正規化イベントだけを受け取ります。"
                "ログはパーサーレジストリを通して解析してください。"
            )


def build_lesson(name: str, sources: dict[str, str], lesson_id: str,
                 parser_ids: list[str] | None = None,
                 registry: "parsers.ParserRegistry | None" = None) -> dict | None:
    """{論理パス: 本文} から教材を作る。解析は必ずパーサーレジストリを通す。

    `parser_ids` はプロファイルが指定したパーサー。None なら登録済みの
    すべてを候補にし、各ログで `detect()` に判定させる（自動判定）。
    解析の結果（どのパーサーが何を読んだか）も必要なときは、
    `parsers.REGISTRY.parse_sources()` と `lesson_from_parsed()` を
    直接呼ぶ。
    """
    reg = registry if registry is not None else parsers.REGISTRY
    return lesson_from_parsed(name, reg.parse_sources(sources, parser_ids), lesson_id)


def lesson_from_parsed(name: str, parsed: ParsedSources, lesson_id: str) -> dict | None:
    """正規化イベントから教材を作る。ログの形式には触れない。"""
    events = parsed.events
    _require_normalized(events)
    if not events:
        return None

    readers = _Readers(parsed.parsers)
    store = parsed.store
    shown = display_events(events, store, readers)
    procs = [e for e in shown if e["type"] == "process"]
    files = [e for e in shown if e["type"] == "file"]
    network = [e for e in shown if e["type"] == "network"]
    # 端末側の記録（通信以外）。導入文の「何台から何件」はここから数える。
    endpoint = [e for e in events if e.kind != "network"]
    hosts = Counter(e.host for e in endpoint)

    stages = []
    if procs:
        stages.append(_stage_endpoint(len(endpoint), procs, hosts, store, readers,
                                      _producers(events, "process")))
    if files:
        stages.append(_stage_files(files, store, readers))
    if network:
        stages.append(_stage_network(
            sum(1 for e in events if e.kind == "network"), network, store, readers,
            _producers(events, "network"),
        ))

    if not stages:
        return None

    # 観測を手法へ対応させる設問と、1 行から言えることを分ける設問。
    # どちらも根拠の事象がある段階へ足す。別の段階へ置くと、その設問が
    # 指す記録が画面に無い段階になってしまう。
    correlation_notes: list[str] = []
    for maker, qid in ((_attck_quiz, "q-attck-01"), (_limits_quiz, "q-limits-01")):
        quiz, at, why = maker(store, stages, qid, readers)
        if quiz:
            stages[at].setdefault("quizzes", []).append(quiz)
        elif why:
            correlation_notes.append(why)

    # 複数の証拠を突き合わせる設問。同じ端末で近接している組があるときだけ
    # 作る。作れなければ理由を残す。
    #
    # 探索は段階に載った事象からではなく、完全な事象集合から行う。段階の
    # 一覧は表示のために重複を間引き、`STAGE_EVENTS` 件で切ってあるので、
    # そこから探すと近接した組を見落とす。
    #
    # これは独立した段階にする。二つの記録は別の段階から来ることがあり、
    # 既存の段階へ足すと、その段階には無い記録を根拠として指すことになる。
    # 突き合わせ自体が一つの作業なので、段階として分けるほうが筋も通る。
    corr, why, pair = _correlation_quiz(
        store, correlation_candidates(events), "q-correlate-01", readers=readers
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
            "note": "読み込んだデータセットのログから自動生成した演習です。内容を確認のうえ使用してください。",
            "inputs": sorted(parsed.sources),
        },
        "evidence": evidence,
        "introduction": _introduction(stages, events, hosts, parsed.sources, readers),
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
