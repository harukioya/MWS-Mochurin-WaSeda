"""static_lesson.py — 検証済みの静的事実から、根拠付きの演習を作る。

ログ教材（explain.py）とは別の組み立てにする。共用するのは、画面側の
設問・証拠カード・採点・振り返りの部品と、`evidence.visible` / `pick_index`
だけ。ログの出来事（時刻・ホスト・実行）を模した項目は作らない。

設問は次の三種類を候補にし、根拠が揃ったものだけを作る。

  * 文字列参照   関数内の命令と、Ghidra が保存した参照先の定義済み文字列
  * 直接呼び出し 呼び出し命令と、一意に解決された呼び出し先の関数
  * 外部関数     外部関数（EXTERNAL 空間）の記録と、その識別情報

どの設問も「正解はこの構造化された記録から一意に決まる」ことを、作った後に
`verify_quiz` で確かめてから採用する。誤答は、同じ文字列・同じ名前・同じ
アドレスを持たないものだけから選ぶ。単に似た名前や同じ文字列があるだけでは
正解にならない。

言わないこと: 実行されたこと、呼ばれた回数や順序、悪性かどうか、ATT&CK の
手法。呼び出し命令が存在することは、実行時にその呼び出しが起きたことを
意味しない。
"""

from __future__ import annotations

import hashlib

from evidence import pick_index, visible
from static_facts import MAX_INSTRUCTION, SCHEMA, StaticFacts

LESSON_PREFIX = "gen-gzf-"

#: 選択肢として出す文字列の最大長。これを超える文字列は、表示で切ると
#: 根拠（どの文字列か）が見えなくなるので、設問に使わない。
MAX_OPTION = 60
MAX_STRING_QUESTIONS = 2
MAX_CALL_QUESTIONS = 2
MAX_EXTERNAL_QUESTIONS = 1
OPTIONS = 4

STORED = "stored"   # 証拠の確からしさ：「保存済みの解析情報に記録されている」


class NoQuestions(Exception):
    """根拠の揃った設問を 1 問も作れなかった。"""

    code = "no-questions"

    def __init__(self, reasons: list[str]):
        super().__init__("; ".join(reasons))
        self.reasons = reasons


def lesson_id(input_sha256: str) -> str:
    return LESSON_PREFIX + input_sha256[:16]


def show_addr(address: str) -> str:
    """`ram:0000000000101234` を `ram:00101234` のように短くする。桁は 8 桁まで残す。"""
    space, _, off = address.rpartition(":")
    off = off.lstrip("0").rjust(8, "0")
    return f"{space}:{off}"


def _quote(value: str) -> str:
    return f"「{visible(value, MAX_OPTION)}」"


class _Evidence:
    """静的な根拠。ID は入力と記録の位置から決まり、毎回同じになる。"""

    def __init__(self, facts: StaticFacts):
        self.facts = facts
        self.items: dict[str, dict] = {}
        self.program = visible(facts.program["name"], 120)

    def _add(self, kind: str, key: str, source: dict) -> str:
        digest = hashlib.sha256()
        for part in ("static", self.facts.input_sha256, kind, key):
            digest.update(part.encode("utf-8", "surrogateescape"))
            digest.update(b"\0")
        ident = "ev-" + digest.hexdigest()[:24]
        if ident not in self.items:
            self.items[ident] = {
                "id": ident,
                "kind": kind,
                "evidenceType": "static",
                "confidence": STORED,
                "source": {"program": self.program, **source},
            }
        return ident

    def instruction(self, function_id: str, address: str, text: str,
                    relation: str, target: str) -> str:
        fn = self.facts.functions[function_id]
        return self._add("instruction", address + "\0" + relation, {
            "function": visible(fn["name"], 120),
            "address": show_addr(address),
            "instruction": visible(text, MAX_INSTRUCTION),
            # 参照先・呼び出し先は、アドレスだけを書く。名前や文字列の中身は
            # 別の記録にあり、それを突き合わせるのが設問で問う読み方である。
            "reference": f"{relation}: {show_addr(target)}",
            "excerpt": visible(text, MAX_INSTRUCTION),
        })

    def string(self, sid: str) -> str:
        s = self.facts.strings[sid]
        return self._add("string", s["address"], {
            "function": None,
            "address": show_addr(s["address"]),
            "instruction": None,
            "reference": f"定義済み文字列（{s['length']} 文字）",
            "excerpt": _quote(s["value"]),
        })

    def function(self, fid: str) -> str:
        f = self.facts.functions[fid]
        return self._add("function", f["entry"], {
            "function": visible(f["name"], 120),
            "address": show_addr(f["entry"]),
            "instruction": None,
            "reference": "関数の入口（このプログラム内）",
            "excerpt": f"{visible(f['name'], 120)} @ {show_addr(f['entry'])}",
        })

    def external(self, eid: str) -> str:
        e = self.facts.externals[eid]
        lib = visible(e["library"] or "（ライブラリ名の記録なし）", 120)
        return self._add("external", e["address"], {
            "function": visible(e["name"], 120),
            "address": show_addr(e["address"]),
            "instruction": None,
            "reference": f"外部関数（登録先: {lib}）",
            "excerpt": f"{visible(e['name'], 120)} @ {show_addr(e['address'])} — {lib}",
        })


def _usable_instruction(text: str) -> bool:
    # 抽出側は上限で切る。上限ちょうどの長さは切られた可能性があるので使わない。
    return 0 < len(text) < MAX_INSTRUCTION and visible(text, MAX_INSTRUCTION) == text


def _usable_string(s: dict) -> bool:
    v = s["value"]
    return (not s["clipped"] and len(v.strip()) >= 3 and len(v) <= MAX_OPTION
            and visible(v, MAX_OPTION) == v)


def _plain_name(name: str) -> bool:
    return 0 < len(name) <= 80 and visible(name, 80) == name


def _choose(seed: str, items: list, count: int, key=None) -> list:
    """候補から決定的に count 件選ぶ。key が同じものは 2 件目以降を避ける。"""
    chosen, used = [], set()
    pool = list(items)
    start = pick_index(seed, len(pool)) if pool else 0
    ordered = pool[start:] + pool[:start]
    for item in ordered:
        k = key(item) if key else None
        if k is not None and k in used:
            continue
        chosen.append(item)
        if k is not None:
            used.add(k)
        if len(chosen) >= count:
            break
    return chosen


def _arrange(seed: str, right, wrong: list) -> tuple[list, int]:
    at = pick_index(seed, len(wrong) + 1)
    return wrong[:at] + [right] + wrong[at:], at


# ---------------------------------------------------------------------------
# 設問の検証（作ったあとに、構造化された記録から正解を確かめ直す）
# ---------------------------------------------------------------------------

#: その種類の設問の正解が一つだと言うために、欠けていてはいけない一覧。
#: 文字列参照: 参照の一覧が欠けていると、同じ命令が誤答の文字列も参照して
#:   いる（＝誤答も正解）可能性を否定できない。
#: 外部関数: 外部関数・関数の一覧が欠けていると、誤答に使ったプログラム内の
#:   関数と同じ名前の外部関数や thunk が一覧の外にある可能性を否定できない。
#: 直接呼び出しは、1 つの命令の行き先が 1 つに決まり、打ち切りで省かれるのは
#: 記録ごとなので、一覧が欠けても正解の一意性は崩れない。
REQUIRES_COMPLETE = {
    "string-ref": ("stringRefs",),
    "external": ("externals", "functions"),
}


def verify_quiz(facts: StaticFacts, quiz: dict) -> bool:
    check = quiz.get("answerCheck") or {}
    if any(t in facts.truncated for t in REQUIRES_COMPLETE.get(check.get("kind"), ())):
        return False
    ids = quiz.get("optionIds") or []
    if len(ids) != len(quiz.get("options") or []) or len(set(ids)) != len(ids):
        return False
    correct = quiz.get("correct")
    if not isinstance(correct, int) or not 0 <= correct < len(ids):
        return False
    kind = check.get("kind")
    if kind == "string-ref":
        refs = [r for r in facts.string_refs
                if r["from"] == check.get("from") and r["function"] == check.get("function")]
        answers = {r["string"] for r in refs}
        if ids[correct] not in answers or len(answers) != 1:
            return False
        in_function = {facts.strings[r["string"]]["value"] for r in facts.string_refs
                       if r["function"] == check.get("function")}
        values = [facts.strings[i]["value"] for i in ids]
        if len(set(values)) != len(values):
            return False
        return all(facts.strings[i]["value"] not in in_function
                   for n, i in enumerate(ids) if n != correct)
    if kind == "call":
        calls = [c for c in facts.calls
                 if c["from"] == check.get("from") and c["function"] == check.get("function")]
        if len(calls) != 1 or calls[0]["resolvedTarget"] is not None:
            return False
        target = calls[0]["target"]
        if ids[correct] != target:
            return False
        names = [facts.functions[i]["name"] for i in ids]
        if len(set(names)) != len(names):
            return False
        return all(facts.functions[i]["entry"] != calls[0]["targetAddress"]
                   for n, i in enumerate(ids) if n != correct)
    if kind == "external":
        if ids[correct] not in facts.externals:
            return False
        ext_names = {e["name"] for e in facts.externals.values()}
        thunk_names = {f["name"] for f in facts.functions.values() if f["thunk"]}
        for n, i in enumerate(ids):
            if n == correct:
                continue
            f = facts.functions.get(i)
            if f is None or f["thunk"] or f["name"] in ext_names or f["name"] in thunk_names:
                return False
        names = [facts.name_of(i) for i in ids]
        return len(set(names)) == len(names)
    return False


# ---------------------------------------------------------------------------
# 設問づくり
# ---------------------------------------------------------------------------

STRING_HINTS = [
    "命令の欄にあるオペランドと、その下の「参照先」に書かれたアドレスに注目してください。",
    "そのアドレスを、この段階に並んだ「定義済み文字列」の記録のアドレスと照らし合わせてください。",
    "文字列の中身が関数名と関係ありそうかどうかでは決めません。アドレスが一致する記録を選びます。",
]
CALL_HINTS = [
    "CALL などの呼び出し命令は、オペランドに呼び出し先の入口アドレスを持ちます。「呼び出し先」の欄も見てください。",
    "この段階に並んだ関数の記録から、入口アドレスが呼び出し先と一致するものを探してください。",
    "名前の印象ではなく、アドレスの一致で判断します。命令があることと、実行時に呼ばれたことは別です。",
]
EXTERNAL_HINTS = [
    "外部関数は、このプログラムの外（共有ライブラリなど）にある関数として、EXTERNAL というアドレス空間に登録されます。",
    "並んでいる記録それぞれのアドレス空間と、「登録先」の欄を確かめてください。",
    "有名なライブラリ関数の名前に似ているかどうかでは決めません。記録上の登録先で判断します。",
]


def _string_questions(facts: StaticFacts, ev: _Evidence, reasons: list) -> list[dict]:
    if any(t in facts.truncated for t in REQUIRES_COMPLETE["string-ref"]):
        reasons.append(
            "文字列参照: 参照の一覧が上限で打ち切られているため、同じ命令が誤答の文字列も"
            "参照していないことを確かめられません。正解が一つに決まらないおそれがあるので、"
            "この種類の設問は作っていません。"
        )
        return []
    by_function: dict[str, set] = {}
    for r in facts.string_refs:
        by_function.setdefault(r["function"], set()).add(facts.strings[r["string"]]["value"])
    by_from: dict[tuple, set] = {}
    for r in facts.string_refs:
        by_from.setdefault((r["from"], r["function"]), set()).add(r["string"])

    referenced = {r["string"] for r in facts.string_refs}
    candidates = []
    for r in facts.string_refs:
        f = facts.functions[r["function"]]
        s = facts.strings[r["string"]]
        if f["thunk"] or not _plain_name(f["name"]) or not _usable_string(s):
            continue
        if not _usable_instruction(r["instruction"]):
            continue
        if len(by_from[(r["from"], r["function"])]) != 1:
            continue  # 1 命令が複数の文字列を指すと、正解が一つに決まらない
        candidates.append(r)
    candidates.sort(key=lambda r: (r["from"], r["string"]))
    if not candidates:
        reasons.append("文字列参照: 関数内の命令から参照され、表示上限に収まる文字列がありませんでした。")
        return []

    quizzes = []
    picked = _choose(facts.input_sha256 + ":string", candidates, len(candidates),
                     key=lambda r: r["function"])
    for r in picked:
        if len(quizzes) >= MAX_STRING_QUESTIONS:
            break
        s = facts.strings[r["string"]]
        avoid = by_function[r["function"]]
        pool, seen = [], {s["value"]}
        # 他の関数から実際に参照されている文字列を先に使う。どこからも参照
        # されない文字列ばかりだと、「参照されていそうなもの」で当てられる。
        for sid in sorted(facts.strings, key=lambda i: (i not in referenced, i)):
            t = facts.strings[sid]
            if t["value"] in avoid or t["value"] in seen or not _usable_string(t):
                continue
            pool.append(sid)
            seen.add(t["value"])
        wrong = _choose(facts.input_sha256 + r["from"], pool, OPTIONS - 1)
        if len(wrong) < OPTIONS - 1:
            continue
        seed = facts.input_sha256 + ":s:" + r["from"]
        ids, at = _arrange(seed, r["string"], wrong)
        fn = facts.functions[r["function"]]
        instr_ev = ev.instruction(r["function"], r["from"], r["instruction"], "参照先", s["address"])
        right_ev = ev.string(r["string"])
        shown = sorted(ids, key=lambda i: facts.strings[i]["address"])
        ask = (f"関数 {visible(fn['name'], 80)} の {show_addr(r['from'])} にある命令について。"
               "この命令が参照している定義済み文字列はどれですか。")
        quiz = {
            "id": f"q-str-{len(quizzes) + 1}",
            "type": "single_choice",
            "category": "static-string",
            "learningObjective": "命令が参照するアドレスを、定義済み文字列の記録と突き合わせる",
            "q": ask,
            "prompt": ask,
            "options": [_quote(facts.strings[i]["value"]) for i in ids],
            "optionIds": ids,
            "correct": at,
            "hints": list(STRING_HINTS),
            "explain": (
                f"{show_addr(r['from'])} の命令「{visible(r['instruction'], MAX_INSTRUCTION)}」には、"
                f"Ghidra が保存した参照（種類 {visible(r['refType'], 32)}）があり、参照先は "
                f"{show_addr(s['address'])} です。このアドレスに定義されている文字列は "
                f"{_quote(s['value'])} です。\n\n"
                "ほかの選択肢は、この関数のどの命令からも参照されていない文字列です。"
                "参照があることは、その文字列が実行時に使われたことまでは示しません。"
            ),
            "evidenceIds": [instr_ev, right_ev],
            "subjectEvidenceIds": [instr_ev],
            "answerCheck": {"kind": "string-ref", "function": r["function"],
                            "from": r["from"], "string": r["string"]},
            "_events": [
                {"type": "instruction",
                 "detail": f"{visible(fn['name'], 80)} / {show_addr(r['from'])}: "
                           f"{visible(r['instruction'], MAX_INSTRUCTION)}",
                 "evidenceIds": [instr_ev]},
            ] + [
                {"type": "string",
                 "detail": f"{show_addr(facts.strings[i]['address'])}: "
                           f"{_quote(facts.strings[i]['value'])}",
                 "evidenceIds": [ev.string(i)]}
                for i in shown
            ],
        }
        if verify_quiz(facts, quiz):
            quizzes.append(quiz)
    if not quizzes:
        reasons.append("文字列参照: 誤答にできる別の文字列（同じ関数から参照されていないもの）が足りませんでした。")
    return quizzes


def _internal_functions(facts: StaticFacts) -> list[dict]:
    return sorted((f for f in facts.functions.values()
                   if not f["thunk"] and _plain_name(f["name"])),
                  key=lambda f: f["entry"])


def _call_questions(facts: StaticFacts, ev: _Evidence, reasons: list) -> list[dict]:
    internal = _internal_functions(facts)
    per_from: dict[tuple, int] = {}
    for c in facts.calls:
        per_from[(c["from"], c["function"])] = per_from.get((c["from"], c["function"]), 0) + 1
    candidates = []
    for c in facts.calls:
        caller = facts.functions[c["function"]]
        target = facts.functions.get(c["target"])
        if target is None or target["thunk"] or c["resolvedTarget"] is not None:
            continue
        if caller["thunk"] or not _plain_name(caller["name"]) or not _plain_name(target["name"]):
            continue
        if not _usable_instruction(c["instruction"]) or per_from[(c["from"], c["function"])] != 1:
            continue
        candidates.append(c)
    candidates.sort(key=lambda c: c["from"])
    if not candidates:
        reasons.append("直接呼び出し: 呼び出し先を一意に解決できた、このプログラム内の関数への呼び出しがありませんでした。")
        return []

    quizzes = []
    picked = _choose(facts.input_sha256 + ":call", candidates, len(candidates),
                     key=lambda c: c["target"])
    for c in picked:
        if len(quizzes) >= MAX_CALL_QUESTIONS:
            break
        target = facts.functions[c["target"]]
        pool, seen = [], {target["name"]}
        for f in internal:
            if f["id"] == target["id"] or f["entry"] == c["targetAddress"] or f["name"] in seen:
                continue
            pool.append(f["id"])
            seen.add(f["name"])
        wrong = _choose(facts.input_sha256 + c["from"], pool, OPTIONS - 1)
        if len(wrong) < OPTIONS - 1:
            continue
        ids, at = _arrange(facts.input_sha256 + ":c:" + c["from"], target["id"], wrong)
        caller = facts.functions[c["function"]]
        instr_ev = ev.instruction(c["function"], c["from"], c["instruction"], "呼び出し先",
                                  c["targetAddress"])
        right_ev = ev.function(target["id"])
        shown = sorted(ids, key=lambda i: facts.functions[i]["entry"])
        mnemonic = visible(c["mnemonic"], 32)
        ask = (f"関数 {visible(caller['name'], 80)} の {show_addr(c['from'])} にある "
               f"{mnemonic} 命令について。この命令が直接呼び出す関数はどれですか。")
        quiz = {
            "id": f"q-call-{len(quizzes) + 1}",
            "type": "single_choice",
            "category": "static-call",
            "learningObjective": "呼び出し命令の行き先アドレスを、関数の入口アドレスと突き合わせる",
            "q": ask,
            "prompt": ask,
            "options": [visible(facts.functions[i]["name"], 80) for i in ids],
            "optionIds": ids,
            "correct": at,
            "hints": list(CALL_HINTS),
            "explain": (
                f"{show_addr(c['from'])} の命令「{visible(c['instruction'], MAX_INSTRUCTION)}」の"
                f"呼び出し先は {show_addr(c['targetAddress'])} です。この入口アドレスを持つ関数は "
                f"{visible(target['name'], 80)} です。\n\n"
                "ここで分かるのは「呼び出す命令がある」ことまでです。条件分岐の先にある場合も"
                "あり、実行時に実際に呼ばれたかどうかは、この記録だけでは分かりません。"
            ),
            "evidenceIds": [instr_ev, right_ev],
            "subjectEvidenceIds": [instr_ev],
            "answerCheck": {"kind": "call", "function": c["function"], "from": c["from"]},
            "_events": [
                {"type": "call",
                 "detail": f"{visible(caller['name'], 80)} / {show_addr(c['from'])}: "
                           f"{visible(c['instruction'], MAX_INSTRUCTION)}",
                 "evidenceIds": [instr_ev]},
            ] + [
                {"type": "function",
                 "detail": f"{visible(facts.functions[i]['name'], 80)} — 入口 "
                           f"{show_addr(facts.functions[i]['entry'])}",
                 "evidenceIds": [ev.function(i)]}
                for i in shown
            ],
        }
        if verify_quiz(facts, quiz):
            quizzes.append(quiz)
    if not quizzes:
        reasons.append("直接呼び出し: 誤答にできる別の関数（名前も入口も異なるもの）が足りませんでした。")
    return quizzes


def _external_questions(facts: StaticFacts, ev: _Evidence, reasons: list) -> list[dict]:
    if any(t in facts.truncated for t in REQUIRES_COMPLETE["external"]):
        reasons.append(
            "外部関数: 関数または外部関数の一覧が上限で打ち切られているため、誤答に使う関数と"
            "同じ名前の外部関数が一覧の外にないことを確かめられません。この種類の設問は"
            "作っていません。"
        )
        return []
    ext_names = {e["name"] for e in facts.externals.values()}
    thunk_names = {f["name"] for f in facts.functions.values() if f["thunk"]}
    called = {c["resolvedTarget"] for c in facts.calls if c["resolvedTarget"]}
    externals = sorted((e for e in facts.externals.values() if _plain_name(e["name"])),
                       key=lambda e: (e["id"] not in called, e["address"]))
    pool = [f["id"] for f in _internal_functions(facts)
            if f["name"] not in ext_names and f["name"] not in thunk_names]
    if not externals:
        reasons.append("外部関数: 外部関数の記録がありませんでした。")
        return []
    if len({facts.functions[i]["name"] for i in pool}) < OPTIONS - 1:
        reasons.append("外部関数: 誤答にできる、このプログラム内の関数が足りませんでした。")
        return []

    quizzes = []
    for e in _choose(facts.input_sha256 + ":ext", externals, MAX_EXTERNAL_QUESTIONS):
        seen, names = set(), []
        for i in pool:
            n = facts.functions[i]["name"]
            if n not in seen:
                names.append(i)
                seen.add(n)
        wrong = _choose(facts.input_sha256 + e["id"], names, OPTIONS - 1)
        ids, at = _arrange(facts.input_sha256 + ":e:" + e["id"], e["id"], wrong)
        right_ev = ev.external(e["id"])
        evs = {i: (ev.external(i) if i in facts.externals else ev.function(i)) for i in ids}
        lib = visible(e["library"] or "（記録なし）", 120)
        ask = "次の関数のうち、このプログラムに外部関数（プログラムの外にある関数）として登録されているものはどれですか。"
        quiz = {
            "id": f"q-ext-{len(quizzes) + 1}",
            "type": "single_choice",
            "category": "static-external",
            "learningObjective": "関数の記録から、プログラム内の関数と外部関数を見分ける",
            "q": ask,
            "prompt": ask,
            "options": [visible(facts.name_of(i), 80) for i in ids],
            "optionIds": ids,
            "correct": at,
            "hints": list(EXTERNAL_HINTS),
            "explain": (
                f"{visible(e['name'], 80)} は {show_addr(e['address'])}（EXTERNAL 空間）に"
                f"外部関数として登録されており、登録先のライブラリは {lib} です。"
                "ほかの選択肢は、このプログラムのメモリ上に入口を持つ関数です。\n\n"
                "外部関数として登録されていることは、その関数を使う準備があることを示すだけで、"
                "何のために使うのか、実行時に呼ばれたのかは分かりません。関数名だけから"
                "悪性や攻撃手法を決めつけないでください。"
            ),
            "evidenceIds": [right_ev],
            "subjectEvidenceIds": [],
            "answerCheck": {"kind": "external", "external": e["id"]},
            "_events": [
                {"type": "external" if i in facts.externals else "function",
                 "detail": (f"{visible(facts.name_of(i), 80)} — "
                            + (f"{show_addr(facts.externals[i]['address'])}"
                               if i in facts.externals
                               else f"入口 {show_addr(facts.functions[i]['entry'])}")),
                 "evidenceIds": [evs[i]]}
                for i in sorted(ids, key=lambda i: facts.name_of(i).lower())
            ],
        }
        if verify_quiz(facts, quiz):
            quizzes.append(quiz)
    return quizzes


# ---------------------------------------------------------------------------
# 教材
# ---------------------------------------------------------------------------

def _stage(stage_id: str, name: str, intro: str, quizzes: list[dict]) -> dict:
    events, seen = [], set()
    for q in quizzes:
        for e in q.pop("_events"):
            key = (e["type"], e["detail"])
            if key not in seen:
                events.append(e)
                seen.add(key)
    return {"id": stage_id, "name": name, "intro": intro, "events": events,
            "quizzes": quizzes}


def build(facts: StaticFacts, *, image: dict, origin: dict,
          sample: dict | None = None) -> dict:
    """静的事実から演習を 1 つ作る。設問が 1 問も作れなければ NoQuestions。

    同じ入力・同じ固定ツール版からは、同じ教材（ID・設問・選択肢の並び）になる。
    """
    reasons: list[str] = []
    if not facts.program["analyzed"]:
        raise NoQuestions([
            "この GZF は解析済みとして保存されていません。自動再解析は行わない設計のため、"
            "Ghidra で解析してから保存した GZF を使ってください。"
        ])
    if not facts.functions:
        raise NoQuestions(["関数の記録が 1 件もありませんでした。解析情報が不足しています。"])

    ev = _Evidence(facts)
    strings = _string_questions(facts, ev, reasons)
    calls = _call_questions(facts, ev, reasons)
    externals = _external_questions(facts, ev, reasons)
    if not (strings or calls or externals):
        raise NoQuestions(reasons or ["根拠の揃う設問を作れませんでした。"])

    name = visible(facts.program["name"], 80)
    stages = []
    if strings:
        stages.append(_stage(
            "static-strings", "段階1 — 文字列の参照を読む",
            "Ghidra は、命令がどのアドレスのデータを指しているかを「参照」として保存します。\n\n"
            "下の記録には、ある関数の命令と、プログラム内に定義された文字列が並んでいます。"
            "命令の参照先アドレスと、文字列が置かれたアドレスを突き合わせてください。",
            strings))
    if calls:
        stages.append(_stage(
            "static-calls", f"段階{len(stages) + 1} — 直接呼び出しを読む",
            "呼び出し命令（x86 の CALL など）は、行き先のアドレスを持ちます。そのアドレスが"
            "どの関数の入口かを、関数の記録と照らし合わせて確かめます。\n\n"
            "間接呼び出し（レジスタやメモリの値で行き先が決まるもの）は、この教材では扱いません。",
            calls))
    if externals:
        stages.append(_stage(
            "static-externals", f"段階{len(stages) + 1} — 外部関数を見分ける",
            "プログラムの中にある関数と、共有ライブラリなど外から取り込む関数は、Ghidra の"
            "記録では登録先（アドレス空間）が違います。",
            externals))

    counts = facts.counts()
    unknowns = [
        {"topic": "実行はしていません",
         "detail": ("この教材は、GZF に保存済みの解析情報を読み出して作りました。対象プログラムの"
                    "起動・エミュレーション・デバッガ接続は行っていません。実行時の挙動（何が"
                    "起きたか、どの順で呼ばれたか）は、ここからは分かりません。")},
        {"topic": "呼び出し命令と実際の呼び出し",
         "detail": ("呼び出し命令が存在することは、実行時にその呼び出しが起きたことを意味しません。"
                    f"間接呼び出し {counts['indirectCalls']} 件と、行き先を一意に解決できなかった"
                    f"呼び出し {counts['unresolvedCalls']} 件は、設問に使っていません。")},
        {"topic": "悪性の判断",
         "detail": ("文字列や外部関数の名前だけから、悪性かどうかや攻撃手法を決めることはしていません。"
                    "この教材は ATT&CK との対応付けを行いません。")},
        {"topic": "保存時点の解析結果であること",
         "detail": ("記録は GZF を保存した時点の Ghidra の解析結果です。自動解析はやり直していないので、"
                    "解析の設定や版が違えば、関数や参照の数は変わり得ます。")},
    ]
    if facts.truncated:
        unknowns.append({
            "topic": "抽出の打ち切り",
            "detail": (f"上限に達したため、{'、'.join(sorted(facts.truncated))} の一部を"
                       "読み出していません。完全な一覧ではない前提で読んでください。"),
        })
    for r in reasons:
        unknowns.append({"topic": "作れなかった設問", "detail": r})

    facts_list = []
    for stage in stages:
        for q in stage["quizzes"]:
            facts_list.append({
                "title": q["explain"].split("\n\n", 1)[0],
                "category": q["category"],
                "evidenceIds": list(q["evidenceIds"]),
            })

    question_counts = {"string": len(strings), "call": len(calls), "external": len(externals)}
    total = sum(question_counts.values())
    meta = {
        "schemaVersion": SCHEMA,
        "input": {"sha256": facts.input_sha256, "bytes": facts.input_bytes},
        "tool": {"ghidraVersion": facts.ghidra_version, "scriptVersion": facts.script_version,
                 **{k: image[k] for k in ("imageRef", "imageId", "scriptSha256",
                                          "baseImage", "arch") if k in image}},
        "program": {
            "name": name,
            "languageId": visible(facts.program["languageId"], 128),
            "compilerSpecId": visible(facts.program["compilerSpecId"], 64),
            "executableFormat": visible(facts.program["executableFormat"] or "", 120),
            "storedExecutableSha256": facts.program["storedExecutableSha256"],
            "imageBase": show_addr(facts.program["imageBase"]),
        },
        "counts": counts,
        "truncated": list(facts.truncated),
        "questionCounts": question_counts,
        "skipped": list(reasons),
        "origin": origin,
        "sample": sample,
    }
    return {
        "id": lesson_id(facts.input_sha256),
        "kind": "static",
        "title": f"{name} — Ghidra 静的解析",
        "tagline": "Ghidra の保存済み解析情報から自動生成しました。使用前に内容を確認してください。",
        "difficulty": "入門",
        "family": "静的解析",
        "source": {
            "type": "generated-static",
            "note": "GZF に保存済みの解析情報から自動生成した演習です。対象プログラムは実行していません。",
        },
        "static": meta,
        "evidence": {k: ev.items[k] for k in sorted(ev.items)},
        "introduction": {
            "kind": "static",
            "status": "draft",
            "scenario": (
                "Ghidra で解析して保存されたプログラムの記録を読み、命令・文字列・関数の"
                "つながりを確かめます。プログラムは動かさず、保存済みの記録だけを使います。"
            ),
            "objectives": [
                "命令が参照するアドレスを、定義済み文字列の記録と突き合わせる",
                "呼び出し命令の行き先を、関数の入口アドレスから特定する",
                "プログラム内の関数と、外部関数の記録を見分ける",
                "記録から言えることと、実行しないと分からないことを分ける",
            ],
            "estimatedMinutes": 5 + 2 * total,
            "static": meta,
        },
        "report": {
            "timeline": [],
            "techniques": [],
            "facts": facts_list,
            "unknowns": unknowns,
            "nextInvestigations": [
                "Ghidra で同じアドレスを開き、前後の命令と引数の準備を読む",
                "参照（XREF）の一覧で、同じ文字列や関数を使っている別の箇所を確かめる",
                "間接呼び出しの行き先は、データの流れを追うか、隔離環境での動的解析で確かめる",
            ],
        },
        "recap": {
            "summary": (
                f"{name} の保存済み解析情報から、文字列の参照 {len(strings)} 問、直接呼び出し "
                f"{len(calls)} 問、外部関数 {len(externals)} 問を解きました。どれも静的に確認できる"
                "記録の読み方で、実行時の挙動は含みません。"
            ),
        },
        "stages": stages,
    }
