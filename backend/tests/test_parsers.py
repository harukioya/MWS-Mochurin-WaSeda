"""Parser registry and normalized events: the seam between logs and lessons.

What this file pins down:

  * the built-in formats (InfoTrace Mark II, Squid-style proxy) are parsed
    THROUGH the registry, on the production path;
  * a new format needs a parser and a `register()` call -- nothing in
    `explain.py` changes, and a dummy format with its own line syntax reaches
    a complete lesson (stages, grounded questions, timeline, correlation);
  * lesson generation accepts normalized events only, never raw records;
  * whatever a parser returns is checked against the contract, and a broken
    parser is contained and reported rather than trusted;
  * the order parsers were registered in never changes the lesson.

NO REAL DATASET. Invented hosts, RFC 5737 addresses, harmless commands.
"""

import ast
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import evidence  # noqa: E402
import explain  # noqa: E402
import parsers  # noqa: E402
import timeline  # noqa: E402
from parsers import (  # noqa: E402
    ContractError,
    FactReading,
    FactText,
    InputSource,
    NormalizedEvent,
    ParsedSources,
    Parser,
    ParserRegistry,
    clean_host_keys,
    itm2,
    proxy,
    source_of,
)

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ITM2_TEXT = "\n".join([
    '10/05/2022 14:00:01.000 +0900 loc=en-US type=ITM2 sn=1 lv=5 evt=ps '
    'subEvt=start os=Win com="WS99" psPath="C:\\Windows\\System32\\cmd.exe"',
    '10/05/2022 14:00:09.000 +0900 loc=en-US type=ITM2 sn=2 lv=5 evt=ps '
    'subEvt=start os=Win com="WS99" '
    'psPath="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"',
    '10/05/2022 14:00:11.000 +0900 loc=en-US type=ITM2 sn=3 lv=5 evt=ps '
    'subEvt=start os=Win com="DC01" psPath="C:\\Windows\\System32\\whoami.exe"',
    '10/05/2022 14:00:05.500 +0900 loc=en-US type=ITM2 sn=4 lv=5 evt=file '
    'subEvt=create os=Win com="WS99" path="C:\\Users\\test\\AppData\\demo.dat"',
])
PROXY_TEXT = "\n".join([
    '192.0.2.10 - - [05/Oct/2022:14:00:07 +0900] "GET http://198.51.100.23/a HTTP/1.1" 200 42',
    '192.0.2.11 - - [05/Oct/2022:14:00:08 +0900] "POST http://203.0.113.9/b HTTP/1.1" 200 42',
])
SOURCES = {
    "case/evidence/logs.zip :: logs/host.log": ITM2_TEXT,
    "case/evidence/logs.zip :: logs/proxy.log": PROXY_TEXT,
}


# ---------------------------------------------------------------------------
# ダミーの形式。教材生成が一度も見たことのない行の書き方。
#
#   DUMMY|2026-01-02T03:04:05+0900|<端末>|<動作>|<対象>
#
# 動作が start ならプロセス開始、write ならファイル書き込み、fetch なら通信。
# ---------------------------------------------------------------------------

DUMMY_TEXT = "\n".join([
    "# dummy format, invented",
    "DUMMY|2026-01-02T03:04:00+0900|HOST-A|start|/opt/tools/alpha",
    "DUMMY|2026-01-02T03:04:20+0900|HOST-A|write|/var/tmp/alpha.out",
    "DUMMY|2026-01-02T03:05:00+0900|HOST-A|start|/opt/tools/beta",
    "DUMMY|2026-01-02T03:06:00+0900|HOST-B|start|/opt/tools/gamma",
    "DUMMY|2026-01-02T03:06:30+0900|HOST-B|write|/var/tmp/gamma.out",
    "DUMMY|2026-01-02T03:07:00+0900|HOST-A|fetch|http://198.51.100.9/x",
    "DUMMY|2026-01-02T03:07:10+0900|HOST-B|fetch|http://203.0.113.5/y",
    "DUMMY|not-a-time|HOST-C|start|/opt/tools/delta",
])


class DummyParser(Parser):
    """テストのためだけの形式。教材生成を一切変えずに足せることを示す。"""

    id = "dummy"
    label = "ダミー形式（テスト用）"

    ABOUTS = {"process": "ダミー形式は、端末ごとの操作を 1 行ずつ残します。"}
    RECORD_NOUNS = {"network": "ダミーの通信記録"}
    FACT_TEXTS = {
        ("process", "program_name"): FactText(
            where="ダミー形式では、5 列目（`{field}`）に起動した実行ファイルが入ります。",
            next="ダミー形式の前後の行を確かめる",
        ),
    }

    _KIND = {"start": "process", "write": "file", "fetch": "network"}
    #: 行の先頭の印。派生クラスで変えると、同じ書き方の別形式になる。
    PREFIX = "DUMMY"

    def detect(self, source):
        return 1.0 if f"{self.PREFIX}|" in source.text else 0.0

    @staticmethod
    def _stamp(text, name):
        # 2026-01-02T03:04:05+0900
        try:
            date, rest = text.split("T", 1)
            year, mon, day = (int(x) for x in date.split("-"))
            clock, tz = rest[:8], rest[8:] or None
            hh, mm, ss = (int(x) for x in clock.split(":"))
        except ValueError:
            return timeline.UNKNOWN
        return timeline.stamp(year=year, mon=mon, day=day, hh=hh, mm=mm, ss=ss,
                              frac=0.0, tz=tz, display=text, source=name)

    def parse(self, source, evidence_store=None):
        out = []
        for line_no, line in enumerate(source.lines(), 1):
            parts = line.split("|")
            if len(parts) != 5 or parts[0] != self.PREFIX:
                continue
            _, when, host, verb, target = parts
            kind = self._KIND.get(verb, "other")
            base = target.rsplit("/", 1)[-1]
            if kind == "process":
                attrs = {"program": target, "program_name": base}
                summary = f"{host}: {target} を起動"
            elif kind == "file":
                attrs = {"path": target, "name": base}
                summary = f"{host}: {target} に書き込み"
            elif kind == "network":
                attrs = {"client": host, "method": "FETCH", "target": target}
                summary = f"{host} -> FETCH {target}"
            else:
                attrs, summary = {}, ""
            out.append(NormalizedEvent(
                kind=kind, action=verb, timestamp=self._stamp(when, source.name),
                host=host, summary=summary, source=source_of(source.name, line_no, line),
                parser_id=self.id, attributes=attrs,
                correlation_keys=clean_host_keys([host]),
            ))
        return out

    def reread(self, kind, fact, excerpt):
        parts = (excerpt or "").split("|")
        if len(parts) != 5:
            return None
        column = {
            ("process", "program_name"): (4, "対象"),
            ("process", "host"): (2, "端末"),
            ("file", "path"): (4, "対象"),
            ("file", "host"): (2, "端末"),
            ("network", "client"): (2, "端末"),
            ("network", "target"): (4, "対象"),
        }.get((kind, fact))
        if column is None:
            return None
        value = parts[column[0]]
        if fact == "program_name":
            value = value.rsplit("/", 1)[-1]
        return FactReading(value=value, field=column[1]) if value else None


class AltParser(DummyParser):
    """ダミーと同じ種別を出す、別の書き方（`ALT|...`）。

    ITM2 と Proxy は別々の種別しか出さないので、二つの順序を入れ替えても、
    段階の中の並びには差が出にくい。同じログから同じ種別を出す二つを
    並べて、はじめて「登録の順序で結果が変わらない」を確かめられる。
    ID は "dummy" より若いので、登録順と ID 順が食い違う。
    """

    id = "alt"
    label = "別のダミー形式（テスト用）"
    PREFIX = "ALT"


#: ダミーと別形式の行が 1 本のログに混ざったもの。
MIXED_TEXT = "\n".join([
    "DUMMY|2026-01-02T03:04:00+0900|HOST-A|start|/opt/tools/alpha",
    "ALT|2026-01-02T03:04:10+0900|HOST-A|start|/opt/tools/zeta",
    "DUMMY|2026-01-02T03:04:20+0900|HOST-A|write|/var/tmp/alpha.out",
    "ALT|2026-01-02T03:04:30+0900|HOST-B|start|/opt/tools/eta",
    "ALT|2026-01-02T03:04:40+0900|HOST-B|write|/var/tmp/eta.out",
    "DUMMY|2026-01-02T03:05:00+0900|HOST-B|start|/opt/tools/beta",
    "DUMMY|2026-01-02T03:07:00+0900|HOST-A|fetch|http://198.51.100.9/x",
    "ALT|2026-01-02T03:07:10+0900|HOST-B|fetch|http://203.0.113.5/y",
])


class RegistryCase(unittest.TestCase):
    """既定の登録簿へダミーを足し、終わったら必ず外す。"""

    def setUp(self):
        self.dummy = DummyParser()
        parsers.REGISTRY.register(self.dummy)

    def tearDown(self):
        parsers.REGISTRY.unregister(self.dummy.id)


class TestBuiltInParsers(unittest.TestCase):

    def test_itm2_and_proxy_are_registered(self):
        self.assertEqual(parsers.REGISTRY.ids(), ["itm2", "proxy"])
        self.assertEqual(parsers.REGISTRY.label("itm2"), "InfoTrace Mark II（端末の記録）")
        self.assertEqual(parsers.REGISTRY.label("proxy"), "Proxy（通信の記録）")

    def test_builtin_formats_are_parsed_through_the_registry(self):
        """教材の入口（build_lesson）は、必ず登録簿の parse_sources を通る。"""
        calls = []
        real = parsers.REGISTRY.parse_sources

        def spy(sources, parser_ids=None):
            calls.append(sorted(sources))
            return real(sources, parser_ids)

        parsers.REGISTRY.parse_sources = spy
        try:
            lesson = explain.build_lesson("t", SOURCES, "gen-reg")
        finally:
            del parsers.REGISTRY.parse_sources
        self.assertIsNotNone(lesson)
        self.assertEqual(calls, [sorted(SOURCES)])

    def test_each_source_is_read_by_the_parser_that_recognises_it(self):
        parsed = parsers.REGISTRY.parse_sources(SOURCES, ["itm2", "proxy"])
        self.assertEqual(parsed.recognized, {
            "case/evidence/logs.zip :: logs/host.log": ["itm2"],
            "case/evidence/logs.zip :: logs/proxy.log": ["proxy"],
        })
        self.assertEqual({e.parser_id for e in parsed.events}, {"itm2", "proxy"})
        self.assertEqual(parsed.unrecognized, [])
        self.assertEqual(parsed.failures, [])

    def test_a_profile_can_restrict_the_parsers(self):
        parsed = parsers.REGISTRY.parse_sources(SOURCES, ["itm2"])
        self.assertEqual({e.parser_id for e in parsed.events}, {"itm2"})
        self.assertEqual(parsed.unrecognized, ["case/evidence/logs.zip :: logs/proxy.log"])

    def test_unknown_parser_ids_are_reported_not_ignored(self):
        parsed = parsers.REGISTRY.parse_sources(SOURCES, ["itm2", "no-such-format"])
        self.assertEqual(parsed.unknown_parsers, ["no-such-format"])
        self.assertEqual(parsed.report()["unknownParsers"], ["no-such-format"])

    def test_unrecognised_sources_are_reported(self):
        parsed = parsers.REGISTRY.parse_sources({"a.log": "no known format here\n"})
        self.assertEqual(parsed.events, [])
        self.assertEqual(parsed.unrecognized, ["a.log"])


class TestRegistryContract(unittest.TestCase):

    def test_duplicate_registration_is_refused(self):
        registry = ParserRegistry([itm2.PARSER])
        with self.assertRaises(ContractError):
            registry.register(itm2.Itm2Parser())

    def test_registration_checks_the_contract(self):
        class NoId(Parser):
            label = "x"

            def detect(self, source):
                return 0.0

            def parse(self, source, evidence_store=None):
                return []

        class NoParse(Parser):
            id = "noparse"
            label = "x"

            def detect(self, source):
                return 0.0

        class BadId(NoId):
            id = "Bad ID!"

        registry = ParserRegistry()
        for bad in (NoId(), NoParse(), BadId(), object()):
            with self.subTest(parser=type(bad).__name__):
                with self.assertRaises(ContractError):
                    registry.register(bad)

    def _run_one(self, parser):
        registry = ParserRegistry([parser, proxy.PARSER])
        return registry.parse_sources({"x.log": DUMMY_TEXT + "\n" + PROXY_TEXT},
                                      [parser.id, "proxy"])

    def test_raw_records_from_a_parser_are_rejected(self):
        """生のレコード（辞書）は正規化イベントではない。教材へは流さない。"""

        class Raw(DummyParser):
            id = "raw"

            def parse(self, source, evidence_store=None):
                return [{"type": "ps", "psPath": "x"}]

        parsed = self._run_one(Raw())
        self.assertFalse([e for e in parsed.events if e.parser_id == "raw"])
        self.assertEqual([f["reason"] for f in parsed.failures], ["contract"])
        # 契約を守る他のパーサーは影響を受けない。
        self.assertTrue([e for e in parsed.events if e.parser_id == "proxy"])

    def test_events_missing_required_attributes_are_rejected(self):
        class Thin(DummyParser):
            id = "thin"

            def parse(self, source, evidence_store=None):
                events = super().parse(source, evidence_store)
                return [NormalizedEvent(
                    kind=e.kind, action=e.action, timestamp=e.timestamp, host=e.host,
                    summary=e.summary, source=e.source, parser_id=self.id,
                    attributes={}, correlation_keys=e.correlation_keys,
                ) for e in events]

        parsed = self._run_one(Thin())
        self.assertFalse([e for e in parsed.events if e.parser_id == "thin"])
        self.assertIn("必須の属性", parsed.failures[0]["detail"])

    def test_a_parser_cannot_claim_another_parsers_id(self):
        """別のパーサーの ID を名乗ると、そのパーサーの読み直しが使われてしまう。"""

        class Impostor(DummyParser):
            id = "impostor"

            def parse(self, source, evidence_store=None):
                events = super().parse(source, evidence_store)
                return [NormalizedEvent(
                    kind=e.kind, action=e.action, timestamp=e.timestamp, host=e.host,
                    summary=e.summary, source=e.source, parser_id="proxy",
                    attributes=e.attributes, correlation_keys=e.correlation_keys,
                ) for e in events]

        parsed = self._run_one(Impostor())
        self.assertFalse([e for e in parsed.events if "DUMMY|" in e.source.excerpt])
        self.assertEqual(parsed.failures[0]["reason"], "contract")
        self.assertEqual(parsed.failures[0]["parser"], "impostor")

    def test_placeholder_host_keys_are_rejected(self):
        class Loose(DummyParser):
            id = "loose"

            def parse(self, source, evidence_store=None):
                events = super().parse(source, evidence_store)
                return [NormalizedEvent(
                    kind=e.kind, action=e.action, timestamp=e.timestamp, host=e.host,
                    summary=e.summary, source=e.source, parser_id=self.id,
                    attributes=e.attributes, correlation_keys=frozenset({"?"}),
                ) for e in events]

        parsed = self._run_one(Loose())
        self.assertEqual(parsed.failures[0]["reason"], "contract")

    def test_a_crashing_parser_is_contained(self):
        class Crash(DummyParser):
            id = "crash"

            def parse(self, source, evidence_store=None):
                raise KeyError("secret log content")

        parsed = self._run_one(Crash())
        self.assertEqual(parsed.failures[0]["reason"], "error")
        # 例外文は載せない。ログの中身が紛れ込みうる。
        self.assertNotIn("secret log content", json.dumps(parsed.report(), ensure_ascii=False))
        self.assertTrue([e for e in parsed.events if e.parser_id == "proxy"])

    def test_detect_must_answer_with_a_score(self):
        for bad in (2.0, -0.1, "yes", float("nan"), None):
            with self.subTest(value=bad):
                class Odd(DummyParser):
                    id = "odd"

                    def detect(self, source, _v=bad):
                        return _v

                parsed = self._run_one(Odd())
                self.assertEqual(parsed.failures[0]["reason"], "contract")

    def test_evidence_ids_cannot_be_forged(self):
        """証拠 ID は出典から決まる。引数で渡すことはできない。"""
        src = source_of("a.log", 3, "DUMMY|x|H|start|/p")
        with self.assertRaises(TypeError):
            NormalizedEvent(kind="process", action="start", timestamp=timeline.UNKNOWN,
                            host="H", summary="s", source=src, parser_id="dummy",
                            attributes={"program": "/p", "program_name": "p"},
                            correlation_keys=frozenset(), evidence_id="ev-" + "0" * 24)
        ev = NormalizedEvent(kind="process", action="start", timestamp=timeline.UNKNOWN,
                             host="H", summary="s", source=src, parser_id="dummy",
                             attributes={"program": "/p", "program_name": "p"},
                             correlation_keys=frozenset())
        self.assertEqual(ev.evidence_id, evidence.evidence_id(src, "process"))


class TestDummyParserReachesTheLesson(RegistryCase):
    """登録するだけで、教材生成を変えずに最後まで届く。"""

    def build(self):
        return explain.build_lesson(
            "t", {"case/dummy.log": DUMMY_TEXT}, "gen-dummy"
        )

    def test_a_complete_lesson_is_built(self):
        lesson = self.build()
        self.assertIsNotNone(lesson)
        ids = [s["id"] for s in lesson["stages"]]
        self.assertEqual(ids, ["endpoint", "files", "network", "correlate"])
        quizzes = [q for s in lesson["stages"] for q in s["quizzes"]]
        self.assertTrue(quizzes)
        for quiz in quizzes:
            self.assertTrue(quiz["evidenceIds"])
            for ident in quiz["evidenceIds"]:
                self.assertIn(ident, lesson["evidence"])
        self.assertTrue(lesson["report"]["timeline"])
        self.assertEqual(lesson["introduction"]["logTypes"], ["ダミー形式（テスト用）"])

    def test_questions_are_grounded_in_the_dummy_lines(self):
        """設問の正解は、ダミーのパーサーが抜粋から読み直した値である。"""
        lesson = self.build()
        stage = next(s for s in lesson["stages"] if s["id"] == "endpoint")
        which = next(q for q in stage["quizzes"] if q["id"] == "q-endpoint-01")
        excerpt = lesson["evidence"][which["evidenceIds"][0]]["source"]["excerpt"]
        answer = which["options"][which["correct"]]
        self.assertEqual(self.dummy.reread("process", "program_name", excerpt).value, answer)
        # 解説の書き出しと次の観点は、ダミーの形式が持つ文言。
        self.assertTrue(which["explain"].startswith("ダミー形式では、5 列目（`対象`）"))
        self.assertEqual(which["nextInvestigation"], "ダミー形式の前後の行を確かめる")

    def test_stage_texts_come_from_the_parser(self):
        lesson = self.build()
        endpoint = next(s for s in lesson["stages"] if s["id"] == "endpoint")
        network = next(s for s in lesson["stages"] if s["id"] == "network")
        self.assertIn("ダミー形式は、端末ごとの操作を 1 行ずつ残します。", endpoint["intro"])
        self.assertTrue(network["intro"].startswith("ダミーの通信記録 2 件から"))
        limits = next(q for s in lesson["stages"] for q in s["quizzes"]
                      if q["category"] == "limits")
        self.assertIn("ダミーの通信記録 1 行だけから", limits["q"])

    def test_generic_defaults_fill_in_what_the_parser_does_not_say(self):
        """説明文を持たないパーサーでも設問は作られ、項目名が既定文に入る。"""
        lesson = self.build()
        files = next(s for s in lesson["stages"] if s["id"] == "files")
        where = next(q for q in files["quizzes"] if q["id"] == "q-files-01")
        self.assertTrue(where["explain"].startswith(
            explain.DEFAULT_WHERE.replace("{field}", "対象")))

    def test_correlation_uses_normalized_keys_times_and_kinds(self):
        lesson = self.build()
        corr = next(s for s in lesson["stages"] if s["id"] == "correlate")
        info = corr["quizzes"][0]["correlation"]
        self.assertEqual(info["gapSeconds"], 20.0)
        self.assertEqual(info["hostKey"], "HOST-A")
        self.assertEqual(set(info["types"]), {"process", "file"})

    def test_an_unreadable_time_is_kept_as_unknown(self):
        """読めない時刻の行も捨てず、「時刻不明」として末尾に置く。"""
        lesson = self.build()
        rows = lesson["report"]["timeline"]
        self.assertFalse(rows[-1]["timeKnown"])
        self.assertIn("delta", rows[-1]["title"])
        self.assertTrue(all(r["timeKnown"] for r in rows[:-1]))

    def test_evidence_ids_are_the_normalized_event_ids(self):
        parsed = parsers.REGISTRY.parse_sources({"case/dummy.log": DUMMY_TEXT})
        lesson = explain.lesson_from_parsed("t", parsed, "gen-dummy")
        by_id = {e.evidence_id: e for e in parsed.events}
        for ident, item in lesson["evidence"].items():
            with self.subTest(ident=ident):
                self.assertIn(ident, by_id)
                ev = by_id[ident]
                self.assertEqual(item["source"]["line"], ev.source.line)
                self.assertEqual(item["source"]["excerpt"], evidence.visible(ev.source.excerpt))


class TestQuizHints(unittest.TestCase):
    """Hints describe how to read the evidence, never the answer itself."""

    @staticmethod
    def questions(lesson):
        return {q["id"]: q for stage in lesson["stages"] for q in stage["quizzes"]}

    def setUp(self):
        self.lesson = explain.build_lesson(
            "hint fixture", SOURCES, "gen-hints", parser_ids=["itm2", "proxy"])
        self.assertIsNotNone(self.lesson)
        self.quizzes = self.questions(self.lesson)

    def test_all_five_categories_have_a_hint(self):
        self.assertEqual({q["category"] for q in self.quizzes.values()},
                         set(explain.CATEGORY_LABEL))
        for quiz in self.quizzes.values():
            with self.subTest(question=quiz["id"]):
                self.assertIsInstance(quiz.get("hint"), str)
                self.assertTrue(quiz["hint"].strip())

    def test_program_hint_names_the_actual_field_and_how_to_read_it(self):
        hint = self.quizzes["q-endpoint-01"]["hint"]
        self.assertIn("「psPath」", hint)
        self.assertIn("ファイル名", hint)
        self.assertIn("親プロセス", hint)

    def test_fallback_field_is_not_mislabelled_as_pspath(self):
        lesson = explain.build_lesson(
            "fallback", {"host.log": ITM2_TEXT.replace("psPath=", "path=")},
            "gen-fallback")
        hint = self.questions(lesson)["q-endpoint-01"]["hint"]
        self.assertIn("「path」", hint)
        self.assertNotIn("psPath", hint)

    def test_host_and_network_hints_name_their_own_fields(self):
        self.assertIn("「com」", self.quizzes["q-endpoint-02"]["hint"])
        self.assertIn("「行頭の要求元」", self.quizzes["q-network-01"]["hint"])

    def test_dummy_format_uses_its_fields_without_generator_changes(self):
        lesson = explain.build_lesson(
            "dummy", {"dummy.log": DUMMY_TEXT}, "gen-dummy-hints",
            registry=ParserRegistry([DummyParser()]))
        questions = self.questions(lesson)
        self.assertIn("「対象」", questions["q-endpoint-01"]["hint"])
        self.assertIn("「対象」", questions["q-files-01"]["hint"])
        self.assertIn("「端末」", questions["q-files-02"]["hint"])
        self.assertIn("「端末」", questions["q-network-01"]["hint"])
        for quiz in questions.values():
            self.assertNotIn("psPath", quiz["hint"])
            self.assertNotIn("com", quiz["hint"])

    def test_hints_do_not_embed_answer_values_or_identify_the_right_evidence(self):
        for quiz in self.quizzes.values():
            answer = quiz["options"][quiz["correct"]]
            if isinstance(answer, dict):
                answer = answer["label"]
            with self.subTest(question=quiz["id"]):
                self.assertNotIn(answer, quiz["hint"])
                for ident in quiz["evidenceIds"]:
                    self.assertNotIn(ident, quiz["hint"])
                    self.assertNotIn(
                        self.lesson["evidence"][ident]["source"]["excerpt"], quiz["hint"])


class TestLessonGenerationKnowsNoFormat(unittest.TestCase):
    """教材生成は形式を知らない。静的に確かめる。

    実行時のテストだけでは、分岐があっても通る入力でしか試せない。ここでは
    `explain.py` と `attck.py` のソースそのものを読み、形式ごとの分岐や
    項目名、形式別モジュールへの依存が無いことを確かめる。
    """

    FORMAT_WORDS = ("itm2", "proxy", "squid", "infotrace")
    FIELD_NAMES = ("psPath", "parentPath", "rcCom", "subEvt", "type=ITM2")

    def _tree(self, name):
        with open(os.path.join(BACKEND, name), encoding="utf-8") as fh:
            return ast.parse(fh.read())

    def test_no_format_specific_module_is_imported(self):
        for name in ("explain.py", "attck.py"):
            tree = self._tree(name)
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    mods = [node.module or ""] + [a.name for a in node.names]
                elif isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                else:
                    continue
                for mod in mods:
                    with self.subTest(file=name, module=mod):
                        self.assertFalse(
                            any(w in mod.lower() for w in self.FORMAT_WORDS),
                            f"{name} が形式別モジュール {mod} を読み込んでいる",
                        )

    def test_no_branch_on_a_parser_id_or_a_field_name(self):
        for name in ("explain.py", "attck.py"):
            tree = self._tree(name)
            docstrings = {
                id(n.body[0].value) for n in ast.walk(tree)
                if isinstance(n, (ast.Module, ast.FunctionDef, ast.ClassDef))
                and n.body and isinstance(n.body[0], ast.Expr)
                and isinstance(n.body[0].value, ast.Constant)
            }
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if id(node) in docstrings:
                        continue
                    low = node.value.lower()
                    with self.subTest(file=name, literal=node.value[:40]):
                        self.assertFalse(
                            any(w == low or f"'{w}'" in low for w in self.FORMAT_WORDS),
                            f"{name} に形式の ID が文字列として現れる",
                        )
                        for field in self.FIELD_NAMES:
                            self.assertNotIn(field, node.value,
                                             f"{name} が項目名 {field} を知っている")
                if isinstance(node, (ast.Name, ast.Attribute)):
                    ident = node.id if isinstance(node, ast.Name) else node.attr
                    with self.subTest(file=name, name=ident):
                        self.assertFalse(
                            any(w in ident.lower() for w in self.FORMAT_WORDS),
                            f"{name} が形式名の付いた名前 {ident} を使っている",
                        )

    def test_raw_records_are_rejected(self):
        """生のレコードを教材生成へ渡すと、黙って使わずに拒否する。"""
        raw = ParsedSources(
            events=[{"type": "ps", "psPath": "C:\\x.exe", "_src": None}],
            parsers={}, sources=["a"], recognized={"a": ["x"]},
            unknown_parsers=[], failures=[],
        )
        with self.assertRaises(TypeError):
            explain.lesson_from_parsed("t", raw, "gen-raw")


class TestNormalizedEventsAreEnough(RegistryCase):
    """テキストを経ずに、正規化イベントだけから段階・設問・時系列ができる。"""

    def test_lesson_from_hand_made_events(self):
        name = "hand/made.log"
        lines = DUMMY_TEXT.split("\n")
        events = self.dummy.parse(InputSource(name, "\n".join(lines)))
        parsed = ParsedSources(
            events=events, parsers={"dummy": self.dummy}, sources=[name],
            recognized={name: ["dummy"]}, unknown_parsers=[], failures=[],
        )
        lesson = explain.lesson_from_parsed("t", parsed, "gen-hand")
        self.assertIsNotNone(lesson)
        self.assertTrue(lesson["stages"])
        self.assertTrue(any(s["quizzes"] for s in lesson["stages"]))
        self.assertTrue(lesson["report"]["timeline"])


class TestParserOrderDoesNotMatter(unittest.TestCase):

    def _lesson(self, order, sources=SOURCES):
        registry = ParserRegistry(order)
        lesson = explain.build_lesson("t", sources, "gen-order", registry=registry)
        self.assertIsNotNone(lesson)
        return json.dumps(lesson, sort_keys=True, ensure_ascii=False)

    def test_two_parsers_reading_one_log_in_either_order(self):
        """同じログから同じ種別を出す二つのパーサー。登録順を入れ替えても同じ教材。"""
        sources = {"case/mixed.log": MIXED_TEXT}
        a = self._lesson([DummyParser(), AltParser()], sources)
        b = self._lesson([AltParser(), DummyParser()], sources)
        self.assertEqual(a, b)
        # 両方の形式の行が、実際に教材へ載っていること（片方が黙って
        # 落ちていれば、順序は結果に響きようがない）。
        excerpts = [v["source"]["excerpt"] for v in json.loads(a)["evidence"].values()]
        self.assertTrue(any(e.startswith("DUMMY|") for e in excerpts))
        self.assertTrue(any(e.startswith("ALT|") for e in excerpts))

    def test_source_order_does_not_change_the_lesson(self):
        """入力ソースを渡す順（辞書の並び）で、教材が変わらない。"""
        lines = DUMMY_TEXT.split("\n")
        first = {"case/a.log": "\n".join(lines[:4]), "case/b.log": "\n".join(lines[4:])}
        second = dict(reversed(list(first.items())))
        self.assertNotEqual(list(first), list(second))
        self.assertEqual(self._lesson([DummyParser()], first),
                         self._lesson([DummyParser()], second))

    def test_registration_order_does_not_change_the_lesson(self):
        a = self._lesson([itm2.PARSER, proxy.PARSER])
        b = self._lesson([proxy.PARSER, itm2.PARSER])
        self.assertEqual(a, b)

    def test_an_extra_parser_that_reads_nothing_changes_nothing(self):
        a = self._lesson([itm2.PARSER, proxy.PARSER])
        b = self._lesson([DummyParser(), proxy.PARSER, itm2.PARSER])
        self.assertEqual(a, b)

    def test_same_input_same_lesson(self):
        self.assertEqual(self._lesson([itm2.PARSER, proxy.PARSER]),
                         self._lesson([itm2.PARSER, proxy.PARSER]))


WEB_TEXT = "\n".join(
    f'203.0.113.{i} - - [05/Oct/2022:14:00:0{i} +0900] "GET /index.html HTTP/1.1" 200 42'
    for i in range(1, 5)
)


class TestProxyIsNotAWebServerLog(unittest.TestCase):
    """Web サーバーのアクセスログは、行の形がプロキシのログとほぼ同じ。

    行頭は「サーバーへ要求してきた相手」で、端末から外部への通信ではない。
    以前はこれを Proxy と判定し、「通信 — 外部へ何が出ていったか」の教材を
    作っていた。除外はプロファイルに任せていたので、プロファイル 0 件の
    標準構成では防げなかった。
    """

    def src(self, text, name="web/access.log"):
        return InputSource(name, text)

    def test_origin_form_requests_are_not_claimed(self):
        self.assertEqual(proxy.PARSER.detect(self.src(WEB_TEXT)), 0.0)
        parsed = parsers.REGISTRY.parse_sources({"web/access.log": WEB_TEXT})
        self.assertEqual(parsed.events, [])
        self.assertEqual(parsed.unrecognized, ["web/access.log"])
        self.assertIsNone(explain.build_lesson("t", {"web/access.log": WEB_TEXT}, "g"))

    def test_a_web_log_with_an_open_proxy_probe_is_still_not_claimed(self):
        """走査が送る `GET http://…` が 1 行混ざっても、プロキシとは断定しない。"""
        probe = ('198.51.100.66 - - [05/Oct/2022:14:00:09 +0900] '
                 '"GET http://203.0.113.200/ HTTP/1.1" 404 0')
        self.assertEqual(proxy.PARSER.detect(self.src(WEB_TEXT + "\n" + probe)), 0.0)

    def test_proxy_forms_are_claimed(self):
        self.assertEqual(proxy.PARSER.detect(self.src(PROXY_TEXT)), 1.0)
        connect = ('192.0.2.10 - - [05/Oct/2022:14:00:07 +0900] '
                   '"CONNECT 198.51.100.23:443 HTTP/1.1" 200 1588')
        self.assertEqual(proxy.PARSER.detect(self.src(connect)), 1.0)
        self.assertEqual(len(proxy.PARSER.parse(self.src(PROXY_TEXT + "\n" + connect))), 3)

    def test_requests_that_are_not_proxy_requests_are_not_events(self):
        odd = "\n".join([
            '192.0.2.10 - - [05/Oct/2022:14:00:07 +0900] "GET 198.51.100.23:443 HTTP/1.1" 200 1',
            '192.0.2.10 - - [05/Oct/2022:14:00:08 +0900] "CONNECT http://x/ HTTP/1.1" 200 1',
            '192.0.2.10 - - [05/Oct/2022:14:00:09 +0900] "GET /local HTTP/1.1" 200 1',
        ])
        self.assertEqual(proxy.PARSER.parse(self.src(odd)), [])

    def test_request_form(self):
        cases = {
            ("GET", "http://198.51.100.1/a"): "proxy",
            ("CONNECT", "198.51.100.1:443"): "proxy",
            ("CONNECT", "[2001:db8::1]:443"): "proxy",
            ("GET", "/index.html"): "origin",
            ("OPTIONS", "*"): "origin",
            ("GET", "198.51.100.1:443"): "other",
            ("CONNECT", "http://x/"): "other",
        }
        for (method, dest), want in cases.items():
            with self.subTest(method=method, dest=dest):
                self.assertEqual(proxy.request_form(method, dest), want)


#: 絶対 URL（absolute-form）だけから成る Web サーバーのアクセスログ。
#: HTTP の仕様上、普通の Web サーバーもこの形の要求を受け付ける
#: （RFC 9112 §3.2.2）。行の書き方からは、プロキシの記録と区別できない。
ABSOLUTE_WEB_TEXT = "\n".join(
    f'203.0.113.{i} - - [05/Oct/2022:14:00:0{i} +0900] '
    f'"GET http://web.example/index{i}.html HTTP/1.1" 200 42'
    for i in range(1, 5)
)


class TestProxyNeedsAnExplicitDesignation(unittest.TestCase):
    """Proxy は自動判定に参加しない。プロファイルで明示したときだけ使う。

    宛先を丸ごと書いた要求だけのログも、Web サーバー側の記録でありうる。
    以前はこれを Proxy と判定し、サーバーへのアクセスを「外部へ出ていった
    通信」として教えていた。
    """

    def test_proxy_is_not_an_auto_detect_parser(self):
        self.assertFalse(proxy.PARSER.AUTO_DETECT)
        self.assertTrue(itm2.PARSER.AUTO_DETECT)
        auto, unknown = parsers.REGISTRY.resolve(None)
        self.assertEqual([p.id for p in auto], ["itm2"])
        self.assertEqual(unknown, [])

    def test_an_absolute_form_web_log_is_not_claimed_automatically(self):
        name = "site/access.log"
        parsed = parsers.REGISTRY.parse_sources({name: ABSOLUTE_WEB_TEXT})
        self.assertEqual(parsed.events, [])
        self.assertEqual(parsed.unrecognized, [name])
        # 黙って落とさない。「指定すれば読めるが、内容だけでは断定しない」。
        self.assertEqual(parsed.explicit_only, {name: ["proxy"]})
        self.assertEqual(parsed.report()["explicitOnly"], {name: ["proxy"]})
        self.assertIsNone(explain.build_lesson("t", {name: ABSOLUTE_WEB_TEXT}, "g"))

    def test_a_proxy_log_is_not_claimed_automatically_either(self):
        """内容からは区別できないので、本物のプロキシのログでも同じ扱い。"""
        parsed = parsers.REGISTRY.parse_sources({"p.log": PROXY_TEXT})
        self.assertEqual(parsed.events, [])
        self.assertEqual(parsed.explicit_only, {"p.log": ["proxy"]})

    def test_naming_proxy_reads_it(self):
        parsed = parsers.REGISTRY.parse_sources({"p.log": PROXY_TEXT}, ["proxy"])
        self.assertEqual({e.parser_id for e in parsed.events}, {"proxy"})
        self.assertEqual(parsed.explicit_only, {})
        lesson = explain.build_lesson("t", {"p.log": PROXY_TEXT}, "g", parser_ids=["proxy"])
        self.assertIn("network", [st["id"] for st in lesson["stages"]])

    def test_logs_no_parser_could_read_are_not_listed_as_explicit_only(self):
        parsed = parsers.REGISTRY.parse_sources({"a.log": "nothing recognisable here"})
        self.assertEqual(parsed.unrecognized, ["a.log"])
        self.assertEqual(parsed.explicit_only, {})

    def test_auto_detect_must_be_a_bool(self):
        class Vague(DummyParser):
            id = "vague"
            AUTO_DETECT = "yes"

        with self.assertRaises(ContractError):
            ParserRegistry([Vague()])


class LateClientParser(DummyParser):
    """要求元が行の末尾（抜粋の保存上限より後ろ）に来る架空の形式。

        LATE|<時刻>|<宛先>|<長い中身>|<要求元>
    """

    id = "late"
    label = "末尾に要求元を書く形式（テスト用）"
    PREFIX = "LATE"

    def parse(self, source, evidence_store=None):
        out = []
        for no, line in enumerate(source.lines(), 1):
            parts = line.split("|")
            if len(parts) != 5 or parts[0] != self.PREFIX:
                continue
            _, when, target, _body, who = parts
            out.append(NormalizedEvent(
                kind="network", action="fetch", timestamp=self._stamp(when, source.name),
                host=who, summary=f"{who} -> FETCH {target}",
                source=source_of(source.name, no, line), parser_id=self.id,
                attributes={"client": who, "method": "FETCH", "target": target},
                correlation_keys=clean_host_keys([who]),
            ))
        return out

    def reread(self, kind, fact, excerpt):
        parts = (excerpt or "").split("|")
        if kind != "network" or len(parts) != 5:
            return None
        column = {"client": (4, "末尾の要求元"), "target": (2, "宛先")}.get(fact)
        if column is None or not parts[column[0]]:
            return None
        return FactReading(value=parts[column[0]], field=column[1])


def _late_text(body_len):
    return "\n".join(
        f"LATE|2026-01-02T03:0{i}:00+0900|http://198.51.100.{i + 1}/x|{'p' * body_len}|HOST-{i}"
        for i in range(4)
    )


class TestNetworkQuestionIsGroundedInTheExcerpt(unittest.TestCase):
    """通信の設問も、引用した 1 行から読み直せる値だけで作る。

    以前は正解を `attributes["client"]` から取っていた。要求元が抜粋の
    保存上限より後ろにある形式では、引用に書かれていない値が正解になった。
    """

    def lesson(self, body_len):
        registry = ParserRegistry([LateClientParser()])
        return explain.build_lesson("t", {"case/net.log": _late_text(body_len)},
                                    "gen-late", registry=registry)

    def quizzes(self, lesson):
        return {q["id"]: q for s in lesson["stages"] for q in s["quizzes"]}

    def test_no_question_when_the_answer_is_cut_from_the_excerpt(self):
        lesson = self.lesson(1200)
        self.assertIsNotNone(lesson)
        quizzes = self.quizzes(lesson)
        self.assertNotIn("q-network-01", quizzes)
        self.assertNotIn("q-network-evidence", quizzes)

    def test_every_answer_is_readable_from_its_own_excerpt(self):
        for body_len in (10, 1200):
            lesson = self.lesson(body_len)
            parser = LateClientParser()
            for qid, quiz in self.quizzes(lesson).items():
                if quiz.get("category") != "log-reading":
                    continue
                with self.subTest(body_len=body_len, quiz=qid):
                    excerpt = lesson["evidence"][quiz["evidenceIds"][0]]["source"]["excerpt"]
                    answer = quiz["options"][quiz["correct"]]
                    readings = {r.value for f in parsers.FACTS["network"]
                                if (r := parser.reread("network", f, excerpt))}
                    self.assertIn(answer, readings)

    def test_the_question_is_made_when_the_excerpt_holds_the_answer(self):
        quizzes = self.quizzes(self.lesson(10))
        self.assertIn("q-network-01", quizzes)
        self.assertIn("末尾の要求元", quizzes["q-network-01"]["explain"])


if __name__ == "__main__":
    unittest.main()
