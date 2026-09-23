"""Tests for the evidence layer added in phase 2.

NO REAL CONTEST DATA. Fixtures use invented hostnames, RFC 5737 documentation
addresses and harmless commands, built at run time.

The load-bearing tests are about what a lesson PROMISES: every question must be
answerable with "because of this line, in this file, at this number", and the
line number must be the one someone would land on if they opened the log.
"""

import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import evidence  # noqa: E402
import explain  # noqa: E402
from api import ROLE_CAPS, ROUTES, Capability  # noqa: E402

HOST = "WS99"
ITM2 = [
    # InfoTrace Mark II では、起動したプロセスが `psPath`、親が `parentPath`。
    # 実データの起動記録 676 件すべてがこの形で、`path` は空だった。
    '10/05/2022 14:00:01.000 +0900 loc=en-US type=ITM2 sn=1 lv=5 evt=ps '
    f'subEvt=start os=Win com="{HOST}" parentPath="C:\\Windows\\explorer.exe" '
    'psPath="C:\\Windows\\System32\\cmd.exe"',
    '10/05/2022 14:00:02.000 +0900 loc=en-US type=ITM2 sn=2 lv=5 evt=ps '
    f'subEvt=start os=Win com="{HOST}" parentPath="C:\\Windows\\System32\\cmd.exe" '
    'psPath="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"',
    '10/05/2022 14:00:03.000 +0900 loc=en-US type=ITM2 sn=3 lv=5 evt=ps '
    f'subEvt=start os=Win com="{HOST}" parentPath="C:\\Windows\\System32\\cmd.exe" '
    'psPath="C:\\Windows\\System32\\whoami.exe"',
    '10/05/2022 14:00:04.000 +0900 loc=en-US type=ITM2 sn=4 lv=5 evt=ps '
    f'subEvt=start os=Win com="{HOST}" parentPath="C:\\Windows\\System32\\cmd.exe" '
    'psPath="C:\\Windows\\System32\\net.exe"',
    '10/05/2022 14:00:05.000 +0900 loc=en-US type=ITM2 sn=5 lv=5 evt=file '
    f'subEvt=create os=Win com="{HOST}" path="C:\\Users\\test\\AppData\\demo.dat"',
    '10/05/2022 14:00:06.000 +0900 loc=en-US type=ITM2 sn=6 lv=5 evt=reg '
    f'subEvt=setVal os=Win com="{HOST}" '
    'path="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Demo"',
]
PROXY = [
    '192.0.2.10 - - [05/Oct/2022:14:00:07 +0900] '
    '"CONNECT 198.51.100.23:443 HTTP/1.1" 200 1588',
    '192.0.2.10 - - [05/Oct/2022:14:00:08 +0900] '
    '"GET http://203.0.113.9/a HTTP/1.1" 200 42',
]

ENDPOINT_NAME = "case2022/DFIR/logs.zip :: logs/ws99.log"
PROXY_NAME = "case2022/DFIR/logs.zip :: logs/proxy01.log"


def endpoint_text() -> str:
    """Blank and unparseable lines sit between the records on purpose."""
    return "\n".join(
        [
            "# 先頭のコメント行",          # 1
            "",                            # 2
            ITM2[0],                       # 3
            "",                            # 4
            "解析できないごみ行",            # 5
            ITM2[1],                       # 6
            ITM2[2],                       # 7
            "",                            # 8
            ITM2[3],                       # 9
            ITM2[4],                       # 10
            ITM2[5],                       # 11
        ]
    )


def proxy_text() -> str:
    return "\n".join(["", "# コメント", PROXY[0], "", PROXY[1]])


def sources() -> dict[str, str]:
    return {ENDPOINT_NAME: endpoint_text(), PROXY_NAME: proxy_text()}


def build() -> dict:
    lesson = explain.build_lesson("t", sources(), "gen-test")
    assert lesson is not None
    return lesson


class TestLineNumbers(unittest.TestCase):
    """A line number that is off by even one makes the evidence useless."""

    def test_itm2_line_numbers_match_the_original(self):
        recs = explain.parse_itm2(endpoint_text(), name=ENDPOINT_NAME)
        got = [r["_src"].line for r in recs]
        self.assertEqual(got, [3, 6, 7, 9, 10, 11])

    def test_proxy_line_numbers_match_the_original(self):
        recs = explain.parse_proxy(proxy_text(), name=PROXY_NAME)
        self.assertEqual([r["_src"].line for r in recs], [3, 5])

    def test_blank_and_unparseable_lines_still_advance_the_count(self):
        """Skipped lines must not compress the numbering."""
        lines = endpoint_text().split("\n")
        for rec in explain.parse_itm2(endpoint_text(), name=ENDPOINT_NAME):
            self.assertEqual(lines[rec["_src"].line - 1], rec["_src"].excerpt)

    def test_numbering_is_one_based(self):
        recs = explain.parse_itm2(ITM2[0], name=ENDPOINT_NAME)
        self.assertEqual(recs[0]["_src"].line, 1)

    def test_same_member_name_in_different_containers_is_distinct(self):
        """`logs/a.log` in two inner ZIPs must not collapse into one source."""
        a = "case/DFIR/one.zip :: logs/a.log"
        b = "case/DFIR/two.zip :: logs/a.log"
        ra = explain.parse_itm2(ITM2[0], name=a)[0]["_src"]
        rb = explain.parse_itm2(ITM2[0], name=b)[0]["_src"]
        self.assertEqual(ra.member, rb.member)
        self.assertNotEqual(ra.archive_path, rb.archive_path)
        self.assertNotEqual(
            evidence.evidence_id(ra, "process"), evidence.evidence_id(rb, "process")
        )


class TestEvidenceId(unittest.TestCase):
    def source(self, **kw):
        base = dict(
            archive_path="case/DFIR/logs.zip :: logs/a.log",
            member="logs/a.log", line=10, excerpt="hello",
        )
        base.update(kw)
        return evidence.Source(**base)

    def test_stable_across_calls(self):
        a = evidence.evidence_id(self.source(), "process")
        b = evidence.evidence_id(self.source(), "process")
        self.assertEqual(a, b)

    def test_stable_across_processes(self):
        """Pinned to SHA-256, so it cannot depend on PYTHONHASHSEED."""
        src = self.source()
        digest = hashlib.sha256()
        for part in (src.archive_path, src.member, str(src.line), src.excerpt,
                     "process"):
            digest.update(part.encode("utf-8"))
            digest.update(b"\x00")
        self.assertEqual(
            evidence.evidence_id(src, "process"),
            "ev-" + digest.hexdigest()[: evidence.ID_HEX],
        )

    def test_line_changes_the_id(self):
        self.assertNotEqual(
            evidence.evidence_id(self.source(line=10), "process"),
            evidence.evidence_id(self.source(line=11), "process"),
        )

    def test_excerpt_changes_the_id(self):
        self.assertNotEqual(
            evidence.evidence_id(self.source(excerpt="a"), "process"),
            evidence.evidence_id(self.source(excerpt="b"), "process"),
        )

    def test_source_path_changes_the_id(self):
        self.assertNotEqual(
            evidence.evidence_id(self.source(archive_path="x"), "process"),
            evidence.evidence_id(self.source(archive_path="y"), "process"),
        )

    def test_field_boundaries_cannot_be_shifted(self):
        """"ab"+"c" must not hash the same as "a"+"bc"."""
        self.assertNotEqual(
            evidence.evidence_id(self.source(member="ab", excerpt="c"), ""),
            evidence.evidence_id(self.source(member="a", excerpt="bc"), ""),
        )

    def test_order_does_not_affect_ids(self):
        store_a = evidence.EvidenceStore()
        store_b = evidence.EvidenceStore()
        one, two = self.source(line=1), self.source(line=2)
        ids_a = [store_a.add(one, "process"), store_a.add(two, "process")]
        ids_b = [store_b.add(two, "process"), store_b.add(one, "process")]
        self.assertEqual(set(ids_a), set(ids_b))

    def test_the_same_line_is_stored_once(self):
        store = evidence.EvidenceStore()
        first = store.add(self.source(), "process")
        second = store.add(self.source(), "process")
        self.assertEqual(first, second)
        self.assertEqual(len(store.items), 1)


class TestExcerptSafety(unittest.TestCase):
    """Excerpts are attacker-controlled text from inside a ZIP."""

    def test_bidi_override_is_made_visible(self):
        out = evidence.visible("payroll\u202egnp.exe")
        self.assertNotIn("\u202e", out)
        self.assertIn("<U+202E>", out)

    def test_nul_and_control_characters_are_made_visible(self):
        out = evidence.visible("a\x00b\x1bc")
        self.assertNotIn("\x00", out)
        self.assertIn("<U+0000>", out)
        self.assertIn("<U+001B>", out)

    def test_html_is_kept_as_text(self):
        """Escaping is the page's job; the point here is it is not stripped."""
        out = evidence.visible("<script>alert(1)</script>")
        self.assertIn("<script>", out)

    def test_excerpt_is_capped(self):
        out = evidence.visible("x" * 5000)
        self.assertLessEqual(len(out), evidence.MAX_EXCERPT + 1)

    def test_source_names_are_sanitised_too(self):
        src = evidence.Source(
            archive_path="a\u202eb", member="c\x00d", line=1, excerpt="e"
        )
        body = src.as_json()
        self.assertNotIn("\u202e", body["archivePath"])
        self.assertNotIn("\x00", body["member"])


class TestLessonEvidence(unittest.TestCase):
    def setUp(self):
        self.lesson = build()

    def test_evidence_is_stored_on_the_lesson(self):
        self.assertTrue(self.lesson["evidence"])
        for ident, item in self.lesson["evidence"].items():
            self.assertEqual(item["id"], ident)
            self.assertEqual(item["confidence"], evidence.OBSERVED)
            self.assertIn("source", item)

    def test_every_displayed_event_has_evidence(self):
        for stage in self.lesson["stages"]:
            for event in stage["events"]:
                self.assertTrue(event.get("evidenceIds"), event)
                for ident in event["evidenceIds"]:
                    self.assertIn(ident, self.lesson["evidence"])

    def test_source_carries_path_member_line_and_excerpt(self):
        item = next(iter(self.lesson["evidence"].values()))
        src = item["source"]
        self.assertIn("logs.zip :: ", src["archivePath"])
        self.assertTrue(src["member"].startswith("logs/"))
        self.assertGreaterEqual(src["line"], 1)
        self.assertTrue(src["excerpt"])

    def test_no_local_absolute_path_is_stored(self):
        blob = repr(self.lesson)
        self.assertNotIn("/Users/", blob)
        self.assertNotIn("/private/", blob)
        self.assertNotIn(os.getcwd(), blob)

    def test_only_referenced_evidence_is_kept(self):
        referenced = set()
        for stage in self.lesson["stages"]:
            for event in stage["events"]:
                referenced.update(event.get("evidenceIds", []))
            for quiz in stage["quizzes"]:
                referenced.update(quiz.get("evidenceIds", []))
                for opt in quiz.get("options", []):
                    if isinstance(opt, dict):
                        referenced.add(opt["evidenceId"])
        self.assertEqual(set(self.lesson["evidence"]), referenced)

    def test_confidence_is_observed_only(self):
        """Nothing in this phase is correlated or hypothesised."""
        kinds = {i["confidence"] for i in self.lesson["evidence"].values()}
        self.assertEqual(kinds, {"observed"})


class TestQuestionsAreGrounded(unittest.TestCase):
    def setUp(self):
        self.lesson = build()

    def quizzes(self):
        for stage in self.lesson["stages"]:
            for quiz in stage["quizzes"]:
                yield quiz

    def test_every_question_cites_evidence(self):
        seen = 0
        for quiz in self.quizzes():
            seen += 1
            self.assertTrue(quiz.get("evidenceIds"), quiz.get("id"))
            for ident in quiz["evidenceIds"]:
                self.assertIn(ident, self.lesson["evidence"], quiz.get("id"))
        self.assertGreater(seen, 0)

    def test_ungrounded_questions_are_dropped(self):
        """A quiz with no evidence must not survive into the lesson."""
        original = explain._stage_files

        def stripped(files, store):
            stage = original(files, store)
            for quiz in stage["quizzes"]:
                quiz["evidenceIds"] = []
            return stage

        explain._stage_files = stripped
        try:
            lesson = explain.build_lesson("t", sources(), "gen-test")
        finally:
            explain._stage_files = original
        stage = next(s for s in lesson["stages"] if s["id"] == "files")
        # フェーズ3以降、段階は消さない。観測できた事実は見せたうえで、
        # 設問を作れなかったことを言う（仕様書 5 節「空状態」）。
        self.assertEqual(stage["quizzes"], [])
        self.assertIn("根拠が不足", stage.get("note", ""))

    def test_question_evidence_ids_are_never_invented(self):
        for quiz in self.quizzes():
            for opt in quiz.get("options", []):
                if isinstance(opt, dict):
                    self.assertIn(opt["evidenceId"], self.lesson["evidence"])


class TestEvidencePick(unittest.TestCase):
    def setUp(self):
        self.lesson = build()
        self.picks = [
            q for s in self.lesson["stages"] for q in s["quizzes"]
            if q["type"] == "evidence_pick"
        ]

    def test_at_least_one_is_generated(self):
        self.assertTrue(self.picks)

    def test_all_options_reference_real_evidence(self):
        for quiz in self.picks:
            self.assertGreaterEqual(len(quiz["options"]), 2)
            for opt in quiz["options"]:
                self.assertIn(opt["evidenceId"], self.lesson["evidence"])

    def test_correct_index_is_in_range_and_matches_evidence_ids(self):
        for quiz in self.picks:
            self.assertTrue(0 <= quiz["correct"] < len(quiz["options"]))
            chosen = quiz["options"][quiz["correct"]]["evidenceId"]
            self.assertEqual(quiz["evidenceIds"], [chosen])

    def test_options_do_not_repeat_evidence(self):
        for quiz in self.picks:
            ids = [o["evidenceId"] for o in quiz["options"]]
            self.assertEqual(len(ids), len(set(ids)))

    def test_option_labels_do_not_leak_the_answer(self):
        """Labels are file+line only, so length or wording cannot give it away."""
        for quiz in self.picks:
            for opt in quiz["options"]:
                self.assertRegex(opt["label"], r"の \d+ 行目$")

    def test_correct_position_is_deterministic_but_not_always_first(self):
        again = build()
        picks = [
            q for s in again["stages"] for q in s["quizzes"]
            if q["type"] == "evidence_pick"
        ]
        self.assertEqual(
            [q["correct"] for q in self.picks], [q["correct"] for q in picks]
        )
        spread = {evidence.pick_index(f"seed-{i}", 4) for i in range(40)}
        self.assertGreater(len(spread), 1, "the answer must move between slots")

    def test_not_generated_without_alternatives(self):
        store = evidence.EvidenceStore()
        src = evidence.Source("a", "a", 1, "cmd.exe を起動")
        event = {"evidenceIds": [store.add(src, "process")]}
        self.assertIsNone(
            explain._evidence_pick(
                store, event, [event], "q", "o", "cmd.exe",
                lambda v: f"{v}?", "e", "n",
            )
        )

    def test_a_mention_elsewhere_in_the_line_is_not_a_basis(self):
        """Regression: a matching substring is not the same as proof.

        `cmd="cmd.exe --x"` and `parentPath="...\\cmd.exe"` both contain the
        name, so a plain `claim in excerpt` check passed even when `psPath` --
        the field that says which process actually started -- fell outside the
        excerpt. The cited line then only showed that the name appears in a
        command string, not that the program ran.
        """
        # `cmd` に名前が早く現れ、`psPath` は 1000 字の抜粋外へ押し出す。
        pad = "filler=" + "z" * 1400 + " "
        def line(seq, exe, cmd):
            return (
                f'10/05/2022 14:0{seq}:00.000 +0900 loc=en-US type=ITM2 sn={seq} '
                f'lv=5 evt=ps subEvt=start os=Win com="WS9{seq}" cmd="{cmd}" '
                f'{pad}psPath="C:\\Windows\\System32\\{exe}"'
            )

        text = "\n".join([
            line(0, "cmd.exe", "cmd.exe --early-mention"),
            line(1, "powershell.exe", "powershell.exe -enc AAAA"),
        ])
        store = evidence.EvidenceStore()
        events = explain.events_from_itm2(
            explain.parse_itm2(text, name=ENDPOINT_NAME), store
        )
        excerpt = store.get(events[0]["evidenceIds"][0])["source"]["excerpt"]

        # 前提を固定する。これが崩れるとテストが意味を失う。
        self.assertIn("cmd.exe", excerpt, "名前は抜粋内にある")
        self.assertNotIn("psPath=", excerpt, "起動対象の項目は抜粋外")

        self.assertIsNone(
            explain._evidence_pick(
                store, events[0], events, "q", "o", "cmd.exe",
                lambda v: f"{v}?", "e", "n",
                proves=explain._started_program,
            ),
            "psPath が読めないなら根拠にならない",
        )

    def test_parent_path_alone_is_not_a_basis(self):
        """The parent's name is in the line, but it did not start."""
        line = (
            '10/05/2022 14:00:01.000 +0900 type=ITM2 evt=ps subEvt=start '
            'com="WS99" parentPath="C:\\Windows\\System32\\cmd.exe" '
            'psPath="C:\\Windows\\System32\\whoami.exe"'
        )
        store = evidence.EvidenceStore()
        events = explain.events_from_itm2(
            explain.parse_itm2(line, name=ENDPOINT_NAME), store
        )
        excerpt = store.get(events[0]["evidenceIds"][0])["source"]["excerpt"]
        self.assertIn("cmd.exe", excerpt, "親の名前は行の中にある")
        # 起動したのは whoami.exe なので、cmd.exe の起動の根拠にはならない。
        self.assertEqual(explain._started_program(excerpt), "whoami.exe")
        self.assertIsNone(
            explain._evidence_pick(
                store, events[0], events, "q", "o", "cmd.exe",
                lambda v: f"{v}?", "e", "n",
                proves=explain._started_program,
            )
        )

    def test_started_program_reads_psPath_then_path(self):
        self.assertEqual(
            explain._started_program('psPath="C:\\W\\a.exe" path="C:\\W\\b.exe"'),
            "a.exe",
        )
        self.assertEqual(explain._started_program('path="C:\\W\\b.exe"'), "b.exe")
        self.assertEqual(explain._started_program('cmd="a.exe --x"'), "")

    def test_proxy_client_reads_the_leading_address(self):
        self.assertEqual(
            explain._proxy_client('192.0.2.10 - - [05/Oct/2022] "GET x" 200'),
            "192.0.2.10",
        )
        self.assertEqual(explain._proxy_client(""), "")

    def test_not_generated_when_the_claim_is_absent_from_the_excerpt(self):
        """Regression: the claim must be checkable against the cited line.

        The prompt used to be built from the event's summary text, which is
        assembled from the parsed record and survives even when the excerpt was
        truncated before the value appeared. On very long lines that left an
        evidence_pick question asserting something the shown excerpt does not
        contain -- the one shape of question this phase exists to prevent.
        """
        store = evidence.EvidenceStore()
        a = evidence.Source("a", "a", 1, "この行に実行ファイル名は入っていない")
        b = evidence.Source("a", "a", 2, "こちらも別の行")
        one = {"evidenceIds": [store.add(a, "process")]}
        two = {"evidenceIds": [store.add(b, "process")]}
        self.assertIsNone(
            explain._evidence_pick(
                store, one, [one, two], "q", "o", "powershell.exe",
                lambda v: f"{v}?", "e", "n",
            )
        )

    def test_generated_when_the_proving_field_says_so(self):
        store = evidence.EvidenceStore()
        a = evidence.Source("a", "a", 1, 'psPath="C:\\W\\powershell.exe"')
        b = evidence.Source("a", "a", 2, 'psPath="C:\\W\\cmd.exe"')
        one = {"evidenceIds": [store.add(a, "process")]}
        two = {"evidenceIds": [store.add(b, "process")]}
        quiz = explain._evidence_pick(
            store, one, [one, two], "q", "o", "powershell.exe",
            lambda v: f"{v}?", "e", "n",
            proves=explain._started_program,
        )
        self.assertIsNotNone(quiz)
        self.assertIn("powershell.exe", quiz["q"])

    def test_default_prover_refuses_rather_than_assuming(self):
        """With no way to check the claim, refuse. Fail closed."""
        store = evidence.EvidenceStore()
        src = evidence.Source("a", "a", 1, 'psPath="C:\\W\\powershell.exe"')
        one = {"evidenceIds": [store.add(src, "process")]}
        two = {"evidenceIds": [store.add(
            evidence.Source("a", "a", 2, 'psPath="C:\\W\\cmd.exe"'), "process"
        )]}
        self.assertIsNone(
            explain._evidence_pick(
                store, one, [one, two], "q", "o", "powershell.exe",
                lambda v: f"{v}?", "e", "n",
            )
        )


class TestDeterminism(unittest.TestCase):
    def test_same_input_gives_the_same_lesson(self):
        import json

        a = json.dumps(build(), sort_keys=True, ensure_ascii=False)
        b = json.dumps(build(), sort_keys=True, ensure_ascii=False)
        self.assertEqual(a, b)

    def test_source_order_does_not_change_the_result(self):
        import json

        forward = dict(sources())
        backward = dict(reversed(list(sources().items())))
        a = explain.build_lesson("t", forward, "gen-test")
        b = explain.build_lesson("t", backward, "gen-test")
        self.assertEqual(
            json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True)
        )


class TestBackwardCompatibility(unittest.TestCase):
    """Lessons made before this phase must still load and display."""

    def test_old_lesson_without_evidence_is_still_valid(self):
        old = {
            "id": "gen-old", "title": "t", "stages": [
                {"id": "s", "name": "n", "events": [{"type": "process", "detail": "d"}],
                 "quiz": {"q": "?", "options": ["a", "b"], "correct": 1,
                          "explain": "e"}}
            ],
        }
        stage = old["stages"][0]
        self.assertNotIn("evidence", old)
        self.assertNotIn("evidenceIds", stage["quiz"])
        self.assertNotIn("quizzes", stage)

    def test_new_lesson_keeps_the_legacy_quiz_field(self):
        lesson = build()
        checked = 0
        for stage in lesson["stages"]:
            if not stage["quizzes"]:
                # 設問を作れなかった段階。旧形式の読み手には設問なしとして
                # 見える必要があるので、None のままにする。
                self.assertIsNone(stage.get("quiz"))
                continue
            checked += 1
            self.assertIsNotNone(stage.get("quiz"))
            self.assertEqual(stage["quiz"], stage["quizzes"][0])
        self.assertGreater(checked, 0)

    def test_parsers_still_work_without_a_source_name(self):
        recs = explain.parse_itm2(endpoint_text())
        self.assertTrue(recs)
        self.assertEqual(recs[0]["_src"].archive_path, "")


class TestQuestionsAnswerableFromTheLog(unittest.TestCase):
    """The point of phase 2: the cited line must actually settle the answer.

    Attaching an evidence id to a general-knowledge question does not make it
    grounded. The earlier version asked why cmd.exe is useful to an attacker
    and cited a line that only proves cmd.exe started -- and its wording
    ("only cmd.exe is marked") contradicted the displayed list, where several
    executables carry a technique tag.
    """

    def setUp(self):
        self.lesson = build()
        self.quizzes = [
            q for s in self.lesson["stages"] for q in s["quizzes"]
        ]

    def test_single_choice_answers_appear_in_the_cited_line(self):
        checked = 0
        for quiz in self.quizzes:
            # 相関問題は「二つの記録の前後」を問うので、選択肢は 1 行から
            # 読み取る値ではない。こちらは別のテストで契約を固定する。
            if quiz.get("category") != "log-reading":
                continue
            checked += 1
            item = self.lesson["evidence"][quiz["evidenceIds"][0]]
            answer = quiz["options"][quiz["correct"]]
            self.assertIn(
                answer, item["source"]["excerpt"],
                f'{quiz["id"]}: 正解が引用行に現れない',
            )
        self.assertGreater(checked, 0)

    def test_every_distractor_also_comes_from_a_real_line(self):
        """Wrong options must be real values, not invented ones."""
        excerpts = " ".join(
            i["source"]["excerpt"] for i in self.lesson["evidence"].values()
        )
        for quiz in self.quizzes:
            if quiz.get("category") != "log-reading":
                continue
            for option in quiz["options"]:
                self.assertIn(option, excerpts, f'{quiz["id"]}: {option}')

    def test_evidence_pick_answer_is_the_cited_evidence(self):
        for quiz in self.quizzes:
            if quiz["type"] != "evidence_pick":
                continue
            chosen = quiz["options"][quiz["correct"]]["evidenceId"]
            self.assertEqual([chosen], quiz["evidenceIds"])

    def test_evidence_pick_claim_is_proved_by_the_right_field(self):
        """Not just "the name appears" — the field that proves it must say so.

        A substring check is satisfied by `cmd=` or `parentPath=`, neither of
        which establishes that the program started.
        """
        provers = {
            "q-endpoint-evidence": explain._started_program,
            "q-network-evidence": explain._proxy_client,
        }
        checked = 0
        for quiz in self.quizzes:
            if quiz["type"] != "evidence_pick":
                continue
            checked += 1
            excerpt = self.lesson["evidence"][quiz["evidenceIds"][0]]["source"]["excerpt"]
            claim = quiz["q"].split("「", 1)[-1].split(" が", 1)[0]
            proves = provers.get(quiz["id"])
            self.assertIsNotNone(proves, f'{quiz["id"]}: 検証関数が未定義')
            self.assertEqual(
                proves(excerpt), claim,
                f'{quiz["id"]}: 主張を裏付ける項目が引用行に無い',
            )
        self.assertGreater(checked, 0)

    def test_prompt_names_the_line_it_is_about(self):
        for quiz in self.quizzes:
            if quiz.get("category") != "log-reading":
                continue
            item = self.lesson["evidence"][quiz["evidenceIds"][0]]
            self.assertIn(item["source"]["member"], quiz["q"])
            self.assertIn(str(item["source"]["line"]), quiz["q"])

    def test_no_question_claims_a_unique_tag(self):
        """Several executables carry a tag, so "only X is marked" is false."""
        for quiz in self.quizzes:
            self.assertNotIn("だけに印", quiz["q"])

    def test_a_truncated_excerpt_cannot_hide_the_answer(self):
        """Regression: the excerpt cap used to cut off the field being asked about.

        Real ITM2 lines put `psPath` around character 364 and `path` around
        427, so a 400-character excerpt dropped exactly the values the
        questions needed, and those stages silently produced no questions.
        """
        for quiz in self.quizzes:
            if quiz["type"] != "single_choice":
                continue
            if quiz.get("category") != "log-reading":
                continue
            excerpt = self.lesson["evidence"][quiz["evidenceIds"][0]]["source"]["excerpt"]
            self.assertNotIn(
                "…", excerpt[: len(excerpt) - 1],
                "答えの手前で切れていないこと",
            )


class TestDisplayMatchesTheAnswer(unittest.TestCase):
    """Regression: the event list and the question must read the same field.

    The display used `path or psPath` while the question used `psPath`. In
    InfoTrace Mark II, `psPath` is the process that started and `parentPath` is
    its parent, so on a record carrying both the list said "cmd.exe started"
    while the question's answer was the parent, explorer.exe. Real data hid it:
    all 676 start records there leave `path` empty, so the fallback happened to
    agree.
    """

    def setUp(self):
        self.lesson = build()

    def test_started_program_shown_equals_the_answer(self):
        stage = next(s for s in self.lesson["stages"] if s["id"] == "endpoint")
        quiz = next(
            (q for q in stage["quizzes"] if q["id"] == "q-endpoint-01"), None
        )
        self.assertIsNotNone(quiz, "psPath の設問があること")
        answer = quiz["options"][quiz["correct"]]

        shown = [e["detail"] for e in stage["events"]]
        cited = self.lesson["evidence"][quiz["evidenceIds"][0]]
        # 設問が指す行に対応する表示行を探し、そこに正解が現れることを見る。
        matching = [d for d in shown if answer in d]
        self.assertTrue(
            matching,
            f"表示 {shown} に正解 {answer} が現れない（別フィールドを読んでいる）",
        )
        self.assertIn(answer, cited["source"]["excerpt"])

    def test_parent_path_is_not_offered_as_the_started_program(self):
        stage = next(s for s in self.lesson["stages"] if s["id"] == "endpoint")
        quiz = next(q for q in stage["quizzes"] if q["id"] == "q-endpoint-01")
        # fixture の親は explorer.exe。起動プロセスとして出してはいけない。
        self.assertNotIn("explorer.exe", quiz["options"])

    def test_display_reads_psPath_even_when_path_is_also_present(self):
        """Pin the field preference directly.

        Real logs never fill both, and the fixture above follows them, so a
        lesson-level test cannot tell `psPath or path` from `path or psPath` --
        both fall back to the same value. This record carries both, which is
        the only way to state which field the display is required to read.
        """
        line = (
            '10/05/2022 14:00:01.000 +0900 loc=en-US type=ITM2 sn=9 lv=5 evt=ps '
            'subEvt=start os=Win com="WS99" '
            'path="C:\\Windows\\explorer.exe" '
            'psPath="C:\\Windows\\System32\\cmd.exe"'
        )
        store = evidence.EvidenceStore()
        records = explain.parse_itm2(line, name=ENDPOINT_NAME)
        events = explain.events_from_itm2(records, store)
        self.assertEqual(len(events), 1)
        self.assertIn("cmd.exe", events[0]["detail"])
        self.assertNotIn("explorer.exe", events[0]["detail"])


class TestLongRealisticLines(unittest.TestCase):
    """Regression: the excerpt cap must not cut off the field being asked about.

    The short fixtures above cannot catch this — their lines fit well inside
    any cap. Real ITM2 lines run to a median of 609 characters and put the
    interesting fields late: `psPath` around character 364, `path` around 427.
    With the cap at 400 those fields were dropped, `_grounded_choice` found no
    value to ask about, and two of the three stages silently produced no
    questions at all. Only real data showed it.

    So this fixture pads the head of each line the way the real logs do.
    """

    def line(self, seq: int, exe: str) -> str:
        # 実データと同じ並び: 先頭に識別子が続き、psPath は後ろに来る。
        pad = (
            f'tmid=f02cca14-4aae-402b-a8d9-2a287395709{seq} '
            'csid=S-1-5-21-1720067203-2924128797-2708492278 '
            'ip=172.16.2.101,fe80::74c9:7795:eb11:ce0 mac=06:00:f2:4b:34:cd '
            'rcCom="WS02" rcIP=192.0.2.10 usr="tester" usrDomain="EXAMPLE" '
            'sessionID=2 psGUID={9B28000B-0000-0000-0000-00000000000' + str(seq) + '} '
        )
        return (
            f'10/05/2022 14:0{seq}:00.000 +0900 loc=en-US type=ITM2 sn={seq} lv=5 '
            f'evt=ps subEvt=start os=Win com="WS9{seq}" domain="EXAMPLE" '
            f'profile="fixture" {pad}psPath="C:\\Windows\\System32\\{exe}" '
            f'cmd="{exe} --flag"'
        )

    def setUp(self):
        exes = ["cmd.exe", "powershell.exe", "whoami.exe", "net.exe"]
        text = "\n".join(self.line(i, e) for i, e in enumerate(exes))
        self.text = text
        self.lesson = explain.build_lesson(
            "t", {ENDPOINT_NAME: text}, "gen-long"
        )

    def test_the_fixture_really_is_long_enough_to_matter(self):
        """Pin the premise, so this test cannot pass for the wrong reason."""
        first = self.text.split("\n")[0]
        self.assertGreater(first.index("psPath="), 400, first.index("psPath="))
        self.assertGreater(len(first), 400)

    def test_the_question_about_the_late_field_survives(self):
        """Specifically the psPath question.

        Asserting only that SOME question exists is not enough: `com` sits near
        the start of the line and survives any cap, so a truncated excerpt
        still leaves that one standing while the psPath question disappears.
        """
        self.assertIsNotNone(self.lesson)
        ids = {q["id"] for s in self.lesson["stages"] for q in s["quizzes"]}
        self.assertIn("q-endpoint-01", ids, f"psPath の設問が落ちている: {ids}")

    def test_the_answer_survives_in_the_excerpt(self):
        """値を選ばせる設問は、正解がそのまま抜粋に残っていること。

        手法を選ぶ設問（`attck`）と、言えることを選ぶ設問（`limits`）は
        選択肢が文章なので、ここでは対象外。そちらは
        `test_report.TestAttckFromStoredExcerpt` が、抜粋から同じ判定を
        引き直せることで確かめている。
        """
        checked = 0
        for stage in self.lesson["stages"]:
            for quiz in stage["quizzes"]:
                if quiz["type"] != "single_choice":
                    continue
                if quiz["category"] not in ("log-reading", "evidence"):
                    continue
                item = self.lesson["evidence"][quiz["evidenceIds"][0]]
                self.assertIn(
                    quiz["options"][quiz["correct"]], item["source"]["excerpt"]
                )
                checked += 1
        self.assertTrue(checked, "値を問う設問が 1 つも無く、検査が空回りしている")

    def test_excerpt_cap_still_applies(self):
        for item in self.lesson["evidence"].values():
            self.assertLessEqual(
                len(item["source"]["excerpt"]), evidence.MAX_EXCERPT + 1
            )


class TestEvidenceApiBehaviour(unittest.TestCase):
    """The endpoint itself, not just its route pattern."""

    def setUp(self):
        import tempfile

        import api
        from store import Store

        self.tmp = tempfile.mkdtemp()
        self.store = Store(os.path.join(self.tmp, "m.sqlite3"))
        self.lesson = build()
        self.store.save_lesson(self.lesson, "fixture")
        self.ident = next(iter(self.lesson["evidence"]))

        class FakeState:
            store = self.store

        self._saved = api.STATE
        api.STATE = FakeState()
        self.api = api
        self.handler = api.Handler.__new__(api.Handler)
        self.sent = []
        self.handler._json = lambda obj, code=200: self.sent.append((code, obj))
        self.handler._error = lambda code, msg: self.sent.append((code, {"error": msg}))

    def tearDown(self):
        self.api.STATE = self._saved
        self.store.close()

    def call(self, lesson_id, evidence_id):
        self.sent.clear()
        self.api.Handler.h_evidence(self.handler, lesson_id, evidence_id)
        return self.sent[0]

    def test_returns_an_existing_piece_of_evidence(self):
        code, body = self.call("gen-test", self.ident)
        self.assertEqual(code, 200)
        self.assertEqual(body["id"], self.ident)
        self.assertIn("excerpt", body["source"])
        self.assertGreaterEqual(body["source"]["line"], 1)

    def test_missing_lesson_is_404(self):
        code, body = self.call("gen-nope", self.ident)
        self.assertEqual(code, 404)
        self.assertIn("演習", body["error"])

    def test_missing_evidence_is_404(self):
        code, body = self.call("gen-test", "ev-" + "0" * 24)
        self.assertEqual(code, 404)
        self.assertIn("証拠", body["error"])

    def test_response_fields_are_an_explicit_allowlist(self):
        """An internal field added later must not leak through by default."""
        stored = self.store.lesson("gen-test")
        stored["evidence"][self.ident]["_internal"] = "秘密の値"
        self.store.save_lesson(stored, "fixture")
        code, body = self.call("gen-test", self.ident)
        self.assertEqual(code, 200)
        self.assertEqual(set(body), {"id", "kind", "confidence", "source"})
        self.assertEqual(
            set(body["source"]), {"archivePath", "member", "line", "excerpt"}
        )
        self.assertNotIn("秘密の値", repr(body))

    def test_no_local_path_or_whole_log_is_returned(self):
        code, body = self.call("gen-test", self.ident)
        blob = repr(body)
        self.assertNotIn("/Users/", blob)
        self.assertNotIn(os.getcwd(), blob)
        # 抜粋は 1 行ぶん。ログ全体ではない。
        self.assertLessEqual(len(body["source"]["excerpt"]), evidence.MAX_EXCERPT + 1)
        self.assertNotIn("\n", body["source"]["excerpt"])


class TestEvidenceRoute(unittest.TestCase):
    def route(self):
        matches = [r for r in ROUTES if "evidence" in r.pattern.pattern]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_declares_a_capability(self):
        self.assertIn(self.route().capability, vars(Capability).values())

    def test_is_read_only_for_students(self):
        self.assertEqual(self.route().capability, Capability.READ)
        self.assertIn(Capability.READ, ROLE_CAPS["student"])

    def test_ids_are_bounded_and_anchored(self):
        pattern = self.route().pattern
        self.assertIsNotNone(
            pattern.fullmatch("/api/lessons/gen-4/evidence/ev-" + "a" * 24)
        )
        # Anything that is not a bounded id must not match.
        for bad in (
            "/api/lessons/gen-4/evidence/../../etc/passwd",
            "/api/lessons/gen-4/evidence/ev-ZZZZZZZZ",
            "/api/lessons/gen-4/evidence/notanid",
            "/api/lessons/" + "x" * 80 + "/evidence/ev-" + "a" * 24,
            "/api/lessons/gen-4/evidence/ev-" + "a" * 80,
            "/api/lessons/gen-4/evidence/ev-abc",
        ):
            self.assertIsNone(pattern.fullmatch(bad), bad)

    def test_neither_id_can_carry_a_path_separator(self):
        """A captured id must never be able to spell a path.

        Checked by matching, not by reading the pattern text: the literal
        `/evidence/` in the middle is a separator, so inspecting the source
        string is easy to get wrong.
        """
        pattern = self.route().pattern
        for bad in (
            "/api/lessons/gen%2F4/evidence/ev-" + "a" * 24,
            "/api/lessons/a/b/evidence/ev-" + "a" * 24,
            "/api/lessons/gen-4/evidence/ev-" + "a" * 12 + "/x",
            "/api/lessons/gen-4/evidence/ev-aaaaaaaa/../ev-bbbbbbbb",
        ):
            self.assertIsNone(pattern.fullmatch(bad), bad)

        match = pattern.fullmatch(
            "/api/lessons/gen-4/evidence/ev-" + "a" * 24
        )
        for group in match.groups():
            self.assertNotIn("/", group)
            self.assertNotIn("..", group)


if __name__ == "__main__":
    unittest.main()
