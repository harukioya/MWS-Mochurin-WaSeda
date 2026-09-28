"""GZF の確認・抽出 JSON の検証・静的教材の組み立てのテスト。

実データは使わない。GZF は Ghidra と同じ並びで組んだ擬似ファイル、抽出結果は
架空の小さなゲームを模した JSON（ghidra_fixtures）。
"""

import copy
import io
import json
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ghidra_fixtures as fx  # noqa: E402
import gzf  # noqa: E402
import static_facts as sf  # noqa: E402
import static_lesson as sl  # noqa: E402


def inspect(data: bytes):
    return gzf.inspect_file(io.BytesIO(data), len(data))


class TestGzfHeader(unittest.TestCase):
    def test_a_well_formed_program_gzf_is_accepted(self):
        header = inspect(fx.make_gzf(name="termmines"))
        self.assertEqual(header.content_type, "Program")
        self.assertEqual(header.item_name, "termmines")

    def test_an_executable_renamed_to_gzf_is_refused(self):
        for head in (b"MZ\x90\x00" + b"\x00" * 200, b"\x7fELF" + b"\x00" * 200,
                     b"PK\x03\x04" + b"\x00" * 200):
            with self.subTest(head=head[:4]):
                with self.assertRaises(gzf.NotGzf) as ctx:
                    inspect(head)
                self.assertEqual(ctx.exception.code, "not-gzf")

    def test_java_serialization_without_the_ghidra_magic_is_refused(self):
        with self.assertRaises(gzf.NotGzf) as ctx:
            inspect(fx.make_gzf(magic=0x1122334455667788))
        self.assertEqual(ctx.exception.code, "not-gzf")

    def test_non_program_content_is_refused(self):
        with self.assertRaises(gzf.NotGzf) as ctx:
            inspect(fx.make_gzf(content_type="Archive"))
        self.assertEqual(ctx.exception.code, "not-program")

    def test_unknown_packed_format_version_is_refused(self):
        with self.assertRaises(gzf.NotGzf) as ctx:
            inspect(fx.make_gzf(version=2))
        self.assertEqual(ctx.exception.code, "version-unsupported")

    def test_declared_size_over_the_limit_is_refused_before_expanding(self):
        with self.assertRaises(gzf.NotGzf) as ctx:
            inspect(fx.make_gzf(declared=gzf.MAX_UNPACKED_BYTES + 1))
        self.assertEqual(ctx.exception.code, "too-large-unpacked")

    def test_content_longer_than_declared_is_refused(self):
        with self.assertRaises(gzf.NotGzf):
            inspect(fx.make_gzf(content=b"a" * 5000, declared=4000))

    def test_content_shorter_than_declared_is_refused(self):
        with self.assertRaises(gzf.NotGzf):
            inspect(fx.make_gzf(content=b"a" * 3000, declared=4000))

    def test_crc_mismatch_is_refused(self):
        with self.assertRaises(gzf.NotGzf) as ctx:
            inspect(fx.make_gzf(crc=0x12345678))
        self.assertEqual(ctx.exception.code, "crc")

    def test_truncated_file_is_refused(self):
        data = fx.make_gzf()
        for cut in (10, 40, len(data) // 2, len(data) - 20):
            with self.subTest(cut=cut):
                with self.assertRaises(gzf.NotGzf):
                    inspect(data[:cut])

    def test_extreme_compression_ratio_is_refused(self):
        with self.assertRaises(gzf.NotGzf) as ctx:
            inspect(fx.make_gzf(content=b"\x00" * (8 * 1024 * 1024)))
        self.assertEqual(ctx.exception.code, "ratio")

    def test_empty_and_oversized_files_are_refused(self):
        with self.assertRaises(gzf.NotGzf) as ctx:
            gzf.inspect_file(io.BytesIO(b""), 0)
        self.assertEqual(ctx.exception.code, "empty")
        with self.assertRaises(gzf.NotGzf) as ctx:
            gzf.inspect_file(io.BytesIO(b"x"), gzf.MAX_GZF_BYTES + 1)
        self.assertEqual(ctx.exception.code, "too-large")


def parse(raw: bytes, sha: str = fx.PROGRAM_SHA):
    return sf.parse(raw, expected_sha256=sha, expected_ghidra="12.1.4",
                    expected_script="1.0.0")


class TestFactsContract(unittest.TestCase):
    def mutate(self, fn):
        doc = fx.facts_doc()
        fn(doc)
        return json.dumps(doc).encode()

    def assertRefused(self, raw, code="output-invalid"):
        with self.assertRaises(sf.FactsInvalid) as ctx:
            parse(raw)
        self.assertEqual(ctx.exception.code, code, ctx.exception)

    def test_the_fixture_is_accepted(self):
        facts = parse(fx.facts_bytes())
        self.assertEqual(len(facts.functions), 7)
        self.assertEqual(facts.counts()["indirectCalls"], 2)

    def test_input_hash_must_match_the_copied_file(self):
        self.assertRefused(fx.facts_bytes(sha="ef" * 32), "hash-mismatch")

    def test_stored_executable_hash_is_kept_apart_from_the_input_hash(self):
        facts = parse(fx.facts_bytes())
        self.assertEqual(facts.program["storedExecutableSha256"], "cd" * 32)
        self.assertNotEqual(facts.program["storedExecutableSha256"], facts.input_sha256)

    def test_unknown_schema_is_refused(self):
        self.assertRefused(self.mutate(lambda d: d.update(schemaVersion="mws-ghidra-static/2")),
                           "schema-unsupported")

    def test_partial_output_is_refused(self):
        raw = fx.facts_bytes()
        self.assertRefused(raw[: len(raw) // 2])
        self.assertRefused(self.mutate(lambda d: d.pop("end")), "output-incomplete")
        self.assertRefused(b"", "output-missing")

    def test_tool_versions_must_match_the_pinned_ones(self):
        self.assertRefused(self.mutate(lambda d: d["tool"].update(ghidraVersion="11.0")),
                           "tool-mismatch")
        self.assertRefused(self.mutate(lambda d: d["tool"].update(scriptVersion="9")),
                           "tool-mismatch")

    def test_unknown_or_missing_keys_are_refused(self):
        self.assertRefused(self.mutate(lambda d: d.update(extra=1)))
        self.assertRefused(self.mutate(lambda d: d["functions"][0].update(comment="x")))
        self.assertRefused(self.mutate(lambda d: d["strings"][0].pop("value")))

    def test_type_violations_are_refused(self):
        self.assertRefused(self.mutate(lambda d: d["functions"][0].update(thunk=1)))
        self.assertRefused(self.mutate(lambda d: d["callStats"].update(indirect=True)))
        self.assertRefused(self.mutate(lambda d: d["strings"][0].update(value=5)))
        self.assertRefused(self.mutate(lambda d: d["program"].update(analyzed="yes")))

    def test_overlong_fields_and_too_many_items_are_refused(self):
        self.assertRefused(self.mutate(lambda d: d["functions"][0].update(name="x" * 257)))
        self.assertRefused(self.mutate(
            lambda d: d.update(functions=d["functions"] * (sf.MAX_FUNCTIONS // 7 + 1))))

    def test_duplicate_ids_are_refused(self):
        self.assertRefused(self.mutate(lambda d: d["functions"].append(d["functions"][2])))
        self.assertRefused(self.mutate(lambda d: d["strings"].append(d["strings"][0])))

    def test_id_must_agree_with_address(self):
        def bad(d):
            d["functions"][2]["id"] = "fn:ram:00000000deadbeef"
        self.assertRefused(self.mutate(bad))

    def test_bad_address_format_is_refused(self):
        def bad(d):
            d["strings"][0]["address"] = "ram:0x102000"
            d["strings"][0]["id"] = "str:ram:0x102000"
        self.assertRefused(self.mutate(bad))

    def test_references_to_missing_records_are_refused(self):
        self.assertRefused(self.mutate(
            lambda d: d["stringRefs"][0].update(string="str:ram:00000000000fffff")))
        self.assertRefused(self.mutate(
            lambda d: d["stringRefs"][0].update(function="fn:ram:00000000000fffff")))
        self.assertRefused(self.mutate(
            lambda d: d["calls"][0].update(target="fn:ram:00000000000fffff")))

    def test_call_target_address_must_match_the_target(self):
        self.assertRefused(self.mutate(
            lambda d: d["calls"][0].update(targetAddress="ram:0000000000101200")))

    def test_resolved_target_must_match_the_thunk(self):
        self.assertRefused(self.mutate(
            lambda d: d["calls"][3].update(resolvedTarget="ext:EXTERNAL:0000000000000018")))

    def test_string_length_must_agree_with_clipping(self):
        self.assertRefused(self.mutate(lambda d: d["strings"][0].update(length=2)))
        self.assertRefused(self.mutate(lambda d: d["strings"][0].update(clipped=True)))

    def test_lengths_are_counted_in_utf16_units_like_java(self):
        """😀 は Java では 2、Python の len() では 1。正常な文字列を拒否しない。"""
        for value in ("😀 ok", "𠮷野家", "a\U0001F600b" * 3):
            with self.subTest(value=value):
                units = sf.utf16_len(value)
                facts = parse(self.mutate(
                    lambda d: d["strings"][0].update(value=value, length=units)))
                self.assertEqual(facts.strings["str:ram:0000000000102000"]["value"], value)
        # 切り詰めた場合（Java の上限 512 単位。ペアの途中では切らない）。
        full = "😀" * 300                      # 600 単位
        clipped = "😀" * 256                   # 512 単位
        facts = parse(self.mutate(lambda d: d["strings"][0].update(
            value=clipped, length=sf.utf16_len(full), clipped=True)))
        self.assertTrue(facts.strings["str:ram:0000000000102000"]["clipped"])
        # 単位を取り違えた長さは、引き続き不整合として断る。
        self.assertRefused(self.mutate(
            lambda d: d["strings"][0].update(value="😀 ok", length=len("😀 ok"))))
        # 上限を UTF-16 の単位で超える値は断る。
        self.assertRefused(self.mutate(lambda d: d["strings"][0].update(
            value="😀" * 257, length=514, clipped=False)))

    def test_unknown_truncation_marker_is_refused(self):
        self.assertRefused(self.mutate(lambda d: d.update(truncated=["everything"])))

    def test_truncated_but_consistent_output_is_accepted(self):
        """抽出側が打ち切った場合の形（一覧の外は参照しない）を受け入れる。

        関数一覧を打ち切ったとき、抽出スクリプトは一覧に無い関数を参照元・
        呼び出し先・thunk の行き先として書かない。その形の出力を、整合性
        検査が拒否しないことを確かめる。
        """
        def cut(d):
            d["functions"] = [f for f in d["functions"] if f["name"] != "print_usage"]
            d["functions"][1]["thunkTarget"] = None          # 行き先の外部関数も打ち切り
            d["externals"] = [e for e in d["externals"] if e["name"] != "printf"]
            gone = "fn:ram:0000000000101180"
            d["stringRefs"] = [r for r in d["stringRefs"] if r["function"] != gone]
            d["calls"] = [c for c in d["calls"] if c["target"] != gone]
            for c in d["calls"]:
                if c["resolvedTarget"]:
                    c["resolvedTarget"] = None
            d["truncated"] = ["functions", "externals", "stringRefs", "calls"]
        facts = parse(self.mutate(cut))
        self.assertEqual(facts.truncated, ["functions", "externals", "stringRefs", "calls"])
        _, lesson = build(json.loads(self.mutate(cut)))
        topics = [u["topic"] for u in lesson["report"]["unknowns"]]
        self.assertIn("抽出の打ち切り", topics)

    def test_truncated_references_block_string_questions(self):
        """参照の一覧が欠けていると、残った参照だけでは正解が一つだと言えない。

        対照: 打ち切られていない出力から作った設問に、省略されていた参照
        （同じ命令から誤答の文字列へ）を戻すと、その設問は検証に落ちる。
        打ち切られた出力では、そもそも文字列の設問を作らず、検証も通さない。
        """
        facts, lesson = build()
        q = next(q for q in quizzes(lesson) if q["category"] == "static-string")
        wrong = [i for n, i in enumerate(q["optionIds"]) if n != q["correct"]][0]
        chk = q["answerCheck"]

        def add_back(d):
            d["stringRefs"].append({"from": chk["from"], "function": chk["function"],
                                    "string": wrong, "instruction": "LEA RDI,[x]",
                                    "refType": "DATA"})
        self.assertFalse(sl.verify_quiz(parse(self.mutate(add_back)), q))

        def cut(d):
            d["truncated"] = ["stringRefs"]
        truncated = parse(self.mutate(cut))
        self.assertFalse(sl.verify_quiz(truncated, q), "the gate itself refuses it")
        _, lesson = build(json.loads(self.mutate(cut)))
        self.assertFalse(any(x["category"] == "static-string" for x in quizzes(lesson)))
        self.assertTrue(any("参照の一覧が上限で打ち切られている" in r
                            for r in lesson["static"]["skipped"]))
        # 参照に関わらない種類は作れる。
        self.assertTrue(any(x["category"] == "static-call" for x in quizzes(lesson)))

    def test_truncated_function_lists_block_external_questions(self):
        for marker in ("externals", "functions"):
            with self.subTest(marker=marker):
                raw = self.mutate(lambda d: d.update(truncated=[marker]))
                facts = parse(raw)
                _, lesson = build(json.loads(raw))
                self.assertFalse(any(x["category"] == "static-external"
                                     for x in quizzes(lesson)))
                _, full = build()
                q = next(x for x in quizzes(full) if x["category"] == "static-external")
                self.assertFalse(sl.verify_quiz(facts, q))

    def test_truncation_is_carried_not_hidden(self):
        facts = parse(self.mutate(lambda d: d.update(truncated=["calls"])))
        self.assertEqual(facts.truncated, ["calls"])

    def test_oversized_output_is_refused_before_parsing(self):
        self.assertRefused(b" " * (sf.MAX_JSON_BYTES + 1), "output-too-large")


def build(doc=None, **kw):
    raw = json.dumps(doc).encode() if doc is not None else fx.facts_bytes()
    facts = parse(raw)
    return facts, sl.build(facts, image={"imageRef": "img"}, origin={"kind": "upload",
                                                                        "name": "a.gzf"}, **kw)


def quizzes(lesson):
    return [q for s in lesson["stages"] for q in s["quizzes"]]


class TestStaticLesson(unittest.TestCase):
    def test_all_three_kinds_are_generated_and_verified(self):
        facts, lesson = build()
        kinds = {q["category"] for q in quizzes(lesson)}
        self.assertEqual(kinds, {"static-string", "static-call", "static-external"})
        for q in quizzes(lesson):
            with self.subTest(q=q["id"]):
                self.assertTrue(sl.verify_quiz(facts, q))
                self.assertEqual(len(q["options"]), 4)
                self.assertEqual(len(set(q["options"])), 4, "options must be distinct")

    def test_generation_is_deterministic(self):
        _, a = build()
        _, b = build()
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))
        self.assertEqual(a["id"], sl.lesson_id(fx.PROGRAM_SHA))

    def test_same_text_elsewhere_is_never_a_distractor(self):
        """main が参照する「Usage: %s」と同じ中身の別の文字列は、誤答に使わない。

        誤答に使うと、同じ文字列が二つの選択肢に現れ、正解が一意でなくなる。
        """
        facts, lesson = build()
        for q in quizzes(lesson):
            if q["category"] != "static-string":
                continue
            fn = q["answerCheck"]["function"]
            used = {facts.strings[r["string"]]["value"] for r in facts.string_refs
                    if r["function"] == fn}
            for n, sid in enumerate(q["optionIds"]):
                if n != q["correct"]:
                    self.assertNotIn(facts.strings[sid]["value"], used)

    def test_verify_rejects_a_wrong_answer_key(self):
        facts, lesson = build()
        for q in quizzes(lesson):
            with self.subTest(q=q["id"]):
                bad = copy.deepcopy(q)
                bad["correct"] = (q["correct"] + 1) % len(q["options"])
                self.assertFalse(sl.verify_quiz(facts, bad))

    def test_verify_rejects_a_same_name_substitute(self):
        """同じ中身の文字列を正解の位置に置いても、参照関係が無ければ通らない。"""
        facts, _ = build()
        a = "ram:00000000001"
        quiz = {
            "answerCheck": {"kind": "string-ref", "function": "fn:" + a + "01200",
                            "from": a + "01210", "string": "str:" + a + "02000"},
            "optionIds": ["str:" + a + "02000", "str:" + a + "02020",
                          "str:" + a + "02040", "str:" + a + "02060"],
            "options": ["a", "b", "c", "d"],
            "correct": 0,
        }
        self.assertTrue(sl.verify_quiz(facts, quiz), "control: the real reference passes")
        twin = copy.deepcopy(quiz)
        twin["optionIds"][0] = "str:" + a + "02030"   # 中身は同じ「Usage: %s」
        self.assertFalse(sl.verify_quiz(facts, twin))

    def test_indirect_and_thunk_calls_are_not_asked_as_direct_calls(self):
        _, lesson = build()
        for q in quizzes(lesson):
            if q["category"] == "static-call":
                self.assertNotEqual(q["answerCheck"]["from"], "ram:0000000000101240",
                                    "call through a thunk is not a direct call to a program function")

    def test_long_or_clipped_strings_are_not_used(self):
        doc = fx.facts_doc()
        for s in doc["strings"]:
            s["value"] = s["value"] + "x" * 80
            s["length"] = len(s["value"])
        facts, lesson = build(doc)
        self.assertFalse(any(q["category"] == "static-string" for q in quizzes(lesson)))
        self.assertTrue(any("文字列参照" in r for r in lesson["static"]["skipped"]))

    def test_instructions_at_the_clip_limit_are_not_used(self):
        doc = fx.facts_doc()
        for c in doc["calls"]:
            c["instruction"] = "C" * 159 + "X"
        _, lesson = build(doc)
        self.assertFalse(any(q["category"] == "static-call" for q in quizzes(lesson)))

    def test_fewer_questions_are_reported_not_hidden(self):
        doc = fx.facts_doc()
        doc["externals"] = []
        doc["functions"][1]["thunk"] = False
        doc["functions"][1]["thunkTarget"] = None
        doc["calls"] = [c for c in doc["calls"] if c["resolvedTarget"] is None]
        _, lesson = build(doc)
        self.assertEqual(lesson["static"]["questionCounts"]["external"], 0)
        topics = [u["topic"] for u in lesson["report"]["unknowns"]]
        self.assertIn("作れなかった設問", topics)

    def test_zero_questions_is_a_reasoned_failure(self):
        doc = fx.facts_doc(stringRefs=[], calls=[], externals=[])
        doc["functions"][1]["thunk"] = False
        doc["functions"][1]["thunkTarget"] = None
        with self.assertRaises(sl.NoQuestions) as ctx:
            build(doc)
        self.assertGreaterEqual(len(ctx.exception.reasons), 3)

    def test_unanalyzed_gzf_is_refused_not_reanalyzed(self):
        doc = fx.facts_doc()
        doc["program"]["analyzed"] = False
        with self.assertRaises(sl.NoQuestions) as ctx:
            build(doc)
        self.assertIn("自動再解析は行わない", ctx.exception.reasons[0])

    def test_no_fake_log_events_and_no_attck(self):
        _, lesson = build()
        self.assertEqual(lesson["kind"], "static")
        self.assertEqual(lesson["report"]["timeline"], [])
        self.assertEqual(lesson["report"]["techniques"], [])
        text = json.dumps(lesson, ensure_ascii=False)
        for banned in ('"timestamp"', '"host"', '"attck"'):
            self.assertNotIn(banned, text)
        for ev in lesson["evidence"].values():
            self.assertEqual(ev["evidenceType"], "static")
            self.assertNotIn("line", ev["source"])
            self.assertNotIn("member", ev["source"])

    def test_every_cited_evidence_exists_and_is_shown_in_its_stage(self):
        _, lesson = build()
        for stage in lesson["stages"]:
            shown = {i for e in stage["events"] for i in e["evidenceIds"]}
            for q in stage["quizzes"]:
                for i in q["evidenceIds"] + q["subjectEvidenceIds"]:
                    self.assertIn(i, lesson["evidence"])
                    self.assertIn(i, shown, "jump target must be on the stage")

    def test_the_answer_is_not_given_away_before_answering(self):
        """解答前に見せる対象の記録（命令）には、正解の名前や文字列を書かない。"""
        _, lesson = build()
        for q in quizzes(lesson):
            answer = q["options"][q["correct"]].strip("「」")
            for i in q["subjectEvidenceIds"]:
                src = lesson["evidence"][i]["source"]
                self.assertNotIn(answer, src["instruction"] or "")
                self.assertNotIn(answer, src["reference"] or "")

    def test_staged_hints_are_present(self):
        _, lesson = build()
        for q in quizzes(lesson):
            self.assertGreaterEqual(len(q["hints"]), 2)

    def test_control_and_bidi_characters_from_the_gzf_are_made_visible(self):
        doc = fx.facts_doc()
        doc["program"]["name"] = "evil‮gnp.exe"
        doc["functions"][6]["name"] = "ma\u0000in"
        _, lesson = build(doc)
        text = json.dumps(lesson, ensure_ascii=False)
        self.assertNotIn("‮", text)
        self.assertIn("<U+202E>", lesson["title"])

    def test_limits_are_stated(self):
        _, lesson = build()
        topics = " ".join(u["topic"] for u in lesson["report"]["unknowns"])
        self.assertIn("実行はしていません", topics)
        self.assertIn("呼び出し命令と実際の呼び出し", topics)
        details = " ".join(u["detail"] for u in lesson["report"]["unknowns"])
        self.assertIn("間接呼び出し 2 件", details)

    def test_sample_provenance_is_carried(self):
        _, lesson = build(sample={"name": "termmines", "note": "ゲームです"})
        self.assertEqual(lesson["static"]["sample"]["name"], "termmines")

    def test_show_addr(self):
        self.assertEqual(sl.show_addr("ram:0000000000101234"), "ram:00101234")
        self.assertEqual(sl.show_addr("EXTERNAL:0000000000000010"), "EXTERNAL:00000010")
        self.assertEqual(sl.show_addr("ram:0000000123456789a"[:4] + "000000123456789a"),
                         "ram:123456789a")


class TestRealSampleExtraction(unittest.TestCase):
    """同梱サンプル termmines を、実コンテナで抽出した出力（事前抽出）での回帰。

    fixtures/ghidra/termmines-facts.json は ghidra_live_check.py --save-fixture が
    Ghidra 12.1.4 の実出力をそのまま保存したもの。本物の GZF → Docker → 教材の
    受け入れ確認の代わりにはしない（それは ghidra_live_check.py で行う）。
    """

    HERE = os.path.dirname(os.path.abspath(__file__))
    REPO = os.path.dirname(os.path.dirname(HERE))

    def setUp(self):
        path = os.path.join(self.HERE, "fixtures", "ghidra", "termmines-facts.json")
        with open(path, encoding="utf-8") as fh:
            self.saved = json.load(fh)
        with open(os.path.join(self.REPO, "ghidra", "sample", "sample.json"),
                  encoding="utf-8") as fh:
            self.sample = json.load(fh)
        doc = self.saved["facts"]
        self.facts = sf.parse(json.dumps(doc).encode(),
                              expected_sha256=doc["input"]["sha256"],
                              expected_ghidra="12.1.4", expected_script="1.0.0")

    def test_the_real_output_satisfies_the_contract(self):
        self.assertEqual(self.facts.truncated, [])
        self.assertTrue(self.facts.program["analyzed"])

    def test_fixture_matches_the_bundled_sample(self):
        self.assertEqual(self.facts.input_sha256, self.sample["sha256"],
                         "re-run ghidra_live_check.py --save-fixture after rebuilding the sample")
        # GZF に Ghidra が保存した元の実行ファイルのハッシュは、コンパイル結果の実物と一致する。
        # 入力 GZF のハッシュとは別の値である。
        self.assertEqual(self.facts.program["storedExecutableSha256"],
                         self.sample["executableSha256"])
        self.assertNotEqual(self.facts.program["storedExecutableSha256"], self.facts.input_sha256)

    def test_all_three_question_kinds_are_generated_and_verified(self):
        lesson = sl.build(self.facts, image={}, origin={"kind": "sample", "name": "termmines"},
                          sample={"name": "termmines"})
        counts = lesson["static"]["questionCounts"]
        self.assertTrue(all(counts[k] >= 1 for k in ("string", "call", "external")), counts)
        for q in quizzes(lesson):
            self.assertTrue(sl.verify_quiz(self.facts, q), q["id"])


class TestUiFixtureIsCurrent(unittest.TestCase):
    """画面テストの固定データが、今のビルダーの出力と一致していること。"""

    def test_fixture_matches_the_builder(self):
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, fx.LESSON_FIXTURE), encoding="utf-8") as fh:
            stored = json.load(fh)
        self.assertEqual(stored, json.loads(json.dumps(fx.static_lesson())),
                         "python3 backend/tests/ghidra_fixtures.py で作り直してください")


if __name__ == "__main__":
    unittest.main(verbosity=2)
