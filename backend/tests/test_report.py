"""Tests for phase 3: timestamps, correlation, grounded ATT&CK, final report.

NO REAL CONTEST DATA. Invented hostnames, RFC 5737 documentation addresses,
harmless commands, built at run time.

The claims this file pins down are the ones a learner would be misled by if
they broke: that the timeline says "recorded in this order" and not "happened
because of", that a correlation question really rests on two records, and that
every ATT&CK tag can say why it is there and which line says so.
"""

import json
import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import attck  # noqa: E402
import evidence  # noqa: E402
import explain  # noqa: E402
import timeline  # noqa: E402
from parsers import InputSource  # noqa: E402
from parsers import itm2 as itm2_fmt  # noqa: E402
from parsers import proxy as proxy_fmt  # noqa: E402

#: このファイルの入力は、どれも「その形式の記録だ」と分かっているログ。
#: Proxy は内容だけでは形式を言い切れない（Web サーバーのログと同じ形）ので
#: 自動判定に参加しない。本番でプロファイルが `parsers` に明示するのと同じく、
#: ここでも明示して読む。
KNOWN_FORMATS = ["itm2", "proxy"]


def build_lesson(name, sources, lesson_id, parser_ids=None, **kwargs):
    return explain.build_lesson(name, sources, lesson_id,
                                parser_ids=KNOWN_FORMATS if parser_ids is None else parser_ids,
                                **kwargs)


ENDPOINT = "example-incident/evidence/logs.zip :: logs/ws99.log"
SECOND = "example-incident/evidence/logs.zip :: logs/dc01.log"
PROXY_NAME = "example-incident/evidence/logs.zip :: logs/proxy01.log"


def parse_itm2(text: str, name: str = ""):
    """ITM2 パーサーの正規化イベント。相関の候補や事象はここから作る。"""
    return itm2_fmt.PARSER.parse(InputSource(name, text), None)


def parse_proxy(text: str, name: str = ""):
    return proxy_fmt.PARSER.parse(InputSource(name, text), None)


def attck_from_excerpt(excerpt: str, ids: list):
    """保存済みの抜粋から、ITM2 の読み方で ATT&CK を引き直す。"""
    reader = itm2_fmt.PARSER
    return attck.for_process(
        reader.reread("process", "program_name", excerpt),
        reader.reread("process", "command_line", excerpt),
        ids,
    )


def itm2(ts, host, evt="ps", sub="start", **fields) -> str:
    extra = " ".join(f'{k}="{v}"' for k, v in fields.items())
    return (
        f'{ts} loc=en-US type=ITM2 sn=1 lv=5 evt={evt} subEvt={sub} os=Win '
        f'com="{host}" {extra}'
    )


def proxy(ts, ip, method="GET", target="http://198.51.100.23/a") -> str:
    return f'{ip} - - [{ts}] "{method} {target} HTTP/1.1" 200 42'


#: 2 台、複数種別、時刻あり。相関と時系列を作れる最小の形。
RICH_ENDPOINT = "\n".join([
    itm2("10/05/2022 14:00:01.000 +0900", "WS99",
         psPath="C:\\Windows\\System32\\cmd.exe"),
    itm2("10/05/2022 14:00:05.500 +0900", "WS99", evt="file", sub="create",
         path="C:\\Users\\test\\AppData\\demo.dat"),
    itm2("10/05/2022 14:00:09.000 +0900", "WS99",
         psPath="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
    itm2("10/05/2022 14:00:11.000 +0900", "DC01",
         psPath="C:\\Windows\\System32\\whoami.exe"),
    itm2("10/05/2022 14:00:12.000 +0900", "DC01", evt="reg", sub="setVal",
         path="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Demo"),
])
RICH_PROXY = "\n".join([
    proxy("05/Oct/2022:14:00:07 +0900", "192.0.2.10"),
    proxy("05/Oct/2022:14:00:08 +0900", "192.0.2.11", method="POST"),
])


def rich_sources() -> dict:
    return {ENDPOINT: RICH_ENDPOINT, PROXY_NAME: RICH_PROXY}


def build(sources=None) -> dict:
    lesson = build_lesson("t", sources or rich_sources(), "gen-rich")
    assert lesson is not None
    return lesson


class TestStampParsing(unittest.TestCase):
    def test_itm2_timestamp_is_kept_verbatim(self):
        """No timezone rewriting: the screen must match the log."""
        stamp = itm2_fmt.parse_timestamp("10/05/2022 14:00:27.738 +0900 rest")
        self.assertTrue(stamp.known)
        self.assertEqual(stamp.display, "10/05/2022 14:00:27.738 +0900")
        self.assertIn("14:00:27", stamp.display)

    def test_proxy_timestamp_is_kept_verbatim(self):
        stamp = proxy_fmt.parse_timestamp("05/Oct/2022:14:00:07 +0900")
        self.assertTrue(stamp.known)
        self.assertEqual(stamp.display, "05/Oct/2022:14:00:07 +0900")

    def test_unparseable_timestamp_is_kept_as_unknown(self):
        """Dropping the record would make it disappear from the investigation."""
        for bad in ("", "not a time", "13/45/2022 99:99:99", None):
            stamp = itm2_fmt.parse_timestamp(bad)
            self.assertFalse(stamp.known)
            self.assertEqual(stamp.display, timeline.UNKNOWN_LABEL)

    def test_unknown_sorts_last(self):
        known = {"_stamp": itm2_fmt.parse_timestamp("10/05/2022 14:00:01.000 +0900")}
        unknown = {"_stamp": timeline.UNKNOWN}
        self.assertLess(timeline.order_key(known), timeline.order_key(unknown))

    def test_fraction_is_honoured(self):
        early = itm2_fmt.parse_timestamp("10/05/2022 14:00:01.100 +0900")
        late = itm2_fmt.parse_timestamp("10/05/2022 14:00:01.900 +0900")
        self.assertLess(early.sort, late.sort)

    def test_timezone_offset_is_applied_for_comparison_only(self):
        """+0900 09:00 and +0000 00:00 are the same instant."""
        jst = itm2_fmt.parse_timestamp("10/05/2022 09:00:00.000 +0900")
        utc = itm2_fmt.parse_timestamp("10/05/2022 00:00:00.000 +0000")
        self.assertEqual(jst.sort, utc.sort)
        self.assertIn("+0900", jst.display)

    def test_missing_offset_is_marked_not_comparable(self):
        naive = itm2_fmt.parse_timestamp("10/05/2022 14:00:01.000")
        aware = itm2_fmt.parse_timestamp("10/05/2022 14:00:01.000 +0900")
        self.assertTrue(naive.known)
        self.assertFalse(naive.comparable)
        self.assertTrue(aware.comparable)


class TestOrdering(unittest.TestCase):
    def entry(self, ts, member, line, ident):
        return {
            "_stamp": itm2_fmt.parse_timestamp(ts),
            "member": member, "line": line, "evidenceId": ident,
        }

    def test_same_timestamp_orders_deterministically(self):
        """Equal seconds must not fall back to input order."""
        a = self.entry("10/05/2022 14:00:01.000 +0900", "b.log", 5, "ev-b")
        b = self.entry("10/05/2022 14:00:01.000 +0900", "a.log", 9, "ev-a")
        forward = sorted([a, b], key=timeline.order_key)
        backward = sorted([b, a], key=timeline.order_key)
        self.assertEqual(
            [x["evidenceId"] for x in forward],
            [x["evidenceId"] for x in backward],
        )
        self.assertEqual(forward[0]["member"], "a.log")

    def test_mixed_formats_sort_together(self):
        itm = {"_stamp": itm2_fmt.parse_timestamp("10/05/2022 14:00:09.000 +0900"),
               "member": "a", "line": 1, "evidenceId": "1"}
        prx = {"_stamp": proxy_fmt.parse_timestamp("05/Oct/2022:14:00:07 +0900"),
               "member": "b", "line": 1, "evidenceId": "2"}
        ordered = sorted([itm, prx], key=timeline.order_key)
        self.assertEqual(ordered[0]["evidenceId"], "2", "proxy が 2 秒早い")


class TestTimelineSection(unittest.TestCase):
    def setUp(self):
        self.lesson = build()
        self.rows = self.lesson["report"]["timeline"]

    def test_timeline_is_not_empty(self):
        self.assertTrue(self.rows)

    def test_rows_are_sorted_by_time_not_by_input_order(self):
        """The order must come from the clock, not from which file was read first.

        Asserting only the first row is not enough: the fixture happens to have
        its earliest record in the first source, so input order and time order
        agree there. Compare the whole sequence against the sorted one.
        """
        self.assertTrue(all(r["timeKnown"] for r in self.rows), "fixture は全件時刻あり")
        seconds = [
            itm2_fmt.parse_timestamp(r["timestamp"]).sort
            if itm2_fmt.parse_timestamp(r["timestamp"]).known
            else proxy_fmt.parse_timestamp(r["timestamp"]).sort
            for r in self.rows
        ]
        self.assertEqual(seconds, sorted(seconds), "時刻順に並んでいない")

        # 入力順とは違う並びになっていること。同じなら、並べ替えを外しても
        # このテストは通ってしまう。
        endpoint_first = [r for r in self.rows if r["member"].endswith("ws99.log")]
        proxy_rows = [r for r in self.rows if r["member"].endswith("proxy01.log")]
        self.assertTrue(endpoint_first and proxy_rows, "両方のログから項目がある")
        positions = [self.rows.index(r) for r in proxy_rows]
        self.assertTrue(
            any(p < len(self.rows) - len(proxy_rows) for p in positions),
            "proxy の行が末尾にまとまっている＝入力順のまま",
        )

    def test_each_row_cites_a_real_evidence_id(self):
        for row in self.rows:
            self.assertTrue(row["evidenceIds"])
            for ident in row["evidenceIds"]:
                self.assertIn(ident, self.lesson["evidence"])
            self.assertTrue(row["member"])
            self.assertGreaterEqual(row["line"], 1)

    def test_rows_are_observed_not_inferred(self):
        self.assertEqual({r["status"] for r in self.rows}, {"observed"})

    def test_ordering_is_deterministic_across_builds(self):
        again = build()
        self.assertEqual(
            [r["evidenceId"] for r in self.rows],
            [r["evidenceId"] for r in again["report"]["timeline"]],
        )


class TestCorrelationQuestion(unittest.TestCase):
    def setUp(self):
        self.lesson = build()
        self.quizzes = [q for s in self.lesson["stages"] for q in s["quizzes"]]
        self.corr = [q for q in self.quizzes if q.get("category") == "correlation"]

    def test_one_is_generated_from_sufficient_data(self):
        self.assertEqual(len(self.corr), 1, [q["id"] for q in self.quizzes])

    def test_it_rests_on_two_or_more_evidence_ids(self):
        quiz = self.corr[0]
        self.assertGreaterEqual(len(quiz["evidenceIds"]), 2)
        self.assertEqual(len(set(quiz["evidenceIds"])), len(quiz["evidenceIds"]))
        for ident in quiz["evidenceIds"]:
            self.assertIn(ident, self.lesson["evidence"])

    def test_it_is_marked_correlated(self):
        self.assertEqual(self.corr[0]["status"], "correlated")

    def test_the_underlying_evidence_stays_observed(self):
        """A correlated reading does not change what the raw lines are."""
        for ident in self.corr[0]["evidenceIds"]:
            self.assertEqual(self.lesson["evidence"][ident]["confidence"], "observed")

    def test_it_claims_recording_order_not_causation(self):
        quiz = self.corr[0]
        text = quiz["q"] + quiz["explain"]
        self.assertIn("記録", text)
        for forbidden in ("引き起こした結果", "が原因で", "によって実行された"):
            self.assertNotIn(forbidden, text)
        # 因果を否定する断りが、解説に必ず入っていること。
        self.assertIn("引き起こした、とは言えません", quiz["explain"])

    def test_not_generated_when_times_cannot_be_read(self):
        store = evidence.EvidenceStore()
        cands = explain.correlation_candidates(parse_itm2(
            "\n".join([
                itm2("時刻不明", "WS99", psPath="C:\\W\\cmd.exe"),
                itm2("こちらも不明", "WS99", psPath="C:\\W\\powershell.exe"),
            ]),
            name=ENDPOINT,
        ))
        quiz, why, pair = explain._correlation_quiz(store, cands, "q")
        self.assertIsNone(quiz)
        self.assertEqual(pair, [])
        self.assertIn("時刻", why)

    def test_not_generated_across_different_hosts(self):
        """Two hosts' clocks are not a basis for saying which came first."""
        store = evidence.EvidenceStore()
        cands = explain.correlation_candidates(parse_itm2(
            "\n".join([
                itm2("10/05/2022 14:00:01.000 +0900", "WS99",
                     psPath="C:\\W\\cmd.exe"),
                itm2("10/05/2022 14:00:05.000 +0900", "DC01",
                     psPath="C:\\W\\powershell.exe"),
            ]),
            name=ENDPOINT,
        ))
        quiz, why, _ = explain._correlation_quiz(store, cands, "q")
        self.assertIsNone(quiz)
        self.assertIn("同じ端末", why)

    def test_not_generated_when_timestamps_are_identical(self):
        store = evidence.EvidenceStore()
        same = "10/05/2022 14:00:01.000 +0900"
        cands = explain.correlation_candidates(parse_itm2(
            "\n".join([
                itm2(same, "WS99", psPath="C:\\W\\cmd.exe"),
                itm2(same, "WS99", psPath="C:\\W\\powershell.exe"),
            ]),
            name=ENDPOINT,
        ))
        quiz, _, _ = explain._correlation_quiz(store, cands, "q")
        self.assertIsNone(quiz)

    def test_failure_reason_is_recorded_for_the_learner(self):
        """Not silently absent: the lesson says why it is not there."""
        sources = {ENDPOINT: itm2("bad", "WS99", psPath="C:\\W\\cmd.exe")}
        lesson = build_lesson("t", sources, "gen-x")
        if lesson is None:
            self.skipTest("この入力では教材自体が作れない")
        topics = " ".join(u["detail"] for u in lesson["report"]["unknowns"])
        self.assertIn("関連付けの設問は作りませんでした", topics)


class TestGroundedAttck(unittest.TestCase):
    def setUp(self):
        self.lesson = build()
        self.techniques = self.lesson["report"]["techniques"]

    def test_every_technique_has_reason_evidence_version_confidence(self):
        self.assertTrue(self.techniques)
        for t in self.techniques:
            self.assertTrue(t["reason"], t["id"])
            self.assertTrue(t["evidenceIds"], t["id"])
            self.assertTrue(t["ruleVersion"], t["id"])
            self.assertTrue(t["confidence"], t["id"])
            self.assertIn(t["status"], ("observed", "correlated", "hypothesis"))
            for ident in t["evidenceIds"]:
                self.assertIn(ident, self.lesson["evidence"])

    def test_only_allowlisted_rules_are_used(self):
        allowed = {
            rule[0] for needs, rule in attck.PROCESS_RULES.values() if not needs
        }
        # 引数で決まる規則は、規則表からは ID を読めない。代表的な引数列を
        # 通して、返ってくる ID を許可リストへ入れる。
        for cmd in ("net.exe user", "net.exe group", "net.exe user a /add",
                    "certutil.exe -decode a b", "vssadmin.exe delete shadows",
                    "bcdedit.exe /set x recoveryenabled no",
                    "schtasks.exe /create /tn a", "rundll32.exe a.dll,Start",
                    "regsvr32.exe /i:http://198.51.100.9/a scrobj.dll",
                    "mshta.exe http://198.51.100.9/a.hta"):
            needs, rule = attck.PROCESS_RULES[cmd.split(" ", 1)[0]]
            got = rule(attck.tokens(cmd))
            self.assertIsNotNone(got, cmd)
            allowed.add(got[0])
        allowed |= {r[1] for r in attck.REGISTRY_RULES}
        for t in self.techniques:
            self.assertIn(t["id"], allowed, t["id"])

    def test_outbound_traffic_alone_is_never_tagged(self):
        """POST, an external address, and an .exe are not techniques."""
        store = evidence.EvidenceStore()
        events = explain.display_events(
            parse_proxy(
                "\n".join([
                    proxy("05/Oct/2022:14:00:07 +0900", "192.0.2.10",
                          method="POST", target="http://203.0.113.9/upload.exe"),
                    proxy("05/Oct/2022:14:00:08 +0900", "192.0.2.11",
                          method="CONNECT", target="198.51.100.23:443"),
                ]),
                name=PROXY_NAME,
            ),
            store,
        )
        self.assertTrue(events)
        for e in events:
            self.assertIsNone(e.get("attck"), e["detail"])

    def test_duplicate_techniques_merge_but_keep_every_evidence_id(self):
        text = "\n".join([
            itm2("10/05/2022 14:00:01.000 +0900", "WS99",
                 psPath="C:\\W\\System32\\rundll32.exe",
                 cmd="rundll32.exe payload.dll,Start"),
            itm2("10/05/2022 14:00:02.000 +0900", "DC01",
                 psPath="C:\\W\\SysWOW64\\rundll32.exe",
                 cmd="rundll32.exe other.dll,Run"),
        ])
        lesson = build_lesson("t", {ENDPOINT: text}, "gen-dup")
        rows = [t for t in lesson["report"]["techniques"] if t["id"] == "T1218.011"]
        self.assertEqual(len(rows), 1, "同じ手法は 1 件へまとめる")
        self.assertGreaterEqual(len(rows[0]["evidenceIds"]), 2, "根拠は失わない")

    def test_registry_rule_needs_the_exact_path(self):
        store = evidence.EvidenceStore()
        events = explain.display_events(
            parse_itm2(
                itm2("10/05/2022 14:00:01.000 +0900", "WS99", evt="reg",
                     sub="setVal", path="HKCU\\Software\\Example\\NotAutorun"),
                name=ENDPOINT,
            ),
            store,
        )
        self.assertIsNone(events[0].get("attck"))


class TestReportStructure(unittest.TestCase):
    def setUp(self):
        self.lesson = build()

    def test_introduction_is_present_and_honest(self):
        intro = self.lesson["introduction"]
        self.assertEqual(intro["status"], "draft")
        self.assertTrue(intro["logTypes"])
        self.assertTrue(intro["hosts"])
        self.assertTrue(intro["objectives"])
        self.assertGreater(intro["estimatedMinutes"], 0)

    def test_introduction_says_so_when_hosts_are_unknown(self):
        """No invented values: say it could not be read."""
        text = proxy("05/Oct/2022:14:00:07 +0900", "192.0.2.10")
        lesson = build_lesson("t", {PROXY_NAME: text}, "gen-p")
        if lesson is None:
            self.skipTest("この入力では教材を作れない")
        hosts = lesson["introduction"]["hosts"]
        self.assertTrue(
            hosts == ["記録からは分かりません"] or all(h for h in hosts), hosts
        )

    def test_unknowns_always_warn_about_order_versus_causation(self):
        topics = [u["topic"] for u in self.lesson["report"]["unknowns"]]
        self.assertIn("記録の順序と出来事の順序", topics)

    def test_unknowns_mention_network_limits_when_traffic_is_present(self):
        topics = [u["topic"] for u in self.lesson["report"]["unknowns"]]
        self.assertIn("外部との通信", topics)

    def test_next_investigations_come_from_the_questions(self):
        nxt = self.lesson["report"]["nextInvestigations"]
        self.assertTrue(nxt)
        asked = {
            q.get("nextInvestigation")
            for s in self.lesson["stages"] for q in s["quizzes"]
        }
        for item in nxt:
            self.assertIn(item, asked)

    def test_report_is_deterministic(self):
        a = json.dumps(build()["report"], sort_keys=True, ensure_ascii=False)
        b = json.dumps(build()["report"], sort_keys=True, ensure_ascii=False)
        self.assertEqual(a, b)

    def test_legacy_recap_is_still_produced(self):
        self.assertIn("recap", self.lesson)
        self.assertIn("chain", self.lesson["recap"])

    def test_events_carry_no_internal_keys(self):
        """`_stamp` is a Python object; it must not reach the lesson JSON."""
        blob = json.dumps(self.lesson, ensure_ascii=False)
        self.assertNotIn("_stamp", blob)
        for stage in self.lesson["stages"]:
            for event in stage["events"]:
                self.assertFalse([k for k in event if k.startswith("_")])


class TestEmptyAndPartial(unittest.TestCase):
    """Thin input must degrade into an explanation, not a blank page."""

    def test_stage_without_questions_keeps_its_events_and_says_why(self):
        # 1 件だけでは選択肢が作れないので、設問は生まれない。
        text = itm2("10/05/2022 14:00:01.000 +0900", "WS99",
                    evt="file", sub="create", path="C:\\Users\\a\\only.dat")
        lesson = build_lesson("t", {ENDPOINT: text}, "gen-thin")
        self.assertIsNotNone(lesson)
        stage = lesson["stages"][0]
        self.assertTrue(stage["events"], "観測できた事実は残す")
        self.assertEqual(stage["quizzes"], [])
        self.assertIn("根拠が不足", stage["note"])

    def test_no_technique_is_reported_as_such(self):
        text = itm2("10/05/2022 14:00:01.000 +0900", "WS99",
                    evt="file", sub="create", path="C:\\Users\\a\\only.dat")
        lesson = build_lesson("t", {ENDPOINT: text}, "gen-thin")
        self.assertEqual(lesson["report"]["techniques"], [])
        topics = [u["topic"] for u in lesson["report"]["unknowns"]]
        self.assertIn("ATT&CK の対応", topics)

    def test_unreadable_timestamps_are_counted_in_unknowns(self):
        text = "\n".join([
            itm2("壊れた時刻", "WS99", psPath="C:\\W\\cmd.exe"),
            itm2("これも壊れている", "WS99", psPath="C:\\W\\powershell.exe"),
        ])
        lesson = build_lesson("t", {ENDPOINT: text}, "gen-bad")
        if lesson is None:
            self.skipTest("この入力では教材を作れない")
        topics = [u["topic"] for u in lesson["report"]["unknowns"]]
        self.assertIn("時刻を読めなかった記録", topics)

    def test_lesson_with_no_parseable_logs_returns_none(self):
        self.assertIsNone(
            build_lesson("t", {ENDPOINT: "まったく関係のない文章"}, "gen-0")
        )


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# ATT&CK: 実行ファイル名だけで手法を決めない
# ---------------------------------------------------------------------------

def _tag_for(cmd: str, exe: str = None, ts="10/05/2022 14:00:01.000 +0900"):
    """1 行だけ食わせて、付いた ATT&CK を返す。"""
    exe = exe or cmd.split(" ", 1)[0]
    store = evidence.EvidenceStore()
    events = explain.display_events(
        parse_itm2(
            itm2(ts, "WS99", psPath=f"C:\\Windows\\System32\\{exe}", cmd=cmd),
            name=ENDPOINT,
        ),
        store,
    )
    assert events, cmd
    return events[0].get("attck"), events[0], store


class TestAttckNeedsTheArguments(unittest.TestCase):
    """照会するだけの命令に、破壊や常駐化の手法を割り当てない。

    実行ファイル名だけを見ていた頃は、`vssadmin list shadows`（影の一覧を
    見るだけ）が「復元の妨害」、`certutil -hashfile`（ハッシュ計算）が
    「難読化の解除」として high / observed で出ていた。教材としては、
    誤った断定をそのまま教えることになる。
    """

    HARMLESS = [
        ("certutil.exe -hashfile C:\\temp\\harmless.txt SHA256", "certutil.exe"),
        ("vssadmin.exe list shadows", "vssadmin.exe"),
        ("bcdedit.exe /enum", "bcdedit.exe"),
        ("schtasks.exe /query /fo LIST", "schtasks.exe"),
        ("net.exe use Z: \\\\fileserver.example\\share", "net.exe"),
        ("rundll32.exe", "rundll32.exe"),
        ("regsvr32.exe C:\\temp\\plain.dll", "regsvr32.exe"),
        ("mshta.exe", "mshta.exe"),
        # --- 語ではなく文字の並びで見ていると誤検出するもの ---
        # 共有の接続。宛先のホスト名に "user" が含まれる。
        ("net.exe use Z: \\\\user-files.example\\share", "net.exe"),
        # ハッシュ計算。ファイル名に "-decode" が含まれる。
        ("certutil.exe -hashfile C:\\temp\\-decode.txt SHA256", "certutil.exe"),
        # 引用符の中に空白と紛らわしい語があるもの。
        ('vssadmin.exe list "delete shadows backup"', "vssadmin.exe"),
        # --- MITRE の定義と合わないもの ---
        # 符号化であって復号ではない。
        ("certutil.exe -encode input.bin output.txt", "certutil.exe"),
        # 取得であって復号ではない。内容は行からは決まらない。
        ("certutil.exe -urlcache -split -f http://198.51.100.9/a.txt",
         "certutil.exe"),
        # 何を消すかで意味が変わる汎用の指定。回復の妨害とは限らない。
        ("bcdedit.exe /deletevalue {current} safeboot", "bcdedit.exe"),
        # グループの作成とも、メンバーの追加とも読める。
        ("net.exe localgroup administrators bob /add", "net.exe"),
        # --- 列挙ではなく変更にあたるもの ---
        # 第 2 引数はパスワード。表示ではなく変更。
        ("net.exe user alice newpassword", "net.exe"),
        ("net.exe user alice P@ssw0rd /domain", "net.exe"),
        ("net.exe user alice /delete", "net.exe"),
        ("net.exe user alice /active:no", "net.exe"),
        # --- 縮小したと言い切れないもの ---
        # `resize shadowstorage` は最大容量の変更であって、縮小とは限らない。
        # 変更前の割り当てが分からない以上、どの指定でも断定できない。
        ("vssadmin.exe resize shadowstorage /for=C: /maxsize=unbounded",
         "vssadmin.exe"),
        ("vssadmin.exe resize shadowstorage /for=C: /maxsize=20GB",
         "vssadmin.exe"),
        ("vssadmin.exe resize shadowstorage /for=C: /maxsize=100GB",
         "vssadmin.exe"),
        ("vssadmin.exe resize shadowstorage /for=C:", "vssadmin.exe"),
        # --- 許可リストから外れる net の変更系 ---
        ("net.exe user alice /fullname:Alice", "net.exe"),
        ("net.exe user alice /comment:test", "net.exe"),
        ("net.exe user alice /homedir:\\\\srv\\home", "net.exe"),
        ("net.exe user alice /profilepath:C:\\p", "net.exe"),
        ("net.exe user alice /scriptpath:logon.bat", "net.exe"),
        ("net.exe user alice /workstations:WS01", "net.exe"),
        ("net.exe user alice /passwordreq:no", "net.exe"),
        ("net.exe user alice /times:all", "net.exe"),
        ("net.exe localgroup admins /comment:x", "net.exe"),
    ]

    MEANINGFUL = [
        ("vssadmin.exe delete shadows /all /quiet", "vssadmin.exe", "T1490"),
        ("bcdedit.exe /set {default} recoveryenabled no", "bcdedit.exe", "T1490"),
        ("certutil.exe -decode C:\\temp\\a.txt C:\\temp\\a.exe", "certutil.exe", "T1140"),
        ("schtasks.exe /create /tn upd /tr C:\\temp\\a.exe /sc onlogon",
         "schtasks.exe", "T1053.005"),
        # --- net は下位命令・/domain・値の数で分かれる ---
        ("net.exe user tester /add", "net.exe", "T1136.001"),
        ("net.exe user tester /add /domain", "net.exe", "T1136.002"),
        ("net.exe user", "net.exe", "T1087.001"),
        ("net.exe user /domain", "net.exe", "T1087.002"),
        ("net.exe user alice", "net.exe", "T1087.001"),
        # グループの列挙はアカウントの列挙とは別の Technique。
        ("net.exe localgroup", "net.exe", "T1069.001"),
        ("net.exe localgroup administrators", "net.exe", "T1069.001"),
        ("net.exe group", "net.exe", "T1069.002"),
        ("net.exe group /domain", "net.exe", "T1069.002"),

        ("rundll32.exe C:\\temp\\payload.dll,Start", "rundll32.exe", "T1218.011"),
    ]

    def test_query_only_commands_are_not_tagged(self):
        for cmd, exe in self.HARMLESS:
            with self.subTest(cmd=cmd):
                tag, _, _ = _tag_for(cmd, exe)
                self.assertIsNone(tag, f"{cmd} にタグが付いた: {tag}")

    def test_the_same_programs_are_tagged_when_the_arguments_say_so(self):
        for cmd, exe, tid in self.MEANINGFUL:
            with self.subTest(cmd=cmd):
                tag, _, _ = _tag_for(cmd, exe)
                self.assertIsNotNone(tag, f"{cmd} にタグが付かない")
                self.assertEqual(tag["id"], tid)

    def test_interpreters_are_tagged_on_start_alone(self):
        """解釈系は起動そのものが手法。引数が無くても付く。"""
        for exe, tid in (("cmd.exe", "T1059.003"),
                         ("powershell.exe", "T1059.001"),
                         ("wscript.exe", "T1059.005"),
                         ("whoami.exe", "T1033")):
            with self.subTest(exe=exe):
                store = evidence.EvidenceStore()
                events = explain.display_events(
                    parse_itm2(
                        itm2("10/05/2022 14:00:01.000 +0900", "WS99",
                             psPath=f"C:\\Windows\\System32\\{exe}"),
                        name=ENDPOINT,
                    ),
                    store,
                )
                self.assertEqual(events[0]["attck"]["id"], tid)

    def test_every_rule_declares_what_it_needs(self):
        """起動だけで足りる規則は組、引数で決まる規則は関数。"""
        for exe, (needs_arg, rule) in attck.PROCESS_RULES.items():
            with self.subTest(exe=exe):
                self.assertIsInstance(needs_arg, bool)
                if needs_arg:
                    self.assertTrue(callable(rule), f"{exe} の規則が関数でない")
                    self.assertIsNone(rule(attck.tokens(exe)),
                                      f"{exe} は引数なしでは判定できないはず")
                else:
                    self.assertEqual(len(rule), 3, exe)
                    self.assertTrue(all(rule), exe)


class TestAttckFromStoredExcerpt(unittest.TestCase):
    """high / observed と言う以上、保存した抜粋から同じ判定を引き直せること。"""

    def test_not_tagged_when_the_field_falls_outside_the_excerpt(self):
        """抜粋に psPath が残らない長い行には、対応を付けない。

        解析済みのレコードには行全体が入っているので、そちらで判定すると
        「この 1 行の psPath に書かれています」と言いながら、画面に出る
        抜粋には psPath が無い、という状態になる。
        """
        filler = " ".join(f'f{i}="{"x" * 40}"' for i in range(40))
        line = (
            '10/05/2022 14:00:01.000 +0900 loc=en-US type=ITM2 sn=1 lv=5 '
            'evt=ps subEvt=start os=Win com="WS99" '
            f'{filler} psPath="C:\\Windows\\System32\\cmd.exe"'
        )
        self.assertGreater(line.index("psPath="), evidence.MAX_EXCERPT,
                           "前提が崩れている: psPath が抜粋内に収まっている")
        store = evidence.EvidenceStore()
        events = explain.display_events(
            parse_itm2(line, name=ENDPOINT), store
        )
        self.assertTrue(events)
        excerpt = store.get(events[0]["evidenceIds"][0])["source"]["excerpt"]
        self.assertNotIn("psPath=", excerpt)
        self.assertIsNone(events[0].get("attck"),
                          "抜粋に無い項目を根拠にタグが付いている")

    def test_every_tag_can_be_rederived_from_what_was_saved(self):
        lesson = build()
        checked = 0
        for stage in lesson["stages"]:
            for event in stage["events"]:
                tag = event.get("attck")
                if not tag:
                    continue
                excerpt = lesson["evidence"][event["evidenceIds"][0]]["source"]["excerpt"]
                if event["type"] == "process":
                    again = attck_from_excerpt(excerpt, event["evidenceIds"])
                    self.assertIsNotNone(again, excerpt[:120])
                    self.assertEqual(again["id"], tag["id"])
                    self.assertEqual(again["reason"], tag["reason"])
                else:
                    # レジストリ規則も、抜粋の path から引き直せること。
                    kept = itm2_fmt.field_in(excerpt, "path")
                    self.assertTrue(
                        any(n in kept for n, *_ in attck.REGISTRY_RULES),
                        kept,
                    )
                self.assertEqual(tag["confidence"], "high")
                self.assertEqual(tag["status"], "observed")
                checked += 1
        self.assertTrue(checked, "タグが 1 つも無く、検査が空回りしている")


class TestTechniqueReasonsStayWithTheirEvidence(unittest.TestCase):
    """同じ Technique でも、観測が違えば理由を混ぜない。"""

    def setUp(self):
        text = "\n".join([
            itm2("10/05/2022 14:00:01.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\vssadmin.exe",
                 cmd="vssadmin.exe delete shadows /all /quiet"),
            itm2("10/05/2022 14:00:02.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\bcdedit.exe",
                 cmd="bcdedit.exe /set {default} recoveryenabled no"),
        ])
        self.lesson = build_lesson("t", {ENDPOINT: text}, "gen-t1490")
        rows = [t for t in self.lesson["report"]["techniques"] if t["id"] == "T1490"]
        self.assertEqual(len(rows), 1, "T1490 は 1 件にまとまる")
        self.row = rows[0]

    def test_both_observations_are_kept_with_their_own_evidence(self):
        self.assertEqual(len(self.row["reasons"]), 2, self.row["reasons"])
        by_reason = {r["reason"]: r["evidenceIds"] for r in self.row["reasons"]}
        vss = [r for r in by_reason if "vssadmin" in r]
        bcd = [r for r in by_reason if "bcdedit" in r]
        self.assertEqual(len(vss), 1, by_reason)
        self.assertEqual(len(bcd), 1, by_reason)
        self.assertEqual(len(by_reason[vss[0]]), 1)
        self.assertEqual(len(by_reason[bcd[0]]), 1)
        self.assertNotEqual(by_reason[vss[0]], by_reason[bcd[0]])

    def test_each_reason_matches_the_line_it_cites(self):
        """理由に書いた実行ファイルが、その根拠の抜粋にあること。"""
        for r in self.row["reasons"]:
            exe = "vssadmin" if "vssadmin" in r["reason"] else "bcdedit"
            for ident in r["evidenceIds"]:
                excerpt = self.lesson["evidence"][ident]["source"]["excerpt"]
                self.assertIn(exe, excerpt, r["reason"])

    def test_the_legacy_single_reason_field_does_not_hide_the_other(self):
        self.assertIn("vssadmin", self.row["reason"])
        self.assertIn("bcdedit", self.row["reason"])

    def test_no_evidence_id_is_lost(self):
        seen = {i for r in self.row["reasons"] for i in r["evidenceIds"]}
        self.assertEqual(seen, set(self.row["evidenceIds"]))


class TestCorrelationRejectsMixedTimeBases(unittest.TestCase):
    """タイムゾーンの有無が揃っていない組で、前後を問わない。"""

    def _events(self):
        store = evidence.EvidenceStore()
        text = "\n".join([
            itm2("10/05/2022 09:00:00.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe"),
            # 基準の分からない時刻。並べ替えでは真ん中へ来る。
            itm2("10/05/2022 01:00:00.000", "WS99", evt="file", sub="create",
                 path="C:\\Users\\test\\middle.dat"),
            itm2("10/05/2022 12:00:00.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
        ])
        return store, explain.correlation_candidates(
            parse_itm2(text, name=ENDPOINT)
        )

    def test_the_fixture_really_mixes_time_bases(self):
        """前提を固定する。全部が比較可能なら、この検査は意味を持たない。"""
        _, cands = self._events()
        flags = {c.timestamp.comparable for c in cands}
        self.assertEqual(flags, {True, False}, "混在していない")

    def test_the_naive_record_in_the_middle_is_not_used(self):
        """並べ替えの途中に居るタイムゾーン無しの行を、素通りさせない。

        この並びで唯一近接しているのは 09:00(+0900) と 01:00(なし) の組だが、
        基準が違うので使えない。残る 09:00 と 12:00 は 3 時間離れており、
        どちらもプロセス開始なので対象の組み合わせでもない。よって設問は
        作られず、理由が残る。
        """
        store, cands = self._events()
        quiz, why, pair = explain._correlation_quiz(store, cands, "q")
        self.assertIsNone(quiz, quiz and quiz["q"])
        self.assertEqual(pair, [])
        self.assertIn("関連付けの設問は作りませんでした", why)

    def test_a_close_pair_with_mismatched_bases_is_refused(self):
        """種別も時間差も条件を満たすのに、基準だけが違う組。

        ここを通してしまうと、+0900 の 09:00:00 と、基準の分からない
        09:00:10 を「10 秒差」と言って並べることになる。実際の差は
        何時間でもありうる。
        """
        store = evidence.EvidenceStore()
        text = "\n".join([
            itm2("10/05/2022 09:00:00.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe"),
            itm2("10/05/2022 09:00:10.000", "WS99", evt="file", sub="create",
                 path="C:\\Users\\test\\near.dat"),
        ])
        cands = explain.correlation_candidates(
            parse_itm2(text, name=ENDPOINT)
        )
        bases = {c.timestamp.basis for c in cands}
        self.assertEqual(len(bases), 2, f"前提が崩れている: {bases}")
        quiz, why, _ = explain._correlation_quiz(store, cands, "q")
        self.assertIsNone(quiz)
        self.assertIn("関連付けの設問は作りませんでした", why)

    def test_a_pair_that_shares_a_basis_is_still_usable(self):
        """検査を厳しくしただけで、作れるものまで作らなくなっていないこと。

        同じログのタイムゾーン無しどうしなら、同じ時計で測られていると
        言えるので使える。ここでは 30 秒差のプロセス開始とファイル作成を
        置く。どちらもタイムゾーンが無い。
        """
        store = evidence.EvidenceStore()
        text = "\n".join([
            itm2("10/05/2022 01:00:00.000", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe"),
            itm2("10/05/2022 01:00:30.000", "WS99", evt="file", sub="create",
                 path="C:\\Users\\test\\made.dat"),
        ])
        cands = explain.correlation_candidates(
            parse_itm2(text, name=ENDPOINT)
        )
        quiz, why, pair = explain._correlation_quiz(store, cands, "q")
        self.assertIsNotNone(quiz, why)
        self.assertEqual(len(pair), 2)
        self.assertEqual({e["time"]["basis"] for e in pair},
                         {f"local:{ENDPOINT}"})
        self.assertIn("30 秒以内", quiz["correlation"]["reason"])


class TestLearningCategories(unittest.TestCase):
    """仕様書 15.3。データが許す範囲で 4 つ以上の観点を出す。"""

    def setUp(self):
        self.lesson = build()
        self.quizzes = [q for s in self.lesson["stages"] for q in s["quizzes"]]

    def test_at_least_four_categories_are_present(self):
        cats = {q["category"] for q in self.quizzes}
        self.assertGreaterEqual(len(cats), 4, sorted(cats))

    def test_every_category_has_a_japanese_label(self):
        for q in self.quizzes:
            self.assertIn(q["category"], explain.CATEGORY_LABEL, q["id"])

    def test_correlation_lives_in_its_own_stage(self):
        """突き合わせの設問は、その 2 件を並べた段階に置く。"""
        stage = next(
            (s for s in self.lesson["stages"]
             if any(q["category"] == "correlation" for q in s["quizzes"])),
            None,
        )
        self.assertIsNotNone(stage, "突き合わせの段階が無い")
        shown = {i for e in stage["events"] for i in e.get("evidenceIds", [])}
        for q in stage["quizzes"]:
            for ident in q["evidenceIds"]:
                self.assertIn(ident, shown,
                              "設問が指す記録が、その段階に出ていない")

    def test_the_limits_question_answer_is_about_what_the_line_records(self):
        q = next((x for x in self.quizzes if x["category"] == "limits"), None)
        self.assertIsNotNone(q, "言えることを問う設問が無い")
        excerpt = self.lesson["evidence"][q["evidenceIds"][0]]["source"]["excerpt"]
        answer = q["options"][q["correct"]]
        # 正解に出てくる要求元と宛先は、示した行から取ったものであること。
        for token in answer.replace("から", " ").replace("への要求が記録されたこと", " ").split():
            self.assertIn(token, excerpt, answer)
        for wrong in q["options"]:
            if wrong is answer:
                continue
            self.assertTrue(
                wrong.endswith("こと"), wrong
            )

    def test_the_attck_question_distractors_are_real_techniques(self):
        q = next((x for x in self.quizzes if x["category"] == "attck"), None)
        if q is None:
            self.skipTest("この教材では対応が 3 種類に満たない")
        labels = {f'{t["id"]} · {t["name"]}'
                  for t in self.lesson["report"]["techniques"]}
        for option in q["options"]:
            self.assertIn(option, labels, option)


class TestEveryReportReferenceHasEvidence(unittest.TestCase):
    """レポートが指す証拠は、必ず教材に入っていること。

    画面側は、レポートが参照する証拠だけにアンカーを置く。教材に無い ID を
    指していると、その「根拠ログを見る」は押しても何も起きないボタンになる。
    """

    def setUp(self):
        self.lesson = build()

    def test_timeline_techniques_and_quizzes_all_resolve(self):
        have = set(self.lesson["evidence"])
        report = self.lesson["report"]
        refs = []
        for row in report["timeline"]:
            refs += row["evidenceIds"]
        for t in report["techniques"]:
            refs += t["evidenceIds"]
            for r in t.get("reasons", []):
                refs += r["evidenceIds"]
        for s in self.lesson["stages"]:
            for q in s["quizzes"]:
                refs += q["evidenceIds"]
        self.assertTrue(refs)
        for ident in refs:
            self.assertIn(ident, have, ident)

    def test_timeline_rows_say_whether_they_can_be_compared(self):
        for row in self.lesson["report"]["timeline"]:
            self.assertIn("timeComparable", row)
            self.assertIsInstance(row["timeComparable"], bool)


class TestMixedTimeBasesAreDisclosed(unittest.TestCase):
    """一本の軸に基準の違う時刻が並んだら、レポートでそう言う。"""

    def test_the_report_says_the_bases_are_not_aligned(self):
        text = "\n".join([
            itm2("10/05/2022 09:00:00.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe"),
            itm2("10/05/2022 01:00:00.000", "WS99", evt="file", sub="create",
                 path="C:\\Users\\test\\middle.dat"),
        ])
        lesson = build_lesson("t", {ENDPOINT: text}, "gen-mixed")
        topics = " ".join(u["topic"] for u in lesson["report"]["unknowns"])
        self.assertIn("時刻の基準が揃っていない", topics)
        rows = lesson["report"]["timeline"]
        self.assertEqual({r["timeComparable"] for r in rows}, {True, False})

    def test_it_is_not_said_when_every_record_shares_a_basis(self):
        """当てはまらないときに出さない。毎回出る注意書きは読まれなくなる。"""
        lesson = build()
        topics = " ".join(u["topic"] for u in lesson["report"]["unknowns"])
        if all(r["timeComparable"] for r in lesson["report"]["timeline"]
               if r["timeKnown"]):
            self.assertNotIn("時刻の基準が揃っていない", topics)


# ---------------------------------------------------------------------------
# 相関（仕様書 14.2）
# ---------------------------------------------------------------------------

class TestCorrelationFollowsTheSpecifiedRule(unittest.TestCase):
    """同一ホスト・対象種別・近接時刻の三つを満たしたときだけ相関とする。

    以前は「同一ホスト」と「時刻が違うこと」しか見ていなかった。24 時間
    離れたプロセス開始とファイル作成からも設問が出て、しかも `correlated` と
    名乗っていた。それは時系列を読む練習であって、二つの証拠を関連付ける
    練習ではない。
    """

    def _quiz(self, text, name=None, **kw):
        store = evidence.EvidenceStore()
        cands = explain.correlation_candidates(
            parse_itm2(text, name=name or ENDPOINT)
        )
        self.store = store
        return explain._correlation_quiz(store, cands, "q", **kw)

    def _excerpts(self, quiz):
        """選ばれた 2 件の原文。証拠 ID は行番号を含むので、入力の並びを
        変えると当然変わる。同じ行が選ばれたかどうかは原文で見る。"""
        return [self.store.get(i)["source"]["excerpt"] for i in quiz["evidenceIds"]]

    def test_a_day_apart_is_not_a_correlation(self):
        text = "\n".join([
            itm2("10/05/2022 09:00:00.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe"),
            itm2("10/06/2022 09:00:00.000 +0900", "WS99", evt="file",
                 sub="create", path="C:\\Users\\test\\later.dat"),
        ])
        quiz, why, _ = self._quiz(text)
        self.assertIsNone(quiz, "24 時間離れた組から相関問題が出ている")
        self.assertIn("60 秒以内", why)

    def test_just_inside_the_window_is_used(self):
        text = "\n".join([
            itm2("10/05/2022 09:00:00.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe"),
            itm2("10/05/2022 09:00:59.000 +0900", "WS99", evt="file",
                 sub="create", path="C:\\Users\\test\\in.dat"),
        ])
        quiz, why, _ = self._quiz(text)
        self.assertIsNotNone(quiz, why)
        self.assertEqual(quiz["correlation"]["gapSeconds"], 59.0)

    def test_just_outside_the_window_is_not(self):
        text = "\n".join([
            itm2("10/05/2022 09:00:00.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe"),
            itm2("10/05/2022 09:01:01.000 +0900", "WS99", evt="file",
                 sub="create", path="C:\\Users\\test\\out.dat"),
        ])
        quiz, _, _ = self._quiz(text)
        self.assertIsNone(quiz, "61 秒差が 60 秒の幅を通っている")

    def test_the_window_is_configurable(self):
        """仕様書 14.2「近接時間幅はプロファイルで設定可能にし」。"""
        text = "\n".join([
            itm2("10/05/2022 09:00:00.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe"),
            itm2("10/05/2022 09:02:00.000 +0900", "WS99", evt="file",
                 sub="create", path="C:\\Users\\test\\wide.dat"),
        ])
        self.assertIsNone(self._quiz(text)[0])
        quiz, why, _ = self._quiz(text, window=300)
        self.assertIsNotNone(quiz, why)
        self.assertEqual(quiz["correlation"]["windowSeconds"], 300)

    def test_two_process_starts_are_not_a_correlation_pair(self):
        """仕様に無い組み合わせは作らない。"""
        text = "\n".join([
            itm2("10/05/2022 09:00:00.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe"),
            itm2("10/05/2022 09:00:10.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\whoami.exe"),
        ])
        quiz, _, _ = self._quiz(text)
        self.assertIsNone(quiz, "起動どうしを関連付けている")

    def test_process_and_file_is_a_pair(self):
        text = "\n".join([
            itm2("10/05/2022 09:00:00.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe"),
            itm2("10/05/2022 09:00:34.000 +0900", "WS99", evt="file",
                 sub="create", path="C:\\Users\\test\\a.dat"),
        ])
        quiz, why, _ = self._quiz(text)
        self.assertIsNotNone(quiz, why)
        self.assertEqual(set(quiz["correlation"]["types"]), {"process", "file"})

    def test_process_and_network_is_a_pair_across_log_types(self):
        """端末ログとプロキシは端末の呼び名が違う。IP で結び付ける。"""
        store = evidence.EvidenceStore()
        itm2_recs = parse_itm2(
            itm2("10/05/2022 14:00:00.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe", ip="192.0.2.10"),
            name=ENDPOINT,
        )
        proxy_recs = parse_proxy(
            proxy("05/Oct/2022:14:00:20 +0900", "192.0.2.10",
                  target="http://198.51.100.23/a"),
            name=PROXY_NAME,
        )
        # 前提: 表示名は一致していない。IP で結ぶしかない。
        self.assertNotEqual(
            explain.display_events(itm2_recs, store)[0]["host"],
            explain.display_events(proxy_recs, store)[0]["host"],
        )
        cands = explain.correlation_candidates(itm2_recs + proxy_recs)
        self.assertEqual(len(cands), 2)
        quiz, why, _ = explain._correlation_quiz(store, cands, "q")
        self.assertIsNotNone(quiz, why)
        self.assertEqual(set(quiz["correlation"]["types"]), {"process", "network"})
        self.assertEqual(quiz["correlation"]["hostKey"], "192.0.2.10")

    def test_different_hosts_are_never_paired(self):
        text = "\n".join([
            itm2("10/05/2022 09:00:00.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe", ip="192.0.2.10"),
            itm2("10/05/2022 09:00:10.000 +0900", "DC01", evt="file",
                 sub="create", path="C:\\Users\\test\\a.dat", ip="192.0.2.11"),
        ])
        quiz, _, _ = self._quiz(text)
        self.assertIsNone(quiz, "別の端末どうしを関連付けている")

    def test_a_valid_pair_later_in_the_log_is_still_found(self):
        """いちばん早い記録が組めなくても、後続どうしの組を見落とさない。

        以前は並べ替えた先頭を起点に固定して相手を探していた。先頭が
        どの相手とも組めない並びでは、後ろに有効な組があっても諦めていた。
        """
        text = "\n".join([
            # 先頭。以降のどれとも組めない（起動どうし／3 時間差）。
            itm2("10/05/2022 09:00:00.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe"),
            itm2("10/05/2022 12:00:00.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\whoami.exe"),
            itm2("10/05/2022 12:00:20.000 +0900", "WS99", evt="file",
                 sub="create", path="C:\\Users\\test\\late.dat"),
        ])
        quiz, why, _ = self._quiz(text)
        self.assertIsNotNone(quiz, why)
        self.assertEqual(quiz["correlation"]["gapSeconds"], 20.0)
        self.assertTrue(any("late.dat" in e for e in self._excerpts(quiz)))

    def test_two_naive_logs_are_not_paired_with_each_other(self):
        """どちらもタイムゾーン無しでも、別のログなら時計が別。

        真偽値で「比較可能か」を見ていると、`False == False` が成立して
        しまい、別々にずれた二つの時計を並べて「10 秒差」と言うことになる。
        基準は札で持ち、同じ札どうしだけを結ぶ。
        """
        store = evidence.EvidenceStore()
        cands = []
        for name, line in (
            ("case/logs.zip :: logs/a.log",
             itm2("10/05/2022 09:00:00.000", "WS99",
                  psPath="C:\\Windows\\System32\\cmd.exe", ip="192.0.2.10")),
            ("case/logs.zip :: logs/b.log",
             itm2("10/05/2022 09:00:10.000", "WS99", evt="file", sub="create",
                  path="C:\\Users\\test\\a.dat", ip="192.0.2.10")),
        ):
            cands += explain.correlation_candidates(
                parse_itm2(line, name=name)
            )
        self.assertEqual(len(cands), 2)
        # 前提: どちらも「タイムゾーン無し」で、真偽値では区別が付かない。
        self.assertEqual({c.timestamp.comparable for c in cands}, {False})
        self.assertEqual(len({c.timestamp.basis for c in cands}), 2)
        # 種別も時間差も条件を満たしている。落ちる理由は基準だけ。
        self.assertEqual({c.kind for c in cands}, {"process", "file"})
        self.assertEqual(abs(cands[0].timestamp.sort - cands[1].timestamp.sort), 10.0)
        quiz, why, _ = explain._correlation_quiz(store, cands, "q")
        self.assertIsNone(quiz, "別のログの時計どうしを結び付けている")
        self.assertIn("関連付けの設問は作りませんでした", why)

    def test_the_reason_is_in_the_form_the_spec_requires(self):
        """「同一端末で 34 秒以内」の形。出せない組は採用しない。"""
        text = "\n".join([
            itm2("10/05/2022 09:00:00.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe"),
            itm2("10/05/2022 09:00:34.000 +0900", "WS99", evt="file",
                 sub="create", path="C:\\Users\\test\\a.dat"),
        ])
        quiz, why, _ = self._quiz(text)
        self.assertIsNotNone(quiz, why)
        self.assertEqual(quiz["correlation"]["reason"], "同一端末（WS99）で 34 秒以内")
        self.assertIn("同一端末（WS99）で 34 秒以内", quiz["q"])
        self.assertIn("同一端末（WS99）で 34 秒以内", quiz["explain"])

    def test_it_still_refuses_to_claim_causation(self):
        text = "\n".join([
            itm2("10/05/2022 09:00:00.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe"),
            itm2("10/05/2022 09:00:34.000 +0900", "WS99", evt="file",
                 sub="create", path="C:\\Users\\test\\a.dat"),
        ])
        quiz, _, _ = self._quiz(text)
        self.assertIn("引き起こした、とは言えません", quiz["explain"])
        for forbidden in ("が原因で", "によって実行された", "引き起こした結果"):
            self.assertNotIn(forbidden, quiz["q"] + quiz["explain"])

    def test_the_closest_pair_wins_and_the_choice_is_stable(self):
        """入力の並びを変えても同じ組が選ばれること。"""
        lines = [
            itm2("10/05/2022 09:00:00.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe"),
            itm2("10/05/2022 09:00:50.000 +0900", "WS99", evt="file",
                 sub="create", path="C:\\Users\\test\\far.dat"),
            itm2("10/05/2022 09:00:02.000 +0900", "WS99", evt="file",
                 sub="create", path="C:\\Users\\test\\near.dat"),
        ]
        a = self._quiz("\n".join(lines))[0]
        self.assertIsNotNone(a)
        self.assertEqual(a["correlation"]["gapSeconds"], 2.0, "最も近い組を選ぶ")
        first = self._excerpts(a)
        self.assertTrue(any("near.dat" in e for e in first), first)
        self.assertFalse(any("far.dat" in e for e in first), first)

        b = self._quiz("\n".join([lines[2], lines[0], lines[1]]))[0]
        self.assertEqual(self._excerpts(b), first,
                         "入力の並びで選ばれる行が変わっている")


class TestTimeArithmeticIsReal(unittest.TestCase):
    """時間差が実際の秒数であること。

    以前の写像は `((year*12+mon)*31+day)*24*3600` で、順序は決まるが差が
    実時間にならなかった。「34 秒以内」と言う以上、差が正しくなければ嘘になる。
    """

    def test_one_minute_across_an_hour_boundary(self):
        a = itm2_fmt.parse_timestamp("10/05/2022 09:59:30.000 +0900 x")
        b = itm2_fmt.parse_timestamp("10/05/2022 10:00:30.000 +0900 x")
        self.assertEqual(b.sort - a.sort, 60.0)

    def test_one_minute_across_a_day_boundary(self):
        a = itm2_fmt.parse_timestamp("10/05/2022 23:59:30.000 +0900 x")
        b = itm2_fmt.parse_timestamp("10/06/2022 00:00:30.000 +0900 x")
        self.assertEqual(b.sort - a.sort, 60.0)

    def test_one_minute_across_a_month_boundary(self):
        """月の日数が 31 でない境目。便宜的な写像ではここが狂う。

        旧来の `((year*12+mon)*31+day)` は、どの月も 31 日として数える。
        10 月のように 31 日ある月をまたぐ分には偶然合ってしまうので、
        30 日の月の末日で見る。
        """
        a = itm2_fmt.parse_timestamp("09/30/2022 23:59:30.000 +0900 x")
        b = itm2_fmt.parse_timestamp("10/01/2022 00:00:30.000 +0900 x")
        self.assertEqual(b.sort - a.sort, 60.0)

    def test_a_year_boundary(self):
        a = itm2_fmt.parse_timestamp("12/31/2022 23:59:30.000 +0900 x")
        b = itm2_fmt.parse_timestamp("01/01/2023 00:00:30.000 +0900 x")
        self.assertEqual(b.sort - a.sort, 60.0)

    def test_a_february_boundary_in_a_leap_year(self):
        a = itm2_fmt.parse_timestamp("02/28/2024 23:59:30.000 +0900 x")
        b = itm2_fmt.parse_timestamp("02/29/2024 00:00:30.000 +0900 x")
        self.assertEqual(b.sort - a.sort, 60.0)

    def test_a_short_month_does_not_stretch_the_gap(self):
        """相関の判定に直接効く形で確かめる。

        便宜的な写像だと、30 日の月の末日をまたぐ 20 秒差が 1 日以上として
        計算され、60 秒の幅から外れて設問が作られなくなる。
        """
        store = evidence.EvidenceStore()
        text = "\n".join([
            itm2("09/30/2022 23:59:50.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe"),
            itm2("10/01/2022 00:00:10.000 +0900", "WS99", evt="file",
                 sub="create", path="C:\\Users\\test\\a.dat"),
        ])
        cands = explain.correlation_candidates(
            parse_itm2(text, name=ENDPOINT)
        )
        quiz, why, _ = explain._correlation_quiz(store, cands, "q")
        self.assertIsNotNone(quiz, why)
        self.assertEqual(quiz["correlation"]["gapSeconds"], 20.0)

    def test_a_date_that_does_not_exist_is_unreadable(self):
        self.assertFalse(itm2_fmt.parse_timestamp("02/31/2022 09:00:00.000 +0900 x").known)

    def test_a_leap_second_is_still_readable(self):
        stamp = itm2_fmt.parse_timestamp("06/30/2022 23:59:60.000 +0000 x")
        self.assertTrue(stamp.known)
        self.assertIn("23:59:60", stamp.display)

    def test_the_same_instant_in_two_zones_is_equal(self):
        jst = itm2_fmt.parse_timestamp("10/05/2022 09:00:00.000 +0900 x")
        utc = itm2_fmt.parse_timestamp("10/05/2022 00:00:00.000 +0000 x")
        self.assertEqual(jst.sort, utc.sort)


class TestComparisonBasis(unittest.TestCase):
    """比較基準は真偽値ではなく札。同じ札どうしだけが比べられる。"""

    def test_a_timezone_makes_it_comparable_anywhere(self):
        st = itm2_fmt.parse_timestamp("10/05/2022 09:00:00.000 +0900 x", "logs/a.log")
        self.assertEqual(st.basis, "utc")
        self.assertTrue(st.comparable)

    def test_without_a_timezone_the_basis_is_the_log_itself(self):
        st = itm2_fmt.parse_timestamp("10/05/2022 09:00:00.000 x", "logs/a.log")
        self.assertEqual(st.basis, "local:logs/a.log")
        self.assertFalse(st.comparable)

    def test_two_naive_lines_from_different_logs_do_not_share_a_basis(self):
        a = itm2_fmt.parse_timestamp("10/05/2022 09:00:00.000 x", "logs/a.log")
        b = itm2_fmt.parse_timestamp("10/05/2022 09:00:10.000 x", "logs/b.log")
        self.assertNotEqual(a.basis, b.basis)

    def test_an_unreadable_time_has_no_basis(self):
        self.assertEqual(itm2_fmt.parse_timestamp("なんだこれ", "logs/a.log").basis, "")
        self.assertEqual(timeline.UNKNOWN.basis, "")

    def test_the_basis_reaches_the_lesson_json(self):
        lesson = build()
        for row in lesson["report"]["timeline"]:
            self.assertIn("timeBasis", row)
            if row["timeKnown"]:
                self.assertTrue(row["timeBasis"], row)


class TestHostIdentityIsRequired(unittest.TestCase):
    """端末を特定できない記録どうしを「同一端末」として結ばない。

    `host` は表示用で、端末名が読めない行には `?` が入る。照合キーが空の
    ときにそこへ戻していたため、端末名も IP も無い 2 行が `?` どうしで
    一致し、「同一端末（?）で 10 秒以内」という相関が出ていた。
    """

    HEAD = "loc=en-US type=ITM2 sn=1 lv=5 os=Win"

    def _events(self, com=None, ip=None):
        store = evidence.EvidenceStore()
        extra = ""
        if com is not None:
            extra += f' com="{com}"'
        if ip is not None:
            extra += f' ip="{ip}"'
        text = "\n".join([
            f'10/05/2022 09:00:00.000 +0900 {self.HEAD}{extra} '
            f'evt=ps subEvt=start psPath="C:\\Windows\\System32\\cmd.exe"',
            f'10/05/2022 09:00:10.000 +0900 {self.HEAD}{extra} '
            f'evt=file subEvt=create path="C:\\Users\\test\\a.dat"',
        ])
        records = parse_itm2(text, name=ENDPOINT)
        # 照合キーは正規化イベントが持つ。候補は相関へ渡すため。
        return store, records, explain.correlation_candidates(records)

    def test_records_without_a_host_get_no_matching_key(self):
        store, events, _ = self._events()
        self.assertEqual(len(events), 2)
        self.assertEqual(len(explain.display_events(events, store)), 2)
        self.assertEqual([e.host for e in events], ["?", "?"],
                         "前提が崩れている: 表示用の host が ? でない")
        for e in events:
            self.assertEqual(e.correlation_keys, frozenset(), e.summary)

    def test_no_correlation_between_records_with_no_host(self):
        store, _, cands = self._events()
        quiz, why, _ = explain._correlation_quiz(store, cands, "q")
        self.assertIsNone(quiz, quiz and quiz["correlation"])
        self.assertTrue(why)

    def test_placeholder_host_names_are_not_matching_keys(self):
        for com in ("?", "-", "unknown", "N/A", ""):
            with self.subTest(com=com):
                _, events, _ = self._events(com=com)
                for e in events:
                    self.assertEqual(e.correlation_keys, frozenset(),
                                     f"{com!r} が採用された")

    def test_loopback_and_unspecified_addresses_are_not_matching_keys(self):
        """どの端末にもある住所なので、一致しても同じ端末とは言えない。"""
        for addr in ("127.0.0.1", "::1", "localhost", "0.0.0.0", "::"):
            with self.subTest(addr=addr):
                store, events, cands = self._events(ip=addr)
                for e in events:
                    self.assertEqual(e.correlation_keys, frozenset(),
                                     f"{addr} が採用された")
                self.assertEqual(cands, [], f"{addr} が候補に残っている")
                quiz, _, _ = explain._correlation_quiz(store, cands, "q")
                self.assertIsNone(quiz, f"{addr} どうしを結んでいる")

    def test_a_real_host_name_still_works(self):
        """締め付けただけで、使えるものまで使えなくなっていないこと。"""
        store, events, cands = self._events(com="WS99")
        self.assertEqual([e.correlation_keys for e in events],
                         [frozenset({"WS99"}), frozenset({"WS99"})])
        quiz, why, _ = explain._correlation_quiz(store, cands, "q")
        self.assertIsNotNone(quiz, why)
        self.assertEqual(quiz["correlation"]["hostKey"], "WS99")

    def test_an_ip_alone_is_enough(self):
        store, _, cands = self._events(ip="192.0.2.10")
        quiz, why, _ = explain._correlation_quiz(store, cands, "q")
        self.assertIsNotNone(quiz, why)
        self.assertEqual(quiz["correlation"]["hostKey"], "192.0.2.10")

    def test_the_reason_never_names_a_placeholder(self):
        lesson = build()
        for stage in lesson["stages"]:
            for q in stage["quizzes"]:
                info = q.get("correlation")
                if info:
                    self.assertNotIn(info["hostKey"], ("?", "", "-"))
                    self.assertNotIn("（?）", q["q"])


class TestCorrelationSearchesEveryEvent(unittest.TestCase):
    """探索は、表示用に間引く前の完全な集合に対して行う。

    段階の一覧は、同じ端末の同じ実行ファイルを 1 件へ間引き、さらに
    `STAGE_EVENTS` 件で切ってある。そこから相手を探すと、近接した組を
    見落とす。
    """

    def test_a_repeated_program_start_is_still_available_for_correlation(self):
        """指摘された再現入力そのもの。"""
        text = "\n".join([
            itm2("10/05/2022 09:00:00.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe"),
            itm2("10/05/2022 10:00:00.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe"),
            itm2("10/05/2022 10:00:10.000 +0900", "WS99", evt="file",
                 sub="create", path="C:\\Users\\test\\a.dat"),
        ])
        lesson = build_lesson("t", {ENDPOINT: text}, "gen-dedup")
        self.assertIsNotNone(lesson)
        corr = [q for s in lesson["stages"] for q in s["quizzes"]
                if q["category"] == "correlation"]
        self.assertEqual(len(corr), 1,
                         "間引かれた 2 回目の起動が相関に使われていない")
        self.assertEqual(corr[0]["correlation"]["gapSeconds"], 10.0)

    def test_the_displayed_list_is_still_deduplicated(self):
        """相関のために間引きをやめたのではない。一覧は今までどおり。"""
        text = "\n".join([
            itm2(f"10/05/2022 09:00:{i:02d}.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe")
            for i in range(5)
        ])
        store = evidence.EvidenceStore()
        records = parse_itm2(text, name=ENDPOINT)
        self.assertEqual(len(records), 5)
        self.assertEqual(len(explain.display_events(records, store)), 1,
                         "一覧の間引きが効いていない")
        # 相関の候補は間引かない。
        self.assertEqual(len(explain.correlation_candidates(records)), 5)

    def test_a_pair_beyond_the_stage_cap_is_still_found(self):
        """`STAGE_EVENTS` 件を越えた先にある組も見つかること。"""
        lines = [
            itm2(f"10/05/2022 09:{i:02d}:00.000 +0900", "WS99",
                 psPath=f"C:\\Windows\\System32\\tool{i:02d}.exe")
            for i in range(explain.STAGE_EVENTS + 6)
        ]
        # 一覧に載らない位置に、近接した組を置く。
        lines.append(itm2("10/05/2022 09:30:00.000 +0900", "WS99",
                          psPath="C:\\Windows\\System32\\late.exe"))
        lines.append(itm2("10/05/2022 09:30:15.000 +0900", "WS99", evt="file",
                          sub="create", path="C:\\Users\\test\\late.dat"))
        lesson = build_lesson("t", {ENDPOINT: "\n".join(lines)}, "gen-cap")
        stage = next(s for s in lesson["stages"] if s["id"] == "endpoint")
        self.assertLessEqual(len(stage["events"]), explain.STAGE_EVENTS,
                             "前提が崩れている: 一覧が切られていない")
        corr = [q for s in lesson["stages"] for q in s["quizzes"]
                if q["category"] == "correlation"]
        self.assertEqual(len(corr), 1, "一覧の外にある組を見落としている")
        self.assertEqual(corr[0]["correlation"]["gapSeconds"], 15.0)

    def test_the_chosen_pair_is_shown_and_cited(self):
        """採用した 2 件は、その段階に出て、証拠表にも入っていること。"""
        text = "\n".join([
            itm2("10/05/2022 09:00:00.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe"),
            itm2("10/05/2022 10:00:00.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe"),
            itm2("10/05/2022 10:00:10.000 +0900", "WS99", evt="file",
                 sub="create", path="C:\\Users\\test\\a.dat"),
        ])
        lesson = build_lesson("t", {ENDPOINT: text}, "gen-dedup2")
        stage = next(s for s in lesson["stages"] if s["id"] == "correlate")
        shown = {i for e in stage["events"] for i in e.get("evidenceIds", [])}
        for q in stage["quizzes"]:
            for ident in q["evidenceIds"]:
                self.assertIn(ident, shown, "設問が指す記録が段階に出ていない")
                self.assertIn(ident, lesson["evidence"], "証拠表に入っていない")

    def _candidates(self, n, spacing):
        """n 件の候補を作る。`spacing` は隣りあう記録の秒差。

        `0` なら全件同時刻。プロセス開始とファイル作成を交互に置くので、
        どの組も種別の条件は満たす。落とせるのは時間差の条件だけになる。
        """
        lines = []
        for i in range(n):
            at = i * spacing
            ts = (f"10/05/2022 {9 + int(at) // 3600:02d}:"
                  f"{int(at) // 60 % 60:02d}:{int(at) % 60:02d}."
                  f"{int(at * 1000) % 1000:03d} +0900")
            if i % 2:
                lines.append(itm2(ts, "WS99", evt="file", sub="create",
                                  path=f"C:\\Users\\test\\f{i}.dat"))
            else:
                lines.append(itm2(ts, "WS99",
                                  psPath=f"C:\\Windows\\System32\\p{i}.exe"))
        cands = explain.correlation_candidates(
            parse_itm2("\n".join(lines), name=ENDPOINT)
        )
        self.assertEqual(len(cands), n)
        return cands

    def _comparisons(self, n, spacing):
        _, count = explain._best_pair(self._candidates(n, spacing), 60.0)
        return count

    #: 疎・密集・全件同時刻。二乗になるのは後ろ二つで、以前の打ち切りは
    #: 前者にしか効かなかった。
    SHAPES = (
        ("1 秒刻み", 1.0),
        ("60 秒以内に密集", 0.01),
        ("全件同時刻", 0.0),
    )

    def test_comparisons_do_not_grow_quadratically(self):
        """比較回数で見る。実時間は計測機の速さに左右される。

        以前は時刻順に並べて「幅を越えたら打ち切る」形だったので、記録が幅の
        中に密集すると打ち切りが効かなかった。同時刻なら読み飛ばすだけなので
        まったく効かない。件数を 4 倍にしたとき、比較回数も約 4 倍までに
        収まること（二乗なら約 16 倍になる）。
        """
        for label, spacing in self.SHAPES:
            with self.subTest(shape=label):
                small = self._comparisons(2000, spacing)
                large = self._comparisons(8000, spacing)
                if small == 0:
                    # 全件同時刻では、前後どちらにも相手が居ないので比較が
                    # 起きない。二乗の実装ではここが約 200 万回になる。
                    self.assertEqual(large, 0, f"{label}: {large} 回")
                    continue
                ratio = large / small
                self.assertLess(
                    ratio, 8.0,
                    f"{label}: 件数 4 倍で比較が {ratio:.1f} 倍（{small}→{large}）",
                )

    def test_comparisons_stay_near_the_candidate_count(self):
        """1 件あたりの比較は定数。直前と直後の 2 か所しか見ない。"""
        for label, spacing in self.SHAPES:
            with self.subTest(shape=label):
                n = 4000
                self.assertLessEqual(
                    self._comparisons(n, spacing), 2 * n,
                    f"{label}: 1 件あたり 2 回を超えている",
                )

    def test_the_dense_shape_really_is_dense(self):
        """前提を固定する。疎な並びでしか試していないと検査が空回りする。"""
        for label, spacing in self.SHAPES[1:]:
            with self.subTest(shape=label):
                cands = self._candidates(2000, spacing)
                span = (max(c.timestamp.sort for c in cands)
                        - min(c.timestamp.sort for c in cands))
                self.assertLessEqual(span, 60.0,
                                     f"{label}: 全体で {span} 秒に広がっている")

    def test_a_same_time_neighbour_does_not_hide_the_real_one(self):
        """同時刻の相手を掴んで、その先にある本当の相手を見落とさないこと。

        索引から「直後」を取るとき、同時刻のものまで含めて拾うと、前後の
        決まらない組を掴んだところで終わってしまう。取りこぼしなので、
        誤った組が出るわけではない。総当たりとの突き合わせでも、この並びが
        たまたま作られない限り表に出ない。

            09:00:00  プロセス開始   ← 起点
            09:00:00  ファイル作成   ← 同時刻。使えない
            09:00:10  ファイル作成   ← これが正しい相手
        """
        text = "\n".join([
            itm2("10/05/2022 09:00:00.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe"),
            itm2("10/05/2022 09:00:00.000 +0900", "WS99", evt="file",
                 sub="create", path="C:\\Users\\test\\same.dat"),
            itm2("10/05/2022 09:00:10.000 +0900", "WS99", evt="file",
                 sub="create", path="C:\\Users\\test\\later.dat"),
        ])
        store = evidence.EvidenceStore()
        cands = explain.correlation_candidates(
            parse_itm2(text, name=ENDPOINT)
        )
        quiz, why, _ = explain._correlation_quiz(store, cands, "q")
        self.assertIsNotNone(quiz, why)
        self.assertEqual(quiz["correlation"]["gapSeconds"], 10.0)
        excerpts = [store.get(i)["source"]["excerpt"] for i in quiz["evidenceIds"]]
        self.assertTrue(any("later.dat" in e for e in excerpts), excerpts)

    def test_a_same_time_neighbour_does_not_hide_the_earlier_one(self):
        """前側も同じ。同時刻を掴んで、その手前を見落とさないこと。"""
        text = "\n".join([
            itm2("10/05/2022 09:00:00.000 +0900", "WS99", evt="file",
                 sub="create", path="C:\\Users\\test\\earlier.dat"),
            itm2("10/05/2022 09:00:10.000 +0900", "WS99", evt="file",
                 sub="create", path="C:\\Users\\test\\same.dat"),
            itm2("10/05/2022 09:00:10.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe"),
        ])
        store = evidence.EvidenceStore()
        cands = explain.correlation_candidates(
            parse_itm2(text, name=ENDPOINT)
        )
        quiz, why, _ = explain._correlation_quiz(store, cands, "q")
        self.assertIsNotNone(quiz, why)
        self.assertEqual(quiz["correlation"]["gapSeconds"], 10.0)
        excerpts = [store.get(i)["source"]["excerpt"] for i in quiz["evidenceIds"]]
        self.assertTrue(any("earlier.dat" in e for e in excerpts), excerpts)

    def test_the_same_pair_is_chosen_as_a_full_scan_would(self):
        """索引化は速さのためで、選ぶ組を変えるものではない。

        条件を総当たりで確かめた結果と、同じ組が選ばれること。入力は端末・
        時刻・種別・タイムゾーンの有無をばらけさせ、乱数で 200 通り作る。
        """
        def brute(cands, window):
            best = None
            for i, a in enumerate(cands):
                for b in cands[i + 1:]:
                    first, other = (a, b) if a.timestamp.sort < b.timestamp.sort else (b, a)
                    gap = other.timestamp.sort - first.timestamp.sort
                    if gap <= 0 or gap > window:
                        continue
                    if frozenset({first.kind, other.kind}) not in \
                            explain.CORRELATION_PAIRS:
                        continue
                    if not (first.correlation_keys & other.correlation_keys):
                        continue
                    if first.timestamp.basis != other.timestamp.basis:
                        continue
                    if explain._place(first) == explain._place(other):
                        continue
                    key = (gap, first.timestamp.sort,
                           explain._place(first), explain._place(other))
                    if best is None or key < best:
                        best = key
            return best

        rng = random.Random(20260921)
        for trial in range(200):
            lines = []
            for i in range(rng.randint(2, 30)):
                host = rng.choice(["WS01", "WS02", "WS03"])
                ip = rng.choice(["192.0.2.10", "192.0.2.11", ""])
                # 時刻の取りうる値を狭くして、同時刻の重なりを起こしやすく
                # する。広く散らすと、同時刻がからむ場合をほとんど試さない。
                sec = rng.randint(0, 8)
                ts = (f"10/05/2022 09:00:{sec:02d}."
                      f"{rng.choice([0, 0, 500]):03d}"
                      f"{rng.choice([' +0900', ' +0900', ''])}")
                pick = rng.choice(["ps", "file", "reg"])
                if pick == "ps":
                    lines.append(itm2(ts, host,
                                      psPath=f"C:\\W\\p{i}.exe", ip=ip))
                elif pick == "file":
                    lines.append(itm2(ts, host, evt="file", sub="create",
                                      path=f"C:\\U\\f{i}.dat", ip=ip))
                else:
                    lines.append(itm2(ts, host, evt="reg", sub="setVal",
                                      path=f"HKCU\\k{i}", ip=ip))
            cands = explain.correlation_candidates(
                parse_itm2("\n".join(lines), name=ENDPOINT)
            )
            window = rng.choice([60.0, 10.0, 300.0])
            with self.subTest(trial=trial):
                got, _ = explain._best_pair(cands, window)
                self.assertEqual(got[:4] if got else None,
                                 brute(cands, window))


class TestDiscoveryIsAnAllowList(unittest.TestCase):
    """列挙だと言い切れる形だけを列挙として扱う。

    変更系のスイッチを並べて除外する書き方では、数え落としたものが
    そのまま Discovery として通る。`net user` のスイッチは Microsoft の
    仕様だけでも十数個あり、列挙しきれない。
    """

    def _tag(self, cmd):
        needs, rule = attck.PROCESS_RULES["net.exe"]
        self.assertTrue(needs)
        return rule(attck.tokens(cmd))

    #: 仕様にある変更系スイッチ。どれか一つでも付いたら列挙とは言えない。
    MODIFYING = [
        "/fullname:Alice", "/comment:test", "/homedir:\\\\srv\\home",
        "/profilepath:C:\\p", "/scriptpath:logon.bat", "/workstations:WS01",
        "/passwordreq:no", "/passwordchg:no", "/times:M-F,08:00-17:00",
        "/expires:12/31/2026", "/active:no", "/countrycode:081",
        "/usercomment:x", "/logonpasswordchg:yes",
    ]

    def test_no_modifying_switch_is_read_as_discovery(self):
        for sw in self.MODIFYING:
            with self.subTest(switch=sw):
                self.assertIsNone(self._tag(f"net.exe user alice {sw}"), sw)

    def test_an_unknown_switch_is_also_refused(self):
        """規則を書いた時点で知らなかったスイッチでも、列挙にはしない。

        許可リストにしたので、将来増えたスイッチにも自動で効く。
        """
        for sw in ("/futureoption:1", "/somethingnew", "/x:y"):
            with self.subTest(switch=sw):
                self.assertIsNone(self._tag(f"net.exe user alice {sw}"), sw)

    def test_only_the_three_allowed_shapes_are_discovery(self):
        self.assertEqual(self._tag("net.exe user")[0], "T1087.001")
        self.assertEqual(self._tag("net.exe user alice")[0], "T1087.001")
        self.assertEqual(self._tag("net.exe user /domain")[0], "T1087.002")
        self.assertEqual(self._tag("net.exe user alice /domain")[0], "T1087.002")
        self.assertEqual(self._tag("net.exe localgroup")[0], "T1069.001")
        self.assertEqual(self._tag("net.exe localgroup admins")[0], "T1069.001")
        self.assertEqual(self._tag("net.exe group")[0], "T1069.002")

    def test_groups_refuse_modifying_switches_too(self):
        for cmd in ("net.exe localgroup admins /comment:x",
                    "net.exe group devs /comment:x",
                    "net.exe localgroup admins bob /add"):
            with self.subTest(cmd=cmd):
                self.assertIsNone(self._tag(cmd), cmd)

    def test_add_still_wins_because_it_is_unambiguous(self):
        """`/add` は他のスイッチが付いていても作成であることが決まる。"""
        self.assertEqual(
            self._tag("net.exe user alice pw /add /fullname:Alice")[0],
            "T1136.001",
        )
        self.assertEqual(
            self._tag("net.exe user alice /add /domain /comment:x")[0],
            "T1136.002",
        )


class TestResizeShadowstorageIsNeverTagged(unittest.TestCase):
    """最大容量の変更であって、縮小とは限らない。

    `/maxsize=100GB` が縮小か拡大かは、変更前の割り当てが分からなければ
    決まらない。Microsoft の定義でも、控えが消えるのは「起こり得る」結果に
    過ぎない。この 1 行から縮小を示せない以上、復元の妨害と断定しない。
    """

    def _tag(self, cmd):
        return attck.PROCESS_RULES["vssadmin.exe"][1](attck.tokens(cmd))

    def test_no_size_is_ever_read_as_inhibiting_recovery(self):
        for size in ("100GB", "20GB", "5%", "unbounded", "1MB", "900GB"):
            with self.subTest(size=size):
                self.assertIsNone(
                    self._tag(f"vssadmin.exe resize shadowstorage "
                              f"/for=C: /on=C: /maxsize={size}"), size)

    def test_without_a_size_either(self):
        self.assertIsNone(self._tag("vssadmin.exe resize shadowstorage /for=C:"))

    def test_deleting_shadows_is_still_tagged(self):
        """締め付けただけで、断定できるものまで落としていないこと。"""
        got = self._tag("vssadmin.exe delete shadows /all /quiet")
        self.assertIsNotNone(got)
        self.assertEqual(got[0], "T1490")


class TestCorrelationDoesNotMaterialiseEveryRecord(unittest.TestCase):
    """相関の探索で、全行分の事象と証拠を作らない。

    完全な事象を作ると、1 件ごとに説明文・ATT&CK 判定・最大 1000 文字の
    抜粋・証拠表への登録が発生する。2 万行の合成ログでは、その追加分だけで
    ピークが 25 MiB 増えていた。パーサーは 1 ログ 20 万行まで許すので、
    想定内の入力でも効いてくる。
    """

    def _records(self, n):
        return parse_itm2("\n".join(
            itm2(f"10/05/2022 {9 + i // 3600:02d}:{i // 60 % 60:02d}:"
                 f"{i % 60:02d}.000 +0900", "WS99",
                 psPath=f"C:\\Windows\\System32\\p{i % 40}.exe",
                 cmd=f"p{i % 40}.exe --run {'x' * 300}")
            for i in range(n)), name=ENDPOINT)

    def test_candidates_do_not_touch_the_evidence_store(self):
        store = evidence.EvidenceStore()
        cands = explain.correlation_candidates(self._records(500))
        self.assertEqual(len(cands), 500)
        self.assertEqual(len(store.items), 0)

    def test_only_the_chosen_pair_is_registered(self):
        store = evidence.EvidenceStore()
        records = parse_itm2("\n".join([
            itm2("10/05/2022 09:00:00.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe"),
            itm2("10/05/2022 09:00:20.000 +0900", "WS99", evt="file",
                 sub="create", path="C:\\Users\\test\\a.dat"),
        ] + [
            itm2(f"10/05/2022 11:{i // 60:02d}:{i % 60:02d}.000 +0900", "WS99",
                 psPath=f"C:\\Windows\\System32\\other{i}.exe")
            for i in range(300)
        ]), name=ENDPOINT)
        cands = explain.correlation_candidates(records)
        self.assertEqual(len(cands), 302)
        quiz, why, pair = explain._correlation_quiz(store, cands, "q")
        self.assertIsNotNone(quiz, why)
        self.assertEqual(len(store.items), 2,
                         f"採用した 2 件以外も登録されている: {len(store.items)}")
        self.assertEqual(sorted(store.items), sorted(quiz["evidenceIds"]))

    def test_the_extra_peak_stays_small(self):
        """探索のために増えるメモリが、行数に対してわずかであること。

        解析そのものの保持量（全レコードを辞書として持つ）はこの検査の外。
        ここで見るのは「相関のために追加で積むもの」だけ。
        """
        import tracemalloc
        records = self._records(20_000)
        tracemalloc.start()
        before = tracemalloc.get_traced_memory()[0]
        store = evidence.EvidenceStore()
        cands = explain.correlation_candidates(records)
        explain._correlation_quiz(store, cands, "q")
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        added = (peak - before) / 2 ** 20
        self.assertEqual(len(cands), 20_000)
        self.assertLess(added, 8.0,
                        f"相関の探索で {added:.1f} MiB 増えている")

    def test_building_a_lesson_does_not_event_every_record(self):
        """教材の生成全体を通しても、事象を作る回数が行数に比例しないこと。

        メモリの実測だけでは、`build_lesson` の中で全行を事象化する実装へ
        戻してもすり抜ける（実際そうなった）。事象を作った回数そのものを
        数える。作ってよいのは、画面に出る一覧の分と、相関に採用した 2 件
        だけである。
        """
        lines = [
            itm2("10/05/2022 09:00:00.000 +0900", "WS99",
                 psPath="C:\\Windows\\System32\\cmd.exe"),
            itm2("10/05/2022 09:00:20.000 +0900", "WS99", evt="file",
                 sub="create", path="C:\\Users\\test\\a.dat"),
        ] + [
            # 同じ 20 本を繰り返し起動する。一覧は 20 件へ間引かれるので、
            # 「行数ぶん作っているか」と「間引いた数だけ作っているか」が
            # はっきり分かれる。
            itm2(f"10/05/2022 11:{i // 60:02d}:{i % 60:02d}.000 +0900", "WS99",
                 psPath=f"C:\\Windows\\System32\\p{i % 20}.exe")
            for i in range(2000)
        ]
        real = explain._lesson_event
        calls = []

        def counted(nev, store, readers=None):
            calls.append(nev.kind)
            return real(nev, store, readers)

        explain._lesson_event = counted
        try:
            lesson = build_lesson(
                "t", {ENDPOINT: "\n".join(lines)}, "gen-count")
        finally:
            explain._lesson_event = real
        self.assertIsNotNone(lesson)
        # 作ってよいのは、間引いたあとの一覧と、相関に採用した 2 件だけ。
        # 一覧は起動 21 種（cmd.exe と p0〜p19）とファイル 1 件で 22。
        # 合わせて 24 が上限で、2002 行に対して定数のままであること。
        distinct = 22
        self.assertLessEqual(
            len(calls), distinct + 2,
            f"{len(calls)} 回作っている（2002 行、一覧は {distinct} 件）")

    def test_host_key_sets_are_shared_between_records(self):
        """端末キーの集合を行ごとに作らない。ログに出る端末は数台しかない。"""
        cands = explain.correlation_candidates(self._records(500))
        self.assertEqual(len({id(c.correlation_keys) for c in cands}), 1)

    def test_candidates_reference_the_parsed_record_without_copying(self):
        records = self._records(50)
        cands = explain.correlation_candidates(records)
        by_id = {id(r) for r in records}
        for c in cands:
            self.assertIn(id(c), by_id, "レコードを複製している")
