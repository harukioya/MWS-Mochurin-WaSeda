"""Optional checks against real datasets, driven by a PRIVATE manifest.

    REAL_DATA_MANIFEST=/path/to/private-manifest.json \\
        python3 -m unittest backend.tests.test_real_data -v

Without the variable, the real-data class is skipped and nothing here needs
real data: CI never touches it.

This file knows nothing about any particular dataset. The manifest -- kept
outside Git, next to the site's own profiles -- says which archives to check,
which profile each should be detected as, and the minimum a lesson built from
it must reach. The manifest format is documented in the developer guide.

Rules this file holds itself to, because real datasets are often not
redistributable:

  * only the paths the manifest names are opened -- no directory is walked;
  * nothing from the data is written anywhere, snapshotted, or committed;
  * NOTHING FROM THE DATA OR THE MANIFEST REACHES A FAILURE MESSAGE. No
    password, log line, member name, profile id, or expected count. Archives
    are named by their position in the manifest ("archive #2");
  * an archive that is absent is skipped with a reason, so "not checked" never
    reads as "passed".

The third rule is enforced by construction: every check goes through
`_check`, which takes a bool. `unittest`'s own assertions report what they
compared, and a custom `msg` is APPENDED to that report rather than replacing
it -- so `assertNotIn(password, repr(failures))` prints the password the
moment it catches a regression. `TestTheHarnessLeaksNothing` runs this very
harness against a synthetic manifest with failing expectations and scans every
failure message for the secrets it planted. Because each archive stops at its
first failing check, that run cannot reach every message, so
`TestTheHarnessCannotLeakByConstruction` also reads the harness's source and
checks every message it could ever build.
"""

from __future__ import annotations

import ast
import fnmatch
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import attck  # noqa: E402
import dataset  # noqa: E402
import parsers  # noqa: E402
from archive import enumerate_zip  # noqa: E402
from explain import build_lesson  # noqa: E402

MANIFEST_ENV = "REAL_DATA_MANIFEST"


def _digest(obj) -> str:
    """中身を出さずに同一性だけを比べるための指紋。"""
    blob = json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def load_manifest(path: str) -> tuple[list[dict], list[str]]:
    """(archives, profile_dirs)。相対パスはマニフェストの場所から解決する。"""
    base = os.path.dirname(os.path.abspath(path))
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)

    def resolve(p: str) -> str:
        p = os.path.expanduser(p)
        return p if os.path.isabs(p) else os.path.normpath(os.path.join(base, p))

    dirs = [resolve(d) for d in raw.get("profileDirs") or []]
    archives = []
    for entry in raw.get("archives") or []:
        item = dict(entry)
        item["path"] = resolve(entry["path"])
        archives.append(item)
    return archives, dirs


class RealDataChecks:
    """マニフェストに書かれた実データを確かめる本体。unittest.TestCase と混ぜて使う。

    メッセージには、アーカイブの番号・検査項目・固定の符号（設問 id、失敗の
    理由の符号、役割名）だけを入れる。件数も入れない（期待値はマニフェストに
    あり、それ自体がデータセット固有の情報である）。
    """

    manifest_path: str = ""

    def _check(self, ok: bool, detail: str) -> None:
        """真偽値だけを受け取って判定する。比較は呼び出し側で済ませておく。"""
        if not ok:
            self.fail(detail)

    def _run_manifest(self) -> None:
        archives, dirs = load_manifest(self.manifest_path)
        catalog = dataset.load_catalog(dirs)
        self._check(not catalog.errors,
                    "マニフェストが指すプロファイルに、読み込めないものがあります")
        self._check(bool(archives), "マニフェストにアーカイブがありません")
        for index, entry in enumerate(archives, 1):
            with self.subTest(archive=index):
                if not os.path.isfile(entry["path"]):
                    self.skipTest(f"archive #{index} がありません")
                try:
                    self._check_archive(index, entry, catalog)
                except self.failureException:
                    raise
                except Exception as exc:  # noqa: BLE001 - 例外文は出さない
                    self.fail(f"archive #{index}: 検査中に {type(exc).__name__} が起きました")

    def _check_archive(self, i: int, entry: dict, catalog) -> None:
        tag = f"archive #{i}"
        names = [m.name for m in enumerate_zip(entry["path"]).members]

        # 1. プロファイルの判定が正しく、他のプロファイルに化けない。
        view = dataset.detect(names, profiles=catalog.profiles)
        self._check(not view.generic, f"{tag}: プロファイルを判定できませんでした")
        self._check(
            view.profile is not None and view.profile.id == entry.get("profileId"),
            f"{tag}: 期待したものと違うプロファイルが選ばれました",
        )
        self._check(not view.forced, f"{tag}: 自動判定のはずが forced になっています")
        rivals = sum(
            1 for p in catalog.profiles
            if p.id != entry.get("profileId")
            and dataset._score(names, p) >= dataset.MIN_OPTIONAL_RATIO
        )
        self._check(rivals == 0, f"{tag}: 別のプロファイルも同じZIPに強く一致しています")

        # 2. 問題ログがある。3. 平常時ログと取り違えていない。
        challenge = view.named("challenge")
        baseline = view.named("baseline")
        self._check(bool(challenge), f"{tag}: 問題ログが見つかりません")
        if entry.get("requireBaseline"):
            self._check(bool(baseline), f"{tag}: 平常時ログが見つかりません")
        self._check(not (set(challenge) & set(baseline)),
                    f"{tag}: 問題ログと平常時ログが重複しています")
        if entry.get("requireTool"):
            self._check(bool(view.named("tool")), f"{tag}: 同梱ツールが見当たりません")

        # 4. 問題ログにしてはならないもの（マニフェストがパターンで名指し）。
        never = entry.get("neverChallenge") or []
        mistaken = [n for n, r in view.roles.items()
                    if r == "challenge" and any(fnmatch.fnmatchcase(n, p) for p in never)]
        self._check(not mistaken, f"{tag}: 問題ログにしてはならないものが問題ログになっています")

        # 5. 同梱の案内からパスワード候補を検出できる。値は決して出さない。
        candidates: list[str] = []
        if entry.get("credential", "embedded") == "embedded":
            candidates = dataset.find_password_candidates(entry["path"], view)
            self._check(bool(candidates), f"{tag}: 同梱の案内からパスワード候補を見つけられません")

        # 6. 利用者の明示操作にあたる credential 指定のあとで読み取れる。
        read = dataset.read_logs(entry["path"], view, "challenge", candidates)
        self._check(len(read.sources) >= int(entry.get("minReadableLogs", 1)),
                    f"{tag}: 読み取れた問題ログが期待の本数に届きません"
                    f"（失敗の符号: {sorted({f['reason'] for f in read.failures})}）")
        if "exactReadableLogs" in entry:
            self._check(len(read.sources) == int(entry["exactReadableLogs"]),
                        f"{tag}: 読み取れた問題ログの本数が期待と違います")
        if entry.get("requireNoFailures"):
            self._check(not read.failures, f"{tag}: 読み取れなかった問題ログがあります")
        outsiders = [
            s for s in read.sources
            if view.roles.get(s.name, "challenge") != "challenge"
            or any(fnmatch.fnmatchcase(s.name, p) for p in never)
        ]
        self._check(not outsiders, f"{tag}: 問題ログ以外が教材の入力になっています")

        # 7. 読み取れなかったもの・未対応のものは理由付きで報告される。
        self._check(all(f.get("reason") and f.get("detail") for f in read.failures),
                    f"{tag}: 理由の無い読み取り失敗があります")
        self._check(all(r.get("label") and r.get("detail") for r in read.unsupported),
                    f"{tag}: 理由の無い未対応報告があります")
        self._check(all(view.roles[r["name"]] == "challenge" for r in read.unsupported),
                    f"{tag}: 未対応形式の役割が問題ログから変わっています")
        self._check(len(read.unsupported) == int(entry.get("expectUnsupported", 0)),
                    f"{tag}: 未対応形式の数が期待と違います")
        needle = entry.get("unsupportedLabelIncludes")
        if needle:
            self._check(all(needle in r["label"] for r in read.unsupported),
                        f"{tag}: 未対応形式の表示名が期待と違います")

        # 失敗しても鍵は出さない。比較はここで済ませ、真偽値だけを渡す。
        reported = repr(read.failures) + repr(read.unsupported)
        self._check(not any(c in reported for c in candidates),
                    f"{tag}: 認証情報が失敗情報へ混入しています")

        # 8. 同じ入力からは同じ教材になる。本体ではなく指紋で比べる。
        first = read.as_mapping
        second = dataset.read_logs(entry["path"], view, "challenge", candidates).as_mapping
        self._check(list(first) == list(second), f"{tag}: 2 回の読み取りで入力の並びが変わりました")
        lesson_a = build_lesson("t", first, "gen-local", parser_ids=view.parser_ids)
        lesson_b = build_lesson("t", second, "gen-local", parser_ids=view.parser_ids)
        self._check(lesson_a is not None, f"{tag}: 教材を作れませんでした")
        self._check(_digest(lesson_a) == _digest(lesson_b),
                    f"{tag}: 同じ入力から同じ教材になりません")

        # 9. 設問・証拠・ATT&CK・時系列の整合。10. 正解は引用行から読み直せる。
        self._check_lesson(tag, lesson_a, entry)

    def _check_lesson(self, tag: str, lesson: dict, entry: dict) -> None:
        store = lesson["evidence"]
        quizzes = [q for s in lesson["stages"] for q in (s.get("quizzes") or [])]
        self._check(len(quizzes) >= int(entry.get("minQuestions", 1)),
                    f"{tag}: 設問が期待の数に届きません")
        for quiz in quizzes:
            qid = quiz.get("id", "?")
            self._check(bool(quiz.get("evidenceIds")), f"{tag}: {qid} に根拠証拠がありません")
            self._check(all(i in store for i in quiz.get("evidenceIds", [])),
                        f"{tag}: {qid} の根拠証拠が教材にありません")
            self._check(all(o["evidenceId"] in store for o in quiz.get("options", [])
                            if isinstance(o, dict) and o.get("evidenceId")),
                        f"{tag}: {qid} の選択肢が実在しない証拠を指しています")
            self._check_answer(tag, quiz, store)

        def complete(item: dict) -> bool:
            src = item.get("source") or {}
            return bool(src.get("member") and isinstance(src.get("line"), int)
                        and src["line"] >= 1 and src.get("excerpt"))

        self._check(all(complete(v) for v in store.values()),
                    f"{tag}: 出典・行番号・原文のどれかが欠けた証拠があります")

        for technique in lesson["report"]["techniques"]:
            tid = technique.get("id") or "?"
            self._check(bool(technique.get("reason")), f"{tag}: {tid} に理由がありません")
            self._check(technique.get("ruleVersion") == attck.RULE_VERSION,
                        f"{tag}: {tid} の対応規則の版が想定と違います")
            self._check(bool(technique.get("evidenceIds"))
                        and all(i in store for i in technique["evidenceIds"]),
                        f"{tag}: {tid} の根拠証拠が欠けています")
        self._check(all(i in store for row in lesson["report"]["timeline"]
                        for i in row.get("evidenceIds", [])),
                    f"{tag}: 時系列が実在しない証拠を指しています")

        if entry.get("fullReport"):
            self._check(bool(lesson["introduction"].get("objectives")),
                        f"{tag}: 導入に学習目標がありません")
            report = lesson["report"]
            self._check(bool(report["timeline"]), f"{tag}: 最終レポートに時系列がありません")
            self._check(bool(report["techniques"]), f"{tag}: 最終レポートに ATT&CK がありません")
            self._check(bool(report["unknowns"]), f"{tag}: 最終レポートの未確定事項が空です")

    def _check_answer(self, tag: str, quiz: dict, store: dict) -> None:
        """正解を、引用した行から（その形式の読み方で）読み直せること。

        `evidence_pick` は正解の選択肢が根拠証拠そのものであること。
        `log-reading` は、正解の文字列が、登録済みのパーサーが引用行から
        読み直した事実のどれかと一致すること。部分一致では足りない。
        """
        qid = quiz.get("id", "?")
        options = quiz.get("options") or []
        correct = quiz.get("correct")
        self._check(isinstance(correct, int) and 0 <= correct < len(options),
                    f"{tag}: {qid} の正解の位置が選択肢の範囲外です")
        chosen = options[correct]
        if quiz.get("type") == "evidence_pick":
            self._check(isinstance(chosen, dict)
                        and chosen.get("evidenceId") == quiz["evidenceIds"][0]
                        and chosen["evidenceId"] in store,
                        f"{tag}: {qid} の正解が根拠証拠と食い違っています")
            return
        if quiz.get("category") != "log-reading":
            return
        item = store[quiz["evidenceIds"][0]]
        excerpt, kind = item["source"]["excerpt"], item["kind"]
        readable = set()
        for pid in parsers.REGISTRY.ids():
            parser = parsers.REGISTRY.get(pid)
            for fact in parsers.FACTS.get(kind, ()):
                reading = parser.reread(kind, fact, excerpt)
                if reading is not None and reading.value:
                    readable.add(reading.value)
        self._check(str(chosen) in readable,
                    f"{tag}: {qid} の正解を、引用行の項目として読み直せません")


@unittest.skipUnless(os.environ.get(MANIFEST_ENV),
                     f"set {MANIFEST_ENV} to run the optional real-data check")
class TestRealDataManifest(RealDataChecks, unittest.TestCase):
    """実データでの確認。マニフェストが無ければ何もしない。"""

    def setUp(self):
        self.manifest_path = os.environ[MANIFEST_ENV]

    def test_every_archive_in_the_manifest(self):
        self._run_manifest()


class TestTheHarnessLeaksNothing(unittest.TestCase):
    """上の検査が失敗したとき、データの中身が一文字も出ないこと。

    架空の「実データ」を作り、わざと満たせない期待値を書いたマニフェストで
    検査を走らせる。出てきた失敗文すべてを集め、仕込んだ秘密（鍵、ログの
    本文、メンバー名、プロファイル ID、期待値の数字）が現れないことを見る。
    """

    SECRET_KEY = "planted-secret-key-1b7f"
    SECRET_LINE = "planted-log-body-9c2e"
    SECRET_MEMBER = "planted-member-4d8a.log"
    SECRET_PROFILE = "planted-profile-6e1c"
    SECRET_COUNT = 987

    def _fixture(self, tmp: str) -> str:
        itm2 = (
            '10/05/2022 14:00:01.000 +0900 loc=en-US type=ITM2 sn=1 lv=5 evt=ps '
            f'subEvt=start os=Win com="WS99" psPath="C:\\W\\cmd.exe" note="{self.SECRET_LINE}"'
        )
        logs = io.BytesIO()
        with zipfile.ZipFile(logs, "w") as zf:
            zf.writestr(f"logs/{self.SECRET_MEMBER}", itm2 + "\n")
        archive = os.path.join(tmp, "case.zip")
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("case/evidence/logs.zip", logs.getvalue())
            zf.writestr("case/brief.md", f"logs.zip のパスワード: `{self.SECRET_KEY}`\n")
        profiles = os.path.join(tmp, "profiles")
        os.makedirs(profiles)
        with open(os.path.join(profiles, "p.json"), "w", encoding="utf-8") as fh:
            json.dump({
                "id": self.SECRET_PROFILE, "label": "Planted",
                "match": {"requiredPathPatterns": ["*/evidence/logs.zip"]},
                "roles": {"challenge": ["*/evidence/logs.zip", "*/evidence/logs.zip :: *"],
                          "narrative": ["*/*.md"]},
                "passwordHintPatterns": ["*/*.md"],
            }, fh)
        manifest = os.path.join(tmp, "manifest.json")
        with open(manifest, "w", encoding="utf-8") as fh:
            json.dump({
                "profileDirs": ["profiles"],
                "archives": [
                    # 満たせない期待値。検査は必ずどこかで失敗する。
                    {"path": "case.zip", "profileId": self.SECRET_PROFILE,
                     "minReadableLogs": self.SECRET_COUNT, "exactReadableLogs": self.SECRET_COUNT,
                     "requireBaseline": True, "requireTool": True,
                     "expectUnsupported": self.SECRET_COUNT, "minQuestions": self.SECRET_COUNT,
                     "fullReport": True, "neverChallenge": ["*"]},
                    # 別の ID を期待させて、判定の検査も落とす。
                    {"path": "case.zip", "profileId": "other-" + self.SECRET_PROFILE},
                    # 無いアーカイブは skip になる。
                    {"path": "missing.zip", "profileId": self.SECRET_PROFILE},
                ],
            }, fh)
        return manifest

    def test_failure_messages_carry_no_data(self):
        tmp = tempfile.mkdtemp()
        manifest = self._fixture(tmp)

        class Probe(RealDataChecks, unittest.TestCase):
            def test_run(self):
                self._run_manifest()

        Probe.manifest_path = manifest
        result = unittest.TestResult()
        unittest.defaultTestLoader.loadTestsFromTestCase(Probe).run(result)

        messages = [text for _test, text in result.failures + result.errors]
        self.assertTrue(messages, "前提が崩れている: 検査が 1 つも失敗していない")
        self.assertTrue(result.skipped, "無いアーカイブが skip になっていない")
        blob = "\n".join(messages) + "\n".join(reason for _t, reason in result.skipped)
        for secret in (self.SECRET_KEY, self.SECRET_LINE, self.SECRET_MEMBER,
                       self.SECRET_PROFILE, str(self.SECRET_COUNT),
                       os.path.basename(tmp)):
            with self.subTest(secret=secret[:12]):
                self.assertFalse(secret in blob, "失敗文にデータ由来の文字列が出ています")

    def test_the_real_data_class_is_skipped_without_a_manifest(self):
        if os.environ.get(MANIFEST_ENV):
            self.skipTest("マニフェストが指定されている環境では確かめられない")
        result = unittest.TestResult()
        unittest.defaultTestLoader.loadTestsFromTestCase(TestRealDataManifest).run(result)
        self.assertEqual(result.failures + result.errors, [])
        self.assertTrue(result.skipped)


class TestTheHarnessCannotLeakByConstruction(unittest.TestCase):
    """失敗文の組み立て方を、ソースそのものから確かめる。

    上の自己テストが見られるのは、実際に失敗した検査の文言だけである。各
    アーカイブは最初に失敗した検査で止まるので、後ろにある検査の文言は一度も
    組み立てられない。そこで `RealDataChecks` のすべての検査を静的に調べる。

      * unittest の assert* を使わない（比べた値を失敗文へ載せるため）
      * print しない
      * `_check` / `fail` / `skipTest` の文言は、文字列の定数か f 文字列で、
        差し込めるのは下の `SAFE` にある式だけ
    """

    #: 失敗文へ差し込んでよい式。どれもデータに由来しない。
    #: マニフェスト内の番号、生成した設問の id、規則が決める手法の id、
    #: 例外の型名、読み取り層が決める失敗の符号。
    SAFE = {
        "tag", "index", "qid", "tid",
        "type(exc).__name__",
        "sorted({f['reason'] for f in read.failures})",
    }
    REPORTERS = {"_check": 1, "fail": 0, "skipTest": 0}

    def _methods(self):
        with open(os.path.abspath(__file__), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        harness = next(n for n in tree.body
                       if isinstance(n, ast.ClassDef) and n.name == "RealDataChecks")
        # `_check` 自身は受け取った文言を渡すだけなので、対象から外す。
        return [n for n in harness.body
                if isinstance(n, ast.FunctionDef) and n.name != "_check"]

    def _calls(self):
        for method in self._methods():
            for node in ast.walk(method):
                if isinstance(node, ast.Call):
                    yield method.name, node

    def test_no_unittest_assertion_or_print(self):
        for method, call in self._calls():
            func = call.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            with self.subTest(method=method, line=call.lineno):
                self.assertFalse(name.startswith("assert"),
                                 "実データの検査に unittest の比較を使っています")
                self.assertNotEqual(name, "print", "実データの検査が print しています")

    def test_every_message_interpolates_only_safe_values(self):
        seen = 0
        for method, call in self._calls():
            func = call.func
            if not (isinstance(func, ast.Attribute) and func.attr in self.REPORTERS):
                continue
            seen += 1
            position = self.REPORTERS[func.attr]
            message = (call.args[position] if len(call.args) > position
                       else next((k.value for k in call.keywords
                                  if k.arg in ("detail", "msg", "reason")), None))
            with self.subTest(method=method, line=call.lineno):
                self.assertIsNotNone(message, "文言の無い検査があります")
                if isinstance(message, ast.Constant):
                    self.assertIsInstance(message.value, str)
                    continue
                self.assertIsInstance(message, ast.JoinedStr,
                                      "文言は定数か f 文字列で書きます")
                for part in message.values:
                    if isinstance(part, ast.FormattedValue):
                        self.assertIn(ast.unparse(part.value), self.SAFE,
                                      "失敗文に差し込めない値を使っています")
        # 検査が見つからないなら、この試験そのものが空回りしている。
        self.assertGreater(seen, 20)


if __name__ == "__main__":
    unittest.main()
