"""Profile tests: detection, roles, hints, reading, forcing -- on neutral fixtures.

NO REAL DATASET IS USED OR COMMITTED. The four profiles in
`fixtures/profiles/` are invented, and every archive here is built at run time
from invented hostnames, RFC 5737 documentation addresses and harmless
commands. Each fixture reproduces one STRUCTURE the dataset layer must handle,
not any particular distribution:

  example-incident  flat: evidence/logs.zip, reference/baseline.zip, tools/
  example-nested    the incident logs two containers deep, the hint one deep
  example-keyfile   the key is a bare token in a named file; NFD file names
  example-mixed     formats that can be classified but not parsed

They are loaded exactly the way site-specific profiles are loaded in
production: from an external directory, through the same validating loader.

The load-bearing assertions are the negative ones: no profile claims another's
archive, a tool's bundled sample is never a challenge log, quiet-period logs
never stand in for the real ones, and a format with no parser is reported,
not silently dropped.
"""

import io
import os
import subprocess
import sys
import tempfile
import unicodedata
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dataset  # noqa: E402
from archive import enumerate_zip  # noqa: E402

FIXTURE_PROFILE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "fixtures", "profiles"
)
FIXTURES = dataset.load_catalog([FIXTURE_PROFILE_DIR])
assert not FIXTURES.errors, FIXTURES.errors_json()

# 架空の端末名と RFC 5737 の文書用アドレスだけを使う。
ITM2 = "\n".join(
    [
        '10/05/2021 14:00:01.000 +0900 loc=en-US type=ITM2 sn=1 lv=5 evt=ps '
        'subEvt=start os=Win com="WS99" psPath="C:\\Windows\\explorer.exe" '
        'path="C:\\Windows\\System32\\cmd.exe"',
        '10/05/2021 14:00:02.000 +0900 loc=en-US type=ITM2 sn=2 lv=5 evt=ps '
        'subEvt=start os=Win com="WS99" psPath="C:\\Windows\\System32\\cmd.exe" '
        'path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"',
        '10/05/2021 14:00:03.000 +0900 loc=en-US type=ITM2 sn=3 lv=5 evt=file '
        'subEvt=create os=Win com="WS99" path="C:\\Users\\test\\AppData\\demo.dat"',
    ]
)
PROXY = (
    '192.0.2.10 - - [05/Oct/2021:14:00:07 +0900] '
    '"CONNECT 198.51.100.23:443 HTTP/1.1" 200 1588\n'
)
WEB_ACCESS = (
    '203.0.113.7 - - [05/Oct/2024:14:00:07 +0900] '
    '"GET /index.html HTTP/1.1" 200 120\n'
)
UNIX_LOG = "Oct  5 14:00:07 host02 sshd[1]: Accepted publickey for demo from 192.0.2.10\n"
BASELINE = ITM2.replace("WS99", "WS01").replace("cmd.exe", "notepad.exe")
TOOL_SAMPLE = ITM2.replace("WS99", "SAMPLE-HOST")

#: 架空の鍵。どのデータセットとも関係がない。
PASSWORD = "fixture-pass-not-real"

#: 散文の中に鍵を書く形の案内文。
NARRATIVE = (
    "# 演習用の問題文（架空）\n"
    "\n"
    f"logs.zip のパスワード: `{PASSWORD}`\n"
    "\n"
    "ユーザ名のパスワードを答えよ。\n"
    "フォーマット: `answer-format-not-a-password`\n"
)


def _has_zip_tool() -> bool:
    try:
        subprocess.run(["zip", "-h"], capture_output=True, check=False)
        return True
    except FileNotFoundError:
        return False


HAS_ZIP = _has_zip_tool()


def _zip_bytes(entries: dict[str, str], password: str | None = None) -> bytes:
    """Build a small ZIP in memory. Optionally ZipCrypto-encrypted.

    Python's zipfile can read ZipCrypto but cannot write it, so encryption is
    produced with the system `zip` tool when it is available.
    """
    if password is None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, text in entries.items():
                zf.writestr(name, text)
        return buf.getvalue()

    work = tempfile.mkdtemp()
    for name, text in entries.items():
        full = os.path.join(work, name)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as fh:
            fh.write(text)
    out = os.path.join(work, "out.zip")
    subprocess.run(
        ["zip", "-q", "-r", "-P", password, out] + list(entries),
        cwd=work, check=True, capture_output=True,
    )
    with open(out, "rb") as fh:
        return fh.read()


def _write(path: str, entries: dict[str, bytes | str]) -> str:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, payload in entries.items():
            zf.writestr(name, payload)
    return path


def names_of(path: str) -> list[str]:
    """Member names exactly as the scanner records them (`親 :: 子 :: 孫`).

    Uses the real enumerator rather than a local imitation: the whole point of
    a profile pattern is that it matches what `archive.py` actually produces.
    """
    return [m.name for m in enumerate_zip(path).members]


def detect(names, force_id=None):
    return dataset.detect(names, profiles=FIXTURES.profiles, force_id=force_id)


# ---------------------------------------------------------------------------
# 構造ごとの最小の ZIP
# ---------------------------------------------------------------------------


def build_incident(tmp: str, encrypted: bool = False) -> str:
    """平らな構造。問題ログ ZIP、平常時ログ、同梱ツール、散文の案内。"""
    logs = _zip_bytes(
        {"logs/ws99.log": ITM2, "logs/proxy01.log": PROXY},
        PASSWORD if encrypted else None,
    )
    return _write(os.path.join(tmp, "incident.zip"), {
        "example-incident/evidence/logs.zip": logs,
        "example-incident/reference/baseline.zip": _zip_bytes({"baseline/WS01.log": BASELINE}),
        "example-incident/brief.md": NARRATIVE,
        "example-incident/tools/sample.log": TOOL_SAMPLE,
        "example-incident/tools/README.md": "# 同梱ツールの説明（架空）\n",
        "example-incident/other-task/solution.csv": "a,b\n1,2\n",
    })


def build_nested(tmp: str, encrypted: bool = False) -> str:
    """問題ログが入れ物の二段奥にあり、案内文は一段奥にある。"""
    logs = _zip_bytes(
        {"host/ws99.log": ITM2, "net/access.log": PROXY},
        PASSWORD if encrypted else None,
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("incident/logs.zip", logs)
        zf.writestr("incident/baseline.zip", _zip_bytes({"host/ws01.log": BASELINE}))
        zf.writestr("incident/brief.md", NARRATIVE)
        zf.writestr("incident/diagram.png", "x")
        zf.writestr("incident/tools/sample.log", TOOL_SAMPLE)
        zf.writestr("incident/tools/README.md", "# 同梱ツールの説明（架空）\n")
    return _write(os.path.join(tmp, "nested.zip"), {
        "nested-case/incident-bundle.zip": buf.getvalue(),
        "nested-case/other-task.zip": _zip_bytes({"other/notes.md": "# 別課題（架空）\n"}),
    })


def build_keyfile(tmp: str, encrypted: bool = False) -> str:
    """鍵だけが書かれたファイル。平常時ログの名前に濁点つきの文字を含む。"""
    logs = _zip_bytes(
        {"logs/ws01.log": ITM2, "logs/proxy.log": PROXY},
        PASSWORD if encrypted else None,
    )
    return _write(os.path.join(tmp, "keyfile.zip"), {
        "keyfile-case/evidence/challenge-logs.zip": logs,
        "keyfile-case/evidence/challenge-logs_password.txt": PASSWORD + "\n",
        "keyfile-case/reference/ベースライン.zip": _zip_bytes({"WS02.log": BASELINE}),
        "keyfile-case/tools.zip": _zip_bytes({
            "tools/sample.log": TOOL_SAMPLE, "tools/README.md": "# ツール（架空）\n",
        }),
        "keyfile-case/brief.pdf": "%PDF-1.4\n",
        "keyfile-case/presentations/demo.pdf": "%PDF-1.4\n",
    })


def build_mixed(tmp: str, encrypted: bool = False) -> str:
    """分類はできるが解析できない形式が、問題ログに混ざる。"""
    logs = _zip_bytes(
        {
            "case/host01.log": ITM2,
            "case/proxy.log": PROXY,
            "case/web/access.log": WEB_ACCESS,
            "case/web/error.log": "[Sat Oct 05 14:00:07 2024] [error] demo\n",
            "case/unix/syslog.log": UNIX_LOG,
            "case/credential.bin": "x",
            "case/Readme": "架空の説明\n",
        },
        PASSWORD if encrypted else None,
    )
    return _write(os.path.join(tmp, "mixed.zip"), {
        "mixed-case/evidence/case.zip": logs,
        "mixed-case/evidence/case-key.txt": PASSWORD + "\n",
        "mixed-case/reference/baseline.zip": _zip_bytes({"WS02.log": BASELINE}),
        "mixed-case/tools.zip": _zip_bytes({"tools/sample.log": TOOL_SAMPLE}),
        "mixed-case/brief.pdf": "%PDF-1.4\n",
        "mixed-case/other-task/solution.csv": "a,b\n1,2\n",
        "__MACOSX/mixed-case/._tools.zip": "\x00",
        "mixed-case/evidence/._case-key.txt": "\x00",
    })


BUILDERS = {
    "example-incident": build_incident,
    "example-nested": build_nested,
    "example-keyfile": build_keyfile,
    "example-mixed": build_mixed,
}


class ProfileCase(unittest.TestCase):
    """Small helpers shared by the per-profile cases."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def view_for(self, profile_id: str, encrypted: bool = False):
        path = BUILDERS[profile_id](self.tmp, encrypted)
        return path, detect(names_of(path))

    def role_of(self, view, suffix: str) -> str:
        for name, role in view.roles.items():
            if name.endswith(suffix):
                return role
        raise AssertionError(f"not found: {suffix}\n" + "\n".join(sorted(view.roles)))


class TestProfileDetection(ProfileCase):
    """Each fixture archive must pick its own profile and nobody else's."""

    def test_each_profile_is_recognised(self):
        for ident in BUILDERS:
            with self.subTest(profile=ident):
                _path, view = self.view_for(ident)
                self.assertFalse(view.generic, f"{ident} fell back to generic mode")
                self.assertEqual(view.profile.id, ident)
                self.assertFalse(view.forced)

    def test_no_profile_matches_another_profiles_archive(self):
        """The negative half, stated for every ordered pair.

        With several profiles loaded at once, a pattern that is a little too
        loose does not break its own archive -- it quietly claims another one.
        """
        for ident, build in BUILDERS.items():
            names = names_of(build(self.tmp))
            for profile in FIXTURES.profiles:
                if profile.id == ident:
                    continue
                with self.subTest(archive=ident, profile=profile.id):
                    self.assertLess(
                        dataset._score(names, profile),
                        dataset.MIN_OPTIONAL_RATIO,
                        f"{profile.id} claims the {ident} archive",
                    )

    def test_detection_is_not_decided_by_file_order(self):
        """A tie must be refused, not settled by whichever file sorts first."""
        names = names_of(build_keyfile(self.tmp))
        original = FIXTURES.get("example-keyfile")
        clone = dataset.Profile.from_json({
            "id": "zz-clone", "label": "同点の別候補",
            "match": {
                "requiredPathPatterns": original.required,
                "optionalNamePatterns": original.optional,
            },
            "roles": original.roles,
        })
        view = dataset.detect(names, profiles=[original, clone])
        self.assertTrue(view.generic, "a tie must not be resolved silently")
        self.assertTrue(any("同じ一致度" in w for w in view.warnings), view.warnings)

    def test_a_decomposable_pattern_matches_a_decomposed_name(self):
        """macOS writes member names decomposed; patterns are written composed.

        「ベ」is 「ヘ」＋濁点 in NFD. Byte-for-byte those never compare equal,
        and `fnmatch` has no idea about Unicode equivalence, so the obvious
        spelling of a pattern would silently match nothing and the archive would
        quietly fall back to generic mode. Normalising both sides in
        `_matches_any` is what makes the obvious spelling work.
        """
        composed = "keyfile-case/reference/ベースライン.zip"
        decomposed = unicodedata.normalize("NFD", composed)
        self.assertNotEqual(composed, decomposed, "the fixture must exercise NFD")

        pattern = "*/reference/ベースライン*.zip"
        self.assertTrue(dataset._matches_any(composed, [pattern]))
        self.assertTrue(
            dataset._matches_any(decomposed, [pattern]),
            "a decomposed member name must still match a composed pattern",
        )

        # 分類と採点の両方が同じ規則を通ること。
        profile = dataset.Profile.from_json({
            "id": "t", "label": "t",
            "match": {"requiredPathPatterns": [pattern]},
            "roles": {"baseline": [pattern]},
        })
        self.assertEqual(dataset._score([decomposed], profile), 1.0)
        self.assertEqual(dataset.classify([decomposed], profile)[decomposed], "baseline")

    def test_a_decomposed_archive_is_still_recognised(self):
        path = build_keyfile(self.tmp)
        decomposed = [unicodedata.normalize("NFD", n) for n in names_of(path)]
        view = detect(decomposed)
        self.assertEqual(view.profile.id, "example-keyfile")
        self.assertTrue(view.named("challenge"))
        self.assertTrue(view.named("baseline"))

    def test_an_unrelated_archive_is_still_generic(self):
        path = os.path.join(self.tmp, "plain.zip")
        _write(path, {"holiday/photo.jpg": "x", "holiday/notes.txt": "y"})
        view = detect(names_of(path))
        self.assertTrue(view.generic)
        self.assertEqual(view.named("challenge"), [])


class TestRoles(ProfileCase):
    """Role classification, structure by structure."""

    def test_three_level_nesting(self):
        _path, view = self.view_for("example-nested")
        self.assertEqual(self.role_of(view, "logs.zip :: host/ws99.log"), "challenge")
        self.assertEqual(self.role_of(view, "logs.zip :: net/access.log"), "challenge")
        self.assertEqual(self.role_of(view, "baseline.zip :: host/ws01.log"), "baseline")
        self.assertEqual(self.role_of(view, "incident/brief.md"), "narrative")
        self.assertEqual(self.role_of(view, "incident/tools/sample.log"), "tool")
        self.assertEqual(self.role_of(view, "incident/tools/README.md"), "tool")
        self.assertEqual(self.role_of(view, "other/notes.md"), "unrelated")

    def test_keyfile_roles(self):
        _path, view = self.view_for("example-keyfile")
        self.assertEqual(self.role_of(view, "challenge-logs.zip :: logs/ws01.log"), "challenge")
        self.assertEqual(self.role_of(view, "ベースライン.zip :: WS02.log"), "baseline")
        self.assertEqual(self.role_of(view, "tools.zip :: tools/sample.log"), "tool")
        self.assertEqual(self.role_of(view, "_password.txt"), "narrative")
        self.assertEqual(self.role_of(view, "presentations/demo.pdf"), "unrelated")

    def test_mixed_roles(self):
        _path, view = self.view_for("example-mixed")
        self.assertEqual(self.role_of(view, "case.zip :: case/host01.log"), "challenge")
        self.assertEqual(self.role_of(view, "case.zip :: case/web/access.log"), "challenge")
        self.assertEqual(self.role_of(view, "case.zip :: case/unix/syslog.log"), "challenge")
        self.assertEqual(self.role_of(view, "case.zip :: case/credential.bin"), "artifact")
        self.assertEqual(self.role_of(view, "case.zip :: case/Readme"), "narrative")
        self.assertEqual(self.role_of(view, "baseline.zip :: WS02.log"), "baseline")
        self.assertEqual(self.role_of(view, "tools.zip :: tools/sample.log"), "tool")
        self.assertEqual(self.role_of(view, "other-task/solution.csv"), "unrelated")

    def test_macosx_and_appledouble_are_ignored(self):
        _path, view = self.view_for("example-mixed")
        self.assertEqual(self.role_of(view, "__MACOSX/mixed-case/._tools.zip"), "ignore")
        self.assertEqual(self.role_of(view, "evidence/._case-key.txt"), "ignore")

    def test_a_bundled_sample_is_never_a_challenge_log(self):
        """The regression this whole layer exists to prevent, for every profile."""
        for ident in BUILDERS:
            with self.subTest(profile=ident):
                _path, view = self.view_for(ident)
                hits = [n for n in view.roles if "sample.log" in n]
                self.assertTrue(hits, f"{ident} fixture lost its tool sample")
                for name in hits:
                    self.assertNotEqual(view.roles[name], "challenge", name)

    def test_baseline_is_never_a_challenge_log(self):
        for ident in BUILDERS:
            with self.subTest(profile=ident):
                _path, view = self.view_for(ident)
                self.assertTrue(view.named("baseline"))
                self.assertFalse(set(view.named("challenge")) & set(view.named("baseline")))


class TestUnsupportedFormats(ProfileCase):
    """"Classified but we have no parser" is its own answer, not silence."""

    def test_web_server_logs_are_flagged_not_dropped(self):
        _path, view = self.view_for("example-mixed")
        flagged = [n for n in view.unsupported if "/web/" in n]
        self.assertEqual(len(flagged), 2, view.unsupported)
        for name in flagged:
            # 役割は問題ログのまま。分類できなかったのではなく、読む仕組みが
            # 無いだけ、という区別をここで固定する。
            self.assertEqual(view.roles[name], "challenge", name)
            self.assertIn("Web サーバー", view.unsupported[name]["label"])

    def test_unix_logs_are_flagged_not_dropped(self):
        _path, view = self.view_for("example-mixed")
        flagged = [n for n in view.unsupported if "/unix/" in n]
        self.assertEqual(len(flagged), 1, view.unsupported)
        self.assertEqual(view.roles[flagged[0]], "challenge")
        self.assertIn("Unix", view.unsupported[flagged[0]]["label"])

    def test_profiles_without_unsupported_formats_report_none(self):
        for ident in ("example-incident", "example-nested", "example-keyfile"):
            with self.subTest(profile=ident):
                _path, view = self.view_for(ident)
                self.assertEqual(view.unsupported, {})

    def test_unsupported_logs_are_not_fed_to_the_lesson(self):
        """A web server access line matches the proxy parser, so it is refused.

        The two formats share the common-log shape, so feeding the web log
        through the proxy parser produces events that look right and mean
        something else: a request served BY the server, taught as a request
        made THROUGH a proxy. Wrong-but-plausible is worse than absent.
        """
        path, view = self.view_for("example-mixed")
        read = dataset.read_logs(path, view, "challenge", [])
        used = {s.name for s in read.sources}
        self.assertTrue(used)
        self.assertFalse([n for n in used if "/web/" in n or "/unix/" in n])
        self.assertEqual(len(read.unsupported), 3, read.unsupported)
        for row in read.unsupported:
            self.assertTrue(row["detail"])

    def test_the_summary_keeps_role_and_format_separate(self):
        _path, view = self.view_for("example-mixed")
        rows = [{"name": n, "size": 1, "verdict": "inert-data"} for n in view.roles]
        body = dataset.summarise(view, rows, catalog=FIXTURES)
        web = [m for m in body["members"]["challenge"] if "/web/" in m["name"]]
        self.assertEqual(len(web), 2)
        for entry in web:
            self.assertIn("Web サーバー", entry["unsupported"])
        self.assertEqual(len(body["unsupported"]), 3)
        self.assertIn("InfoTrace Mark II（端末の記録）", body["parserLabels"])
        self.assertEqual(body["edition"], "fixture v2")
        self.assertEqual(body["metadata"], {"producer": "test suite"})


class TestPasswordHints(ProfileCase):
    """Two shapes of hint, one rule: never guess, never echo the value."""

    def test_a_hint_one_container_down(self):
        path, view = self.view_for("example-nested")
        self.assertIn(PASSWORD, dataset.find_password_candidates(path, view))

    def test_bare_password_files_are_read_whole(self):
        """Some datasets put the key in a file with no prose around it.

        The prose detector needs a keyword and a quoted token on the same line,
        and finds nothing in a file whose entire content is the key. The
        profile names those files explicitly; nothing is inferred from size or
        from a word in a filename.
        """
        for ident in ("example-keyfile", "example-mixed"):
            with self.subTest(profile=ident):
                path, view = self.view_for(ident)
                self.assertIn(PASSWORD, dataset.find_password_candidates(path, view))

    def test_a_password_file_is_only_read_when_the_profile_names_it(self):
        self.assertIsNone(dataset.password_from_password_file("two words here"))
        self.assertIsNone(dataset.password_from_password_file(""))
        self.assertIsNone(dataset.password_from_password_file("ab"))
        self.assertEqual(
            dataset.password_from_password_file("  single-token \n"), "single-token"
        )

    def test_hint_containers_are_limited_to_the_profile(self):
        """Only the profile that names an inner container gets it opened."""
        for profile in FIXTURES.profiles:
            with self.subTest(profile=profile.id):
                expected = profile.id == "example-nested"
                self.assertEqual(bool(profile.password_hint_containers), expected)

    def test_no_candidate_value_reaches_the_summary(self):
        for ident in BUILDERS:
            with self.subTest(profile=ident):
                _path, view = self.view_for(ident)
                rows = [{"name": n, "size": 1, "verdict": "inert-data"} for n in view.roles]
                self.assertNotIn(PASSWORD, repr(dataset.summarise(view, rows, catalog=FIXTURES)))


@unittest.skipUnless(HAS_ZIP, "system `zip` is needed to build an encrypted fixture")
class TestEncryptedReadingPerProfile(ProfileCase):
    """The whole point: the real logs are often the encrypted ones."""

    def test_each_profile_reads_its_challenge_logs_after_an_explicit_credential(self):
        for ident in BUILDERS:
            with self.subTest(profile=ident):
                path, view = self.view_for(ident, encrypted=True)
                candidates = dataset.find_password_candidates(path, view)
                self.assertTrue(candidates, f"{ident}: no hint found")
                read = dataset.read_logs(path, view, "challenge", candidates)
                self.assertTrue(read.sources, f"{ident}: {read.failures}")
                self.assertEqual(read.failures, [], f"{ident}: {read.failures}")
                for source in read.sources:
                    self.assertNotIn("sample.log", source.name)
                    self.assertNotIn("baseline", source.name.lower())

    def test_nothing_is_read_without_a_credential(self):
        """A hint being present is not the same as the person asking for it."""
        for ident in BUILDERS:
            with self.subTest(profile=ident):
                path, view = self.view_for(ident, encrypted=True)
                read = dataset.read_logs(path, view, "challenge", [])
                self.assertEqual(read.sources, [])
                self.assertTrue(read.failures)
                for failure in read.failures:
                    self.assertEqual(failure["reason"], "password-required")

    def test_a_wrong_key_never_leaks_its_value(self):
        path, view = self.view_for("example-keyfile", encrypted=True)
        read = dataset.read_logs(path, view, "challenge", ["not-the-key"])
        blob = repr(read.failures)
        self.assertNotIn("not-the-key", blob)
        self.assertNotIn(PASSWORD, blob)

    def test_reads_are_deterministic(self):
        for ident in BUILDERS:
            with self.subTest(profile=ident):
                path, view = self.view_for(ident, encrypted=True)
                cands = dataset.find_password_candidates(path, view)
                a = dataset.read_logs(path, view, "challenge", cands).as_mapping
                b = dataset.read_logs(path, view, "challenge", cands).as_mapping
                self.assertEqual(list(a), list(b))
                self.assertEqual(a, b)


class TestNestedReading(ProfileCase):
    """Reading has to follow the same nesting the scanner recorded."""

    def test_reads_through_two_containers(self):
        """`親 :: 子 :: 孫`: splitting the name once looked for a child that
        does not exist, and logs two containers deep were never read."""
        path, view = self.view_for("example-nested")
        read = dataset.read_logs(path, view, "challenge", [])
        names = sorted(s.name for s in read.sources)
        self.assertEqual(len(names), 2, read.failures)
        for name in names:
            self.assertEqual(name.count(" :: "), 2, name)
            self.assertIn("logs.zip", name)

    def test_nesting_stops_at_the_scanner_s_own_depth(self):
        import archive

        self.assertEqual(dataset.MAX_CONTAINER_DEPTH, 3)
        self.assertEqual(dataset.MAX_CONTAINER_DEPTH, archive.MAX_DEPTH)

    def test_an_unlisted_container_never_falls_back_to_every_log(self):
        """If the scan could not enumerate a container, do not read it blind.

        "Everything ending in .log inside" would pick up `tools/sample.log`
        from the bundle -- exactly the defect this layer removes. The fallback
        re-runs the profile over the name it would use, and reads only what the
        profile itself calls a challenge log.
        """
        path = build_nested(self.tmp)
        view = detect(names_of(path))
        bundle = next(n for n in view.roles if n.endswith("incident-bundle.zip"))
        view.roles = {bundle: "challenge"}
        read = dataset.read_logs(path, view, "challenge", [])
        self.assertEqual(read.sources, [], [s.name for s in read.sources])

    def test_the_fallback_still_reads_a_pure_challenge_container(self):
        path = build_incident(self.tmp)
        view = detect(names_of(path))
        self.assertEqual(view.profile.id, "example-incident")
        view.roles = {"example-incident/evidence/logs.zip": "challenge"}
        read = dataset.read_logs(path, view, "challenge", [])
        self.assertEqual(len(read.sources), 2, read.failures)
        for source in read.sources:
            self.assertNotIn("sample.log", source.name)


class TestForcedProfile(ProfileCase):
    """The person may override the format; the record must say that they did."""

    def test_forcing_marks_the_result(self):
        names = names_of(build_keyfile(self.tmp))
        self.assertFalse(detect(names).forced)
        forced = detect(names, force_id="example-mixed")
        self.assertTrue(forced.forced)
        self.assertEqual(forced.profile.id, "example-mixed")
        self.assertTrue(forced.warnings, "a weak forced match must say so")

    def test_forcing_the_right_profile_classifies_normally(self):
        for ident, build in BUILDERS.items():
            with self.subTest(profile=ident):
                view = detect(names_of(build(self.tmp)), force_id=ident)
                self.assertTrue(view.forced)
                self.assertTrue(view.named("challenge"))

    def test_an_unknown_profile_is_refused(self):
        names = names_of(build_mixed(self.tmp))
        with self.assertRaises(dataset.UnknownProfile):
            detect(names, force_id="example-missing")

    def test_every_loaded_profile_can_be_forced(self):
        """`choices()` is what the screen offers; every entry must be usable."""
        names = names_of(build_nested(self.tmp))
        for choice in FIXTURES.choices():
            with self.subTest(profile=choice["id"]):
                view = detect(names, force_id=choice["id"])
                self.assertEqual(view.profile.id, choice["id"])
                self.assertTrue(view.forced)

    def test_the_choice_list_follows_the_declared_order(self):
        """表示順（order）、label、id の順。年度のような特別な並びは無い。"""
        ids = [c["id"] for c in FIXTURES.choices()]
        self.assertEqual(
            ids, ["example-incident", "example-nested", "example-keyfile", "example-mixed"]
        )
        for choice in FIXTURES.choices():
            self.assertEqual(set(choice), {"id", "label", "edition"})


class TestGenericModeStillWorks(ProfileCase):
    """No profile claiming the archive is a normal outcome."""

    def test_a_plain_archive_of_logs_is_generic_and_claims_nothing(self):
        path = _write(os.path.join(self.tmp, "plain.zip"), {
            "stuff/server.log": ITM2, "stuff/notes.md": "# メモ\n",
        })
        view = detect(names_of(path))
        self.assertTrue(view.generic)
        self.assertEqual(view.label, dataset.GENERIC_LABEL)
        self.assertEqual(view.named("challenge"), [])
        self.assertEqual(self.role_of(view, "stuff/notes.md"), "narrative")

    def test_generic_mode_reads_nothing_by_itself(self):
        path = _write(os.path.join(self.tmp, "plain.zip"), {"stuff/server.log": ITM2})
        view = detect(names_of(path))
        self.assertEqual(dataset.read_logs(path, view, "challenge", []).sources, [])

    def test_a_similar_archive_from_an_unknown_source_stays_generic(self):
        path = _write(os.path.join(self.tmp, "future.zip"), {
            "future-case/evidence/something.log": ITM2,
            "future-case/evidence/notes.md": "# メモ\n",
        })
        view = detect(names_of(path))
        self.assertTrue(view.generic)
        self.assertEqual(view.named("challenge"), [])


class HandlerCase(ProfileCase):
    """Drive `_generate_with` with the store and integrity re-check stubbed.

    Exercises the real handler body without a socket or a database. What is
    pinned is the SHAPE of the reply and of the saved lesson.
    """

    def _run(self, path: str, payload: dict, profiles=None):
        import api

        profiles = FIXTURES.profiles if profiles is None else profiles
        handler = api.Handler.__new__(api.Handler)
        names = names_of(path)
        handler._dataset_for = lambda _id, forced=None: (
            dataset.detect(names, profiles=profiles, force_id=forced),
            [{"name": n} for n in names],
        )
        handler._json = lambda obj, code=200: (code, obj)
        handler._error = lambda code, msg: (code, {"error": msg})
        handler._recheck = lambda _fh, _row: True

        saved: list = []
        real_state = api.STATE

        class Store:
            def save_lesson(self, lesson, base):
                saved.append((lesson, base))

        class State:
            store = Store()

        api.STATE = State()
        try:
            with open(path, "rb") as fh:
                code, body = api.Handler._generate_with(
                    handler, payload, 1, {"path": path, "sha256": "0" * 64}, fh
                )
        finally:
            api.STATE = real_state
        return code, body, saved


class TestGenerateHandlerReporting(HandlerCase):

    def test_unsupported_is_reported_apart_from_unreadable(self):
        """Different problems need different words.

        「読み取れなかった」 invites another password attempt;
        「専用解析が未対応」 says no attempt will help. Putting the web log in
        the first list sends someone to retype a key for a log that was never
        going to be read.
        """
        path = build_mixed(self.tmp)
        code, body, saved = self._run(path, {"archive": 1})
        self.assertEqual(code, 200, body)
        ds = body["dataset"]
        self.assertEqual(ds["unreadable"], [], ds["unreadable"])
        self.assertEqual(len(ds["unsupported"]), 3, ds["unsupported"])
        self.assertTrue(ds["incomplete"], "未対応が残る教材は完全とは言えない")
        self.assertEqual(ds["profileId"], "example-mixed")
        self.assertEqual(ds["edition"], "fixture v2")
        self.assertFalse(ds["forced"])
        self.assertNotIn("year", ds)

        lesson, _base = saved[0]
        topics = [u["topic"] for u in lesson["report"]["unknowns"]]
        self.assertIn("専用解析が未対応のログ", topics)
        self.assertEqual(lesson["introduction"]["dataset"]["unsupported"], 3)
        self.assertTrue(lesson["introduction"]["dataset"]["incomplete"])
        self.assertNotIn("year", lesson["introduction"]["dataset"])

    def test_a_complete_read_is_not_marked_incomplete(self):
        """The flag has to mean something, so it must be able to be false."""
        path = build_keyfile(self.tmp)
        code, body, _saved = self._run(path, {"archive": 1})
        self.assertEqual(code, 200, body)
        ds = body["dataset"]
        self.assertEqual(ds["unreadable"], [])
        self.assertEqual(ds["unsupported"], [])
        self.assertEqual(ds["unrecognized"], [])
        self.assertFalse(ds["incomplete"])
        self.assertEqual(ds["parserLabels"],
                         ["InfoTrace Mark II（端末の記録）", "Proxy（通信の記録）"])
        self.assertEqual(ds["parsing"]["parsers"], ["itm2", "proxy"])

    def test_a_forced_profile_is_recorded_in_the_lesson(self):
        """Whoever reads the lesson later must be able to tell who chose."""
        path = build_mixed(self.tmp)
        code, body, saved = self._run(path, {"archive": 1, "profileId": "example-mixed"})
        self.assertEqual(code, 200, body)
        self.assertTrue(body["dataset"]["forced"])
        lesson, _base = saved[0]
        self.assertTrue(lesson["introduction"]["dataset"]["forced"])

    def test_automatic_and_forced_stay_consistent(self):
        """自動判定なら画面・生成結果・導入がどれも forced=False。指定なら True。"""
        path = build_incident(self.tmp)
        for payload, want in (({"archive": 1}, False),
                              ({"archive": 1, "profileId": "example-incident"}, True)):
            with self.subTest(payload=payload):
                _code, body, saved = self._run(path, payload)
                lesson = saved[-1][0]
                self.assertEqual(body["dataset"]["forced"], want)
                self.assertEqual(lesson["dataset"]["forced"], want)
                self.assertEqual(lesson["introduction"]["dataset"]["forced"], want)

    def test_an_unknown_profile_is_refused_with_400(self):
        path = build_keyfile(self.tmp)
        code, body, saved = self._run(path, {"archive": 1, "profileId": "example-missing"})
        self.assertEqual(code, 400, body)
        self.assertEqual(saved, [], "拒否したのに教材が保存されています")

    def test_the_baseline_logs_are_named_but_never_used(self):
        path = build_keyfile(self.tmp)
        _code, body, _saved = self._run(path, {"archive": 1})
        ds = body["dataset"]
        self.assertTrue(ds["baselineIdentified"])
        for name in ds["challengeInputs"]:
            self.assertNotIn("ベースライン", name)
        for name in ds["baselineIdentified"]:
            self.assertNotIn(name, ds["challengeInputs"])


class TestZeroProfiles(HandlerCase):
    """公開版はプロファイルを 1 件も同梱しない。それでも最後まで動く。"""

    def test_detection_and_summary_work_with_no_profiles(self):
        path = build_incident(self.tmp)
        view = dataset.detect(names_of(path), profiles=[])
        self.assertTrue(view.generic)
        rows = [{"name": n, "size": 1, "verdict": "inert-data"} for n in view.roles]
        body = dataset.summarise(view, rows, catalog=dataset.ProfileCatalog())
        self.assertEqual(body["profiles"], [])
        self.assertIsNone(body["profileId"])
        self.assertEqual(body["label"], dataset.GENERIC_LABEL)
        # 汎用解析の候補は、自動判定に参加するパーサーだけ。Proxy は内容だけ
        # では形式を言い切れないので、プロファイルで明示されたときだけ使う。
        self.assertEqual(body["parsers"], ["itm2"])
        self.assertEqual(body["explicitOnlyLabels"], ["Proxy（通信の記録）"])

    def test_generic_analysis_builds_a_lesson_with_no_profiles(self):
        """プロファイルが一致しないのは正常系。汎用解析で教材まで届く。"""
        path = _write(os.path.join(self.tmp, "plain.zip"), {
            "case/host.log": ITM2,
            "case/proxy.log": PROXY,
            "case/app.log": "2026-01-01 something happened in an unknown format\n",
        })
        code, body, saved = self._run(path, {"archive": 1}, profiles=[])
        self.assertEqual(code, 200, body)
        ds = body["dataset"]
        self.assertTrue(ds["generic"])
        self.assertIsNone(ds["profileId"])
        self.assertEqual(ds["label"], dataset.GENERIC_LABEL)
        self.assertFalse(ds["forced"])
        # 読めた形式と、どのパーサーでも読めなかったものを分けて残す。
        # プロキシ形の行は、プロファイルの明示が無いので通信として扱わず、
        # 「通信の向きを断定できない」として別に残す。
        self.assertEqual(ds["parsing"]["parsers"], ["itm2"])
        self.assertEqual(ds["unrecognized"], ["case/app.log", "case/proxy.log"])
        self.assertEqual(ds["explicitOnly"], {"case/proxy.log": ["proxy"]})
        self.assertTrue(ds["incomplete"])
        lesson = saved[0][0]
        self.assertTrue(lesson["stages"])
        self.assertNotIn("network", [s["id"] for s in lesson["stages"]])
        topics = [u["topic"] for u in lesson["report"]["unknowns"]]
        self.assertIn("形式を判別できなかったログ", topics)
        self.assertIn("通信の向きを断定できないログ", topics)

    def test_a_profile_that_names_proxy_reads_the_proxy_log(self):
        """プロキシの記録だと人が明示したときは、通信として読む。"""
        path = build_incident(self.tmp)
        code, body, saved = self._run(path, {"archive": 1})
        self.assertEqual(code, 200, body)
        ds = body["dataset"]
        self.assertEqual(ds["profileId"], "example-incident")
        self.assertIn("proxy", ds["parsing"]["parsers"])
        self.assertEqual(ds["explicitOnly"], {})
        proxy_logs = [n for n, ids in ds["parsing"]["recognized"].items() if "proxy" in ids]
        self.assertEqual(len(proxy_logs), 1)
        self.assertTrue(proxy_logs[0].endswith("logs/proxy01.log"))
        self.assertNotIn(proxy_logs[0], ds["unrecognized"])


class TestGenericReadingIsBudgetedAndReported(HandlerCase):
    """汎用解析（公開版の標準経路）の読み取り。

    以前は汎用解析だけが別の読み方をしていた。内側 ZIP を読んでも共有予算を
    減らさず、1 ログを上限で切っても、暗号化や予算切れで読み飛ばしても、
    教材には `truncated=False`・`unreadable=[]` と記録していた。欠けた証拠
    から作った教材が、完全なものに見えていた。
    """

    def setUp(self):
        super().setUp()
        self._saved = (dataset.GENERIC_TOTAL_BYTES, dataset.GENERIC_LOG_BYTES)

    def tearDown(self):
        dataset.GENERIC_TOTAL_BYTES, dataset.GENERIC_LOG_BYTES = self._saved

    @staticmethod
    def _stored_container(tag: str, pad: int) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr(f"{tag}/pad.bin", b"\0" * pad)
            zf.writestr(f"{tag}/{tag}.log", ITM2.replace("WS99", tag.upper()))
        return buf.getvalue()

    def test_inner_containers_are_charged_before_they_are_read(self):
        dataset.GENERIC_TOTAL_BYTES = 1024 * 1024
        path = _write(os.path.join(self.tmp, "nest.zip"), {
            f"c{i}.zip": self._stored_container(f"c{i}", 400 * 1024) for i in range(3)
        })
        read = dataset.read_all_logs(path)
        opened = sorted(s.name.split(" :: ")[0] for s in read.sources)
        self.assertEqual(opened, ["c0.zip", "c1.zip"])
        self.assertEqual([(f["name"], f["reason"]) for f in read.failures],
                         [("c2.zip", "limit-exceeded")])
        self.assertTrue(read.truncated)

    def test_containers_cannot_multiply_the_budget(self):
        """入れ物をいくつ並べても、読むのは予算まで（＋進行中の 1 ブロック）。"""
        dataset.GENERIC_TOTAL_BYTES = 1024 * 1024
        path = _write(os.path.join(self.tmp, "many.zip"), {
            f"c{i}.zip": self._stored_container(f"c{i}", 300 * 1024) for i in range(10)
        })
        with zipfile.ZipFile(path) as zf:
            sizes = {i.filename: i.file_size for i in zf.infolist()}
        read = dataset.read_all_logs(path)
        opened = {s.name.split(" :: ")[0] for s in read.sources}
        self.assertLessEqual(sum(sizes[n] for n in opened),
                             dataset.GENERIC_TOTAL_BYTES)
        self.assertEqual(len(read.failures), 10 - len(opened))

    def test_a_log_cut_at_the_per_log_limit_makes_the_lesson_incomplete(self):
        dataset.GENERIC_LOG_BYTES = 64 * 1024
        big = (ITM2 + "\n") * 200   # 約 70 KB 超
        self.assertGreater(len(big.encode()), dataset.GENERIC_LOG_BYTES)
        path = _write(os.path.join(self.tmp, "big.zip"), {"case/host.log": big})
        code, body, saved = self._run(path, {"archive": 1}, profiles=[])
        self.assertEqual(code, 200, body)
        ds = body["dataset"]
        self.assertTrue(ds["truncated"])
        self.assertTrue(ds["incomplete"])
        lesson = saved[0][0]
        self.assertTrue(lesson["introduction"]["dataset"]["truncated"])
        topics = [u["topic"] for u in lesson["report"]["unknowns"]]
        self.assertIn("読み取りの打ち切り", topics)

    def test_a_log_within_the_limit_is_not_marked_truncated(self):
        path = _write(os.path.join(self.tmp, "small.zip"), {"case/host.log": ITM2})
        code, body, _saved = self._run(path, {"archive": 1}, profiles=[])
        self.assertEqual(code, 200, body)
        self.assertFalse(body["dataset"]["truncated"])
        self.assertEqual(body["dataset"]["unreadable"], [])

    def test_budget_exhaustion_is_reported_per_log(self):
        dataset.GENERIC_TOTAL_BYTES = 64 * 1024
        dataset.GENERIC_LOG_BYTES = 64 * 1024
        big = (ITM2 + "\n") * 200
        path = _write(os.path.join(self.tmp, "two.zip"), {
            "case/a.log": big, "case/b.log": ITM2,
        })
        code, body, saved = self._run(path, {"archive": 1}, profiles=[])
        self.assertEqual(code, 200, body)
        ds = body["dataset"]
        self.assertEqual([(u["name"], u["reason"]) for u in ds["unreadable"]],
                         [("case/b.log", "budget")])
        self.assertTrue(ds["truncated"] and ds["incomplete"])
        topics = [u["topic"] for u in saved[0][0]["report"]["unknowns"]]
        self.assertIn("読み取れなかったログ", topics)

    @unittest.skipUnless(HAS_ZIP, "system `zip` is needed to build an encrypted fixture")
    def test_encrypted_logs_are_reported_not_silently_skipped(self):
        locked = _zip_bytes({"locked/secret.log": ITM2}, password=PASSWORD)
        path = _write(os.path.join(self.tmp, "enc.zip"), {
            "case/host.log": ITM2, "case/locked.zip": locked,
        })
        with zipfile.ZipFile(io.BytesIO(locked)) as zf:
            self.assertTrue(zf.infolist()[0].flag_bits & 0x1)
        code, body, _saved = self._run(path, {"archive": 1}, profiles=[])
        self.assertEqual(code, 200, body)
        ds = body["dataset"]
        self.assertEqual([(u["name"], u["reason"]) for u in ds["unreadable"]],
                         [("case/locked.zip :: locked/secret.log", "password-required")])
        self.assertTrue(ds["incomplete"])
        self.assertNotIn(PASSWORD, repr(body))

    def test_a_web_server_log_is_not_taught_as_outbound_traffic(self):
        """プロファイル 0 件でも、サーバーへのアクセスを外部への通信と教えない。"""
        web = "".join(
            f'203.0.113.{i} - - [05/Oct/2024:14:00:0{i} +0900] "GET /page{i}.html HTTP/1.1" 200 120\n'
            for i in range(1, 6)
        )
        path = _write(os.path.join(self.tmp, "web.zip"), {
            "case/host.log": ITM2, "case/web/access.log": web,
        })
        code, body, saved = self._run(path, {"archive": 1}, profiles=[])
        self.assertEqual(code, 200, body)
        ds = body["dataset"]
        self.assertIn("case/web/access.log", ds["unrecognized"])
        self.assertNotIn("proxy", ds["parsing"]["parsers"])
        stages = [s["id"] for s in saved[0][0]["stages"]]
        self.assertNotIn("network", stages)


class TestAbsoluteFormWebLogInGenericMode(HandlerCase):
    """絶対 URL だけの Web ログも、プロファイル 0 件では通信として教えない。"""

    def test_it_is_reported_not_taught(self):
        web = "".join(
            f'203.0.113.{i} - - [05/Oct/2024:14:00:0{i} +0900] '
            f'"GET http://web.example/page{i}.html HTTP/1.1" 200 120\n'
            for i in range(1, 6)
        )
        path = _write(os.path.join(self.tmp, "absweb.zip"), {
            "case/host.log": ITM2, "case/web/access.log": web,
        })
        code, body, saved = self._run(path, {"archive": 1}, profiles=[])
        self.assertEqual(code, 200, body)
        ds = body["dataset"]
        self.assertNotIn("proxy", ds["parsing"]["parsers"])
        self.assertIn("case/web/access.log", ds["unrecognized"])
        self.assertEqual(ds["explicitOnly"], {"case/web/access.log": ["proxy"]})
        lesson = saved[0][0]
        self.assertNotIn("network", [st["id"] for st in lesson["stages"]])
        topics = [u["topic"] for u in lesson["report"]["unknowns"]]
        self.assertIn("通信の向きを断定できないログ", topics)


    def test_a_web_log_alone_says_why_nothing_was_built(self):
        web = ('203.0.113.1 - - [05/Oct/2024:14:00:01 +0900] '
               '"GET http://web.example/ HTTP/1.1" 200 120\n')
        path = _write(os.path.join(self.tmp, "onlyweb.zip"), {"site/access.log": web})
        code, body, saved = self._run(path, {"archive": 1}, profiles=[])
        self.assertEqual(code, 422)
        self.assertIn("通信の向きを内容だけでは決められません", body["error"])
        self.assertEqual(saved, [])

class TestDamagedOuterArchive(unittest.TestCase):
    """外側の ZIP が壊れていても、例外をハンドラの外へ漏らさない。

    `_open_archive` は contextmanager なので、ZIP を開くのは呼び出した時点
    ではなく `with` に入った時点。呼び出しだけを try で囲んでいたため、
    `BadZipFile` が `ArchiveDamaged` に変換されずに漏れていた。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "broken.zip")
        with open(self.path, "wb") as fh:
            fh.write(b"PK\x03\x04 not really a zip archive " * 20)
        profile = FIXTURES.get("example-incident")
        self.view = dataset.Dataset(
            profile=profile, confidence=1.0,
            roles={"case/evidence/logs.zip :: logs/ws99.log": "challenge"},
        )

    def _generate(self, view, payload):
        import api

        handler = api.Handler.__new__(api.Handler)
        handler._dataset_for = lambda _id, forced=None: (view, [])
        handler._json = lambda obj, code=200: (code, obj)
        handler._error = lambda code, msg: (code, {"error": msg})
        handler._recheck = lambda _fh, _row: True
        with open(self.path, "rb") as fh:
            return api.Handler._generate_with(
                handler, payload, 1, {"path": self.path, "sha256": "0" * 64}, fh)

    def test_the_readers_raise_archive_damaged(self):
        with self.assertRaises(dataset.ArchiveDamaged):
            dataset.read_all_logs(self.path)
        with self.assertRaises(dataset.ArchiveDamaged):
            dataset.read_logs(self.path, self.view, "challenge", [])
        with open(self.path, "rb") as fh, self.assertRaises(dataset.ArchiveDamaged):
            dataset.read_all_logs(fh)
        self.assertEqual(dataset.find_password_candidates(self.path, self.view), [])

    def test_generic_generation_answers_422_with_a_fixed_message(self):
        generic = dataset.Dataset(profile=None, confidence=0.0, roles={})
        code, body = self._generate(generic, {"archive": 1})
        self.assertEqual(code, 422)
        self.assertEqual(body, {"error": "圧縮ファイルを読み取れませんでした。"})

    def test_profile_generation_answers_422_with_a_fixed_message(self):
        code, body = self._generate(
            self.view, {"archive": 1, "credential": {"mode": "none"}})
        self.assertEqual(code, 422)
        self.assertEqual(body, {"error": "ZIPファイルを開けませんでした。"})

    def test_errors_inside_the_with_block_are_not_rewritten(self):
        """変換するのは開く処理だけ。本体の例外まで ArchiveDamaged にしない。"""
        good = _write(os.path.join(self.tmp, "ok.zip"), {"a.log": "x"})
        with self.assertRaises(KeyError):
            with dataset._open_archive(good):
                raise KeyError("body")


if __name__ == "__main__":
    unittest.main()
