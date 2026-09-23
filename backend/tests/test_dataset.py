"""Tests for the MWS Cup dataset layer.

NO REAL CONTEST DATA IS USED OR COMMITTED. Every fixture here is built at run
time from invented hostnames, RFC 5737 documentation addresses, and harmless
commands. The encrypted fixtures are ZipCrypto archives this test creates
itself, so nothing redistributable is involved.

The load-bearing tests are the ones that pin down what must NOT happen:
`Tools/example.log` must never become a lesson's input, `baseline` must never
stand in for the real logs, and a password must never reach the database, the
event log, an API response, or an exception message.
"""

import io
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dataset  # noqa: E402
from api import ROLE_CAPS, ROUTES, Capability  # noqa: E402

# 架空の端末名と RFC 5737 の文書用アドレスだけを使う。
ITM2_LINES = "\n".join(
    [
        '10/05/2022 14:00:01.000 +0900 loc=en-US type=ITM2 sn=1 lv=5 evt=ps '
        'subEvt=start os=Win com="WS99" psPath="C:\\Windows\\explorer.exe" '
        'path="C:\\Windows\\System32\\cmd.exe"',
        '10/05/2022 14:00:02.000 +0900 loc=en-US type=ITM2 sn=2 lv=5 evt=ps '
        'subEvt=start os=Win com="WS99" psPath="C:\\Windows\\System32\\cmd.exe" '
        'path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"',
        '10/05/2022 14:00:03.000 +0900 loc=en-US type=ITM2 sn=3 lv=5 evt=file '
        'subEvt=create os=Win com="WS99" path="C:\\Users\\test\\AppData\\demo.dat"',
        '10/05/2022 14:00:04.000 +0900 loc=en-US type=ITM2 sn=4 lv=5 evt=reg '
        'subEvt=setVal os=Win com="WS99" '
        'path="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Demo"',
    ]
)
PROXY_LINES = (
    '192.0.2.10 - - [05/Oct/2022:14:00:07 +0900] '
    '"CONNECT 198.51.100.23:443 HTTP/1.1" 200 1588\n'
)
BASELINE_LINES = ITM2_LINES.replace("WS99", "WS01").replace("cmd.exe", "notepad.exe")
TOOL_SAMPLE = ITM2_LINES.replace("WS99", "SAMPLE-HOST")

PASSWORD = "fixture-pass-2022"
NARRATIVE = (
    "# 演習用の問題文（架空）\n"
    "\n"
    f"logs.zip のパスワード: `{PASSWORD}`\n"
    "\n"
    "ユーザ名のパスワードを答えよ。\n"
    "フォーマット: `answer-format-not-a-password`\n"
)


def _inner_zip(entries: dict[str, str], password: str | None = None) -> bytes:
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


def _has_zip_tool() -> bool:
    try:
        subprocess.run(["zip", "-h"], capture_output=True, check=False)
        return True
    except FileNotFoundError:
        return False


HAS_ZIP = _has_zip_tool()


def build_2022_like(tmpdir: str, encrypted: bool = True) -> str:
    """A miniature of the 2022 layout. Invented content only."""
    logs = _inner_zip(
        {"logs/ws99.log": ITM2_LINES, "logs/proxy01.log": PROXY_LINES},
        PASSWORD if encrypted else None,
    )
    sample = _inner_zip(
        {"log_sample_2022/WS01.log": BASELINE_LINES},
        PASSWORD if encrypted else None,
    )
    path = os.path.join(tmpdir, "mwscup2022-like.zip")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("mwscup2022/DFIR/logs.zip", logs)
        zf.writestr("mwscup2022/DFIR/log_sample_2022.zip", sample)
        zf.writestr("mwscup2022/DFIR/問題文.md", NARRATIVE)
        zf.writestr("mwscup2022/DFIR/Tools/example.log", TOOL_SAMPLE)
        zf.writestr("mwscup2022/DFIR/Tools/README.md", "# 同梱ツールの説明\n")
        zf.writestr("mwscup2022/Surface/solution.csv", "a,b\n1,2\n")
        zf.writestr("__MACOSX/mwscup2022/._DFIR", "\x00")
        zf.writestr("mwscup2022/DFIR/._問題文.md", "\x00")
    return path


def names_of(path: str) -> list[str]:
    """Member names as the enumerator would record them (parent :: child)."""
    out = []
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            name = info.filename
            out.append(name)
            if name.lower().endswith(".zip"):
                try:
                    inner = zipfile.ZipFile(io.BytesIO(zf.read(info)))
                except zipfile.BadZipFile:
                    continue
                with inner:
                    for child in inner.infolist():
                        out.append(f"{name} :: {child.filename}")
    return out


class TestProfileDetection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_2022_profile_is_selected(self):
        names = names_of(build_2022_like(self.tmp))
        view = dataset.detect(names)
        self.assertEqual(view.year, 2022)
        self.assertEqual(view.profile.id, "mwscup-2022-dfir")
        self.assertFalse(view.generic)

    def test_weak_match_is_not_called_2022(self):
        """A DFIR-shaped archive from another year must not be claimed as 2022.

        `*/DFIR/*` alone matches every year's layout, so the year is only
        asserted when enough year-specific names are also present.
        """
        path = os.path.join(self.tmp, "other.zip")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("mwscup2099/DFIR/something.log", "x\n")
            zf.writestr("mwscup2099/DFIR/notes.md", "y\n")
        view = dataset.detect(names_of(path))
        self.assertTrue(view.generic)
        self.assertIsNone(view.year)

    def test_unrelated_archive_is_generic(self):
        path = os.path.join(self.tmp, "plain.zip")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("holiday/photo.jpg", "x")
        view = dataset.detect(names_of(path))
        self.assertTrue(view.generic)

    def test_generic_mode_never_invents_challenge_logs(self):
        """Guessing a challenge log is the bug this whole layer exists to fix."""
        path = os.path.join(self.tmp, "plain.zip")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("stuff/server.log", "x\n")
        view = dataset.detect(names_of(path))
        self.assertEqual(view.named("challenge"), [])


class TestRoleClassification(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = build_2022_like(self.tmp)
        self.view = dataset.detect(names_of(self.path))

    def role(self, suffix: str) -> str:
        for name, role in self.view.roles.items():
            if name.endswith(suffix):
                return role
        raise AssertionError(f"not found: {suffix}")

    def test_challenge_logs(self):
        self.assertEqual(self.role("logs.zip :: logs/ws99.log"), "challenge")
        self.assertEqual(self.role("logs.zip :: logs/proxy01.log"), "challenge")

    def test_baseline_logs(self):
        self.assertEqual(
            self.role("log_sample_2022.zip :: log_sample_2022/WS01.log"), "baseline"
        )

    def test_narrative(self):
        self.assertEqual(self.role("DFIR/問題文.md"), "narrative")

    def test_tool_sample_is_a_tool(self):
        """The regression this phase exists to prevent."""
        self.assertEqual(self.role("Tools/example.log"), "tool")

    def test_tool_readme_beats_the_narrative_pattern(self):
        """`*/DFIR/*.md` also matches Tools/README.md; precedence decides."""
        self.assertEqual(self.role("Tools/README.md"), "tool")

    def test_unrelated(self):
        self.assertEqual(self.role("Surface/solution.csv"), "unrelated")

    def test_macosx_and_appledouble_are_ignored(self):
        self.assertEqual(self.role("__MACOSX/mwscup2022/._DFIR"), "ignore")
        self.assertEqual(self.role("DFIR/._問題文.md"), "ignore")

    def test_example_log_is_never_challenge(self):
        for name, role in self.view.roles.items():
            if "example.log" in name:
                self.assertNotEqual(role, "challenge")


class TestPasswordHints(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_candidate_found(self):
        path = build_2022_like(self.tmp)
        view = dataset.detect(names_of(path))
        self.assertIn(PASSWORD, dataset.find_password_candidates(path, view))

    def test_no_candidate_when_no_hint(self):
        logs = _inner_zip({"logs/a.log": ITM2_LINES})
        path = os.path.join(self.tmp, "nohint.zip")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("mwscup2022/DFIR/logs.zip", logs)
            zf.writestr("mwscup2022/DFIR/log_sample_2022.zip", _inner_zip({"s/a.log": "x"}))
            zf.writestr("mwscup2022/DFIR/問題文.md", "# 案内なし\n本文だけです。\n")
            zf.writestr("mwscup2022/DFIR/Tools/example.log", TOOL_SAMPLE)
        view = dataset.detect(names_of(path))
        self.assertEqual(dataset.find_password_candidates(path, view), [])

    def test_question_prose_is_not_mistaken_for_a_key(self):
        """"パスワードを答えよ" plus a nearby format example is not a password."""
        text = (
            "ユーザ名edenのパスワードを答えよ。\n"
            "フォーマット: `example-format`\n"
        )
        self.assertEqual(dataset.password_candidates_from_text(text), [])

    def test_same_line_keyword_and_quote_is_a_candidate(self):
        text = "logs.zip のパスワード: `secret-value`\n"
        self.assertEqual(
            dataset.password_candidates_from_text(text), ["secret-value"]
        )

    def test_candidate_count_is_bounded(self):
        text = "\n".join(f"パスワード: `v{i}`" for i in range(50))
        self.assertLessEqual(
            len(dataset.password_candidates_from_text(text)),
            dataset.MAX_PASSWORD_CANDIDATES,
        )


@unittest.skipUnless(HAS_ZIP, "system `zip` is needed to build an encrypted fixture")
class TestEncryptedReading(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = build_2022_like(self.tmp, encrypted=True)
        self.view = dataset.detect(names_of(self.path))

    def test_correct_password_reads_challenge_logs(self):
        res = dataset.read_logs(self.path, self.view, "challenge", [PASSWORD])
        self.assertEqual(len(res.sources), 2)
        self.assertEqual(res.failures, [])
        self.assertIn("powershell.exe", "".join(s.text for s in res.sources))

    def test_wrong_password_is_reported_without_the_value(self):
        res = dataset.read_logs(self.path, self.view, "challenge", ["not-the-key"])
        self.assertEqual(res.sources, [])
        self.assertTrue(res.failures)
        blob = repr(res.failures)
        self.assertNotIn("not-the-key", blob)
        self.assertNotIn(PASSWORD, blob)
        for f in res.failures:
            self.assertEqual(f["reason"], "password-rejected")

    def test_missing_password_is_distinguished_from_a_wrong_one(self):
        res = dataset.read_logs(self.path, self.view, "challenge", [])
        self.assertTrue(
            all(f["reason"] == "password-required" for f in res.failures), res.failures
        )

    def test_nothing_is_written_to_disk(self):
        """The decrypted text must exist only in memory."""
        watch = tempfile.mkdtemp()
        before = set(os.listdir(watch))
        cwd = os.getcwd()
        os.chdir(watch)
        try:
            dataset.read_logs(self.path, self.view, "challenge", [PASSWORD])
        finally:
            os.chdir(cwd)
        self.assertEqual(set(os.listdir(watch)), before)

    def test_read_is_deterministic(self):
        a = dataset.read_logs(self.path, self.view, "challenge", [PASSWORD]).as_mapping
        b = dataset.read_logs(self.path, self.view, "challenge", [PASSWORD]).as_mapping
        self.assertEqual(list(a), list(b))
        self.assertEqual(a, b)

    def test_total_budget_truncates_rather_than_reading_everything(self):
        original = dataset.MAX_TOTAL_BYTES
        dataset.MAX_TOTAL_BYTES = 40
        try:
            res = dataset.read_logs(self.path, self.view, "challenge", [PASSWORD])
        finally:
            dataset.MAX_TOTAL_BYTES = original
        self.assertTrue(res.truncated or any(s.truncated for s in res.sources))

    def test_baseline_is_readable_but_kept_separate(self):
        res = dataset.read_logs(self.path, self.view, "baseline", [PASSWORD])
        self.assertTrue(res.sources)
        for s in res.sources:
            self.assertIn("log_sample", s.name)


class TestDamagedAndUnsupported(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_damaged_inner_zip_is_reported_not_raised(self):
        path = os.path.join(self.tmp, "broken.zip")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("mwscup2022/DFIR/logs.zip", b"this is not a zip at all")
            zf.writestr("mwscup2022/DFIR/log_sample_2022.zip", _inner_zip({"s/a.log": "x"}))
            zf.writestr("mwscup2022/DFIR/問題文.md", NARRATIVE)
            zf.writestr("mwscup2022/DFIR/Tools/example.log", TOOL_SAMPLE)
        view = dataset.detect(names_of(path))
        res = dataset.read_logs(path, view, "challenge", [PASSWORD])
        self.assertEqual(res.sources, [])
        self.assertTrue(any(f["reason"] == "damaged" for f in res.failures))

    def test_aes_member_is_refused_as_unsupported(self):
        """AES is out of reach for the stdlib, so it must fail closed."""
        info = zipfile.ZipInfo("x.log")
        info.compress_type = 99
        self.assertTrue(dataset._is_aes(info))
        plain = zipfile.ZipInfo("y.log")
        plain.compress_type = 8
        self.assertFalse(dataset._is_aes(plain))

    def test_oversized_container_is_skipped_with_a_reason(self):
        path = build_2022_like(self.tmp, encrypted=False)
        view = dataset.detect(names_of(path))
        original = dataset.MAX_CONTAINER_BYTES
        dataset.MAX_CONTAINER_BYTES = 1
        try:
            res = dataset.read_logs(path, view, "challenge", [])
        finally:
            dataset.MAX_CONTAINER_BYTES = original
        self.assertTrue(
            any(f["reason"] == "container-too-large" for f in res.failures)
        )


class TestReadLimitsAreRealLimits(unittest.TestCase):
    """Regression: the caps must bound memory, not just the returned text.

    Iterating a TextIOWrapper line by line looked like it honoured
    MAX_LINE_BYTES, but a file with no newline in it was pulled into memory
    whole before anything could be trimmed. A 5 MB unbroken line peaked at
    ~10.5 MB against a 1-byte budget.
    """

    def _one_member_zip(self, payload: bytes) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("big.log", payload)
        return buf.getvalue()

    def _read(self, payload: bytes, budget: int):
        blob = self._one_member_zip(payload)
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            with zf.open(zf.infolist()[0]) as fh:
                got = dataset._read_stream(fh, budget)
        return got.text, got.lines, got.truncated

    def test_unbroken_line_is_capped_at_the_line_limit(self):
        text, _lines, truncated = self._read(b"A" * (5 * 1024 * 1024), 1)
        self.assertLessEqual(len(text), dataset.MAX_LINE_BYTES)
        self.assertTrue(truncated)

    def test_unbroken_line_does_not_blow_up_memory(self):
        import tracemalloc

        payload = b"A" * (5 * 1024 * 1024)
        blob = self._one_member_zip(payload)
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            info = zf.infolist()[0]
            tracemalloc.start()
            try:
                with zf.open(info) as fh:
                    dataset._read_stream(fh, 1)
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
        # Generous, but far below the size of the input: what must not happen
        # is peak growing with the length of the line.
        self.assertLess(peak, 2 * 1024 * 1024, f"peak={peak}")

    def test_tail_of_an_overlong_line_is_discarded_not_buffered(self):
        payload = b"A" * (dataset.MAX_LINE_BYTES * 3) + b"\n" + b"second\n"
        text, lines, truncated = self._read(payload, dataset.MAX_TOTAL_BYTES)
        self.assertTrue(truncated)
        self.assertEqual(lines, 2)
        first = text.split("\n")[0]
        self.assertLessEqual(len(first), dataset.MAX_LINE_BYTES)
        self.assertIn("second", text)

    def test_total_budget_overshoot_is_bounded_by_one_line(self):
        """The first line is always kept, so state the bound and hold to it."""
        payload = (b"x" * 100 + b"\n") * 50
        text, _lines, truncated = self._read(payload, 10)
        self.assertTrue(truncated)
        self.assertLessEqual(len(text), dataset.MAX_LINE_BYTES)

    def test_discarded_bytes_count_against_the_limit(self):
        """Regression: the cap must bound what is DECOMPRESSED, not what is kept.

        Skipping to the next newline still costs CPU and still inflates the
        member, so an unbroken 5 MB line was read to the end even though only
        64 KB came back. Memory was fine; the work was not bounded.
        """
        blob = self._one_member_zip(b"A" * (5 * 1024 * 1024))
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            with zf.open(zf.infolist()[0]) as fh:
                got = dataset._read_stream(fh, 1)
        self.assertLess(got.consumed, 1024 * 1024, f"consumed={got.consumed}")
        self.assertFalse(got.eof)
        self.assertTrue(got.truncated)

    def test_consumed_is_bytes_not_characters(self):
        """Regression: the budget was decremented by len(str).

        A Japanese log is several bytes per character, so subtracting the
        character count let the 128 MB total be overshot several times over.
        """
        text = "".join(f"日本語のログ行です{i}\n" for i in range(200))
        blob = self._one_member_zip(text.encode("utf-8"))
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            with zf.open(zf.infolist()[0]) as fh:
                got = dataset._read_stream(fh, 40)
        self.assertGreaterEqual(got.consumed, len(got.text.encode("utf-8")))
        self.assertGreater(got.consumed, len(got.text))

    def test_eof_is_reported_when_the_member_fits(self):
        blob = self._one_member_zip(b"short\n")
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            with zf.open(zf.infolist()[0]) as fh:
                got = dataset._read_stream(fh, dataset.MAX_TOTAL_BYTES)
        self.assertTrue(got.eof)
        self.assertFalse(got.truncated)

    def test_record_cap_stops_the_read(self):
        original = dataset.MAX_RECORDS
        dataset.MAX_RECORDS = 3
        try:
            text, lines, truncated = self._read(b"line\n" * 100, dataset.MAX_TOTAL_BYTES)
        finally:
            dataset.MAX_RECORDS = original
        self.assertEqual(lines, 3)
        self.assertTrue(truncated)


@unittest.skipUnless(HAS_ZIP, "system `zip` is needed to build an encrypted fixture")
class TestZipCryptoHeaderCollision(unittest.TestCase):
    """Regression: a wrong password can pass ZipCrypto's one-byte check.

    zipfile then hands the garbage to zlib, which raises `zlib.error: Error -3
    while decompressing data`. That is not one of the exceptions the read loop
    used to catch, so a wrong password surfaced as a request traceback instead
    of "パスワードが合いませんでした". Roughly 1 attempt in 256 collides, so a
    handful of candidates is enough to hit it.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        with open(os.path.join(self.tmp, "a.log"), "w", encoding="utf-8") as fh:
            fh.write(ITM2_LINES + "\n")
        self.zip = os.path.join(self.tmp, "enc.zip")
        subprocess.run(
            ["zip", "-q", "-P", PASSWORD, self.zip, "a.log"],
            cwd=self.tmp, check=True, capture_output=True,
        )

    def _view(self):
        class V:
            profile = None
            year = None
            confidence = 0.0
            warnings: list = []
            roles = {"a.log": "challenge"}
            generic = True

            def named(self, role):
                return [n for n, r in self.roles.items() if r == role]

        return V()

    def test_a_collision_really_happens(self):
        """Pin the premise, so the test below is not quietly vacuous."""
        seen = 0
        with zipfile.ZipFile(self.zip) as zf:
            info = zf.infolist()[0]
            for i in range(3000):
                try:
                    with zf.open(info, pwd=f"wrong-{i}".encode()) as fh:
                        fh.read(64)
                except RuntimeError:
                    continue  # rejected by the check byte, as expected
                except Exception:
                    seen += 1
                    break
        if not seen:
            self.skipTest("no check-byte collision in 3000 attempts")
        self.assertTrue(seen)

    def test_collision_is_reported_as_a_wrong_password(self):
        candidates = [f"wrong-{i}" for i in range(3000)]
        res = dataset.read_logs(self.zip, self._view(), "challenge", candidates)
        self.assertEqual(res.sources, [])
        self.assertTrue(res.failures)
        for f in res.failures:
            self.assertEqual(f["reason"], "password-rejected")
        self.assertNotIn("zlib", repr(res.failures).lower())

    def test_the_right_password_still_works_among_wrong_ones(self):
        candidates = [f"wrong-{i}" for i in range(400)] + [PASSWORD]
        res = dataset.read_logs(self.zip, self._view(), "challenge", candidates)
        self.assertEqual(len(res.sources), 1)
        self.assertIn("powershell.exe", res.sources[0].text)


@unittest.skipUnless(HAS_ZIP, "system `zip` is needed to build an encrypted fixture")
class TestTruncatedEncryptedIsNeverTrusted(unittest.TestCase):
    """Regression: a wrong key that returns non-empty garbage was accepted.

    ZipCrypto's check byte only looks at one byte, so ~1 key in 256 gets past
    it. The real verification is the CRC-32, and zipfile only performs that on
    reaching the member's end. Stopping at a read limit therefore skipped the
    check entirely, and a STORED (uncompressed) member does not even go through
    zlib, so nothing else objected either: the garbage came back as text and
    was taught as the incident log.

    The rule now is that an encrypted member is only used when it was read all
    the way to EOF inside the limit, so the CRC has actually been checked.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        # STORED so a wrong key produces plausible-looking bytes, not a zlib
        # error -- the case that used to slip through.
        with open(os.path.join(self.tmp, "a.log"), "w", encoding="utf-8") as fh:
            fh.write(("y" * 200 + "\n") * 3000)
        self.zip = os.path.join(self.tmp, "stored.zip")
        subprocess.run(
            ["zip", "-q", "-0", "-P", PASSWORD, self.zip, "a.log"],
            cwd=self.tmp, check=True, capture_output=True,
        )

    def _view(self):
        class V:
            profile = None
            year = None
            confidence = 0.0
            warnings: list = []
            roles = {"a.log": "challenge"}
            generic = True

            def named(self, role):
                return [n for n, r in self.roles.items() if r == role]

        return V()

    def test_a_wrong_key_can_return_non_empty_bytes(self):
        """Pin the premise: partial reads really do skip the CRC."""
        got_garbage = False
        with zipfile.ZipFile(self.zip) as zf:
            info = zf.infolist()[0]
            for i in range(6000):
                try:
                    fh = zf.open(info, pwd=f"w{i}".encode())
                    chunk = fh.read(4096)
                except RuntimeError:
                    continue
                except Exception:
                    continue
                if chunk:
                    got_garbage = True
                    break
        if not got_garbage:
            self.skipTest("no check-byte collision in 6000 attempts")
        self.assertTrue(got_garbage)

    def test_truncated_encrypted_read_is_refused(self):
        original = dataset.MAX_LOG_BYTES
        dataset.MAX_LOG_BYTES = 4096
        try:
            res = dataset.read_logs(
                self.zip, self._view(), "challenge",
                [f"w{i}" for i in range(6000)],
            )
        finally:
            dataset.MAX_LOG_BYTES = original
        self.assertEqual(res.sources, [], "garbage must never be taught as a log")
        self.assertTrue(
            any(f["reason"] == "limit-exceeded" for f in res.failures), res.failures
        )

    def test_even_the_right_password_is_refused_when_unverifiable(self):
        """Correct key, but too big to verify inside the limit: still refused.

        Better to say "could not confirm" than to teach bytes whose integrity
        was never checked.
        """
        original = dataset.MAX_LOG_BYTES
        dataset.MAX_LOG_BYTES = 4096
        try:
            res = dataset.read_logs(self.zip, self._view(), "challenge", [PASSWORD])
        finally:
            dataset.MAX_LOG_BYTES = original
        self.assertEqual(res.sources, [])
        self.assertTrue(any(f["reason"] == "limit-exceeded" for f in res.failures))

    def test_within_the_limit_the_right_password_is_accepted(self):
        res = dataset.read_logs(self.zip, self._view(), "challenge", [PASSWORD])
        self.assertEqual(len(res.sources), 1)
        self.assertIn("yyy", res.sources[0].text)

    def test_garbage_is_rejected_by_the_text_check(self):
        self.assertFalse(dataset._looks_like_text("�" * 100))
        self.assertFalse(dataset._looks_like_text(""))
        self.assertTrue(dataset._looks_like_text(ITM2_LINES))
        self.assertTrue(dataset._looks_like_text("日本語のログ\n"))


@unittest.skipUnless(HAS_ZIP, "system `zip` is needed to build an encrypted fixture")
class TestSharedBudget(unittest.TestCase):
    """Regression: only successful reads were charged to the total.

    The 128 MB cap was subtracted from just once per accepted log, so bytes
    spent on wrong keys, on reads cut short before the CRC, and on members that
    turned out to be damaged were free. The number of candidate passwords is
    capped at 8, but the number of challenge logs is not, so a pile of
    unreadable logs could inflate well past the total.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.tmp, "logs"))
        for i in range(20):
            with open(
                os.path.join(self.tmp, f"logs/a{i:02}.log"), "w", encoding="utf-8"
            ) as fh:
                fh.write(("z" * 99 + "\n") * 1000)  # 100 KB each
        inner = os.path.join(self.tmp, "logs.zip")
        subprocess.run(
            ["zip", "-q", "-0", "-r", "-P", PASSWORD, inner, "logs"],
            cwd=self.tmp, check=True, capture_output=True,
        )
        self.container_size = os.path.getsize(inner)
        self.outer = os.path.join(self.tmp, "top.zip")
        with zipfile.ZipFile(self.outer, "w") as zf:
            with open(inner, "rb") as fh:
                zf.writestr("mwscup2022/DFIR/logs.zip", fh.read())

    def _view(self):
        names = ["mwscup2022/DFIR/logs.zip"] + [
            f"mwscup2022/DFIR/logs.zip :: logs/a{i:02}.log" for i in range(20)
        ]

        class V:
            profile = None
            year = None
            confidence = 0.0
            warnings: list = []
            generic = True
            roles = {n: "challenge" for n in names}

            def named(self, role):
                return sorted(n for n, r in self.roles.items() if r == role)

        return V()

    def _run_with_total(self, total, passwords):
        seen = {"bytes": 0}
        original_stream = dataset._read_stream
        original_total = dataset.MAX_TOTAL_BYTES

        def spy(fh, budget, shared=None):
            got = original_stream(fh, budget, shared)
            seen["bytes"] += got.consumed
            return got

        dataset._read_stream = spy
        dataset.MAX_TOTAL_BYTES = total
        try:
            res = dataset.read_logs(self.outer, self._view(), "challenge", passwords)
        finally:
            dataset._read_stream = original_stream
            dataset.MAX_TOTAL_BYTES = original_total
        return res, seen["bytes"]

    def test_total_decompressed_stays_within_the_shared_budget(self):
        total = 3 * 1024 * 1024
        res, consumed = self._run_with_total(total, [PASSWORD])
        allowance = total - self.container_size + dataset._READ_BLOCK
        self.assertLessEqual(consumed, allowance, f"consumed={consumed}")
        self.assertLess(len(res.sources), 20, "the cap must actually bite")
        self.assertTrue(res.truncated)

    def test_exhausted_budget_is_reported_per_member(self):
        res, _ = self._run_with_total(3 * 1024 * 1024, [PASSWORD])
        self.assertTrue(
            any(f["reason"] == "budget" for f in res.failures), res.failures
        )

    def test_container_bytes_are_charged_too(self):
        """Loading the inner ZIP into memory is decompression as well."""
        res, consumed = self._run_with_total(self.container_size // 2, [PASSWORD])
        self.assertEqual(consumed, 0, "no member should be read once it is gone")
        self.assertEqual(res.sources, [])

    def test_budget_object_counts_down(self):
        budget = dataset._Budget(100)
        self.assertFalse(budget.exhausted)
        budget.take(60)
        self.assertEqual(budget.remaining, 40)
        budget.refund(10)
        self.assertEqual(budget.remaining, 50)
        budget.take(50)
        self.assertTrue(budget.exhausted)


class TestContainerBudget(unittest.TestCase):
    """Regression: inner ZIPs were read first and charged afterwards.

    A nested archive has its central directory at the end, so it is all-or-
    nothing: it cannot be used from a partial read. Charging after the read
    therefore meant one whole container could be loaded however little budget
    was left -- and the loop then moved on to the next one. Measured at a
    budget of 1 byte, two 100 KB containers were both read and the remaining
    budget fell to -200,215.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.blobs = {}
        for tag in "abc":
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
                zf.writestr(f"logs/{tag}.log", ("x" * 99 + "\n") * 1000)
            self.blobs[tag] = buf.getvalue()
        # Sizes are read back from the fixture rather than written as
        # constants, so a change in zip metadata cannot silently shift what the
        # budget assertions mean.
        self.size = len(self.blobs["a"])
        with zipfile.ZipFile(io.BytesIO(self.blobs["a"])) as zf:
            self.log_size = zf.infolist()[0].file_size
        self.assertEqual(
            {len(b) for b in self.blobs.values()}, {self.size},
            "the three containers must be the same size for these bounds",
        )
        self.outer = os.path.join(self.tmp, "top.zip")
        with zipfile.ZipFile(self.outer, "w", zipfile.ZIP_STORED) as zf:
            for i, tag in enumerate("abc"):
                zf.writestr(f"mwscup2022/DFIR/logs{i}.zip", self.blobs[tag])

    def _view(self):
        names = [f"mwscup2022/DFIR/logs{i}.zip" for i in range(3)] + [
            f"mwscup2022/DFIR/logs{i}.zip :: logs/{t}.log"
            for i, t in enumerate("abc")
        ]

        class V:
            profile = None
            year = None
            confidence = 0.0
            warnings: list = []
            generic = True
            roles = {n: "challenge" for n in names}

            def named(self, role):
                return sorted(n for n, r in self.roles.items() if r == role)

        return V()

    def _run(self, total):
        """Return (result, bytes actually pulled out of the archive)."""
        seen = {"bytes": 0}
        original_read = zipfile.ZipExtFile.read

        def spy(zf_self, n=-1):
            data = original_read(zf_self, n)
            seen["bytes"] += len(data)
            return data

        original_total = dataset.MAX_TOTAL_BYTES
        zipfile.ZipExtFile.read = spy
        dataset.MAX_TOTAL_BYTES = total
        try:
            res = dataset.read_logs(self.outer, self._view(), "challenge", [])
        finally:
            zipfile.ZipExtFile.read = original_read
            dataset.MAX_TOTAL_BYTES = original_total
        return res, seen["bytes"]

    def test_no_container_is_read_when_the_budget_is_gone(self):
        res, read_bytes = self._run(1)
        self.assertEqual(read_bytes, 0, "nothing should be pulled out at all")
        self.assertEqual(res.sources, [])
        self.assertTrue(res.truncated)
        self.assertEqual(len(res.failures), 3)

    def test_only_the_container_that_fits_is_read(self):
        """A budget with room for exactly one container must read exactly one.

        The earlier version of this test only bounded the bytes read, with
        enough slack that reading a second container could still pass. What
        matters is stricter than a byte ceiling: the containers that do not fit
        must not be opened at all, and they must be reported rather than
        silently dropped. All expectations are derived from the fixture sizes
        so that a different zip layout cannot quietly loosen them.
        """
        container = self.size          # bytes of one inner ZIP
        log = self.log_size            # uncompressed bytes of the log inside it

        # Enough for one container plus its log, and short of a second
        # container by a wide margin.
        budget = container + log + dataset._READ_BLOCK
        self.assertLess(
            budget - (container + log), container,
            "the budget must not leave room for a second container",
        )

        res, read_bytes = self._run(budget)

        # 1. Exactly one log is taken as lesson input.
        self.assertEqual(len(res.sources), 1, [s.name for s in res.sources])

        # 2. The two remaining containers are refused, and each is reported.
        #
        # The reason is exactly "limit-exceeded", not "budget": the size check
        # runs first and catches a container that cannot fit in what is left.
        # "budget" is what the exhausted check reports, and the two are not
        # interchangeable -- accepting either here would stop the test from
        # noticing if the size check disappeared.
        self.assertEqual(len(res.failures), 2, res.failures)
        for failure in res.failures:
            self.assertEqual(failure["reason"], "limit-exceeded", failure)

        # 3. Every container that was refused is named in the failures, so
        #    nothing is dropped without a trace.
        refused = {f["name"] for f in res.failures}
        accepted_parent = res.sources[0].name.split(" :: ")[0]
        expected_refused = {
            f"mwscup2022/DFIR/logs{i}.zip" for i in range(3)
        } - {accepted_parent}
        self.assertEqual(refused, expected_refused)

        # 4. The caller is told the result is incomplete.
        self.assertTrue(res.truncated)

        # 5. The bytes actually pulled out cover one container and one log, and
        #    cannot stretch to a second container.
        ceiling = container + log + dataset._READ_BLOCK
        self.assertLessEqual(read_bytes, ceiling, f"read={read_bytes}")
        self.assertLess(
            read_bytes, container * 2,
            f"a second container was read: {read_bytes}",
        )

    def test_everything_is_read_when_the_budget_allows(self):
        res, _ = self._run(self.size * 3 + 400_000)
        self.assertEqual(len(res.sources), 3)
        self.assertEqual(res.failures, [])

    def test_reserving_before_read_survives_an_exception(self):
        """A read that raises mid-decompression must still cost budget."""
        budget = dataset._Budget(10 * dataset._READ_BLOCK)
        before = budget.remaining

        class Exploding:
            def read(self, _n):
                raise zlib_error_for_test()

        def zlib_error_for_test():
            import zlib

            return zlib.error("Error -3 while decompressing data")

        with self.assertRaises(Exception):
            dataset._read_stream(Exploding(), dataset.MAX_LOG_BYTES, budget)
        self.assertLess(budget.remaining, before, "the attempt must not be free")


class TestLessonInput(unittest.TestCase):
    """What actually becomes teaching material."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = build_2022_like(self.tmp, encrypted=False)
        self.view = dataset.detect(names_of(self.path))

    def test_challenge_logs_are_the_input(self):
        sources = dataset.read_logs(self.path, self.view, "challenge", []).as_mapping
        self.assertTrue(sources)
        for name in sources:
            self.assertIn("logs.zip", name)

    def test_example_log_is_not_an_input(self):
        sources = dataset.read_logs(self.path, self.view, "challenge", []).as_mapping
        self.assertFalse(any("example.log" in n for n in sources))

    def test_baseline_is_not_substituted(self):
        sources = dataset.read_logs(self.path, self.view, "challenge", []).as_mapping
        self.assertFalse(any("log_sample" in n for n in sources))

    def test_lesson_is_stable_for_the_same_input(self):
        from explain import build_lesson

        sources = dataset.read_logs(self.path, self.view, "challenge", []).as_mapping
        a = build_lesson("t", sources, "gen-test")
        b = build_lesson("t", sources, "gen-test")
        self.assertEqual(a, b)
        self.assertEqual(a["id"], "gen-test")

    def test_summary_never_carries_the_password(self):
        rows = [{"name": n, "size": 1, "verdict": "inert-data"} for n in self.view.roles]
        body = dataset.summarise(self.view, rows)
        self.assertNotIn(PASSWORD, repr(body))
        self.assertNotIn("passwordCandidates", body)


class TestProfileOverride(unittest.TestCase):
    """The `profile` field in a request must actually do something."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.names = names_of(build_2022_like(self.tmp))

    def test_auto_is_the_same_as_omitting_it(self):
        a = dataset.detect(self.names)
        b = dataset.detect(self.names, force_id="auto")
        self.assertEqual(a.profile.id, b.profile.id)

    def test_named_profile_is_applied(self):
        view = dataset.detect(self.names, force_id="mwscup-2022-dfir")
        self.assertEqual(view.profile.id, "mwscup-2022-dfir")

    def test_unknown_profile_is_refused_not_ignored(self):
        """Silently falling back would classify under the wrong year's rules."""
        with self.assertRaises(dataset.UnknownProfile):
            dataset.detect(self.names, force_id="mwscup-1999-dfir")

    def test_forcing_a_profile_onto_a_weak_match_warns(self):
        path = os.path.join(self.tmp, "plain.zip")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("holiday/photo.jpg", "x")
        view = dataset.detect(names_of(path), force_id="mwscup-2022-dfir")
        self.assertEqual(view.profile.id, "mwscup-2022-dfir")
        self.assertTrue(view.warnings)
        self.assertEqual(view.named("challenge"), [])


class TestStaleArchiveGuard(unittest.TestCase):
    """Regression: classification and bytes come from two different moments.

    Roles are decided from member names recorded at scan time; the logs are
    read from whatever now sits at that path. Without a hash re-check, archive
    A's classification can be used to read archive B's contents while the
    manifest still shows A's hash.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_hash_change_is_detectable_before_reading(self):
        from store import sha256_file

        path = os.path.join(self.tmp, "a.zip")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("mwscup2022/DFIR/logs.zip", _inner_zip({"logs/a.log": ITM2_LINES}))
        first, _ = sha256_file(path)

        # Swap the file at the same path, as an attacker or a careless rebuild
        # would.
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("mwscup2022/DFIR/logs.zip", _inner_zip({"logs/a.log": "different\n"}))
        second, _ = sha256_file(path)
        self.assertNotEqual(first, second)

    def test_api_refuses_a_swapped_archive(self):
        """The handler must return 409 rather than teach the new contents."""
        import api

        path = os.path.join(self.tmp, "a.zip")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("x.log", "a\n")
        from store import sha256_file

        digest, size = sha256_file(path)
        row = {"path": path, "sha256": digest, "size": size}

        handler = api.Handler.__new__(api.Handler)
        self.assertTrue(api.Handler._still_the_same_file(handler, row))

        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("x.log", "b\n")
        self.assertFalse(api.Handler._still_the_same_file(handler, row))

    def test_missing_file_counts_as_changed(self):
        import api

        handler = api.Handler.__new__(api.Handler)
        row = {"path": os.path.join(self.tmp, "gone.zip"), "sha256": "0" * 64}
        self.assertFalse(api.Handler._still_the_same_file(handler, row))

    def test_replacing_the_path_does_not_change_what_is_read(self):
        """A descriptor follows the inode, so a replaced path is not seen.

        This is the half `_open_verified` covers: unlink-and-recreate, or a
        rename over the top, leaves the open descriptor on the verified bytes.
        """
        import api
        from store import sha256_file

        path = os.path.join(self.tmp, "swap.zip")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("original.log", "first\n")
        digest, size = sha256_file(path)
        row = {"path": path, "sha256": digest, "size": size}

        handler = api.Handler.__new__(api.Handler)
        fh = api.Handler._open_verified(handler, row)
        self.assertIsNotNone(fh)

        # Replace the directory entry with a different file.
        other = os.path.join(self.tmp, "other.zip")
        with zipfile.ZipFile(other, "w") as zf:
            zf.writestr("swapped.log", "second\n")
        os.replace(other, path)

        with fh:
            with zipfile.ZipFile(fh) as zf:
                names = zf.namelist()
            self.assertEqual(names, ["original.log"], "must read the verified bytes")
            self.assertTrue(api.Handler._recheck(handler, fh, row))

    def test_in_place_rewrite_is_caught_by_the_recheck(self):
        """The half a descriptor cannot cover, stated honestly.

        `open(path, "w")` truncates the same inode, so the open descriptor does
        see the new bytes. Nothing about a descriptor prevents that; what
        prevents a bad lesson is re-hashing after the read and refusing before
        anything is saved.
        """
        import api
        from store import sha256_file

        path = os.path.join(self.tmp, "inplace.zip")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("original.log", "first\n")
        digest, size = sha256_file(path)
        row = {"path": path, "sha256": digest, "size": size}

        handler = api.Handler.__new__(api.Handler)
        fh = api.Handler._open_verified(handler, row)
        self.assertIsNotNone(fh)

        # Rewrite the SAME file in place, as a careless rebuild would.
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("swapped.log", "second\n")

        with fh:
            self.assertFalse(
                api.Handler._recheck(handler, fh, row),
                "an in-place rewrite must be detected before anything is saved",
            )

    def test_open_verified_refuses_a_changed_file(self):
        import api
        from store import sha256_file

        path = os.path.join(self.tmp, "changed.zip")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("a.log", "a\n")
        digest, size = sha256_file(path)
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("a.log", "b\n")

        handler = api.Handler.__new__(api.Handler)
        row = {"path": path, "sha256": digest, "size": size}
        self.assertIsNone(api.Handler._open_verified(handler, row))

    def test_generate_closes_its_descriptor_on_every_path(self):
        """Regression: the verified descriptor leaked on several early returns.

        `h_generate` opens one descriptor and then has half a dozen ways to
        bail out -- bad credential, bad profile type, unknown profile, a forced
        profile with no challenge logs, and the hand-off to generic generation.
        Each of those used to return without closing it, so a client could leak
        one descriptor per request just by sending malformed input.
        """
        import api

        path = os.path.join(self.tmp, "leak.zip")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("a.log", "x\n")
        from store import sha256_file

        digest, size = sha256_file(path)
        row = {"id": 1, "path": path, "sha256": digest, "size": size}

        opened: list = []
        real_open = api.Handler._open_verified

        def tracking_open(handler, r):
            fh = real_open(handler, r)
            if fh is not None:
                opened.append(fh)
            return fh

        handler = api.Handler.__new__(api.Handler)
        handler._archive_row = lambda _id: row
        handler._dataset_for = lambda _id, _p=None: (
            dataset.detect(["a.log"]), [{"name": "a.log"}]
        )
        handler._json = lambda obj, code=200: obj
        handler._error = lambda code, msg: {"error": msg, "code": code}
        handler._body = lambda: self._payload

        api.Handler._open_verified = tracking_open
        try:
            for payload in (
                {"archive": 1, "credential": "not-a-dict"},
                {"archive": 1, "profile": 123},
                {"archive": 1, "profile": "mwscup-9999-dfir"},
                {"archive": 1},  # falls through to generic generation
            ):
                self._payload = payload
                opened.clear()
                api.Handler.h_generate(handler)
                self.assertTrue(opened, "a descriptor should have been opened")
                for fh in opened:
                    self.assertTrue(fh.closed, f"leaked for payload={payload}")
        finally:
            api.Handler._open_verified = real_open

    def test_read_logs_accepts_an_open_descriptor(self):
        """The dataset layer must work from the verified descriptor, not a path."""
        path = build_2022_like(self.tmp, encrypted=False)
        view = dataset.detect(names_of(path))
        with open(path, "rb") as fh:
            res = dataset.read_logs(fh, view, "challenge", [])
            fh.seek(0)
            cands = dataset.find_password_candidates(fh, view)
        self.assertTrue(res.sources)
        self.assertIn(PASSWORD, cands)


class TestIncompleteReporting(unittest.TestCase):
    """A lesson built from 2 of 6 logs must not look like a clean success."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    @unittest.skipUnless(HAS_ZIP, "system `zip` is needed")
    def test_failures_are_recorded_when_only_some_logs_read(self):
        readable = _inner_zip({"logs/ok.log": ITM2_LINES})
        locked = _inner_zip({"logs/locked.log": ITM2_LINES}, "another-key")
        path = os.path.join(self.tmp, "mixed.zip")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("mwscup2022/DFIR/logs.zip", readable)
            zf.writestr("mwscup2022/DFIR/logs2.zip", locked)
            zf.writestr("mwscup2022/DFIR/log_sample_2022.zip", _inner_zip({"s/a.log": "x"}))
            zf.writestr("mwscup2022/DFIR/問題文.md", NARRATIVE)
            zf.writestr("mwscup2022/DFIR/Tools/example.log", TOOL_SAMPLE)
        view = dataset.detect(names_of(path))
        # Point the challenge role at both archives so one of them must fail.
        view.roles = {
            n: ("challenge" if "logs" in n and n.endswith(".log") else r)
            for n, r in view.roles.items()
        }
        res = dataset.read_logs(path, view, "challenge", [PASSWORD])
        self.assertTrue(res.sources)
        self.assertTrue(res.failures, "a locked log must be reported, not dropped")


class TestApiSurface(unittest.TestCase):
    """The new route must obey the same rules as every other one."""

    def test_dataset_route_declares_a_capability(self):
        routes = [r for r in ROUTES if "dataset" in r.pattern.pattern]
        self.assertEqual(len(routes), 1)
        self.assertIn(routes[0].capability, vars(Capability).values())

    def test_dataset_route_is_anchored_and_bounded(self):
        route = [r for r in ROUTES if "dataset" in r.pattern.pattern][0]
        self.assertIn(r"(\d{1,9})", route.pattern.pattern)
        self.assertIsNone(route.pattern.fullmatch("/api/archives/4/dataset/../x"))
        self.assertIsNotNone(route.pattern.fullmatch("/api/archives/4/dataset"))

    def test_generate_still_requires_scan_so_a_student_cannot_call_it(self):
        route = [r for r in ROUTES if r.pattern.pattern == r"/api/generate"][0]
        self.assertEqual(route.capability, Capability.SCAN)
        self.assertNotIn(Capability.SCAN, ROLE_CAPS["student"])

    def test_student_cannot_reach_any_mutating_route(self):
        student = ROLE_CAPS["student"]
        for route in ROUTES:
            if route.method != "GET":
                self.assertNotIn(route.capability, student, route.pattern.pattern)


class TestNoSecretsLeak(unittest.TestCase):
    """A password must not survive anywhere it could later be read."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = build_2022_like(self.tmp, encrypted=False)
        self.view = dataset.detect(names_of(self.path))

    def test_store_and_event_log_never_see_the_password(self):
        from store import Store

        db_path = os.path.join(self.tmp, "m.sqlite3")
        store = Store(db_path)
        sources = dataset.read_logs(self.path, self.view, "challenge", [PASSWORD]).as_mapping
        from explain import build_lesson

        lesson = build_lesson("t", sources, "gen-test")
        store.save_lesson(lesson, "fixture")
        store.log("generate", "fixture")
        store.close()
        with open(db_path, "rb") as fh:
            blob = fh.read()
        self.assertNotIn(PASSWORD.encode(), blob)

    def test_exception_text_never_carries_the_password(self):
        for exc in (
            dataset.PasswordRejected("パスワードが合いませんでした。"),
            dataset.PasswordRequired("パスワードが必要です。"),
        ):
            self.assertNotIn(PASSWORD, str(exc))


@unittest.skipUnless(
    os.environ.get("MWS_DATA_DIR"),
    "set MWS_DATA_DIR to run the optional check against local contest data",
)
class TestLocalRealData(unittest.TestCase):
    """Opt-in only. Never discovers contest data on its own.

    This exists so a maintainer can confirm the profile still matches the real
    2022 layout without the suite ever touching that data by default.
    """

    def test_2022_archive_classifies(self):
        directory = os.environ["MWS_DATA_DIR"]
        target = None
        for name in sorted(os.listdir(directory)):
            if "2022" in name and name.lower().endswith(".zip"):
                target = os.path.join(directory, name)
                break
        if target is None:
            self.skipTest("no 2022 archive in MWS_DATA_DIR")
        view = dataset.detect(names_of(target))
        self.assertEqual(view.year, 2022)
        self.assertTrue(view.named("challenge"))

        # 本体は tool。AppleDouble の相棒 (__MACOSX/.../._example.log) は
        # 名前に example.log を含むが、これは ignore が正しい。
        for name, role in view.roles.items():
            if name.endswith("Tools/example.log") and "__MACOSX" not in name:
                self.assertEqual(role, "tool", name)
            if "example.log" in name:
                self.assertNotEqual(role, "challenge", name)

        # 問題ログは logs.zip の中のものだけ。
        for name in view.named("challenge"):
            self.assertIn("logs.zip", name)
            self.assertNotIn("log_sample", name)


if __name__ == "__main__":
    unittest.main()
