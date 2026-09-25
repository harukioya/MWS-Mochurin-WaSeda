"""Tests for the API's security invariants.

The important one is `test_every_route_declares_a_capability`. A denylist of
"things a student may not do" can never be enumerated completely, and every
endpoint added later would default to open. Iterating the route table and
failing the build is what keeps that from decaying on the next commit.
"""

import os
import re
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api  # noqa: E402
from api import ROLE_CAPS, ROUTES, Capability, Handler  # noqa: E402


class TestBrowseNavigation(unittest.TestCase):
    def test_unreadable_folder_still_returns_its_parent(self):
        """A permission error must not disable the in-page browser's Up button."""
        with mock.patch.object(api.os, "scandir", side_effect=PermissionError):
            result = api.browse_dir("/parent/locked")

        self.assertEqual(result["parent"], "/parent")
        self.assertIn("error", result)


class TestRouteTable(unittest.TestCase):
    def test_every_route_declares_a_capability(self):
        """Security invariant 1 from BUILD-CONTRACT."""
        known = {
            v for k, v in vars(Capability).items() if not k.startswith("_")
        }
        for route in ROUTES:
            with self.subTest(route=route.pattern.pattern):
                self.assertTrue(route.capability, "route declares no capability")
                self.assertIn(route.capability, known)

    def test_every_route_has_a_real_handler(self):
        for route in ROUTES:
            with self.subTest(route=route.pattern.pattern):
                self.assertTrue(
                    callable(getattr(Handler, route.handler, None)),
                    f"{route.handler} is not a method on Handler",
                )

    def test_route_patterns_are_fully_anchored(self):
        """`fullmatch` is used, so a pattern must not need a trailing wildcard.

        A `{path:path}`-style catch-all is banned outright: it is the one
        construct that reliably reintroduces traversal.
        """
        for route in ROUTES:
            with self.subTest(route=route.pattern.pattern):
                self.assertNotIn(".*", route.pattern.pattern)
                self.assertNotIn(".+", route.pattern.pattern)

    def test_every_capture_group_is_bounded_and_restricted(self):
        """No route parameter may be open-ended.

        An unbounded group is how a path parameter turns back into a traversal
        primitive, so each one must state an explicit upper bound and a
        restricted character class. Digits for ids, [A-Za-z0-9_-] for slugs.
        """
        group_re = re.compile(r"\((?!\?)")
        for route in ROUTES:
            pattern = route.pattern.pattern
            if not route.pattern.groups:
                continue
            with self.subTest(route=pattern):
                # Every group must carry a {min,max} bound...
                self.assertEqual(
                    len(group_re.findall(pattern)),
                    len(re.findall(r"\{\d+,\d+\}", pattern)),
                    "every capture group needs an explicit {min,max} bound",
                )
                # ...and must not use an unbounded quantifier anywhere.
                for bad in ("+", "*"):
                    self.assertNotIn(
                        bad, pattern.replace(r"\+", ""),
                        f"unbounded quantifier {bad!r} in a route pattern",
                    )


class TestRoleCapabilities(unittest.TestCase):
    def test_student_can_only_read(self):
        self.assertEqual(ROLE_CAPS["student"], {Capability.READ})

    def test_student_cannot_reach_any_mutating_route(self):
        """The whole point of student mode: no writes, no acquisition."""
        student = ROLE_CAPS["student"]
        for route in ROUTES:
            if route.method == "GET":
                continue
            with self.subTest(route=route.pattern.pattern):
                self.assertNotIn(
                    route.capability, student,
                    f"student must not have {route.capability}",
                )

    def test_write_and_intake_are_separate_capabilities(self):
        """Materializing a file and downloading one are different powers."""
        self.assertNotEqual(Capability.MATERIALIZE_INERT, Capability.INTAKE)
        caps = {r.capability for r in ROUTES if r.method == "POST"}
        self.assertIn(Capability.MATERIALIZE_INERT, caps)
        self.assertIn(Capability.INTAKE, caps)

    def test_instructor_is_a_superset_of_student(self):
        self.assertTrue(ROLE_CAPS["student"] <= ROLE_CAPS["instructor"])

    def test_unknown_role_is_not_silently_accepted(self):
        self.assertNotIn("admin", ROLE_CAPS)
        self.assertNotIn("root", ROLE_CAPS)


class TestNoCorsAnywhere(unittest.TestCase):
    def test_no_access_control_headers_are_ever_sent(self):
        """Same-origin by construction: there is no CORS surface to misconfigure.

        Matches header-SETTING code, not prose. An earlier version of this test
        matched the module docstring that explains the absence of the header,
        which made it fail for the opposite of the right reason.
        """
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(here, "api.py"), encoding="utf-8") as fh:
            source = fh.read()
        code = "\n".join(
            line for line in source.splitlines() if not line.lstrip().startswith("#")
        )
        for banned in ('send_header("Access-Control', "CORSMiddleware",
                       'send_header("access-control'):
            self.assertNotIn(banned, code, f"{banned} must never appear")

    def test_csp_has_no_unsafe_inline_for_scripts(self):
        self.assertNotIn("'unsafe-inline'", api.CSP.split("style-src")[0])
        self.assertIn("frame-ancestors 'none'", api.CSP)
        self.assertIn("object-src 'none'", api.CSP)

    def test_static_serving_is_allowlisted(self):
        self.assertEqual(set(api.STATIC_DIRS), {"js", "styles", "data"})
        self.assertEqual(set(api.STATIC_EXT), {".js", ".css", ".json"})


class TestNetworkIsolation(unittest.TestCase):
    def test_only_net_module_imports_a_network_client(self):
        """`net.py` is the only place allowed to open a socket.

        Keeping that true is what makes 'nothing else talks to the network' a
        one-file audit rather than a whole-backend one.
        """
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        banned = ("urllib.request", "http.client", "requests", "httpx", "socket.create_connection")
        for name in ("archive.py", "identify.py", "store.py"):
            with open(os.path.join(here, name), encoding="utf-8") as fh:
                source = fh.read()
            for token in banned:
                with self.subTest(module=name, token=token):
                    self.assertNotIn(token, source)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestRoleLoading(unittest.TestCase):
    """The default must be usable; anything malformed must fail closed."""

    def setUp(self):
        self.tmp = os.path.join(
            os.environ.get("TMPDIR", "/tmp"), f"mws-role-{os.getpid()}"
        )
        self._orig = api.ROLE_FILE
        api.ROLE_FILE = self.tmp
        self.addCleanup(lambda: setattr(api, "ROLE_FILE", self._orig))
        self.addCleanup(lambda: os.path.exists(self.tmp) and os.remove(self.tmp))

    def _write(self, text, mode=0o600):
        with open(self.tmp, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(self.tmp, mode)

    def test_default_is_usable_when_no_config_exists(self):
        """Defaulting to `student` made the tool a dead end on first run."""
        self.assertEqual(api.DEFAULT_ROLE, "instructor")
        self.assertFalse(os.path.exists(self.tmp))
        self.assertEqual(api.load_role(), "instructor")

    def test_student_is_an_explicit_opt_in(self):
        self._write("student")
        self.assertEqual(api.load_role(), "student")

    def test_unknown_role_fails_closed(self):
        for text in ("admin", "root", "", "INSTRUCTOR", "instructor extra"):
            with self.subTest(text=text):
                self._write(text)
                self.assertEqual(api.load_role(), "student")

    def test_group_writable_config_is_ignored(self):
        """A config anyone can edit is not evidence of anything."""
        self._write("instructor", mode=0o666)
        self.assertEqual(api.load_role(), "student")

    def test_trailing_whitespace_is_tolerated(self):
        self._write("  student \n")
        self.assertEqual(api.load_role(), "student")


class TestProfileIdContract(unittest.TestCase):
    """`profileId` selects a dataset format; nothing else in the contract does.

    The id never reaches the filesystem -- `dataset.detect` only compares it
    against the profiles it already loaded -- but it is still caller-supplied
    text that ends up in an error message, so it gets the same bounded shape
    the profile loader enforces.

    `profile` is a DEPRECATED alias kept for pages built before profiles were
    generalised. It is read in exactly one place (`_legacy_profile_alias`); the
    tests below pin both that it still works and that the new contract does not
    depend on it.
    """

    def _query(self, path: str):
        handler = Handler.__new__(Handler)
        handler.path = path
        return Handler._profile_request(handler, Handler._query(handler))

    def _body(self, payload: dict):
        handler = Handler.__new__(Handler)
        return Handler._profile_request(handler, payload)

    def test_absent_means_automatic(self):
        self.assertEqual(self._query("/api/archives/1/dataset"), (None, None))
        self.assertEqual(self._query("/api/archives/1/dataset?other=x"), (None, None))
        self.assertEqual(self._query("/api/archives/1/dataset?profileId="), (None, None))
        self.assertEqual(self._body({"archive": 1}), (None, None))

    def test_a_named_profile_is_passed_through(self):
        self.assertEqual(
            self._query("/api/archives/1/dataset?profileId=example-incident"),
            ("example-incident", None),
        )
        self.assertEqual(self._body({"profileId": "example-incident"}),
                         ("example-incident", None))

    def test_auto_is_passed_through_unchanged(self):
        """`detect` already treats "auto" as "decide for yourself"."""
        self.assertEqual(self._query("/api/archives/1/dataset?profileId=auto"),
                         ("auto", None))

    def test_a_malformed_id_is_rejected_rather_than_ignored(self):
        """Ignoring a malformed override would classify under the automatic
        decision while the screen showed the chosen one."""
        for bad in (
            "/api/archives/1/dataset?profileId=../../etc/passwd",
            "/api/archives/1/dataset?profileId=" + "x" * 65,
            "/api/archives/1/dataset?profileId=a%20b",
            "/api/archives/1/dataset?profileId=a/b",
            "/api/archives/1/dataset?profileId=a%2Fb",
        ):
            with self.subTest(path=bad):
                value, problem = self._query(bad)
                self.assertIsNone(value)
                self.assertTrue(problem)
        for bad in (123, ["x"], {"a": 1}, "x" * 65):
            with self.subTest(body=bad):
                value, problem = self._body({"profileId": bad})
                self.assertIsNone(value)
                self.assertTrue(problem)

    def test_deprecated_alias_still_works(self):
        """旧名 `profile` は非推奨の互換として受け付ける。"""
        self.assertEqual(
            self._query("/api/archives/1/dataset?profile=example-incident"),
            ("example-incident", None),
        )
        self.assertEqual(self._body({"profile": "example-incident"}),
                         ("example-incident", None))

    def test_the_new_name_and_the_alias_must_agree(self):
        value, problem = self._body({"profileId": "a", "profile": "b"})
        self.assertIsNone(value)
        self.assertTrue(problem)
        self.assertEqual(self._body({"profileId": "a", "profile": "a"}), ("a", None))

    def test_the_contract_stands_without_the_alias(self):
        """互換層を外しても、新しい契約（profileId）はそのまま成り立つ。"""
        with mock.patch.object(Handler, "_legacy_profile_alias",
                               staticmethod(lambda fields: None)):
            self.assertEqual(self._body({"profileId": "example-incident"}),
                             ("example-incident", None))
            self.assertEqual(
                self._query("/api/archives/1/dataset?profileId=example-incident"),
                ("example-incident", None),
            )
            # 旧名だけを送ってきたものは、互換層が無ければ自動判定になる。
            self.assertEqual(self._body({"profile": "example-incident"}), (None, None))

    def test_every_loadable_profile_id_fits_the_pattern(self):
        """A profile the loader accepts must be expressible in the query."""
        import dataset

        self.assertEqual(Handler.PROFILE_ID.pattern, dataset.PROFILE_ID)


class TestNoYearInTheContract(unittest.TestCase):
    """年度は新しい API 契約に出てこない。"""

    def test_dataset_summary_has_no_year(self):
        import dataset

        view = dataset.detect(["a/b.log"], profiles=[])
        body = dataset.summarise(view, [{"name": "a/b.log"}],
                                 catalog=dataset.ProfileCatalog())
        self.assertNotIn("year", body)
        self.assertNotIn("profile", body, "旧名 profile を返さない（profileId を使う）")
        for key in ("profileId", "label", "edition", "metadata", "forced",
                    "confidence", "generic", "parsers", "parserLabels",
                    "profiles", "profileErrors"):
            self.assertIn(key, body)
        self.assertIsNone(body["profileId"])
        self.assertTrue(body["generic"])
        self.assertEqual(body["profiles"], [])
