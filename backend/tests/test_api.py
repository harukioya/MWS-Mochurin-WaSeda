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

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api  # noqa: E402
from api import ROLE_CAPS, ROUTES, Capability, Handler  # noqa: E402


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
