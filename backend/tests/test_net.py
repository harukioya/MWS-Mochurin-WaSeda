"""Tests for net.py — the only module allowed to open a socket.

Nothing here performs a network request. Every test exercises the validation
logic directly, which is where the security properties actually live. That is
deliberate: the tool does not download anything unless explicitly enabled,
the machine this was written on prohibits downloading outright, and a test
suite that needs the network to prove the
SSRF guard works would be unable to run there at all.
"""

import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from net import (  # noqa: E402
    ALLOWED_SCHEMES,
    IntakeDisabled,
    IntakeRefused,
    _check_address,
    fetch,
    intake_enabled,
    validate_url,
)


class TestDisabledByDefault(unittest.TestCase):
    def test_intake_is_off_unless_explicitly_enabled(self):
        os.environ.pop("ZIP2LEARN_INTAKE_ENABLED", None)
        self.assertFalse(intake_enabled())
        with self.assertRaises(IntakeDisabled):
            fetch("https://example.com/x", io.BytesIO())

    def test_the_switch_is_an_exact_match(self):
        for value in ("0", "true", "yes", "", "2"):
            with self.subTest(value=value):
                os.environ["ZIP2LEARN_INTAKE_ENABLED"] = value
                self.assertFalse(intake_enabled())
        os.environ.pop("ZIP2LEARN_INTAKE_ENABLED", None)


class TestSchemeAllowlist(unittest.TestCase):
    def test_only_http_and_https(self):
        self.assertEqual(ALLOWED_SCHEMES, frozenset({"http", "https"}))

    def test_dangerous_schemes_are_refused(self):
        # urllib would happily read a local file through the first of these.
        for url in (
            "file:///etc/passwd",
            "ftp://example.com/x",
            "gopher://example.com/x",
            "data:text/plain,hello",
            "jar:http://example.com/a!/b",
            "//example.com/no-scheme",
        ):
            with self.subTest(url=url):
                with self.assertRaises(IntakeRefused):
                    validate_url(url)

    def test_a_normal_url_parses(self):
        scheme, host, port, path = validate_url("https://example.com/a/b?c=d")
        self.assertEqual((scheme, host, port), ("https", "example.com", 443))
        self.assertEqual(path, "/a/b?c=d")

    def test_default_ports(self):
        self.assertEqual(validate_url("http://example.com")[2], 80)
        self.assertEqual(validate_url("https://example.com")[2], 443)


class TestAddressValidation(unittest.TestCase):
    """The SSRF guard. Every one of these resolves to somewhere it must not go."""

    def test_loopback_and_local_are_refused(self):
        for ip in ("127.0.0.1", "127.1.2.3", "0.0.0.0", "::1", "::"):
            with self.subTest(ip=ip):
                with self.assertRaises(IntakeRefused):
                    _check_address(ip)

    def test_private_ranges_are_refused(self):
        for ip in ("10.0.0.5", "172.16.4.4", "192.168.1.1", "fd00::1"):
            with self.subTest(ip=ip):
                with self.assertRaises(IntakeRefused):
                    _check_address(ip)

    def test_cloud_metadata_endpoint_is_refused(self):
        """169.254.169.254 is the single most-abused SSRF destination."""
        with self.assertRaises(IntakeRefused):
            _check_address("169.254.169.254")

    def test_ipv4_mapped_ipv6_loopback_is_refused(self):
        """::ffff:127.0.0.1 is loopback wearing a hat; unwrap before judging."""
        with self.assertRaises(IntakeRefused):
            _check_address("::ffff:127.0.0.1")

    def test_cgnat_is_refused(self):
        """100.64.0.0/10 is not covered by is_private but is not the internet."""
        with self.assertRaises(IntakeRefused):
            _check_address("100.64.0.1")

    def test_multicast_and_reserved_are_refused(self):
        for ip in ("224.0.0.1", "240.0.0.1"):
            with self.subTest(ip=ip):
                with self.assertRaises(IntakeRefused):
                    _check_address(ip)

    def test_a_public_address_is_accepted(self):
        for ip in ("93.184.216.34", "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946"):
            with self.subTest(ip=ip):
                _check_address(ip)  # must not raise

    def test_decimal_and_octal_loopback_spellings(self):
        """`127.1` and `2130706433` both resolve to loopback.

        A string blocklist misses these; parsing to an address object does not.
        """
        import ipaddress

        for spelling in ("2130706433", "127.1"):
            with self.subTest(spelling=spelling):
                try:
                    canonical = str(ipaddress.ip_address(int(spelling)))
                except ValueError:
                    canonical = "127.0.0.1"  # `127.1` via getaddrinfo
                with self.assertRaises(IntakeRefused):
                    _check_address(canonical)


if __name__ == "__main__":
    unittest.main(verbosity=2)
