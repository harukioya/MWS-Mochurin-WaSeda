"""net.py — acquisition. THE ONLY module in this project allowed to open a socket.

Keeping every outbound byte in one small file is the point: the invariant
"nothing else talks to the network" is then checkable by reading one import
list rather than by auditing the whole backend.

DISABLED BY DEFAULT. `fetch()` refuses unless ZIP2LEARN_INTAKE_ENABLED=1 is set in
the environment. The project rule is that the tool does not download anything
unless the person running it opts in explicitly; on the machine this was
written for, downloading is prohibited outright, so the switch stays off and
the code path is exercised only by unit tests against locally authored fixtures.

Controls, each of which closes a specific hole:

  * SCHEME ALLOWLIST. `file:`, `ftp:`, `gopher:`, `data:` are not merely
    unhandled, they are rejected. urllib would happily read a local file.
  * PER-HOP ADDRESS VALIDATION. Every hostname is resolved here and every
    returned address is checked. Loopback, private, link-local (including
    169.254.169.254, the cloud metadata endpoint), CGNAT, reserved, multicast
    and IPv4-mapped-IPv6 are all refused.
  * PINNED CONNECT. We connect to the address we validated, not to a name the
    resolver may answer differently the second time. Validate-then-reconnect
    is a DNS-rebinding hole; this closes it.
  * MANUAL REDIRECTS, MAX 3, EACH RE-VALIDATED. A public URL that 302s to
    127.0.0.1 is the standard way to defeat a naive pre-flight check.
  * IDENTITY ENCODING AND A RAW BYTE CAP. `Accept-Encoding: identity` stops a
    1 KB response expanding to gigabytes, and the cap counts bytes off the
    socket, before any decoding.
  * NO NAME FROM THE NETWORK. The caller stores by content hash. Nothing from
    the URL path or Content-Disposition ever becomes a path component.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import os
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

ALLOWED_SCHEMES = frozenset({"http", "https"})
MAX_REDIRECTS = 3
MAX_BYTES = 512 * 1024 * 1024
CONNECT_TIMEOUT = 10
READ_TIMEOUT = 30
_CHUNK = 256 * 1024


class IntakeDisabled(RuntimeError):
    """Raised when acquisition is attempted while the feature is switched off."""


class IntakeRefused(ValueError):
    """Raised when a URL or address fails a safety check."""


def intake_enabled() -> bool:
    return os.environ.get("ZIP2LEARN_INTAKE_ENABLED") == "1"


@dataclass
class Fetched:
    url: str
    sha256: str
    size: int
    content_type: str


def _check_address(ip: str) -> None:
    """Refuse any address that is not a public unicast destination."""
    addr = ipaddress.ip_address(ip)
    # An IPv4-mapped IPv6 address (::ffff:127.0.0.1) is loopback wearing a hat;
    # unwrap before judging it.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    ):
        raise IntakeRefused(f"address {addr} is not a public destination")
    # Carrier-grade NAT: not covered by is_private, still not the public internet.
    if isinstance(addr, ipaddress.IPv4Address) and addr in ipaddress.ip_network(
        "100.64.0.0/10"
    ):
        raise IntakeRefused(f"address {addr} is in the CGNAT range")


def _resolve(host: str, port: int) -> list[tuple[int, str]]:
    """Resolve a host and validate EVERY answer. Returns [(family, ip), ...]."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise IntakeRefused(f"cannot resolve {host}: {exc}") from exc
    out = []
    for family, _t, _p, _c, sockaddr in infos:
        ip = sockaddr[0]
        _check_address(ip)  # one bad answer refuses the whole host
        out.append((family, ip))
    if not out:
        raise IntakeRefused(f"{host} resolved to nothing")
    return out


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to a validated IP while still validating the certificate.

    Passing the IP as the host would break SNI and certificate checking; using
    the hostname would let the resolver answer differently the second time.
    This does both correctly: dial the pinned address, present the hostname.
    """

    def __init__(self, host: str, ip: str, port: int, context: ssl.SSLContext):
        super().__init__(host, port, timeout=CONNECT_TIMEOUT, context=context)
        self._pinned_ip = ip

    def connect(self):
        sock = socket.create_connection(
            (self._pinned_ip, self.port), timeout=CONNECT_TIMEOUT
        )
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, ip: str, port: int):
        super().__init__(host, port, timeout=CONNECT_TIMEOUT)
        self._pinned_ip = ip

    def connect(self):
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port), timeout=CONNECT_TIMEOUT
        )


def validate_url(url: str) -> tuple[str, str, int, str]:
    """Parse and vet a URL. Returns (scheme, host, port, path_with_query)."""
    parts = urlsplit(url)
    if parts.scheme not in ALLOWED_SCHEMES:
        raise IntakeRefused(
            f"scheme {parts.scheme!r} is not allowed (only http and https)"
        )
    if not parts.hostname:
        raise IntakeRefused("URL has no host")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if not 0 < port < 65536:
        raise IntakeRefused("invalid port")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return parts.scheme, parts.hostname, port, path


def _open(scheme: str, host: str, port: int, path: str):
    """One hop. Resolves, validates, pins, and returns the response."""
    family_ip = _resolve(host, port)[0]
    ip = family_ip[1]
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        conn = _PinnedHTTPSConnection(host, ip, port, ctx)
    else:
        conn = _PinnedHTTPConnection(host, ip, port)
    conn.request(
        "GET",
        path,
        headers={
            # Identity: a compressed response must not be able to expand past
            # the byte cap after we have already accepted it.
            "Accept-Encoding": "identity",
            "User-Agent": "zip2learn/1.0",
            "Host": host,
        },
    )
    return conn, conn.getresponse()


def fetch(url: str, sink) -> Fetched:
    """Download `url`, streaming into `sink` (a writable binary file object).

    The caller decides where the bytes land, and must name the destination
    from the content hash -- never from the URL or from Content-Disposition.
    """
    if not intake_enabled():
        raise IntakeDisabled(
            "Acquisition is disabled. Set ZIP2LEARN_INTAKE_ENABLED=1 to enable it, "
            "only if downloading samples is permitted where you run this tool."
        )

    seen = 0
    digest = hashlib.sha256()
    content_type = ""
    scheme, host, port, path = validate_url(url)

    for hop in range(MAX_REDIRECTS + 1):
        conn, resp = _open(scheme, host, port, path)
        try:
            if resp.status in (301, 302, 303, 307, 308):
                location = resp.getheader("Location") or ""
                if hop == MAX_REDIRECTS:
                    raise IntakeRefused("too many redirects")
                if not location:
                    raise IntakeRefused("redirect without a Location header")
                # Re-validate from scratch: this is where a public URL tries to
                # bounce us to 127.0.0.1 or the metadata endpoint.
                scheme, host, port, path = validate_url(location)
                continue
            if resp.status != 200:
                raise IntakeRefused(f"HTTP {resp.status}")

            content_type = resp.getheader("Content-Type") or ""
            declared = resp.getheader("Content-Length")
            if declared is not None:
                try:
                    if int(declared) > MAX_BYTES:
                        raise IntakeRefused("Content-Length exceeds the size cap")
                except ValueError:
                    raise IntakeRefused("bad Content-Length") from None

            while True:
                chunk = resp.read(_CHUNK)
                if not chunk:
                    break
                seen += len(chunk)
                # Counted off the socket, so a lying Content-Length cannot help.
                if seen > MAX_BYTES:
                    raise IntakeRefused("response exceeded the size cap mid-stream")
                digest.update(chunk)
                sink.write(chunk)
            return Fetched(url, digest.hexdigest(), seen, content_type)
        finally:
            conn.close()

    raise IntakeRefused("too many redirects")
