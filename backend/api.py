"""api.py — the local server. Stdlib only; no third-party dependencies.

Serves the existing static front end AND the inspection API from the SAME
origin, which removes the entire CORS surface by construction: with no
Access-Control-Allow-Origin header anywhere, a cross-origin page cannot read a
single response.

Security decisions, in the order they are enforced:

  1. HOST ALLOWLIST, before routing or any I/O. `127.0.0.1` is not a security
     boundary: with DNS rebinding a page on evil.example keeps its own origin
     while resolving to loopback, so the same-origin policy lets it read every
     response. The browser sends `Host: evil.example:PORT`, so an exact-match
     allowlist on Host is what actually stops it. Safari does not implement
     Private Network Access, so nothing else will.
  2. A RANDOM HIGH PORT chosen at startup, so an attacker page must guess it.
  3. NO PATH PARAMETERS THAT REACH THE FILESYSTEM. Ids are integers; static
     paths are matched against an explicit allowlist and re-checked after
     realpath.
  4. NO RAW SAMPLE BYTES. Previews are server-rendered hexdumps. Returning a
     member's bytes on this origin would let an archive containing `x.html`
     execute script inside the application origin.
"""

from __future__ import annotations

import io
import json
import os
import re
import secrets
import socket
import stat
import sys
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from archive import (  # noqa: E402
    MAX_NESTED_BYTES,
    decode_name,
    enumerate_zip,
    raw_name_bytes,
    scan_stream_full,
)
from explain import build_lesson  # noqa: E402
from identify import HEAD_BYTES, Verdict  # noqa: E402
import net  # noqa: E402
from store import Store, blob_path, sha256_file  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_DIR = os.path.join(REPO_ROOT, ".mws-state")
BLOB_DIR = os.path.join(STATE_DIR, "vault")

# Static files we will serve, by directory and extension. An allowlist, so a
# new file type cannot be served by accident.
STATIC_DIRS = ("js", "styles", "data")
STATIC_EXT = {".js": "text/javascript", ".css": "text/css", ".json": "application/json"}

PREVIEW_BYTES = 2048
MAX_BODY = 64 * 1024

# {nonce} is filled per response. Never use 'unsafe-inline' here: the page
# carries the injected mws-token, so script injection would hand it over.
CSP = (
    "default-src 'none'; script-src 'self' 'nonce-{nonce}'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'"
)


class Capability:
    READ = "read"
    SCAN = "scan"
    VERIFY = "verify"
    MATERIALIZE_INERT = "materialize-inert"
    INTAKE = "intake"


ROLE_CAPS = {
    # A student may look at anything already indexed and nothing else.
    "student": {Capability.READ},
    "instructor": {
        Capability.READ, Capability.SCAN, Capability.VERIFY,
        Capability.MATERIALIZE_INERT, Capability.INTAKE,
    },
}


class Route:
    """One endpoint, with the capability it requires.

    Routing is a declarative table rather than a chain of `if path ==` so that
    a test can iterate every route and fail the build when one does not declare
    a capability. A denylist of "things students may not do" can never be
    enumerated completely; this is the inverted, default-deny form.
    """

    __slots__ = ("method", "pattern", "capability", "handler")

    def __init__(self, method: str, pattern: str, capability: str, handler: str):
        self.method = method
        self.pattern = re.compile(pattern)
        self.capability = capability
        self.handler = handler


ROUTES = [
    Route("GET", r"/api/status", Capability.READ, "h_status"),
    Route("GET", r"/api/archives", Capability.READ, "h_archives"),
    Route("GET", r"/api/events", Capability.READ, "h_events"),
    Route("GET", r"/api/archives/(\d{1,9})/members", Capability.READ, "h_members"),
    Route("GET", r"/api/archives/(\d{1,9})/members/(\d{1,9})/preview",
          Capability.READ, "h_preview"),
    Route("GET", r"/api/lessons", Capability.READ, "h_lessons"),
    Route("GET", r"/api/lessons/([A-Za-z0-9_-]{1,64})", Capability.READ, "h_lesson"),
    Route("POST", r"/api/scan", Capability.SCAN, "h_scan"),
    Route("POST", r"/api/generate", Capability.SCAN, "h_generate"),
    Route("POST", r"/api/verify", Capability.VERIFY, "h_verify"),
    Route("POST", r"/api/materialize", Capability.MATERIALIZE_INERT, "h_materialize"),
    Route("POST", r"/api/fetch", Capability.INTAKE, "h_fetch"),
]


ROLE_FILE = os.path.expanduser("~/.config/mws/role")
DEFAULT_ROLE = "instructor"


def load_role() -> str:
    """Read the role from a config file outside the repo.

    The default is `instructor`, deliberately. Whoever launches this server is
    running it on their own machine against their own dataset -- they ARE the
    instructor -- and defaulting to `student` made the tool a dead end on first
    run: nothing indexed, and no capability to index anything. `student` is an
    opt-in downgrade for when the app is handed to a learner.

    That is not a weakened boundary, because `student` was never a boundary.
    Honest framing (BUILD-CONTRACT): it is an anti-footgun control, not
    containment. Someone running as their own uid can edit this file or start
    their own copy of the server. It prevents accidents and limits what a
    hostile web page could drive through the API; it does not restrain a
    motivated student, and the UI must not claim otherwise. The controls that
    do carry weight -- the Host allowlist, the token on every mutation, and
    intake being off unless MWS_INTAKE_ENABLED=1 -- are unaffected by the role.
    """
    try:
        with open(ROLE_FILE, encoding="utf-8") as fh:
            role = fh.read().strip()
    except OSError:
        return DEFAULT_ROLE
    if role not in ROLE_CAPS:
        print(f"[warn] {ROLE_FILE} names an unknown role {role!r}; "
              "falling back to student", file=sys.stderr)
        return "student"  # a malformed file fails CLOSED, not open
    try:
        if os.stat(ROLE_FILE).st_mode & 0o022:
            print(f"[warn] {ROLE_FILE} is group/other-writable; ignoring it",
                  file=sys.stderr)
            return "student"
    except OSError:
        return "student"
    return role


class State:
    def __init__(self) -> None:
        self.store = Store(os.path.join(STATE_DIR, "manifest.sqlite3"))
        self.role = load_role()
        self.caps = ROLE_CAPS[self.role]
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.dataset_dirs: list[str] = []

    def can(self, cap: str) -> bool:
        return cap in self.caps


STATE: State | None = None
ALLOWED_HOSTS: frozenset[str] = frozenset()


def hexdump(data: bytes, base: int = 0) -> list[dict]:
    """Render bytes as inert rows of JSON. Never returns the raw bytes."""
    rows = []
    for off in range(0, len(data), 16):
        chunk = data[off : off + 16]
        rows.append(
            {
                "offset": f"{base + off:08x}",
                "hex": " ".join(f"{b:02x}" for b in chunk),
                "text": "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk),
            }
        )
    return rows


class Handler(BaseHTTPRequestHandler):
    timeout = 15  # a stalled connection must not hold a thread forever
    server_version = "mws-local"
    sys_version = ""

    # -- plumbing ---------------------------------------------------------
    def log_message(self, fmt, *args):  # keep the console quiet and PII-free
        pass

    def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None,
              nonce: str = ""):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", CSP.format(nonce=nonce))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code: int = 200):
        self._send(code, json.dumps(obj).encode(), "application/json")

    def _error(self, code: int, message: str):
        self._json({"error": message}, code)

    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") in ALLOWED_HOSTS

    # -- routing ----------------------------------------------------------
    def _dispatch(self, method: str):
        # (1) Host allowlist runs before ANYTHING else touches the request --
        #     before routing, before any body is read, before any I/O.
        if not self._host_ok():
            self._send(421, b"bad host", "text/plain")
            return

        path = self.path.split("?", 1)[0]

        if method == "GET" and path in ("/", "/index.html"):
            return self._serve_index()
        if method == "GET" and not path.startswith("/api/"):
            return self._static(path)

        for route in ROUTES:
            if route.method != method:
                continue
            m = route.pattern.fullmatch(path)
            if not m:
                continue
            if method != "GET" and not self._mutation_allowed():
                return
            if not STATE.can(route.capability):
                return self._error(
                    403,
                    f"role '{STATE.role}' lacks the '{route.capability}' capability",
                )
            return getattr(self, route.handler)(*m.groups())

        return self._error(404, "no such endpoint")

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _mutation_allowed(self) -> bool:
        """Origin + token check for anything that changes state.

        Layered behind the Host allowlist rather than relied on alone: a
        rebinding page can read the token out of the served HTML, so the Host
        check is what actually stops it.
        """
        origin = self.headers.get("Origin")
        if origin is not None and origin.split("//", 1)[-1] not in ALLOWED_HOSTS:
            self._error(403, "bad origin")
            return False
        if not secrets.compare_digest(
            self.headers.get("X-MWS-Token") or "", STATE.token
        ):
            self._error(403, "missing or invalid token")
            return False
        return True

    def _body(self) -> dict | None:
        """Read and parse a bounded JSON body, or send an error and return None."""
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._error(400, "bad Content-Length")
            return None
        # A negative length previously slipped past the cap and made
        # rfile.read(-1) drain the socket to EOF.
        if not 0 <= n <= MAX_BODY:
            self._error(413, "body too large")
            return None
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._error(400, "invalid JSON")
            return None

    # -- static -----------------------------------------------------------
    def _serve_index(self):
        with open(os.path.join(REPO_ROOT, "index.html"), "rb") as fh:
            html = fh.read()
        # Hand the token to the page. EventSource cannot set headers, so the
        # UI reads this meta tag and sends it as X-MWS-Token via fetch().
        tag = f'<meta name="mws-token" content="{STATE.token}">'.encode()
        html = html.replace(b"<head>", b"<head>\n  " + tag, 1)
        # The no-flash theme init is inline by design (it must run pre-paint),
        # so it needs a nonce rather than 'unsafe-inline'.
        nonce = secrets.token_urlsafe(16)
        html = html.replace(b"<script>", f'<script nonce="{nonce}">'.encode(), 1)
        self._send(200, html, "text/html; charset=utf-8", nonce=nonce)

    def _static(self, path: str):
        parts = [p for p in path.split("/") if p]
        if not parts or parts[0] not in STATIC_DIRS or any(p == ".." for p in parts):
            return self._error(404, "not found")
        ext = os.path.splitext(parts[-1])[1]
        if ext not in STATIC_EXT:
            return self._error(404, "not found")

        target = os.path.realpath(os.path.join(REPO_ROOT, *parts))
        # Re-check containment AFTER realpath: a symlink inside the repo could
        # otherwise point anywhere on disk.
        if not target.startswith(os.path.realpath(REPO_ROOT) + os.sep):
            return self._error(404, "not found")
        try:
            with open(target, "rb") as fh:
                body = fh.read()
        except OSError:
            return self._error(404, "not found")
        self._send(200, body, STATIC_EXT[ext] + "; charset=utf-8")

    # -- api handlers -----------------------------------------------------
    # Each is reached only through ROUTES, which declares its capability.

    def h_status(self):
        return self._json({
            "role": STATE.role,
            "capabilities": sorted(STATE.caps),
            "datasetDirs": STATE.dataset_dirs,
            "claims": {
                "detects": [
                    "a tracked archive being added, changed, or removed",
                ],
                "doesNotDetect": [
                    "execution of any file",
                    "network activity or data leaving this machine",
                    "changes made while this server is not running",
                ],
            },
        })

    def h_archives(self):
        return self._json({"archives": STATE.store.archives()})

    def h_events(self):
        return self._json({"events": STATE.store.events(200)})

    def h_members(self, archive_id: str):
        return self._json({"members": STATE.store.members(int(archive_id))})

    def h_preview(self, archive_id: str, idx: str):
        archive_id, idx = int(archive_id), int(idx)
        rows = [a for a in STATE.store.archives() if a["id"] == archive_id]
        if not rows:
            return self._error(404, "no such archive")
        members = [m for m in STATE.store.members(archive_id) if m["idx"] == idx]
        if not members:
            return self._error(404, "no such member")
        member = members[0]

        if member.get("container"):
            return self._json({
                "member": member, "rows": [],
                "note": "This entry lives inside a nested archive, so it has no "
                        "position in the outer file and cannot be previewed here.",
            })
        if member["verdict"] in (
            Verdict.OPAQUE_ENCRYPTED.value,
            Verdict.UNSUPPORTED_CONTAINER.value,
        ):
            return self._json({
                "member": member, "rows": [],
                "note": "This member cannot be read, so there is nothing to preview.",
            })

        # The archive may have been replaced since it was indexed; pairing a
        # stale verdict with fresh bytes would be worse than refusing.
        try:
            current, _ = sha256_file(rows[0]["path"])
        except OSError as exc:
            return self._json({"member": member, "rows": [], "note": f"Unreadable: {exc}"})
        if current != rows[0]["sha256"]:
            return self._json({
                "member": member, "rows": [],
                "note": "This archive has changed on disk since it was indexed. "
                        "Re-index it before trusting anything shown here.",
            })

        try:
            with zipfile.ZipFile(rows[0]["path"]) as zf:
                info = zf.infolist()[idx]
                with zf.open(info) as fh:
                    data = fh.read(PREVIEW_BYTES)
        except (OSError, zipfile.BadZipFile, RuntimeError, IndexError, ValueError) as exc:
            return self._json(
                {"member": member, "rows": [], "note": f"Could not read: {exc}"}
            )
        return self._json({
            "member": member,
            "rows": hexdump(data),
            "note": f"First {len(data)} bytes, rendered as hex. Raw bytes are "
                    "never served in a form the browser will execute.",
        })

    def h_verify(self):
        results = STATE.store.verify()
        return self._json(
            {"results": [r.__dict__ for r in results], "role": STATE.role}
        )

    def h_materialize(self):
        """Write ONE verified-inert member to the vault, content-addressed.

        The gate here is `scan_stream_full`, not the stored verdict. The stored
        verdict came from a 4 KB prefix, which is fine for display and is not
        good enough to authorize a write: a payload can live past the window,
        and a ZIP is located by its END record, so a polyglot is invisible to a
        prefix scan by construction.

        The destination name is the content hash. Nothing from the archive ever
        becomes a path component, which is what makes zip-slip and traversal
        structurally impossible here rather than merely filtered.
        """
        payload = self._body()
        if payload is None:
            return None
        try:
            archive_id = int(payload.get("archive"))
            idx = int(payload.get("member"))
        except (TypeError, ValueError):
            return self._error(400, 'expected {"archive": int, "member": int}')

        rows = [a for a in STATE.store.archives() if a["id"] == archive_id]
        if not rows:
            return self._error(404, "no such archive")
        members = [m for m in STATE.store.members(archive_id) if m["idx"] == idx]
        if not members:
            return self._error(404, "no such member")
        member = members[0]
        if member.get("container"):
            return self._error(409, "members of nested archives cannot be written out")

        current, _ = sha256_file(rows[0]["path"])
        if current != rows[0]["sha256"]:
            return self._error(409, "archive changed on disk since indexing; re-scan first")

        with STATE.lock:
            try:
                with zipfile.ZipFile(rows[0]["path"]) as zf:
                    info = zf.infolist()[idx]
                    with zf.open(info) as fh:
                        scanned = scan_stream_full(fh, member["name"], info.file_size)
            except (OSError, zipfile.BadZipFile, RuntimeError, IndexError, ValueError) as exc:
                return self._error(422, f"could not read the member: {exc}")

            if scanned is None:
                return self._error(
                    413, "member is too large to verify end to end, so it is refused"
                )
            ident, digest, total = scanned
            if not ident.materializable:
                STATE.store.log("materialize-refused",
                                f"{member['name'][:80]} -> {ident.verdict.value}")
                return self._error(
                    403,
                    f"refused: the whole-file scan says {ident.verdict.value}. "
                    f"{ident.caveat or ident.why}",
                )

            dest = blob_path(BLOB_DIR, digest)
            os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
            if not os.path.exists(dest):
                # O_EXCL|O_NOFOLLOW with the mode set AT CREATION: setting the
                # mode afterwards leaves a window at the umask default, and
                # re-opening by path can follow a symlink planted meanwhile.
                fd = os.open(dest, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                try:
                    with zipfile.ZipFile(rows[0]["path"]) as zf:
                        with zf.open(zf.infolist()[idx]) as src:
                            while True:
                                chunk = src.read(1024 * 1024)
                                if not chunk:
                                    break
                                os.write(fd, chunk)
                    st = os.fstat(fd)
                finally:
                    os.close(fd)
                if st.st_mode & 0o111:
                    os.unlink(dest)
                    return self._error(500, "refusing: file landed with an execute bit")
            STATE.store.log("materialize", f"{digest[:12]} {member['name'][:80]}")

        return self._json({
            "written": os.path.relpath(dest, REPO_ROOT),
            "sha256": digest,
            "bytes": total,
            "verdict": ident.verdict.value,
            "note": "Written read-only, named by content hash. The archive's own "
                    "name was not used for any part of the path.",
        })

    def h_fetch(self):
        """Acquire a URL into the vault. Disabled on this machine by policy."""
        payload = self._body()
        if payload is None:
            return None
        url = payload.get("url")
        if not isinstance(url, str) or not url:
            return self._error(400, 'expected {"url": "..."}')
        if not net.intake_enabled():
            return self._error(403, (
                "Acquisition is disabled on this machine (BUILD-CONTRACT rule 2). "
                "The code path exists and is tested, but downloading is not "
                "permitted here. Set MWS_INTAKE_ENABLED=1 only where it is."
            ))
        try:
            net.validate_url(url)
        except net.IntakeRefused as exc:
            return self._error(400, f"refused: {exc}")

        os.makedirs(BLOB_DIR, mode=0o700, exist_ok=True)
        tmp = os.path.join(BLOB_DIR, f".incoming-{secrets.token_hex(8)}")
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as sink:
                result = net.fetch(url, sink)
        except (net.IntakeRefused, net.IntakeDisabled, OSError) as exc:
            os.unlink(tmp)
            return self._error(400, f"refused: {exc}")
        dest = blob_path(BLOB_DIR, result.sha256)
        os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
        os.replace(tmp, dest)
        STATE.store.log("fetch", f"{result.sha256[:12]} {result.size}B")
        return self._json({
            "sha256": result.sha256, "bytes": result.size,
            "written": os.path.relpath(dest, REPO_ROOT),
            "note": "Stored by content hash; the URL never named the file.",
        })

    def h_lessons(self):
        return self._json({"lessons": STATE.store.lessons()})

    def h_lesson(self, lesson_id: str):
        lesson = STATE.store.lesson(lesson_id)
        if lesson is None:
            return self._error(404, "no such lesson")
        return self._json(lesson)

    def h_generate(self):
        """Build a draft lesson from the readable logs in one archive.

        Reads log text in memory only -- nothing is extracted to disk. Encrypted
        and oversized members are skipped rather than guessed at.
        """
        payload = self._body()
        if payload is None:
            return None
        try:
            archive_id = int(payload.get("archive"))
        except (TypeError, ValueError):
            return self._error(400, 'expected {"archive": int}')
        rows = [a for a in STATE.store.archives() if a["id"] == archive_id]
        if not rows:
            return self._error(404, "no such archive")

        sources: dict[str, str] = {}
        budget = 24 * 1024 * 1024

        def collect(zf, prefix="", depth=0):
            nonlocal budget
            for info in zf.infolist():
                if info.is_dir() or budget <= 0:
                    continue
                # Decode the name the same way the enumerator does. Using
                # info.filename directly yields cp437 mojibake for the CP932/
                # UTF-8 names in this dataset.
                decoded, _enc = decode_name(
                    raw_name_bytes(info), bool(info.flag_bits & 0x800)
                )
                name = prefix + decoded
                if info.flag_bits & 0x1:
                    continue  # encrypted: unreadable, so skipped rather than guessed
                if name.lower().endswith(".log") and info.file_size:
                    try:
                        raw = zf.open(info).read(min(budget, 4 * 1024 * 1024))
                    except Exception:  # noqa: BLE001
                        continue
                    budget -= len(raw)
                    sources[name] = raw.decode("utf-8", "replace")
                elif (
                    name.lower().endswith(".zip")
                    and depth < 2
                    and 0 < info.file_size <= MAX_NESTED_BYTES
                ):
                    try:
                        nested = zipfile.ZipFile(io.BytesIO(zf.open(info).read()))
                    except Exception:  # noqa: BLE001
                        continue
                    with nested:
                        collect(nested, name + " :: ", depth + 1)

        try:
            with zipfile.ZipFile(rows[0]["path"]) as zf:
                collect(zf)
        except Exception as exc:  # noqa: BLE001
            return self._error(422, f"could not read the archive: {exc}")

        if not sources:
            return self._error(
                422,
                "No readable log files in this archive. The DFIR logs in several "
                "MWS sets are password-protected, and encrypted members are "
                "skipped rather than guessed at.",
            )

        base = os.path.basename(rows[0]["path"]).rsplit(".", 1)[0]
        lesson = build_lesson(f"{base} — DFIR timeline", sources, f"gen-{archive_id}")
        if lesson is None:
            return self._error(422, "logs were readable but no events could be parsed")
        STATE.store.save_lesson(lesson, base)
        return self._json({
            "id": lesson["id"], "title": lesson["title"],
            "stages": len(lesson["stages"]),
            "events": sum(len(s["events"]) for s in lesson["stages"]),
            "tagged": sum(
                1 for s in lesson["stages"] for e in s["events"] if "attck" in e
            ),
            "sources": sorted(sources),
        })

    def h_scan(self):
        payload = self._body()
        if payload is None:
            return None
        directory = payload.get("dir")
        if not isinstance(directory, str) or not directory:
            return self._error(400, 'expected {"dir": "..."}')
        if "\x00" in directory:
            return self._error(400, "invalid path")
        directory = os.path.realpath(os.path.expanduser(directory))
        if not os.path.isdir(directory):
            return self._error(404, "no such directory")

        found = []
        with STATE.lock:
            for name in sorted(os.listdir(directory)):
                if not name.lower().endswith(".zip"):
                    continue
                full = os.path.join(directory, name)
                try:
                    if not stat.S_ISREG(os.lstat(full).st_mode):
                        found.append({"name": name, "skipped": "not a regular file"})
                        continue
                except OSError:
                    continue
                # One hostile archive must not abort the whole batch.
                try:
                    listing = enumerate_zip(full)
                    archive_id = STATE.store.record_archive(full, listing)
                except Exception as exc:  # noqa: BLE001 - fail closed, keep going
                    found.append({"name": name, "skipped": f"{type(exc).__name__}: {exc}"})
                    continue
                found.append(
                    {"id": archive_id, "name": name, "members": len(listing.members)}
                )
            if directory not in STATE.dataset_dirs:
                STATE.dataset_dirs.append(directory)
        return self._json({"scanned": found})


def main() -> None:
    global STATE, ALLOWED_HOSTS
    os.makedirs(STATE_DIR, exist_ok=True)
    STATE = State()

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))  # random high port: the attacker must guess it
    port = sock.getsockname()[1]
    sock.close()

    ALLOWED_HOSTS = frozenset(
        {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
    )

    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    # flush=True matters: Python block-buffers stdout when it is a pipe, so
    # launching this from a script or a log redirect would otherwise show
    # nothing at all -- including the port number you need to open the app.
    print(f"  MWS inspector  ->  http://127.0.0.1:{port}/", flush=True)
    if STATE.role == "instructor":
        print("  role: instructor  (full access - this is your own machine)", flush=True)
        print(f"        hand it to a learner with:  "
              f"mkdir -p {os.path.dirname(ROLE_FILE)} && "
              f"echo student > {ROLE_FILE}", flush=True)
    else:
        print(f"  role: {STATE.role}  (read-only; delete {ROLE_FILE} to restore "
              "full access)", flush=True)
    print("  Ctrl+C to stop.", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped.")


if __name__ == "__main__":
    main()
