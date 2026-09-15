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
import subprocess
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

# How long to leave the OS folder chooser open before giving up on it. Long
# enough that someone can go and find the folder; short enough that a forgotten
# dialog cannot pin a worker thread for the life of the process.
PICKER_TIMEOUT = 180

# When a chosen folder holds no archives, offer its immediate subfolders that
# do. Bounded so a directory with thousands of entries cannot make a huge reply.
MAX_SUBDIR_HINTS = 20

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
    Route("POST", r"/api/browse", Capability.SCAN, "h_browse"),
    Route("POST", r"/api/choose-dir", Capability.SCAN, "h_choose_dir"),
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


# Entries examined per directory when counting archives. A cap is needed
# because the folder browser calls count_zips once per subfolder, and places
# like ~/Library hold subfolders with a hundred thousand files each.
MAX_COUNT_SCAN = 4000


def count_zips(directory: str) -> int:
    """How many regular .zip files sit directly in `directory`.

    scandir rather than listdir + lstat: the entry's type usually arrives with
    the directory read itself, so this costs roughly one syscall per directory
    instead of one per file. Listing ~/Library was measured at 5.9s with the
    lstat form and 0.1s with this one -- the kind of pause that reads as a hang.

    Past MAX_COUNT_SCAN the count is returned as far as it got. It is a hint
    printed next to a folder name, not a figure anything relies on.
    """
    n = 0
    seen = 0
    try:
        with os.scandir(directory) as it:
            for entry in it:
                seen += 1
                if seen > MAX_COUNT_SCAN:
                    break
                if not entry.name.lower().endswith(".zip"):
                    continue
                try:
                    if entry.is_file(follow_symlinks=False):
                        n += 1
                except OSError:
                    continue
    except OSError:
        return 0
    return n


# A directory listing is metadata, never content, and it is capped so that one
# request cannot turn a folder with a hundred thousand entries into a reply the
# browser has to parse.
MAX_BROWSE_ENTRIES = 500


def browse_dir(directory: str) -> dict:
    """List the subfolders of one directory, for the in-page folder chooser.

    Names and counts only -- never bytes. Symlinked directories are listed but
    not descended into by the counter, so a link back up the tree cannot turn a
    glance at a folder into an unbounded walk.
    """
    entries: list[dict] = []
    truncated = False
    try:
        with os.scandir(directory) as it:
            for entry in it:
                if entry.name.startswith("."):
                    continue
                try:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                except OSError:
                    continue
                if len(entries) >= MAX_BROWSE_ENTRIES:
                    truncated = True
                    break
                entries.append({
                    "name": entry.name,
                    "path": entry.path,
                    "zips": count_zips(entry.path),
                })
    except PermissionError:
        return {
            "path": directory,
            "entries": [],
            "zips": 0,
            "error": "このフォルダを見る権限がありません。",
        }
    except OSError as exc:
        return {"path": directory, "entries": [], "zips": 0, "error": str(exc)}

    entries.sort(key=lambda e: e["name"].lower())
    parent = os.path.dirname(directory)
    return {
        "path": directory,
        "parent": None if parent == directory else parent,
        "entries": entries,
        "zips": count_zips(directory),
        "truncated": truncated,
    }


def browse_shortcuts() -> list[dict]:
    """The handful of places a folder hunt actually starts from."""
    home = os.path.expanduser("~")
    out = []
    for label, path in (
        ("ホーム", home),
        ("デスクトップ", os.path.join(home, "Desktop")),
        ("書類", os.path.join(home, "Documents")),
        ("ダウンロード", os.path.join(home, "Downloads")),
    ):
        if os.path.isdir(path):
            out.append({"name": label, "path": path})
    # Folders already read in this session are the likeliest next destination.
    #
    # Read without STATE.lock on purpose. h_scan holds that lock for the whole
    # length of a scan, so taking it here would stall browsing for seconds
    # behind an unrelated read. Copying a list is atomic under the GIL, and the
    # worst a race can do is leave a shortcut out until the next request.
    for path in list(STATE.dataset_dirs):
        if os.path.isdir(path) and all(s["path"] != path for s in out):
            out.append({"name": os.path.basename(path) or path, "path": path})
    return out


def subdirs_with_zips(directory: str) -> list[dict]:
    """Immediate subfolders that contain archives, for the "did you mean" hint.

    One level only, and never through a symlink: following links here would
    turn a glance at a folder into an unbounded walk of the filesystem.
    """
    out: list[dict] = []
    try:
        entries = sorted(os.listdir(directory))
    except OSError:
        return out
    for name in entries:
        if name.startswith("."):
            continue
        full = os.path.join(directory, name)
        try:
            if not stat.S_ISDIR(os.lstat(full).st_mode):
                continue
        except OSError:
            continue
        n = count_zips(full)
        if n:
            out.append({"name": name, "path": full, "zips": n})
        if len(out) >= MAX_SUBDIR_HINTS:
            break
    return out


class PickerUnavailable(Exception):
    """No OS folder chooser on this machine; the caller should fall back."""


class PickerCancelled(Exception):
    """The person closed the dialog without choosing. Not an error."""


class PickerBusy(Exception):
    """A dialog is already open; a second one would hide behind the first."""


# The prompt is a fixed constant, never interpolated from request data, so
# nothing from the network can reach the script these helpers run.
_PICKER_PROMPT = "調べたいZIPファイルが入っているフォルダを選んでください"

# `choose folder` can only ever return a folder, so picking a file by mistake is
# impossible rather than rejected after the fact.
#
# WHICH APPLICATION SHOWS THE DIALOG DECIDES WHETHER IT IS VISIBLE AT ALL.
# `osascript` registers itself as a UIElement -- a background accessory app --
# so a dialog it owns cannot take focus and simply sits behind the browser. The
# symptom is indistinguishable from a hang: the process is alive, the request
# never returns, and the person sees nothing. Measured with `lsappinfo front`,
# only the Finder spelling actually brings a window forward; the System Events
# and bare spellings both leave the caller's window frontmost.
#
# So: ask Finder, a normal foreground app, to own the dialog. The coercion to a
# POSIX path is done AFTER the tell block, because inside it `POSIX path of`
# would be sent to Finder rather than evaluated by AppleScript itself.
#
# The remaining spellings are fallbacks for when Automation permission for
# Finder is refused. They may open behind other windows, which is worse than
# ideal but better than no dialog at all.
def _folder_script(target: str | None) -> str:
    choose = f'choose folder with prompt "{_PICKER_PROMPT}"'
    if target is None:
        return f"POSIX path of ({choose})"
    return (
        f'tell application "{target}"\n'
        f"\tactivate\n"
        f"\tset chosen to {choose}\n"
        f"end tell\n"
        f"POSIX path of chosen"
    )


_PICKER_OSASCRIPT = [
    _folder_script("Finder"),
    _folder_script("System Events"),
    _folder_script(None),
]

# Only one dialog at a time. Without this, an impatient second click opens a
# second dialog behind the first and both threads sit waiting on a person who
# can only answer one of them.
_PICKER_BUSY = threading.Lock()

_PICKER_POWERSHELL = (
    "Add-Type -AssemblyName System.Windows.Forms;"
    "$d = New-Object System.Windows.Forms.FolderBrowserDialog;"
    f'$d.Description = "{_PICKER_PROMPT}";'
    "if ($d.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK)"
    " { [Console]::Out.Write($d.SelectedPath) } else { exit 1 }"
)


# AppleScript's "user cancelled" error number. osascript exits 1 for EVERY
# script error -- a refused Automation permission (-1743) included -- so the
# exit status alone cannot tell a cancel from a failure. Treating them alike
# made a denied permission look like a cancel: the fallback spellings were
# never tried and the UI, which rightly stays quiet on a cancel, showed
# nothing at all. The error number is not localised, so it is what to match on.
APPLESCRIPT_CANCELLED = "-128"


def _run_picker(argv: list[str], cancel_marker: str | None = None) -> str:
    """Run one folder-chooser command. Returns the chosen path.

    `cancel_marker`, when given, is the text that marks a genuine cancel in
    stderr; any other non-zero exit is a failure the caller should fall back
    from. Without it, exit status 1 means cancelled -- the convention zenity,
    kdialog and the PowerShell dialog all follow.
    """
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=PICKER_TIMEOUT
        )
    except FileNotFoundError as exc:
        raise PickerUnavailable(str(exc)) from exc
    except subprocess.TimeoutExpired as exc:
        raise PickerCancelled("時間内に選択されませんでした") from exc

    if proc.returncode != 0:
        err = proc.stderr.strip()
        # Killed by a signal (the dialog's process was terminated, the machine
        # is going to sleep, someone ran pkill). Opening a replacement dialog
        # would be the opposite of what just happened, so stop here.
        if proc.returncode < 0:
            raise PickerCancelled("フォルダ選択画面が終了しました")
        if cancel_marker is not None:
            if cancel_marker in err:
                raise PickerCancelled("選択が取り消されました")
            raise PickerUnavailable(err or f"exit {proc.returncode}")
        if proc.returncode == 1:
            raise PickerCancelled("選択が取り消されました")
        raise PickerUnavailable(err or f"exit {proc.returncode}")

    path = proc.stdout.strip()
    if not path:
        raise PickerCancelled("選択が取り消されました")
    return path


def choose_directory() -> str:
    """Open the machine's own folder chooser and return the folder's path.

    A browser file input cannot do this job. For privacy reasons it hands back
    file contents and relative names -- never an absolute path -- and this
    server needs the path: the integrity re-check (`/api/verify`) and the
    hexdump preview both re-open the archive on disk long after the page that
    selected it is gone. Since the server and the browser are the same machine
    here by construction (the Host allowlist guarantees it), asking the OS is
    the honest way to browse.

    Each backend selects folders only, so a mis-click on a file cannot happen.
    """
    # A dialog nobody can see is worse than none, so refuse to open a second.
    if not _PICKER_BUSY.acquire(blocking=False):
        raise PickerBusy("フォルダ選択画面はすでに開いています")
    try:
        return _choose_directory_locked()
    finally:
        _PICKER_BUSY.release()


def _choose_directory_locked() -> str:
    if sys.platform == "darwin":
        last: PickerUnavailable | None = None
        for script in _PICKER_OSASCRIPT:
            try:
                return _run_picker(
                    ["osascript", "-e", script], cancel_marker=APPLESCRIPT_CANCELLED
                )
            except PickerUnavailable as exc:
                # Permission refused, or that app cannot show it. Say so on the
                # console: this is the one failure a person cannot see, because
                # its whole symptom is that no window appears.
                print(f"[picker] {str(exc)[:200]}", file=sys.stderr, flush=True)
                last = exc
        raise last
    if sys.platform == "win32":
        return _run_picker(
            ["powershell", "-STA", "-NoProfile", "-Command", _PICKER_POWERSHELL]
        )
    # Linux and the BSDs: whichever toolkit's dialog is actually installed.
    for argv in (
        ["zenity", "--file-selection", "--directory", "--title", _PICKER_PROMPT],
        ["kdialog", "--getexistingdirectory", os.path.expanduser("~")],
    ):
        try:
            return _run_picker(argv)
        except PickerUnavailable:
            continue
    raise PickerUnavailable("この環境で使えるフォルダ選択画面が見つかりませんでした")


class Handler(BaseHTTPRequestHandler):
    timeout = 15  # a stalled connection must not hold a thread forever
    server_version = "mws-local"
    sys_version = ""

    # -- plumbing ---------------------------------------------------------
    def log_message(self, fmt, *args):  # keep the console quiet and PII-free
        pass

    def handle_one_request(self):
        """Treat a client that hangs up mid-reply as ordinary, not as a crash.

        The folder chooser makes this routine: the request is outstanding for
        as long as the dialog is open, so reloading the page or navigating away
        closes the socket under a reply that is still being written. Left
        unhandled, socketserver prints a full traceback for what is simply
        someone changing their mind.
        """
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

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
                    f"権限 '{STATE.role}' ではこの操作（{route.capability}）は許可されていません",
                )
            return getattr(self, route.handler)(*m.groups())

        return self._error(404, "該当する API はありません")

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
            self._error(403, "送信元が不正です")
            return False
        if not secrets.compare_digest(
            self.headers.get("X-MWS-Token") or "", STATE.token
        ):
            self._error(403, "トークンがないか無効です")
            return False
        return True

    def _body(self) -> dict | None:
        """Read and parse a bounded JSON body, or send an error and return None."""
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._error(400, "Content-Length が不正です")
            return None
        # A negative length previously slipped past the cap and made
        # rfile.read(-1) drain the socket to EOF.
        if not 0 <= n <= MAX_BODY:
            self._error(413, "要求本文が大きすぎます")
            return None
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._error(400, "JSON が不正です")
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
            return self._error(404, "見つかりません")
        ext = os.path.splitext(parts[-1])[1]
        if ext not in STATIC_EXT:
            return self._error(404, "見つかりません")

        target = os.path.realpath(os.path.join(REPO_ROOT, *parts))
        # Re-check containment AFTER realpath: a symlink inside the repo could
        # otherwise point anywhere on disk.
        if not target.startswith(os.path.realpath(REPO_ROOT) + os.sep):
            return self._error(404, "見つかりません")
        try:
            with open(target, "rb") as fh:
                body = fh.read()
        except OSError:
            return self._error(404, "見つかりません")
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
                    "読み込んだZIPファイルが追加・変更・削除されたこと",
                ],
                "doesNotDetect": [
                    "ファイルの実行",
                    "通信や、この端末からのデータの持ち出し",
                    "サーバー停止中に行われた変更",
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
            return self._error(404, "そのZIPファイルは読み込まれていません")
        members = [m for m in STATE.store.members(archive_id) if m["idx"] == idx]
        if not members:
            return self._error(404, "該当する項目がありません")
        member = members[0]

        if member.get("container"):
            return self._json({
                "member": member, "rows": [],
                "note": "入れ子になった圧縮ファイル内の項目のため、ここでは先頭バイトを表示できません。",
            })
        if member["verdict"] in (
            Verdict.OPAQUE_ENCRYPTED.value,
            Verdict.UNSUPPORTED_CONTAINER.value,
        ):
            return self._json({
                "member": member, "rows": [],
                "note": "この項目は読み取れないため、表示できる内容がありません。",
            })

        # The archive may have been replaced since it was indexed; pairing a
        # stale verdict with fresh bytes would be worse than refusing.
        try:
            current, _ = sha256_file(rows[0]["path"])
        except OSError as exc:
            return self._json({"member": member, "rows": [], "note": f"読み取れません: {exc}"})
        if current != rows[0]["sha256"]:
            return self._json({
                "member": member, "rows": [],
                "note": "このZIPファイルは読み込み後に変更されています。もう一度読み取ってから確認してください。",
            })

        try:
            with zipfile.ZipFile(rows[0]["path"]) as zf:
                info = zf.infolist()[idx]
                with zf.open(info) as fh:
                    data = fh.read(PREVIEW_BYTES)
        except (OSError, zipfile.BadZipFile, RuntimeError, IndexError, ValueError) as exc:
            return self._json(
                {"member": member, "rows": [], "note": f"読み取れませんでした: {exc}"}
            )
        return self._json({
            "member": member,
            "rows": hexdump(data),
            "note": f"先頭 {len(data)} バイトの16進表示",
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
            return self._error(400, '要求の書式が不正です（archive と member が必要です）')

        rows = [a for a in STATE.store.archives() if a["id"] == archive_id]
        if not rows:
            return self._error(404, "そのZIPファイルは読み込まれていません")
        members = [m for m in STATE.store.members(archive_id) if m["idx"] == idx]
        if not members:
            return self._error(404, "該当する項目がありません")
        member = members[0]
        if member.get("container"):
            return self._error(409, "入れ子になった圧縮ファイル内の項目は書き出せません")

        current, _ = sha256_file(rows[0]["path"])
        if current != rows[0]["sha256"]:
            return self._error(409, "このZIPファイルは読み込み後に変更されています。もう一度読み取ってください")

        with STATE.lock:
            try:
                with zipfile.ZipFile(rows[0]["path"]) as zf:
                    info = zf.infolist()[idx]
                    with zf.open(info) as fh:
                        scanned = scan_stream_full(fh, member["name"], info.file_size)
            except (OSError, zipfile.BadZipFile, RuntimeError, IndexError, ValueError) as exc:
                return self._error(422, f"項目を読み取れませんでした: {exc}")

            if scanned is None:
                return self._error(
                    413, "項目が大きすぎて全体を検証できないため、書き出しを拒否しました"
                )
            ident, digest, total = scanned
            if not ident.materializable:
                STATE.store.log("materialize-refused",
                                f"{member['name'][:80]} -> {ident.verdict.value}")
                return self._error(
                    403,
                    f"拒否: 全体の走査による判定は {ident.verdict.value} です。"
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
                    return self._error(500, "拒否: 書き出したファイルに実行権限が付いていました")
            STATE.store.log("materialize", f"{digest[:12]} {member['name'][:80]}")

        return self._json({
            "written": os.path.relpath(dest, REPO_ROOT),
            "sha256": digest,
            "bytes": total,
            "verdict": ident.verdict.value,
            "note": "保存しました。",
        })

    def h_fetch(self):
        """Acquire a URL into the vault. Disabled on this machine by policy."""
        payload = self._body()
        if payload is None:
            return None
        url = payload.get("url")
        if not isinstance(url, str) or not url:
            return self._error(400, '要求の書式が不正です（url が必要です）')
        if not net.intake_enabled():
            return self._error(403, "この環境では URL からの取得は無効になっています。")
        try:
            net.validate_url(url)
        except net.IntakeRefused as exc:
            return self._error(400, f"拒否: {exc}")

        os.makedirs(BLOB_DIR, mode=0o700, exist_ok=True)
        tmp = os.path.join(BLOB_DIR, f".incoming-{secrets.token_hex(8)}")
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as sink:
                result = net.fetch(url, sink)
        except (net.IntakeRefused, net.IntakeDisabled, OSError) as exc:
            os.unlink(tmp)
            return self._error(400, f"拒否: {exc}")
        dest = blob_path(BLOB_DIR, result.sha256)
        os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
        os.replace(tmp, dest)
        STATE.store.log("fetch", f"{result.sha256[:12]} {result.size}B")
        return self._json({
            "sha256": result.sha256, "bytes": result.size,
            "written": os.path.relpath(dest, REPO_ROOT),
            "note": "保存しました。",
        })

    def h_lessons(self):
        return self._json({"lessons": STATE.store.lessons()})

    def h_lesson(self, lesson_id: str):
        lesson = STATE.store.lesson(lesson_id)
        if lesson is None:
            return self._error(404, "該当する演習がありません")
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
            return self._error(400, '要求の書式が不正です（archive が必要です）')
        rows = [a for a in STATE.store.archives() if a["id"] == archive_id]
        if not rows:
            return self._error(404, "そのZIPファイルは読み込まれていません")

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
            return self._error(422, f"圧縮ファイルを読み取れませんでした: {exc}")

        if not sources:
            return self._error(
                422,
                "この圧縮ファイルには読み取れるログファイルがありません。MWS データセットの "
                "DFIR ログの多くはパスワード付きで、暗号化された項目は読み取れません。",
            )

        base = os.path.basename(rows[0]["path"]).rsplit(".", 1)[0]
        lesson = build_lesson(f"{base} — DFIR 時系列", sources, f"gen-{archive_id}")
        if lesson is None:
            return self._error(422, "ログは読み取れましたが、事象を解析できませんでした")
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

    def h_browse(self):
        """Feed the in-page folder chooser.

        This exists because a native dialog cannot be shown inside the browser
        window. On a full-screen browser macOS switches Spaces to show it,
        which loses the page the person was working in. Listing folders here
        and drawing the chooser in the page keeps the whole job in one window.

        No new exposure: the same capability already reads any directory it is
        pointed at via /api/scan, and this returns names and counts only.
        """
        payload = self._body()
        if payload is None:
            return None
        directory = payload.get("dir")
        if directory in (None, ""):
            directory = os.path.expanduser("~")
        if not isinstance(directory, str) or "\x00" in directory:
            return self._error(400, "パスが不正です")
        directory = os.path.realpath(os.path.expanduser(directory))
        if not os.path.isdir(directory):
            return self._error(404, "該当するフォルダがありません")
        result = browse_dir(directory)
        result["shortcuts"] = browse_shortcuts()
        return self._json(result)

    def h_choose_dir(self):
        """Open the OS folder chooser and report what was picked.

        Cancelling is an ordinary outcome, not a failure, so it comes back as
        200 with `cancelled: true`: the UI has nothing to apologise for and
        should simply carry on. The same goes for a machine with no dialog
        available -- the page falls back to the typed path instead of showing
        an error the person cannot act on.
        """
        try:
            directory = choose_directory()
        except (PickerCancelled, PickerBusy) as exc:
            return self._json({"cancelled": True, "detail": str(exc)})
        except PickerUnavailable as exc:
            return self._json({"unavailable": True, "detail": str(exc)})

        directory = os.path.realpath(directory)
        # The dialogs only return folders, so this should not fire. It is here
        # because "should not" is not a guarantee, and the caller of /api/scan
        # deserves a real directory or a clear reason.
        if not os.path.isdir(directory):
            return self._json({
                "unavailable": True,
                "detail": "選ばれた場所がフォルダではありませんでした",
            })
        return self._json({"dir": directory, "zips": count_zips(directory)})

    def h_scan(self):
        payload = self._body()
        if payload is None:
            return None
        directory = payload.get("dir")
        if not isinstance(directory, str) or not directory:
            return self._error(400, '要求の書式が不正です（dir が必要です）')
        if "\x00" in directory:
            return self._error(400, "パスが不正です")
        directory = os.path.realpath(os.path.expanduser(directory))
        if not os.path.isdir(directory):
            # Distinguish the two ways this goes wrong. "フォルダがありません"
            # for a path that is really a file sends people looking for a typo
            # that is not there.
            if os.path.exists(directory):
                return self._error(
                    400,
                    "指定されたのはファイルです。ZIPファイルが入っている"
                    "フォルダのほうを指定してください。",
                )
            return self._error(404, "該当するフォルダがありません")

        found = []
        with STATE.lock:
            for name in sorted(os.listdir(directory)):
                if not name.lower().endswith(".zip"):
                    continue
                full = os.path.join(directory, name)
                try:
                    if not stat.S_ISREG(os.lstat(full).st_mode):
                        found.append({"name": name, "skipped": "通常のファイルではありません"})
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
        # Picking the parent of the folder you meant is the easy mistake to
        # make in a file dialog, and "no archives here" is a dead end when the
        # archives are one level down. Offer those folders instead.
        hints = [] if found else subdirs_with_zips(directory)
        return self._json({"scanned": found, "subdirs": hints})


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
