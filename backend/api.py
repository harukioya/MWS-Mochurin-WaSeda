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

import hashlib
import json
import os
import re
import secrets
import socket
import stat
import subprocess
import sys
import threading
import urllib.parse
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from archive import (  # noqa: E402
    enumerate_zip,
    scan_stream_full,
)
import dataset  # noqa: E402
import explain  # noqa: E402
import ghidra_api  # noqa: E402
import ghidra_docker  # noqa: E402
import ghidra_jobs  # noqa: E402
from identify import HEAD_BYTES, Verdict  # noqa: E402
import net  # noqa: E402
import parsers  # noqa: E402
from store import Store, blob_path, sha256_file  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_DIR = os.path.join(REPO_ROOT, ".mws-state")
BLOB_DIR = os.path.join(STATE_DIR, "vault")
#: GZF の入力コピーを置く、ジョブ専用の一時領域。処理が終われば消える。
GHIDRA_JOB_DIR = os.path.join(STATE_DIR, "ghidra-jobs")

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
    # Ghidra 静的解析教材。GZF を受け取ってローカルの Docker で読むことと、
    # その処理環境（イメージ）を準備することは、別の権限にする。
    GHIDRA_ANALYZE = "ghidra-analyze"
    GHIDRA_PREPARE = "ghidra-prepare"


ROLE_CAPS = {
    # A student may look at anything already indexed and nothing else.
    "student": {Capability.READ},
    "instructor": {
        Capability.READ, Capability.SCAN, Capability.VERIFY,
        Capability.MATERIALIZE_INERT, Capability.INTAKE,
        Capability.GHIDRA_ANALYZE, Capability.GHIDRA_PREPARE,
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
    Route("GET", r"/api/archives/(\d{1,9})/dataset", Capability.READ, "h_dataset"),
    Route("GET", r"/api/archives/(\d{1,9})/members", Capability.READ, "h_members"),
    Route("GET", r"/api/archives/(\d{1,9})/members/(\d{1,9})/preview",
          Capability.READ, "h_preview"),
    Route("GET", r"/api/lessons", Capability.READ, "h_lessons"),
    Route("GET", r"/api/lessons/([A-Za-z0-9_-]{1,64})", Capability.READ, "h_lesson"),
    Route("GET", r"/api/lessons/([A-Za-z0-9_-]{1,64})/evidence/(ev-[0-9a-f]{8,64})",
          Capability.READ, "h_evidence"),
    Route("POST", r"/api/browse", Capability.SCAN, "h_browse"),
    Route("POST", r"/api/choose-dir", Capability.SCAN, "h_choose_dir"),
    Route("POST", r"/api/scan", Capability.SCAN, "h_scan"),
    Route("POST", r"/api/generate", Capability.SCAN, "h_generate"),
    Route("POST", r"/api/verify", Capability.VERIFY, "h_verify"),
    Route("POST", r"/api/materialize", Capability.MATERIALIZE_INERT, "h_materialize"),
    Route("POST", r"/api/fetch", Capability.INTAKE, "h_fetch"),
    # Ghidra 静的解析教材（ghidra_api.py）。状態の取得とキャンセルにも権限を要る。
    Route("GET", r"/api/ghidra/status", Capability.GHIDRA_ANALYZE, "h_ghidra_status"),
    Route("GET", r"/api/ghidra/jobs/([0-9a-f]{32,32})", Capability.GHIDRA_ANALYZE,
          "h_ghidra_job"),
    Route("POST", r"/api/ghidra/jobs/([0-9a-f]{32,32})/cancel", Capability.GHIDRA_ANALYZE,
          "h_ghidra_cancel"),
    Route("POST", r"/api/ghidra/prepare", Capability.GHIDRA_PREPARE, "h_ghidra_prepare"),
    Route("POST", r"/api/ghidra/jobs/new", Capability.GHIDRA_ANALYZE, "h_ghidra_new_upload"),
    Route("POST", r"/api/ghidra/jobs/([0-9a-f]{32,32})/upload", Capability.GHIDRA_ANALYZE,
          "h_ghidra_upload"),
    Route("POST", r"/api/ghidra/jobs/from-archive", Capability.GHIDRA_ANALYZE,
          "h_ghidra_from_archive"),
    Route("POST", r"/api/ghidra/jobs/sample", Capability.GHIDRA_ANALYZE, "h_ghidra_sample"),
    Route("POST", r"/api/lessons/(gen-gzf-[0-9a-f]{16,16})/delete", Capability.GHIDRA_ANALYZE,
          "h_ghidra_delete_lesson"),
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
    Honest framing: it is an anti-footgun control, not containment. Someone running as their own uid can edit this file or start
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
        self.ghidra = ghidra_jobs.JobManager(
            GHIDRA_JOB_DIR,
            ghidra_docker.owner_id(STATE_DIR),
            sink=lambda lesson: self.store.save_lesson(lesson, "ghidra"),
            sample_lookup=ghidra_api.sample_lookup,
            log=self.store.log,
        )

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


def count_zips(directory: str, limit: int | None = None) -> tuple[int, bool]:
    """Count the .zip files sitting directly in `directory`.

    Returns (count, complete). `complete` is False when `limit` stopped the
    walk early, and the caller MUST NOT then treat the count as the truth --
    least of all as "this folder has no archives", since scandir order is
    arbitrary and every archive could lie past the cut. A capped zero means
    "unknown", never "none".

    Every caller that runs while someone is browsing passes a limit. Opening a
    folder is a plain click, and the folder may sit on a network share, in
    iCloud, behind FUSE, or on slow external media, where an unbounded walk of
    a few hundred thousand entries stalls the page. Local APFS timings do not
    generalise to those, so the bound is kept rather than argued away. The
    authoritative count is the scan itself, which the person asks for
    explicitly and which reads the directory in full.

    scandir rather than listdir + lstat: the entry's type usually arrives with
    the directory read itself, so this costs roughly one syscall per directory
    instead of one per file. Listing ~/Library was measured at 5.9s with the
    lstat form and 0.1s with this one -- the kind of pause that reads as a hang.
    """
    n, complete, _examined = _count_zips_scan(directory, limit)
    return n, complete


def _count_zips_scan(directory: str, limit: int | None) -> tuple[int, bool, int]:
    """count_zips, plus how many entries it looked at, for budgeting callers."""
    n = 0
    examined = 0
    complete = True
    try:
        with os.scandir(directory) as it:
            for entry in it:
                if limit is not None and examined >= limit:
                    return n, False, examined
                examined += 1
                if not entry.name.lower().endswith(".zip"):
                    continue
                try:
                    if entry.is_file(follow_symlinks=False):
                        n += 1
                except OSError:
                    # Cannot tell what this is, and it is named like an
                    # archive. Not knowing is not the same as knowing it is
                    # absent, so the count stops claiming to be complete.
                    complete = False
    except OSError:
        # Unreadable, or it went away mid-walk. Whatever was counted so far is
        # all there is to say; reporting `complete` here would let a caller
        # read a failure as a confident "no archives in this folder".
        return n, False, examined
    return n, complete, examined


# Three separate bounds, because they bound three different things and only
# capping one of them leaves the walk unbounded in practice:
#
#   MAX_BROWSE_ENTRIES  folders put in the reply -- keeps the JSON small.
#   MAX_BROWSE_SCAN     filesystem entries LOOKED AT in the folder being
#                       listed. A folder of 5100 plain files yields no
#                       subfolders at all, so a cap on the reply never trips
#                       and every one of those entries still gets examined.
#   MAX_BROWSE_BUDGET   entries looked at by the whole request, the per-folder
#                       archive counts included. Without it the worst case is
#                       MAX_BROWSE_ENTRIES x MAX_COUNT_SCAN -- two million
#                       entries for one click.
#
# Running out of budget is not an error: the folders that go uncounted come
# back marked `zipsPartial`, which the page already treats as "unknown" rather
# than "none", so nothing gets disabled on the strength of a number nobody
# finished computing.
MAX_BROWSE_ENTRIES = 500
MAX_BROWSE_SCAN = 4000
MAX_BROWSE_BUDGET = 20000


def _parent_of(directory: str) -> str | None:
    """1 つ上のフォルダ。ルートでは None。"""
    parent = os.path.dirname(directory)
    return None if parent == directory else parent


def browse_dir(directory: str) -> dict:
    """List the subfolders of one directory, for the in-page folder chooser.

    Returns folder names, archive counts, and the paths needed to keep moving
    around -- this folder's, its parent's, its children's. No file is opened
    and no file content is returned.

    Symlinked directories are left out of the listing entirely
    (`follow_symlinks=False`): a link pointing back up its own tree would
    otherwise offer a path that walks in circles, and one pointing at a slow
    mount would put that cost behind an ordinary click. Someone who really
    means to browse through a link can still type its path.
    """
    entries: list[dict] = []
    truncated = False
    examined = 0
    budget = MAX_BROWSE_BUDGET
    # This folder's own archives are tallied on the same pass as the listing.
    # Walking it a second time to count them doubled the work for no new
    # information: every entry is already in hand here.
    here = 0
    here_complete = True
    try:
        with os.scandir(directory) as it:
            for entry in it:
                # Count every entry looked at, not just the ones kept. A folder
                # of plain files produces no rows, so counting rows alone would
                # walk the whole directory however large it is.
                examined += 1
                if examined > MAX_BROWSE_SCAN:
                    truncated = True
                    here_complete = False
                    break
                if entry.name.lower().endswith(".zip"):
                    # Checked before the dotfile skip, because /api/scan reads
                    # hidden archives too and this number has to agree with it.
                    try:
                        if entry.is_file(follow_symlinks=False):
                            here += 1
                            continue
                    except OSError:
                        here_complete = False
                        continue
                    # Falls through: a *directory* named "something.zip" is
                    # still a folder worth offering.
                if entry.name.startswith("."):
                    continue
                try:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                except OSError:
                    continue
                if len(entries) >= MAX_BROWSE_ENTRIES:
                    truncated = True
                    here_complete = False
                    break
                # Capped per folder AND against the request's shared budget, so
                # a folder full of heavy subfolders cannot add up to an
                # unbounded walk. At zero budget the call returns immediately
                # and the row is marked unknown rather than counted as empty.
                zips, complete, cost = _count_zips_scan(
                    entry.path, min(MAX_COUNT_SCAN, budget)
                )
                budget -= cost
                entries.append({
                    "name": entry.name,
                    "path": entry.path,
                    "zips": zips,
                    "zipsPartial": not complete,
                })
    # A folder that could not be read tells us nothing about what is in it, so
    # zipsPartial stays true here as well: "unknown", never "empty".
    #
    # `parent` is included on the error paths too. Without it the page has no
    # Up button, and a single unreadable folder becomes a dead end: the only
    # way out is to retype a path. Failing to list a folder is not a reason to
    # take away the way back.
    except PermissionError:
        return {
            "path": directory,
            "parent": _parent_of(directory),
            "entries": [],
            "zips": 0,
            "zipsPartial": True,
            "error": "このフォルダを見る権限がありません。",
        }
    except OSError as exc:
        return {
            "path": directory,
            "parent": _parent_of(directory),
            "entries": [],
            "zips": 0,
            "zipsPartial": True,
            "error": str(exc),
        }

    entries.sort(key=lambda e: e["name"].lower())
    return {
        "path": directory,
        "parent": _parent_of(directory),
        "entries": entries,
        # `here` is bounded by MAX_BROWSE_SCAN along with the listing itself.
        # `zipsPartial` is what keeps that bound honest: a cut-off zero means
        # "not known", and the page must not disable anything on it.
        "zips": here,
        "zipsPartial": not here_complete,
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
        # Capped, like every other count taken while browsing. This walks one
        # directory per sibling folder, so leaving it unbounded would put the
        # same stall behind a mis-selected parent folder. A hint that misses a
        # folder is a worse hint; a hint that hangs is a worse product.
        n, complete = count_zips(full, MAX_COUNT_SCAN)
        if n:
            out.append(
                {"name": name, "path": full, "zips": n, "zipsPartial": not complete}
            )
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


class Handler(ghidra_api.GhidraHandlers, BaseHTTPRequestHandler):
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

    @staticmethod
    def _state() -> "State":
        return STATE

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
        catalog = dataset.profile_catalog()
        return self._json({
            "role": STATE.role,
            "capabilities": sorted(STATE.caps),
            "datasetDirs": STATE.dataset_dirs,
            # 読み込めなかったプロファイルは黙って捨てない。理由を画面へ出す。
            "profiles": {
                "loaded": len(catalog.profiles),
                "errors": catalog.errors_json(),
            },
            "parsers": [
                {"id": i, "label": parsers.REGISTRY.label(i)}
                for i in parsers.REGISTRY.ids()
            ],
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

    def _archive_row(self, archive_id: int):
        rows = [a for a in STATE.store.archives() if a["id"] == archive_id]
        return rows[0] if rows else None

    def _still_the_same_file(self, row) -> bool:
        """Has the archive on disk changed since it was indexed?

        The classification and the bytes come from two different moments: the
        roles are decided from member names recorded at scan time, while the
        logs are read from whatever sits at that path now. Without this check
        someone could index archive A, drop archive B at the same path, and get
        B's contents taught under A's classification -- with the manifest still
        showing A's hash. `h_preview` already refuses on drift for exactly this
        reason; reading whole logs deserves at least the same care.

        Checks by path, so there is a window between this and a later open.
        Use `_open_verified` wherever the file is about to be read.
        """
        try:
            current, _ = sha256_file(row["path"])
        except OSError:
            return False
        return current == row["sha256"]

    @staticmethod
    def _hash_descriptor(fh) -> str | None:
        """SHA-256 of everything behind an open descriptor, then rewind it.

        The SEEK_END first is not redundant. A buffered reader answers a seek
        that lands inside its current buffer from memory, without touching the
        file. zipfile reads the local header at offset 0 in small pieces, so
        after a read the first 8 KiB were typically still buffered, and a plain
        seek(0) re-hashed those stale bytes: an in-place rewrite of the start
        of the archive went unnoticed by `_recheck`. Seeking relative to the
        end always goes to the OS and drops the buffer.
        """
        try:
            fh.seek(0, os.SEEK_END)
            fh.seek(0)
            digest = hashlib.sha256()
            for block in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(block)
            fh.seek(0)
            return digest.hexdigest()
        except OSError:
            return None

    def _open_verified(self, row):
        """Open the archive and verify it through the descriptor that will read it.

        Checking a path and then re-opening that path are two separate name
        lookups, and the file can be replaced in between. Hashing and reading
        through ONE descriptor removes that window for the common case: if the
        directory entry is swapped for a different file afterwards, this
        descriptor still refers to the bytes that were verified.

        It is NOT a complete defence, and the limit is worth stating plainly.
        A descriptor follows the inode, so rewriting the SAME file in place
        (`open(path, "w")` truncates rather than replaces) is still visible
        through it. `_recheck` is what covers that: re-hashing the same
        descriptor after the read, before anything is saved or returned.

        Returns an open binary file positioned at 0, or None on a mismatch.
        """
        try:
            fh = open(row["path"], "rb")
        except OSError:
            return None
        if self._hash_descriptor(fh) != row["sha256"]:
            fh.close()
            return None
        return fh

    def _recheck(self, fh, row) -> bool:
        """Confirm the bytes are still the verified ones, after reading them.

        Guards the case `_open_verified` cannot: an in-place rewrite while the
        read was in progress. Catching it here means a tampered archive can
        still waste the work, but it can never be saved as teaching material or
        reported as a success -- which is the outcome that matters.
        """
        return self._hash_descriptor(fh) == row["sha256"]

    STALE_ARCHIVE = (
        "このZIPファイルは読み込み後に変更されています。"
        "もう一度読み取ってから実行してください。"
    )

    def _dataset_for(self, archive_id: int, force_profile: str | None = None):
        """Classify one indexed archive as teaching material.

        Reads nothing from disk: the member names are already in the manifest,
        and the profile/role decision is made from those names alone.
        """
        rows = STATE.store.members(archive_id)
        view = dataset.detect([r["name"] for r in rows], force_id=force_profile)
        return view, rows

    #: A forced profile id comes from the query string or a JSON body, so it
    #: is bounded by the same shape the loader enforces on profile files. It
    #: never reaches the filesystem -- `dataset.detect` only compares it
    #: against the ids it already loaded -- but an unbounded string has no
    #: business being echoed into an error message either.
    PROFILE_ID = re.compile(dataset.PROFILE_ID)

    @staticmethod
    def _legacy_profile_alias(fields: dict):
        """DEPRECATED: accept the old name `profile` for `profileId`.

        Pages built before profiles were generalised sent `profile`. The
        current page and all new code send `profileId` only. This is the one
        place the alias is read; removing it leaves the new contract intact
        (pinned by `test_api.TestProfileIdContract`).
        """
        return fields.get("profile")

    def _profile_request(self, fields: dict) -> tuple[str | None, str | None]:
        """(profile id, error message) from a query or a JSON body.

        None means "decide automatically". "auto" is passed through unchanged;
        `dataset.detect` treats it the same way.
        """
        new = fields.get("profileId")
        old = self._legacy_profile_alias(fields)
        if new not in (None, "") and old not in (None, "") and new != old:
            return None, "profileId と profile が食い違っています"
        value = new if new not in (None, "") else old
        if value in (None, ""):
            return None, None
        if not isinstance(value, str) or not self.PROFILE_ID.fullmatch(value):
            return None, "プロファイルの指定が不正です"
        return value, None

    def _query(self) -> dict:
        """The first value of each query parameter, percent-decoded."""
        _, _, query = self.path.partition("?")
        return {k: v[0] for k, v in urllib.parse.parse_qs(query).items() if v}

    def h_dataset(self, archive_id: str):
        """Report what this archive looks like as a teaching dataset.

        Read-only, and deliberately says only whether a password hint EXISTS.
        The candidate strings never leave the process: putting them in a
        response would park a working key in the browser's memory, in any
        proxy log, and in whatever the page later caches. Rule: a password
        candidate found in the bundled notes is used only inside the request
        that the person explicitly triggers, and is never returned, stored or
        logged.

        `?profileId=<id>` overrides the automatic decision (the person must
        always be able to correct a wrong detection). The reply says which of the two
        happened via `forced`, so the screen can label it rather than leaving
        the person to guess whether the format was detected or chosen. No
        match is not an error: the reply is the generic analysis mode.
        """
        archive_id = int(archive_id)
        row = self._archive_row(archive_id)
        if row is None:
            return self._error(404, "そのZIPファイルは読み込まれていません")

        requested, problem = self._profile_request(self._query())
        if problem:
            return self._error(400, problem)

        # The hint scan reads the file, so verify and read through one
        # descriptor rather than checking the path and opening it again.
        fh = self._open_verified(row)
        if fh is None:
            return self._error(409, self.STALE_ARCHIVE)

        try:
            view, member_rows = self._dataset_for(archive_id, requested)
        except dataset.UnknownProfile as exc:
            fh.close()
            return self._error(400, str(exc))
        body = dataset.summarise(view, member_rows)

        # Only a boolean crosses this boundary.
        try:
            with fh:
                body["passwordHint"] = bool(
                    dataset.find_password_candidates(fh, view)
                )
                # 生成ほど重大ではない（何も保存しない）が、古い分類と
                # 書き換わったあとの中身を混ぜた応答を返さないよう、ここでも
                # 読み取り後に照合する。
                if not self._recheck(fh, row):
                    return self._error(409, self.STALE_ARCHIVE)
        except OSError:
            body["passwordHint"] = False
        body["archive"] = archive_id
        return self._json(body)

    @staticmethod
    def _attach_dataset(lesson: dict, view, parsed, *, truncated: bool,
                        unreadable: list, unsupported: list,
                        baseline: list) -> None:
        """Record where the lesson came from, on the lesson itself.

        Everything a later reader needs to judge the lesson -- which profile,
        whether a person chose it, which parser read what, and what could NOT
        be read -- is kept with it, not only in the reply to this request.
        A lesson built from 2 of 6 logs must never look like a clean success.

        「読めなかった」「読む仕組みが無い」「どの形式にも当たらなかった」を
        混ぜない。前者は鍵や上限の問題で、やり直せば変わる。後の二つは
        対応範囲の話で、何度試しても変わらない。
        """
        info = dataset.dataset_info(view)
        report = parsed.report()
        unrecognized = report["unrecognized"]
        unknown_parsers = sorted(set(info["unknownParsers"]) | set(report["unknownParsers"]))
        explicit_only = report["explicitOnly"]
        incomplete = bool(unreadable or unsupported or unrecognized
                          or unknown_parsers or truncated)
        lesson["dataset"] = {
            **info,
            "unknownParsers": unknown_parsers,
            "parsing": report,
            "challengeInputs": sorted(parsed.sources),
            "baselineIdentified": list(baseline),
            "truncated": truncated,
            "unreadable": unreadable,
            "unsupported": unsupported,
            "unrecognized": unrecognized,
            "explicitOnly": explicit_only,
            "incomplete": incomplete,
            "draft": True,
        }

        # 読み取りの制約は、生成直後の画面だけでなく教材の中にも残す。導入と
        # 最終レポートから「何が読めなかったか」を確かめられるようにするため。
        unknowns = lesson.setdefault("report", {}).setdefault("unknowns", [])
        if truncated:
            unknowns.append({
                "topic": "読み取りの打ち切り",
                "detail": ("上限に達したため、一部のログを最後まで読んでいません。"
                           "見えていない記録がある前提で読んでください。"),
            })
        if unreadable:
            unknowns.append({
                "topic": "読み取れなかったログ",
                "detail": (f"{len(unreadable)} 件の問題ログを読み取れませんでした。"
                           "この教材はその分を欠いた状態で作られています。"),
            })
        if unsupported:
            labels = sorted({u["label"] for u in unsupported})
            unknowns.append({
                "topic": "専用解析が未対応のログ",
                "detail": (
                    f"{len(unsupported)} 件（{'、'.join(labels)}）は問題ログとして"
                    "分類できていますが、専用の解析に対応していないため教材の材料に"
                    "していません。この教材の時系列には、これらのログに記録された"
                    "出来事が含まれていません。"
                ),
            })
        if unrecognized:
            unknowns.append({
                "topic": "形式を判別できなかったログ",
                "detail": (
                    f"{len(unrecognized)} 件のログは、登録済みのどのパーサーでも"
                    "読めませんでした。この教材には、それらに記録された出来事が"
                    "含まれていません。新しい形式に対応するにはパーサーの追加が必要です。"
                ),
            })
        if explicit_only:
            labels = sorted({parsers.REGISTRY.label(i)
                             for ids in explicit_only.values() for i in ids})
            unknowns.append({
                "topic": "通信の向きを断定できないログ",
                "detail": (
                    f"{len(explicit_only)} 件のログは {'、'.join(labels)} の行の形を"
                    "していますが、同じ形は Web サーバーのアクセスログにも現れます。"
                    "端末から外へ出た通信なのか、外からサーバーへ来た要求なのかを"
                    "内容だけでは決められないため、教材の材料にしていません。"
                    "プロキシの記録だと分かっている場合は、プロファイルの parsers に"
                    "指定すると読み取ります。"
                ),
            })
        if unknown_parsers:
            unknowns.append({
                "topic": "登録されていないパーサー",
                "detail": (
                    f"プロファイルが指定したパーサー（{', '.join(unknown_parsers)}）は"
                    "登録されていないため、その形式のログは解析していません。"
                ),
            })
        lesson.setdefault("introduction", {})["dataset"] = {
            "profileId": info["profileId"],
            "label": info["label"],
            "edition": info["edition"],
            "forced": info["forced"],
            "generic": info["generic"],
            "incomplete": incomplete,
            "truncated": truncated,
            "unreadable": len(unreadable),
            "unsupported": len(unsupported),
            "unrecognized": len(unrecognized),
        }

    @staticmethod
    def _generated_reply(lesson: dict) -> dict:
        return {
            "id": lesson["id"], "title": lesson["title"],
            "stages": len(lesson["stages"]),
            "events": sum(len(s["events"]) for s in lesson["stages"]),
            "tagged": sum(
                1 for s in lesson["stages"] for e in s["events"] if "attck" in e
            ),
            "sources": list(lesson["dataset"]["challengeInputs"]),
            "dataset": lesson["dataset"],
        }

    def _generate_generic(self, archive_id: int, row, fh, view):
        """Generic analysis: the path for archives no profile claims.

        Walk the archive, read whatever `.log` files are not encrypted, and let
        the registered parsers decide, file by file, which of them can read it
        (`detect()`). With no profiles installed -- the public default -- this
        is the only path, so "no profile matched" is a normal outcome, not an
        error.

        It is NOT used when a profile matched. Without a profile nothing tells
        the incident logs apart from quiet-period logs or a tool's bundled
        sample, so "any readable .log" is only honest as an explicitly
        labelled generic mode, never as a stand-in for a profile.

        Reads through the caller's already-verified descriptor. Re-opening the
        path here would hand back the TOCTOU window the caller just closed, and
        would leak the descriptor it opened.
        """
        # 読み取りはプロファイル経路と同じ部品で行う（dataset.read_all_logs）。
        # 共有予算は読む前に予約し、内側 ZIP も予約してから開く。打ち切り・
        # 暗号化・壊れ・予算切れは黙って飛ばさず、教材まで伝える。
        try:
            read = dataset.read_all_logs(fh)
        except dataset.ArchiveDamaged:
            return self._error(422, "圧縮ファイルを読み取れませんでした。")

        # 読み終えたあとの再照合。プロファイル経路と同じ扱いにする。
        if not self._recheck(fh, row):
            return self._error(409, self.STALE_ARCHIVE)

        sources = read.as_mapping
        if not sources:
            if read.failures:
                return self._error(
                    422,
                    f"読み取れる .log ファイルがありませんでした（読み取れなかったもの "
                    f"{len(read.failures)} 件）。暗号化された項目は、プロファイルを"
                    "指定して同梱の案内から読み取る必要があります。",
                )
            return self._error(
                422,
                "この圧縮ファイルには、暗号化されていない .log ファイルがありません。"
                "暗号化された項目は、プロファイルを指定して同梱の案内から読み取る"
                "必要があります。",
            )

        base = os.path.basename(row["path"]).rsplit(".", 1)[0]
        # 本番の経路。パーサーレジストリで形式を判定し、正規化イベントから作る。
        parsed = parsers.REGISTRY.parse_sources(sources, None)
        lesson = explain.lesson_from_parsed(
            f"{base} — DFIR 時系列", parsed, f"gen-{archive_id}"
        )
        if lesson is None:
            if parsed.explicit_only:
                return self._error(
                    422,
                    f"{len(parsed.explicit_only)} 件のログはプロキシの記録と同じ形をして"
                    "いますが、同じ形は Web サーバーのアクセスログにも現れるため、"
                    "通信の向きを内容だけでは決められません。プロキシの記録だと"
                    "分かっている場合は、プロファイルの parsers に proxy を指定して"
                    "ください。",
                )
            return self._error(
                422,
                "ログは読み取れましたが、登録済みのパーサーで解析できる記録が"
                "ありませんでした。",
            )
        self._attach_dataset(lesson, view, parsed, truncated=read.truncated,
                             unreadable=read.failures, unsupported=[], baseline=[])
        STATE.store.save_lesson(lesson, base)
        return self._json(self._generated_reply(lesson))

    def h_evidence(self, lesson_id: str, evidence_id: str):
        """Return one stored piece of evidence from one saved lesson.

        Deliberately narrow. The route takes no path from the caller: both ids
        are bounded by the route pattern, and the evidence is looked up in the
        lesson that was already built and saved. No archive is opened, nothing
        is re-read from disk, and nothing outside the stored record is returned.

        That matters because the alternative -- accepting an archive path and a
        member name and fetching the line on demand -- would hand the caller a
        way to read arbitrary files through this endpoint. The excerpt was
        already trimmed, escaped and stored when the lesson was generated, so
        there is nothing here to re-derive.
        """
        lesson = STATE.store.lesson(lesson_id)
        if lesson is None:
            return self._error(404, "該当する演習がありません")
        item = (lesson.get("evidence") or {}).get(evidence_id)
        if item is None:
            return self._error(404, "該当する証拠がありません")

        # 保存されている辞書をそのまま返さず、出す項目をここで列挙する。
        # 証拠オブジェクトへ内部用の項目が増えたとき、黙って API へ漏れる
        # のを防ぐため。増やすかどうかは、そのつど明示的に決める。
        src = item.get("source") or {}
        if item.get("evidenceType") == "static":
            # 静的な根拠は「プログラム名／関数／アドレス／命令または参照関係」。
            # ログの行番号や手元のパスは持たない。ログの根拠の応答は、既存の
            # 画面・教材との互換のため、以前と同じ項目のまま変えない。
            return self._json({
                "id": item.get("id"),
                "kind": item.get("kind"),
                "evidenceType": "static",
                "confidence": item.get("confidence"),
                "source": {
                    "program": src.get("program"),
                    "function": src.get("function"),
                    "address": src.get("address"),
                    "instruction": src.get("instruction"),
                    "reference": src.get("reference"),
                    "excerpt": src.get("excerpt"),
                },
            })
        return self._json({
            "id": item.get("id"),
            "kind": item.get("kind"),
            "confidence": item.get("confidence"),
            "source": {
                "archivePath": src.get("archivePath"),
                "member": src.get("member"),
                "line": src.get("line"),
                "excerpt": src.get("excerpt"),
            },
        })

    def h_generate(self):
        """Build a draft lesson from the CHALLENGE logs in one archive.

        What changed, and why it matters: an earlier version walked the whole
        archive for anything ending in `.log` and skipped every encrypted
        entry. In real distributions that is exactly backwards -- the genuine
        incident logs are often the encrypted ones, so what got taught was a
        sample log shipped with a viewer utility. With a profile, lessons are
        built from members the profile calls `challenge`, and nothing else.

        `baseline` is identified but never substituted for the real logs. A
        quiet fallback to the quiet-period logs would reintroduce the same
        failure in a form that is harder to notice.

        With no profile (the public default ships none) the request falls
        through to generic analysis, which is labelled as such end to end.

        Reads in memory only; nothing is written to disk. The password, if one
        is used, is held for the duration of the call and never stored, logged
        or echoed.
        """
        payload = self._body()
        if payload is None:
            return None
        try:
            archive_id = int(payload.get("archive"))
        except (TypeError, ValueError):
            return self._error(400, '要求の書式が不正です（archive が必要です）')
        row = self._archive_row(archive_id)
        if row is None:
            return self._error(404, "そのZIPファイルは読み込まれていません")

        # 検証済みの記述子を 1 本だけ開き、この関数を抜けるまでに必ず閉じる。
        # 途中の妥当性検査で早期に返る経路がいくつもあり、それぞれで閉じるのは
        # 抜けが出る。実際、汎用生成へ分岐する経路と引数不正の経路で、
        # リクエストごとに記述子が漏れていた。
        archive_fh = self._open_verified(row)
        if archive_fh is None:
            return self._error(409, self.STALE_ARCHIVE)
        try:
            return self._generate_with(payload, archive_id, row, archive_fh)
        finally:
            archive_fh.close()

    def _generate_with(self, payload, archive_id, row, archive_fh):
        """h_generate の本体。記述子の解放は呼び出し側が受け持つ。"""
        credential = payload.get("credential") or {}
        if not isinstance(credential, dict):
            return self._error(400, "要求の書式が不正です（credential）")
        mode = credential.get("mode") or "none"

        requested, problem = self._profile_request(payload)
        if problem:
            return self._error(400, problem)

        try:
            view, _rows = self._dataset_for(archive_id, requested)
        except dataset.UnknownProfile as exc:
            return self._error(400, str(exc))

        if not view.named("challenge"):
            # A profile matched but named no challenge logs: refuse. Falling
            # back to "any readable .log" here is precisely the behaviour that
            # taught a tool's bundled sample instead of the incident logs.
            if view.profile is not None:
                return self._error(
                    422,
                    f"{view.profile.display_label} と判定しましたが、本番の問題ログが"
                    "見つかりませんでした。",
                )
            # No profile matched at all: generic analysis.
            if requested:
                return self._error(
                    422, "指定されたプロファイルでは問題ログを特定できませんでした。"
                )
            return self._generate_generic(archive_id, row, archive_fh, view)

        # 鍵はここで組み立て、この呼び出しの間だけ持つ。保存も記録もしない。
        passwords: list[str] = []
        if mode == "embedded":
            passwords = dataset.find_password_candidates(archive_fh, view)
            if not passwords:
                return self._error(
                    422, "同梱の案内からパスワード候補を見つけられませんでした。"
                )
        elif mode == "manual":
            value = credential.get("value")
            if not isinstance(value, str) or not value:
                return self._error(400, "パスワードが空です。")
            passwords = [value]
        elif mode != "none":
            return self._error(400, "credential.mode が不正です。")

        try:
            read = dataset.read_logs(archive_fh, view, "challenge", passwords)
        except dataset.DatasetError as exc:
            return self._error(422, str(exc))

        # 読み終えた「あと」にもう一度照合する。記述子は inode を追うので、
        # 読んでいる最中に同じファイルが上書きされると内容が変わりうる。
        # ここで気づけば、差し替わった内容が教材として保存されることはない。
        if not self._recheck(archive_fh, row):
            return self._error(409, self.STALE_ARCHIVE)

        sources = read.as_mapping
        if not sources:
            needs = [f for f in read.failures if f["reason"] == "password-required"]
            rejected = [f for f in read.failures if f["reason"] == "password-rejected"]
            unsupported = [
                f for f in read.failures if f["reason"] == "unsupported-encryption"
            ]
            if unsupported:
                return self._error(
                    422, "問題ログが未対応の暗号方式（AES）のため読み取れません。"
                )
            if rejected:
                return self._json(
                    {"error": "パスワードが合いませんでした。もう一度入力してください。",
                     "needsCredential": True}, 422,
                )
            if needs:
                return self._json(
                    {"error": "問題ログは暗号化されています。パスワードが必要です。",
                     "needsCredential": True}, 422,
                )
            return self._error(422, "問題ログを読み取れませんでした。")

        base = os.path.basename(row["path"]).rsplit(".", 1)[0]
        title = f"{view.profile.display_label} — DFIR 時系列"
        # 本番の経路。プロファイルが指定したパーサーで、レジストリを通して
        # 読む。指定が無ければ自動判定に参加するパーサー（AUTO_DETECT）で判定する。
        parsed = parsers.REGISTRY.parse_sources(sources, view.parser_ids)
        lesson = explain.lesson_from_parsed(title, parsed, f"gen-{archive_id}")
        if lesson is None:
            return self._error(422, "ログは読み取れましたが、事象を解析できませんでした")

        # 採用した入力と、読めなかったものを教材側にも残す。
        unreadable = [
            {"name": f["name"], "reason": f["reason"], "detail": f["detail"]}
            for f in read.failures
        ]
        self._attach_dataset(
            lesson, view, parsed, truncated=read.truncated,
            unreadable=unreadable, unsupported=list(read.unsupported),
            baseline=view.named("baseline"),
        )
        STATE.store.save_lesson(lesson, base)
        return self._json(self._generated_reply(lesson))

    def h_browse(self):
        """Feed the in-page folder chooser.

        This exists because a native dialog cannot be shown inside the browser
        window. On a full-screen browser macOS switches Spaces to show it,
        which loses the page the person was working in. Listing folders here
        and drawing the chooser in the page keeps the whole job in one window.

        No new exposure: the same capability already reads any directory it is
        pointed at via /api/scan. What comes back is folder names, archive
        counts, and the folder paths needed to navigate -- never file content.
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
        # Capped: the OS dialog can land on any folder at all, including one on
        # a slow mount, and this reply is only a hint printed alongside the
        # path. The authoritative count comes from the scan that follows.
        chosen_zips, chosen_complete = count_zips(directory, MAX_COUNT_SCAN)
        return self._json({
            "dir": directory,
            "zips": chosen_zips,
            "zipsPartial": not chosen_complete,
        })

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


#: 外部プロファイルのフォルダを指定する環境変数。`os.pathsep` 区切りで複数可。
#: 起動時にだけ読む。HTTP リクエストから任意のフォルダを指定させない。
PROFILE_DIR_ENV = "DATASET_PROFILE_DIR"


def configure_profiles_from_env(environ=None) -> "dataset.ProfileCatalog":
    """起動時の設定からプロファイルを読み込む。無ければ標準のフォルダだけ。"""
    environ = os.environ if environ is None else environ
    raw = environ.get(PROFILE_DIR_ENV) or ""
    dirs = [os.path.expanduser(d) for d in raw.split(os.pathsep) if d.strip()]
    return dataset.configure_profiles(dirs)


def main() -> None:
    global STATE, ALLOWED_HOSTS
    os.makedirs(STATE_DIR, exist_ok=True)
    STATE = State()
    catalog = configure_profiles_from_env()
    # 前回の異常終了で残った GZF の作業データは、待ち受けを始める前に消す
    # （受付と並行させると今回の入力まで消しかねない）。処理コンテナの回収は
    # Docker の応答で遅れることがあるので別スレッドで行い、今回の起動の
    # コンテナはセッションのラベルで除く。
    STATE.ghidra.recover_dirs()
    threading.Thread(target=STATE.ghidra.recover_containers, daemon=True,
                     name="ghidra-recover").start()

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
    print(f"  profiles: {len(catalog.profiles)} loaded"
          f"  (parsers: {', '.join(parsers.REGISTRY.ids())})", flush=True)
    if not os.environ.get(PROFILE_DIR_ENV):
        print(f"        add dataset profiles with:  {PROFILE_DIR_ENV}=/path/to/profiles",
              flush=True)
    # 読み込めなかったものは、ファイル名と理由だけを出す。中身は引用しない。
    for err in catalog.errors:
        print(f"  [profile] {err.source}: {err.reason}", file=sys.stderr, flush=True)
    print("  Ctrl+C to stop.", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped.")


if __name__ == "__main__":
    main()
