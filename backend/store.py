"""store.py — the manifest and the integrity baseline.

Two jobs:

  * MANIFEST. Records what we have seen: archives, their members, and the
    verdict each member was given. Every write is parameterised; member names
    arrive from inside archives and are attacker-controlled strings.
  * INTEGRITY. Hashes tracked files and reports whether they still match, with
    the timestamp of the last successful check. This is the honest half of the
    "logger" requirement: it detects that a file CHANGED. It does not and
    cannot detect that a file was EXECUTED: no userspace check can observe
    execution, so the UI must not claim that it does.

Storage is content-addressed by design: a blob is
written to `blobs/<sha256[:2]>/<sha256>.bin` and the original name is a column,
never a path component. That is what makes traversal and zip-slip structurally
impossible rather than merely filtered.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass

SCHEMA = """
CREATE TABLE IF NOT EXISTS archive (
    id           INTEGER PRIMARY KEY,
    path         TEXT NOT NULL UNIQUE,
    sha256       TEXT NOT NULL,
    size         INTEGER NOT NULL,
    first_seen   REAL NOT NULL,
    last_verified REAL,
    last_status  TEXT
);
CREATE TABLE IF NOT EXISTS member (
    id           INTEGER PRIMARY KEY,
    archive_id   INTEGER NOT NULL REFERENCES archive(id) ON DELETE CASCADE,
    idx          INTEGER NOT NULL,
    name         TEXT NOT NULL,
    size         INTEGER NOT NULL,
    verdict      TEXT NOT NULL,
    kind         TEXT NOT NULL,
    warnings     TEXT NOT NULL DEFAULT '',
    container    TEXT NOT NULL DEFAULT '',
    caveat       TEXT NOT NULL DEFAULT ''
    -- Deliberately NOT unique on (archive_id, idx): a member found inside a
    -- nested archive carries its parent's outer index, so several rows legally
    -- share one idx. A unique constraint here silently dropped all but one.
);
CREATE TABLE IF NOT EXISTS lesson (
    id        TEXT PRIMARY KEY,
    title     TEXT NOT NULL,
    body      TEXT NOT NULL,
    made_at   REAL NOT NULL,
    source    TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS event (
    id        INTEGER PRIMARY KEY,
    at        REAL NOT NULL,
    kind      TEXT NOT NULL,
    detail    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS member_archive ON member(archive_id);
CREATE INDEX IF NOT EXISTS event_at ON event(at);
"""


@dataclass
class IntegrityResult:
    path: str
    ok: bool
    detail: str
    checked_at: float


class Store:
    """SQLite-backed manifest. One connection per thread."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        # ONE connection, guarded by a reentrant lock.
        #
        # The obvious alternative -- threading.local -- looks right and behaves
        # badly here: the server speaks HTTP/1.0, so every request is a new
        # connection and therefore a new thread, and each thread opened its own
        # SQLite handle and re-ran the PRAGMAs (including a WAL switch that
        # takes an exclusive lock). That was measured at 66 open descriptors on
        # the database after light use, climbing under load.
        self._lock = threading.RLock()
        self._db = sqlite3.connect(db_path, check_same_thread=False, timeout=5.0)
        self._db.row_factory = sqlite3.Row
        for pragma in (
            "journal_mode=WAL", "synchronous=NORMAL",
            "foreign_keys=ON", "busy_timeout=5000",
        ):
            self._db.execute(f"PRAGMA {pragma}")
        with self._tx() as c:
            c.executescript(SCHEMA)
        # 0600: the manifest records what is in the archives, which is not
        # secret, but it is not other users' business either.
        try:
            os.chmod(db_path, 0o600)
        except OSError:
            pass

    @contextmanager
    def _tx(self):
        """A write transaction. The lock is held for its whole duration, so a
        request handler and the integrity checker cannot interleave."""
        with self._lock:
            with self._db:
                yield self._db

    def _query(self, sql: str, params: tuple = ()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._db.execute(sql, params)]

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # -- events -----------------------------------------------------------
    def log(self, kind: str, detail: str) -> None:
        with self._tx() as c:
            c.execute(
                "INSERT INTO event (at, kind, detail) VALUES (?, ?, ?)",
                (time.time(), kind, detail),
            )

    def events(self, limit: int = 100) -> list[dict]:
        return self._query(
            "SELECT at, kind, detail FROM event ORDER BY at DESC LIMIT ?",
            (min(int(limit), 1000),),
        )

    # -- archives ---------------------------------------------------------
    def record_archive(self, path: str, listing) -> int:
        """Hash an archive, store it and its members, return the archive id."""
        digest, size = sha256_file(path)
        now = time.time()
        with self._tx() as c:
            cur = c.execute("SELECT id, sha256 FROM archive WHERE path = ?", (path,))
            row = cur.fetchone()
            if row is None:
                cur = c.execute(
                    "INSERT INTO archive (path, sha256, size, first_seen, "
                    "last_verified, last_status) VALUES (?, ?, ?, ?, ?, ?)",
                    (path, digest, size, now, now, "ok"),
                )
                archive_id = int(cur.lastrowid)
                self.log("archive-added", f"{os.path.basename(path)} {digest[:12]}")
            else:
                archive_id = int(row["id"])
                if row["sha256"] != digest:
                    self.log(
                        "archive-changed",
                        f"{os.path.basename(path)} was {row['sha256'][:12]} "
                        f"now {digest[:12]}",
                    )
                c.execute(
                    "UPDATE archive SET sha256=?, size=?, last_verified=?, "
                    "last_status=? WHERE id=?",
                    (digest, size, now, "ok", archive_id),
                )
                c.execute("DELETE FROM member WHERE archive_id = ?", (archive_id,))

            c.executemany(
                "INSERT OR REPLACE INTO member (archive_id, idx, name, size, "
                "verdict, kind, warnings, container, caveat) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        archive_id,
                        m.index,
                        m.name,
                        m.size,
                        m.verdict.value,
                        m.ident.kind,
                        "\n".join(m.warnings),
                        m.container,
                        m.ident.caveat,
                    )
                    for m in listing.members
                ],
            )
        return archive_id

    def archives(self) -> list[dict]:
        return self._query(
            "SELECT a.id, a.path, a.sha256, a.size, a.last_verified, a.last_status,"
            " (SELECT COUNT(*) FROM member m WHERE m.archive_id = a.id) AS members"
            " FROM archive a ORDER BY a.path"
        )

    def members(self, archive_id: int) -> list[dict]:
        return self._query(
            "SELECT idx, name, size, verdict, kind, warnings, container, caveat"
            " FROM member WHERE archive_id = ? ORDER BY id",
            (int(archive_id),),
        )

    # -- generated lessons ------------------------------------------------
    def save_lesson(self, lesson: dict, source: str) -> None:
        import json as _json
        with self._tx() as c:
            c.execute(
                "INSERT OR REPLACE INTO lesson (id, title, body, made_at, source)"
                " VALUES (?, ?, ?, ?, ?)",
                (lesson["id"], lesson["title"], _json.dumps(lesson), time.time(), source),
            )
        self.log("lesson-generated", f"{lesson['id']} from {source}")

    def delete_lesson(self, lesson_id: str) -> bool:
        """保存した教材を 1 件消す。消したら True。"""
        with self._tx() as c:
            cur = c.execute("DELETE FROM lesson WHERE id = ?", (lesson_id,))
            deleted = cur.rowcount > 0
        if deleted:
            self.log("lesson-deleted", lesson_id)
        return deleted

    def lessons(self) -> list[dict]:
        return self._query(
            "SELECT id, title, made_at, source FROM lesson ORDER BY made_at DESC"
        )

    def lesson(self, lesson_id: str) -> dict | None:
        import json as _json
        rows = self._query("SELECT body FROM lesson WHERE id = ?", (lesson_id,))
        return _json.loads(rows[0]["body"]) if rows else None

    # -- integrity --------------------------------------------------------
    def verify(self) -> list[IntegrityResult]:
        """Re-hash every tracked archive and report drift.

        This detects modification, replacement, and deletion. It does NOT
        detect that anything was executed — no userspace check can.
        """
        results: list[IntegrityResult] = []
        now = time.time()
        for row in self.archives():
            path = row["path"]
            if not os.path.exists(path):
                results.append(IntegrityResult(path, False, "ファイルが見つかりません", now))
                self.log("integrity-missing", path)
                status = "missing"
            else:
                digest, size = sha256_file(path)
                if digest == row["sha256"]:
                    results.append(
                        IntegrityResult(path, True, "前回の点検から変化ありません", now)
                    )
                    status = "ok"
                else:
                    results.append(
                        IntegrityResult(
                            path, False,
                            f"内容が変化しました: {row['sha256'][:12]} → {digest[:12]}",
                            now,
                        )
                    )
                    self.log("integrity-changed", path)
                    status = "changed"
            with self._tx() as c:
                c.execute(
                    "UPDATE archive SET last_verified=?, last_status=? WHERE path=?",
                    (now, status, path),
                )
        return results


def sha256_file(path: str, chunk: int = 1024 * 1024) -> tuple[str, int]:
    """Stream a file's SHA-256. Never loads the whole file into memory."""
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
            size += len(block)
    return h.hexdigest(), size


def blob_path(root: str, digest: str) -> str:
    """Where a blob WOULD live. Name is generated from content, never from
    remote or archive input, so no archive or remote name can become a path."""
    if len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest):
        raise ValueError("digest must be a lowercase hex sha256")
    return os.path.join(root, "blobs", digest[:2], f"{digest}.bin")
