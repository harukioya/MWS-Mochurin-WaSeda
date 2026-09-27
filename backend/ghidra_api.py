"""ghidra_api.py — Ghidra 静的解析教材の HTTP 入口（api.Handler のミックスイン）。

ここは受け付けと振り分けだけを持つ。GZF の確認は gzf.py、入力の写しは
ghidra_intake.py、Docker は ghidra_docker.py、ジョブは ghidra_jobs.py、
教材は static_lesson.py が受け持つ。

どのルートも api.ROUTES で権限（capability）を宣言している。Host 検証・
トークン・Origin の検査は、ほかのルートと同じく api.Handler._dispatch が
先に行う。ここで受け取る識別子は、整数の登録 ID・manifest 上の位置・
固定形式のジョブ ID だけで、ホストのパス・イメージ名・コマンドの指定は
受け取らない。
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
import urllib.parse

import ghidra_docker as gd
import ghidra_intake as intake
import ghidra_jobs as jobs
import gzf
from evidence import visible

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_DIR = os.path.join(REPO_ROOT, "ghidra", "sample")
SAMPLE_MANIFEST = os.path.join(SAMPLE_DIR, "sample.json")

UPLOAD_TYPE = "application/octet-stream"
MAX_DISPLAY_NAME = 120
PROBE_CACHE_SECONDS = 5

_probe_lock = threading.Lock()
_probe_cache: dict = {"at": 0.0, "value": None}


def load_sample() -> dict | None:
    """同梱サンプルの来歴。無い・読めない場合は None（機能は使える）。"""
    try:
        with open(SAMPLE_MANIFEST, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("sha256"), str):
        return None
    path = os.path.join(SAMPLE_DIR, str(data.get("file") or ""))
    if os.path.dirname(os.path.realpath(path)) != os.path.realpath(SAMPLE_DIR):
        return None
    data["available"] = os.path.isfile(path)
    data["path"] = path
    return data


def sample_lookup(sha256: str) -> dict | None:
    """入力が同梱サンプルと同じなら、教材に載せる来歴を返す。"""
    s = load_sample()
    if not s or s.get("sha256") != sha256:
        return None
    return {k: s.get(k) for k in ("name", "label", "note", "source", "license",
                                  "sourceSha256", "sourceCommit")}


def probe(force: bool = False) -> dict:
    """Docker とイメージの状態。短い間は結果を使い回す（画面の再読み込み対策）。"""
    with _probe_lock:
        now = time.monotonic()
        if not force and _probe_cache["value"] and now - _probe_cache["at"] < PROBE_CACHE_SECONDS:
            return _probe_cache["value"]
        try:
            envi = gd.resolve()
            docker = {"state": "ready", "arch": envi.server_arch,
                      "version": envi.server_version,
                      "endpoint": envi.endpoint.split("://", 1)[0]}
            image = gd.image_state(envi)
        except gd.DockerProblem as exc:
            docker = {"state": exc.code, "message": jobs.message(exc.code)}
            image = {"state": "unknown", "ref": gd.image_ref()}
        value = {"docker": docker, "image": image}
        _probe_cache.update(at=now, value=value)
        return value


def forget_probe() -> None:
    with _probe_lock:
        _probe_cache.update(at=0.0, value=None)


class GhidraHandlers:
    """api.Handler に混ぜて使う。self._state() が api.State を返す。"""

    # -- 状態 --------------------------------------------------------------
    def h_ghidra_status(self):
        state = self._state()
        query = self._query()
        info = probe(force=query.get("refresh") == "1")
        current = state.ghidra.current()
        sample = load_sample()
        return self._json({
            **info,
            "pinned": gd.pinned(),
            "limits": {
                "maxGzfBytes": gzf.MAX_GZF_BYTES,
                "maxUnpackedBytes": gzf.MAX_UNPACKED_BYTES,
                "runSeconds": gd.RUN_DEADLINE,
                "container": dict(gd.LIMITS),
            },
            "job": current.public() if current else None,
            "sample": ({"available": bool(sample.get("available")),
                        "name": sample.get("name"), "label": sample.get("label"),
                        "note": sample.get("note"), "sha256": sample.get("sha256")}
                       if sample else {"available": False}),
            "canPrepare": state.can("ghidra-prepare"),
        })

    def h_ghidra_job(self, job_id: str):
        job = self._state().ghidra.get(job_id)
        if job is None:
            return self._error(404, "該当する処理がありません")
        return self._json({"job": job.public()})

    def h_ghidra_cancel(self, job_id: str):
        manager = self._state().ghidra
        if not manager.cancel(job_id):
            return self._error(409, "この処理はすでに終わっているか、見つかりません")
        return self._json({"job": manager.get(job_id).public()})

    # -- 準備 --------------------------------------------------------------
    def h_ghidra_prepare(self):
        payload = self._body()
        if payload is None:
            return None
        manager = self._state().ghidra
        try:
            job = manager.reserve("prepare")
        except jobs.Busy:
            return self._fail_json(409, "busy")
        forget_probe()
        manager.start_prepare(job)
        return self._json({"job": job.public()}, 202)

    # -- 入力の受け付け -----------------------------------------------------
    def _fail_json(self, code_http: int, code: str, job=None):
        body = {"error": jobs.message(code), "code": code}
        if job is not None:
            body["job"] = job.public()
        return self._json(body, code_http)

    def _guarded(self, manager, job, work):
        """処理枠を確保したあとの受付を動かす。どう終わっても枠を残さない。

        受付（受信・写し・確認）は、この要求を処理しているスレッドで進む。
        想定外の例外で抜けると、ジョブが receiving / checking のまま残り、
        唯一の処理枠と一時ファイルが解放されず、以後はすべて「処理中」で
        断られる。抽出スレッドへ渡し終えた場合（start_analysis 済み）と、
        すでに理由付きで終えた場合を除き、ここで必ず失敗にして後始末する。
        """
        try:
            return work()
        except Exception:  # noqa: BLE001 - 理由の分からない失敗も枠は解放する
            self.close_connection = True
            manager.release_stranded(job)
            return self._fail_json(409 if job.error == "cancelled" else 500,
                                   job.error or "internal", job)
        finally:
            job.interrupt = None
            manager.release_stranded(job)

    def _ready_or_fail(self, manager, job) -> bool:
        """受け取る前に、処理できる状態かを確かめる。準備と処理は分けておく。"""
        info = probe(force=True)
        if info["docker"]["state"] != "ready":
            manager.fail(job, info["docker"]["state"])
            return False
        if info["image"].get("state") != "ready":
            manager.fail(job, jobs.image_problem(info["image"].get("state")))
            return False
        if not manager.uid:
            manager.fail(job, "root-refused")
            return False
        return True

    def _finish_intake(self, manager, job, dest: str, sha: str, size: int):
        job.state = "checking"
        try:
            intake.check_copy(dest)
        except gzf.NotGzf as exc:
            manager.fail(job, exc.code)
            return self._fail_json(422, exc.code, job)
        except OSError:
            manager.fail(job, "not-gzf")
            return self._fail_json(422, "not-gzf", job)
        if job.cancel.is_set():
            manager.fail(job, "cancelled")
            return self._fail_json(409, "cancelled", job)
        manager.start_analysis(job, sha, size)
        return self._json({"job": job.public()}, 202)

    def _set_receive_timeout(self, seconds: float) -> None:
        # 1 回の受信で待つ時間を、総期限までの残りに合わせる。
        self.connection.settimeout(max(0.05, seconds))

    def _interrupt_receive(self) -> None:
        """キャンセル時に、受信待ちで止まっている読み取りを終わらせる。"""
        try:
            self.connection.shutdown(socket.SHUT_RD)
        except OSError:
            pass

    def h_ghidra_new_upload(self):
        """ブラウザからの送信を予約し、キャンセルできるジョブ ID を返す。

        送信を 1 回の要求にすると、本文が届き終えて確認中・応答待ちになった
        あとで利用者が取り消しても、ブラウザは通信を切ることしかできず、
        サーバー側の処理（抽出・教材の保存）は続いてしまう。先に ID を返し、
        画面の「キャンセル」はこの ID の取り消しと通信の中断を両方行う。

        ここで Docker と処理イメージが使えるかも確かめ、使えなければ本文を
        送らせる前に断る。本文が来ない予約は RESERVE_SECONDS で解放する。
        """
        payload = self._body()
        if payload is None:
            return None
        size = payload.get("size")
        if isinstance(size, bool) or not isinstance(size, int):
            return self._error(400, "要求の書式が不正です（size が必要です）")
        if size <= 0 or size > gzf.MAX_GZF_BYTES:
            return self._fail_json(413, "too-large" if size > 0 else "empty")
        name = payload.get("name")
        name = name if isinstance(name, str) else ""
        display = visible(name[:1024], MAX_DISPLAY_NAME) or "（名前なし）"
        manager = self._state().ghidra
        try:
            job = manager.reserve("analyze", {"kind": "upload", "name": display},
                                  attached=False)
        except jobs.Busy:
            return self._fail_json(409, "busy")
        try:
            ready = self._ready_or_fail(manager, job)
        except Exception:  # noqa: BLE001 - 予約を残さない
            manager.fail(job, "internal")
            return self._fail_json(500, "internal", job)
        if not ready:
            return self._fail_json(409, job.error, job)
        return self._json({"job": job.public(), "reserveSeconds": manager.RESERVE_SECONDS}, 201)

    def h_ghidra_upload(self, job_id: str):
        """予約したジョブへ、.gzf の本文を送る。JSON 用の MAX_BODY とは別の経路。

        本文は application/octet-stream の生のバイト列。宣言長の上限を先に
        確かめ、予約に付いてから読み始める。読まずに断る場合は接続を閉じる
        （残りの本文を読まない）。
        """
        manager = self._state().ghidra
        ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype != UPLOAD_TYPE:
            self.close_connection = True
            return self._error(415, "application/octet-stream で送ってください")
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            return self._error(411, "長さを指定して送ってください")
        try:
            length = int(self.headers.get("Content-Length") or "")
        except ValueError:
            self.close_connection = True
            return self._error(411, "長さを指定して送ってください")
        if length <= 0 or length > gzf.MAX_GZF_BYTES:
            self.close_connection = True
            return self._fail_json(413, "too-large" if length > 0 else "empty")
        job = manager.get(job_id)
        if job is None or job.kind != "analyze" or job.origin.get("kind") != "upload":
            self.close_connection = True
            return self._error(404, "該当する処理がありません")
        if not manager.attach(job):
            # キャンセル済み・期限切れ・送信済みの予約。本文は読まない。
            self.close_connection = True
            code = job.error or ("cancelled" if job.cancel.is_set() else "busy")
            return self._fail_json(409, code, job)
        return self._guarded(manager, job, lambda: self._upload(manager, job, length))

    def _upload(self, manager, job, length: int):
        dest = os.path.join(manager.make_input_dir(job), "input.gzf")
        job.interrupt = self._interrupt_receive
        try:
            sha, size = intake.receive_upload(
                self.rfile, length, dest, cancel=job.cancel,
                deadline=time.monotonic() + intake.RECEIVE_SECONDS,
                set_timeout=self._set_receive_timeout,
            )
        except intake.IntakeError as exc:
            self.close_connection = True
            manager.fail(job, exc.code)
            return self._fail_json(409 if exc.code == "cancelled" else 422, exc.code, job)
        finally:
            job.interrupt = None
            try:
                self.connection.settimeout(self.timeout)
            except OSError:
                pass
        return self._finish_intake(manager, job, dest, sha, size)

    def h_ghidra_from_archive(self):
        """登録済み ZIP の中の .gzf を 1 件だけ処理する。

        受け取るのは登録 ID と、目録（/api/archives/<id>/members）での位置と、
        その名前だけ。名前は照合に使うだけで、パスには使わない。一覧の取得や
        プレビューでは Docker を起動しない。ここで利用者が 1 件を選んだとき
        だけ動かす。パスワードは、この要求を処理する間だけメモリに持つ。
        """
        payload = self._body()
        if payload is None:
            return None
        try:
            archive_id = int(payload.get("archive"))
            ordinal = int(payload.get("member"))
        except (TypeError, ValueError):
            return self._error(400, "要求の書式が不正です（archive と member が必要です）")
        name = payload.get("name")
        password = payload.pop("password", None)
        if not isinstance(name, str) or not name or len(name) > 4096:
            return self._error(400, "要求の書式が不正です（name が必要です）")
        if password is not None and (not isinstance(password, str)
                                     or len(password) > intake.MAX_PASSWORD):
            return self._error(400, "パスワードの形式が不正です")

        state = self._state()
        row = self._archive_row(archive_id)
        if row is None:
            return self._error(404, "そのZIPファイルは読み込まれていません")
        members = state.store.members(archive_id)
        if not 0 <= ordinal < len(members):
            return self._fail_json(404, "zip-member-missing")
        member = members[ordinal]
        if member["name"] != name:
            return self._fail_json(409, "zip-member-changed")

        manager = state.ghidra
        try:
            job = manager.reserve("analyze", {
                "kind": "archive",
                "archive": archive_id,
                "archiveName": visible(os.path.basename(row["path"]), MAX_DISPLAY_NAME),
                "archiveSha256": row["sha256"],
                "member": visible(member["name"], 300),
            })
        except jobs.Busy:
            return self._fail_json(409, "busy")
        return self._guarded(
            manager, job, lambda: self._from_archive(manager, job, row, member, password))

    def _from_archive(self, manager, job, row, member, password):
        if not self._ready_or_fail(manager, job):
            return self._fail_json(409, job.error, job)
        fh = self._open_verified(row)
        if fh is None:
            manager.fail(job, "archive-changed")
            return self._fail_json(409, "archive-changed", job)
        try:
            job.state = "checking"
            dest = os.path.join(manager.make_input_dir(job), "input.gzf")
            try:
                sha, size = intake.copy_member(fh, member, dest, password=password,
                                               cancel=job.cancel)
            except intake.IntakeError as exc:
                manager.fail(job, exc.code)
                status = 409 if exc.code in ("cancelled", "zip-member-changed") else 422
                return self._fail_json(status, exc.code, job)
            # 写し終えたあとに、同じ記述子でもう一度照合する。読んでいる間に
            # 同じファイルが書き換えられていたら、写しは使わない。
            if not self._recheck(fh, row):
                manager.fail(job, "archive-changed")
                return self._fail_json(409, "archive-changed", job)
        finally:
            fh.close()
            password = None  # noqa: F841 - 以後は参照しない
        return self._finish_intake(manager, job, dest, sha, size)

    def h_ghidra_sample(self):
        """同梱のサンプル GZF で演習を作る。パスは要求から受け取らない。"""
        payload = self._body()
        if payload is None:
            return None
        manager = self._state().ghidra
        sample = load_sample()
        if not sample or not sample.get("available"):
            return self._fail_json(404, "sample-missing")
        try:
            job = manager.reserve("analyze", {"kind": "sample",
                                              "name": visible(sample.get("name") or "", 80)})
        except jobs.Busy:
            return self._fail_json(409, "busy")
        return self._guarded(manager, job, lambda: self._sample(manager, job, sample))

    def _sample(self, manager, job, sample):
        if not self._ready_or_fail(manager, job):
            return self._fail_json(409, job.error, job)
        try:
            src_fd = os.open(sample["path"], os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            manager.fail(job, "sample-missing")
            return self._fail_json(404, "sample-missing", job)
        with os.fdopen(src_fd, "rb") as src:
            size = os.fstat(src.fileno()).st_size
            dest = os.path.join(manager.make_input_dir(job), "input.gzf")
            try:
                sha, got = intake.receive_upload(
                    src, size, dest, cancel=job.cancel,
                    deadline=time.monotonic() + intake.RECEIVE_SECONDS,
                )
            except intake.IntakeError as exc:
                manager.fail(job, exc.code)
                return self._fail_json(422, exc.code, job)
        if sha != sample["sha256"]:
            # 同梱物が来歴に記録したものと違う。黙って使わない。
            manager.fail(job, "hash-mismatch")
            return self._fail_json(409, "hash-mismatch", job)
        return self._finish_intake(manager, job, dest, sha, got)

    # -- 教材の削除 ---------------------------------------------------------
    def h_ghidra_delete_lesson(self, lesson_id: str):
        payload = self._body()
        if payload is None:
            return None
        if not self._state().store.delete_lesson(lesson_id):
            return self._error(404, "該当する演習がありません")
        return self._json({"deleted": lesson_id})
