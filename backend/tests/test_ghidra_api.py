"""GZF の受け付け（送信・ZIP 内の 1 件）と、HTTP の入口のテスト。

HTTP は本物のサーバーを 127.0.0.1 の空きポートで動かして確かめる。Docker は
使わず、ジョブ管理に偽の実行部を渡す（偽の実行部は、渡された入力のコピーを
読んでハッシュを計算し、そのハッシュを持つ抽出結果を返す）。
"""

import hashlib
import http.client
import io
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import api  # noqa: E402
import ghidra_api  # noqa: E402
import ghidra_docker as gd  # noqa: E402
import ghidra_fixtures as fx  # noqa: E402
import ghidra_intake as intake  # noqa: E402
import ghidra_jobs as jobs  # noqa: E402
import gzf  # noqa: E402
from archive import enumerate_zip  # noqa: E402
from store import Store  # noqa: E402

HAS_ZIP = shutil.which("zip") is not None
GZF = fx.make_gzf(name="minigame")


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def zip_with(self, entries, name="set.zip", compression=zipfile.ZIP_DEFLATED):
        path = os.path.join(self.tmp, name)
        with zipfile.ZipFile(path, "w", compression) as zf:
            for item in entries:
                zf.writestr(*item)
        return path


def info(name, data, mode=None):
    zi = zipfile.ZipInfo(name)
    zi.compress_type = zipfile.ZIP_DEFLATED
    if mode is not None:
        zi.external_attr = mode << 16
    return zi, data


def member_for(path, name):
    listing = enumerate_zip(path)
    rows = [m for m in listing.members if m.name == name]
    return [{"idx": m.index, "name": m.name, "container": m.container} for m in rows]


class TestReceiveUpload(Tmp):
    def dest(self):
        return os.path.join(self.tmp, "in.gzf")

    def test_exact_length_is_written_and_hashed(self):
        sha, n = intake.receive_upload(io.BytesIO(GZF + b"extra"), len(GZF), self.dest(),
                                       cancel=threading.Event(), deadline=time.monotonic() + 5)
        self.assertEqual(n, len(GZF))
        self.assertEqual(sha, hashlib.sha256(GZF).hexdigest())
        with open(self.dest(), "rb") as fh:
            self.assertEqual(fh.read(), GZF)

    def test_short_body_is_incomplete(self):
        with self.assertRaises(intake.IntakeError) as ctx:
            intake.receive_upload(io.BytesIO(GZF[:10]), len(GZF), self.dest(),
                                  cancel=threading.Event(), deadline=time.monotonic() + 5)
        self.assertEqual(ctx.exception.code, "upload-incomplete")

    def test_deadline_and_cancel(self):
        with self.assertRaises(intake.IntakeError) as ctx:
            intake.receive_upload(io.BytesIO(GZF), len(GZF), self.dest(),
                                  cancel=threading.Event(), deadline=time.monotonic() - 1)
        self.assertEqual(ctx.exception.code, "upload-timeout")
        os.unlink(self.dest())
        ev = threading.Event()
        ev.set()
        with self.assertRaises(intake.IntakeError) as ctx:
            intake.receive_upload(io.BytesIO(GZF), len(GZF), self.dest(), cancel=ev,
                                  deadline=time.monotonic() + 5)
        self.assertEqual(ctx.exception.code, "cancelled")

    def test_declared_length_over_the_limit_is_refused_before_reading(self):
        src = io.BytesIO(GZF)
        with self.assertRaises(intake.IntakeError):
            intake.receive_upload(src, gzf.MAX_GZF_BYTES + 1, self.dest(),
                                  cancel=threading.Event(), deadline=time.monotonic() + 5)
        self.assertEqual(src.tell(), 0)
        self.assertFalse(os.path.exists(self.dest()))

    def test_existing_destination_or_symlink_is_never_followed(self):
        target = os.path.join(self.tmp, "victim")
        open(target, "w").close()
        os.symlink(target, self.dest())
        with self.assertRaises(OSError):
            intake.receive_upload(io.BytesIO(GZF), len(GZF), self.dest(),
                                  cancel=threading.Event(), deadline=time.monotonic() + 5)
        self.assertEqual(os.path.getsize(target), 0)

    def test_check_copy_makes_the_copy_read_only(self):
        intake.receive_upload(io.BytesIO(GZF), len(GZF), self.dest(),
                              cancel=threading.Event(), deadline=time.monotonic() + 5)
        intake.check_copy(self.dest())
        self.assertEqual(stat.S_IMODE(os.stat(self.dest()).st_mode), 0o400)


class TestCopyMember(Tmp):
    def copy(self, path, member, password=None):
        dest = os.path.join(self.tmp, f"out-{time.monotonic_ns()}.gzf")
        with open(path, "rb") as fh:
            sha, n = intake.copy_member(fh, member, dest, password=password,
                                        cancel=threading.Event())
        with open(dest, "rb") as fh:
            return sha, fh.read()

    def test_top_level_member(self):
        path = self.zip_with([("readme.txt", "x"), ("a/prog.gzf", GZF)])
        sha, data = self.copy(path, member_for(path, "a/prog.gzf")[0])
        self.assertEqual(data, GZF)
        self.assertEqual(sha, hashlib.sha256(GZF).hexdigest())

    def test_same_name_members_are_told_apart_by_position(self):
        other = fx.make_gzf(name="second")
        with self.assertWarns(UserWarning):
            path = self.zip_with([("dup.gzf", GZF), ("dup.gzf", other)])
        rows = member_for(path, "dup.gzf")
        self.assertEqual(len(rows), 2)
        self.assertEqual(self.copy(path, rows[1])[1], other)
        self.assertEqual(self.copy(path, rows[0])[1], GZF)

    def test_a_changed_listing_is_refused(self):
        path = self.zip_with([("a.gzf", GZF)])
        with self.assertRaises(intake.IntakeError) as ctx:
            self.copy(path, {"idx": 0, "name": "b.gzf", "container": ""})
        self.assertEqual(ctx.exception.code, "zip-member-changed")
        with self.assertRaises(intake.IntakeError) as ctx:
            self.copy(path, {"idx": 9, "name": "a.gzf", "container": ""})
        self.assertEqual(ctx.exception.code, "zip-member-missing")

    def test_one_level_of_nesting(self):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as zf:
            zf.writestr("x.txt", "x")
            zf.writestr("deep/p.gzf", GZF)
        path = self.zip_with([("inner.zip", inner.getvalue())])
        rows = member_for(path, "inner.zip :: deep/p.gzf")
        self.assertEqual(rows[0]["container"], "inner.zip")
        self.assertEqual(self.copy(path, rows[0])[1], GZF)

    def test_ambiguous_nested_container_is_refused(self):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as zf:
            zf.writestr("p.gzf", GZF)
        with self.assertWarns(UserWarning):
            path = self.zip_with([("i.zip", inner.getvalue()), ("i.zip", inner.getvalue())])
        with self.assertRaises(intake.IntakeError) as ctx:
            self.copy(path, {"idx": 0, "name": "i.zip :: p.gzf", "container": "i.zip"})
        self.assertEqual(ctx.exception.code, "zip-ambiguous")

    def test_deeper_nesting_is_refused(self):
        path = self.zip_with([("i.zip", b"x")])
        with self.assertRaises(intake.IntakeError) as ctx:
            self.copy(path, {"idx": 0, "name": "i.zip :: j.zip :: p.gzf", "container": "i.zip"})
        self.assertEqual(ctx.exception.code, "zip-nested-too-deep")

    def test_symlink_member_is_refused(self):
        path = self.zip_with([info("link.gzf", b"/etc/passwd", 0o120777)])
        with self.assertRaises(intake.IntakeError) as ctx:
            self.copy(path, {"idx": 0, "name": "link.gzf", "container": ""})
        self.assertEqual(ctx.exception.code, "zip-symlink")

    def test_dangerous_names_are_refused(self):
        for name in ("../up.gzf", "/abs.gzf", "a/../../b.gzf", "c\x01.gzf", "C:/x.gzf",
                     "x\u202egzf.exe"):
            with self.subTest(name=name):
                path = self.zip_with([(name, GZF)], name=f"n{time.monotonic_ns()}.zip")
                with zipfile.ZipFile(path) as zf:
                    stored = intake._name(zf.infolist()[0])  # noqa: SLF001
                with self.assertRaises(intake.IntakeError) as ctx:
                    self.copy(path, {"idx": 0, "name": stored, "container": ""})
                self.assertEqual(ctx.exception.code, "zip-unsafe-name")

    def test_crc_failure_is_detected_at_the_end(self):
        path = self.zip_with([("p.gzf", GZF)], compression=zipfile.ZIP_STORED)
        with open(path, "r+b") as fh:
            raw = fh.read()
            at = raw.index(GZF[200:260]) + 10
            fh.seek(at)
            fh.write(bytes([raw[at] ^ 0xFF]))
        with self.assertRaises(intake.IntakeError) as ctx:
            self.copy(path, {"idx": 0, "name": "p.gzf", "container": ""})
        self.assertEqual(ctx.exception.code, "crc")

    def test_extreme_ratio_is_refused(self):
        path = self.zip_with([("z.gzf", b"\x00" * (4 * 1024 * 1024))])
        with self.assertRaises(intake.IntakeError) as ctx:
            self.copy(path, {"idx": 0, "name": "z.gzf", "container": ""})
        self.assertEqual(ctx.exception.code, "ratio")

    def test_shared_budget_covers_the_outer_container(self):
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("pad.bin", os.urandom(300_000))
            zf.writestr("p.gzf", GZF)
        path = self.zip_with([("i.zip", inner.getvalue())], compression=zipfile.ZIP_STORED)
        orig = intake.ARCHIVE_BUDGET
        intake.ARCHIVE_BUDGET = 200_000
        self.addCleanup(setattr, intake, "ARCHIVE_BUDGET", orig)
        with self.assertRaises(intake.IntakeError) as ctx:
            self.copy(path, {"idx": 1, "name": "i.zip :: p.gzf", "container": "i.zip"})
        self.assertEqual(ctx.exception.code, "budget")

    def test_aes_is_refused_without_guessing(self):
        path = self.zip_with([("p.gzf", GZF)], compression=zipfile.ZIP_STORED)
        with open(path, "r+b") as fh:
            raw = bytearray(fh.read())
            # ローカルヘッダーと目録の compression method（オフセット 8 / 10）を 99 に。
            raw[8:10] = (99).to_bytes(2, "little")
            cd = raw.index(b"PK\x01\x02")
            raw[cd + 10:cd + 12] = (99).to_bytes(2, "little")
            raw[cd + 8:cd + 10] = (raw[cd + 8] | 1).to_bytes(2, "little")
            fh.seek(0)
            fh.write(raw)
        with self.assertRaises(intake.IntakeError) as ctx:
            self.copy(path, {"idx": 0, "name": "p.gzf", "container": ""}, password="x")
        self.assertEqual(ctx.exception.code, "zip-aes")

    @unittest.skipUnless(HAS_ZIP, "system `zip` is needed to build an encrypted fixture")
    def test_zipcrypto_password_is_used_in_memory_only(self):
        src = os.path.join(self.tmp, "p.gzf")
        with open(src, "wb") as fh:
            fh.write(GZF)
        path = os.path.join(self.tmp, "enc.zip")
        subprocess.run(["zip", "-q", "-j", "-P", "s3cret-pw", path, src], check=True)
        row = {"idx": 0, "name": "p.gzf", "container": ""}
        with self.assertRaises(intake.IntakeError) as ctx:
            self.copy(path, row)
        self.assertEqual(ctx.exception.code, "password-required")
        with self.assertRaises(intake.IntakeError) as ctx:
            self.copy(path, row, password="wrong")
        self.assertEqual(ctx.exception.code, "password-rejected")
        self.assertEqual(self.copy(path, row, password="s3cret-pw")[1], GZF)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def fake_runner(argv, env, **kw):
    """偽の抽出。マウントされた入力のコピーを読み、そのハッシュで結果を返す。"""
    mount = argv[argv.index("--mount") + 1]
    source = dict(p.split("=", 1) for p in mount.split(",") if "=" in p)["source"]
    with open(os.path.join(source, "input.gzf"), "rb") as fh:
        sha = hashlib.sha256(fh.read()).hexdigest()
    return gd.RunResult(0, fx.facts_bytes(sha=sha), b"", seconds=0.1)


READY = {"docker": {"state": "ready", "arch": "arm64", "version": "28"},
         "image": {"state": "ready", "ref": "img", "id": "sha256:" + "3" * 64}}


class Server(Tmp):
    def setUp(self):
        super().setUp()
        self.state = api.State.__new__(api.State)
        self.state.store = Store(os.path.join(self.tmp, "m.sqlite3"))
        self.addCleanup(self.state.store.close)
        self.state.role = "instructor"
        self.state.caps = set(api.ROLE_CAPS["instructor"])
        self.state.token = "tok"
        self.state.lock = threading.Lock()
        self.state.dataset_dirs = []
        env = gd.Environment("/usr/bin/docker", "unix:///x", {}, "linux", "arm64", "28")
        self.runner = fake_runner
        self.state.ghidra = jobs.JobManager(
            os.path.join(self.tmp, "jobs"), "0" * 16,
            sink=lambda lesson: self.state.store.save_lesson(lesson, "ghidra"),
            resolver=lambda: env,
            image_state=lambda e: dict(READY["image"]),
            run_process=lambda *a, **k: self.runner(*a, **k),
            stop_container=lambda e, j: None, uid=501, gid=20)
        self.probe = dict(READY)
        patches = [(api, "STATE", self.state),
                   (ghidra_api, "probe", lambda force=False: self.probe)]
        for mod, name, value in patches:
            orig = getattr(mod, name)
            setattr(mod, name, value)
            self.addCleanup(setattr, mod, name, orig)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), api.Handler)
        self.port = self.httpd.server_address[1]
        orig_hosts = api.ALLOWED_HOSTS
        api.ALLOWED_HOSTS = frozenset({f"127.0.0.1:{self.port}"})
        self.addCleanup(setattr, api, "ALLOWED_HOSTS", orig_hosts)
        t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        t.start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def request(self, method, path, body=None, headers=None, host=None, token="tok"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Host": host or f"127.0.0.1:{self.port}"}
        if token:
            h["X-MWS-Token"] = token
        h.update(headers or {})
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
            h.setdefault("Content-Type", "application/json")
        conn.request(method, path, body=body, headers=h)
        res = conn.getresponse()
        raw = res.read()
        conn.close()
        try:
            return res.status, json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return res.status, {"raw": raw}

    def reserve(self, size, name="a b.gzf"):
        return self.request("POST", "/api/ghidra/jobs/new", {"name": name, "size": size})

    def send_body(self, job_id, data, **headers):
        h = {"Content-Type": "application/octet-stream"}
        h.update(headers)
        return self.request("POST", f"/api/ghidra/jobs/{job_id}/upload", data, h)

    def upload(self, data, **headers):
        """画面と同じ 2 段階：予約して ID を受け取り、その ID へ本文を送る。"""
        status, body = self.reserve(len(data))
        if status != 201:
            return status, body
        return self.send_body(body["job"]["id"], data, **headers)

    def wait(self, job_id):
        for _ in range(200):
            status, body = self.request("GET", f"/api/ghidra/jobs/{job_id}")
            if body.get("job", {}).get("final"):
                return body["job"]
            time.sleep(0.02)
        self.fail("job did not finish")


def corrupt_gzf() -> bytes:
    """ヘッダーは正しいが、圧縮データが壊れた GZF。"""
    data = bytearray(GZF)
    start = gzf.parse_header(bytes(data[:4096])).zip_offset + 30 + len(b"FOLDER_ITEM")
    for i in range(start, start + 40):
        data[i] ^= 0x5A
    return bytes(data)


class TestGhidraHttp(Server):
    def test_corrupt_gzf_is_refused_and_the_slot_is_released(self):
        """壊れた圧縮データでも、処理枠と一時ファイルが残らず、次を受け付ける。"""
        status, body = self.upload(corrupt_gzf())
        self.assertEqual((status, body["code"]), (422, "not-gzf"))
        self.assertIsNotNone(self.state.ghidra.current())
        self.assertEqual(self.state.ghidra.current().state, "failed")
        self.assertEqual(os.listdir(os.path.join(self.tmp, "jobs")), [])
        status, body = self.upload(GZF)
        self.assertEqual(status, 202, body)
        self.assertEqual(self.wait(body["job"]["id"])["state"], "done")

    def test_unexpected_errors_still_release_the_slot(self):
        """受付の途中で想定外の例外が出ても、枠を残さない（キャンセルも効く状態に戻る）。"""
        orig = intake.check_copy
        intake.check_copy = lambda path: 1 / 0
        self.addCleanup(setattr, intake, "check_copy", orig)
        status, body = self.upload(GZF)
        self.assertEqual((status, body["code"]), (500, "internal"))
        self.assertEqual(self.state.ghidra.current().state, "failed")
        self.assertEqual(os.listdir(os.path.join(self.tmp, "jobs")), [])
        intake.check_copy = orig
        status, body = self.upload(GZF)
        self.assertEqual(status, 202)

    def slow_upload(self, total: int, gap: float):
        """宣言した長さより遅く、少しずつ送る接続。送り続けるスレッドを返す。"""
        status, body = self.reserve(total)
        self.assertEqual(status, 201, body)
        job_id = body["job"]["id"]
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=30)
        self.addCleanup(sock.close)
        head = (f"POST /api/ghidra/jobs/{job_id}/upload HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\n"
                f"X-MWS-Token: tok\r\nContent-Type: application/octet-stream\r\n"
                f"Content-Length: {total}\r\n\r\n").encode()
        sock.sendall(head)
        stop = threading.Event()

        def trickle():
            while not stop.is_set():
                try:
                    sock.sendall(b"x")
                except OSError:
                    return
                time.sleep(gap)
        t = threading.Thread(target=trickle, daemon=True)
        t.start()
        self.addCleanup(stop.set)
        return sock, stop

    def read_status(self, sock) -> int:
        sock.settimeout(10)
        line = sock.makefile("rb").readline()
        return int(line.split()[1])

    def test_slow_trickle_is_cut_at_the_total_deadline(self):
        """1 回の受信より短い間隔で少しずつ送られても、総期限で打ち切る。"""
        orig = intake.RECEIVE_SECONDS
        intake.RECEIVE_SECONDS = 1.0
        self.addCleanup(setattr, intake, "RECEIVE_SECONDS", orig)
        started = time.monotonic()
        sock, stop = self.slow_upload(100_000, 0.05)
        status = self.read_status(sock)
        stop.set()
        self.assertEqual(status, 422)
        self.assertLess(time.monotonic() - started, 5, "must not wait for the whole body")
        job = self.state.ghidra.current()
        self.assertEqual(job.error, "upload-timeout")
        self.assertEqual(os.listdir(os.path.join(self.tmp, "jobs")), [])

    def test_cancel_interrupts_a_stalled_upload(self):
        """何も届かないまま待っている受信も、キャンセルですぐ終わる。"""
        sock, stop = self.slow_upload(100_000, 3600)   # 1 バイト送って止まる
        for _ in range(200):
            job = self.state.ghidra.current()
            if job is not None and job.state == "receiving" and job.interrupt:
                break
            time.sleep(0.01)
        started = time.monotonic()
        status, _ = self.request("POST", f"/api/ghidra/jobs/{job.id}/cancel", {})
        self.assertEqual(status, 200)
        for _ in range(300):
            if job.state in jobs.FINAL:
                break
            time.sleep(0.01)
        self.assertEqual(job.state, "cancelled")
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(os.listdir(os.path.join(self.tmp, "jobs")), [])
        status, body = self.upload(GZF)
        self.assertEqual(status, 202, body)

    def test_upload_to_lesson_end_to_end(self):
        status, body = self.upload(GZF)
        self.assertEqual(status, 202, body)
        job = self.wait(body["job"]["id"])
        self.assertEqual(job["state"], "done", job)
        self.assertEqual(job["origin"], {"kind": "upload", "name": "a b.gzf"})
        lesson_id = job["lessonId"]
        status, lesson = self.request("GET", f"/api/lessons/{lesson_id}")
        self.assertEqual(status, 200)
        self.assertEqual(lesson["kind"], "static")
        self.assertEqual(lesson["static"]["input"]["sha256"], hashlib.sha256(GZF).hexdigest())
        ev_id = lesson["stages"][0]["quizzes"][0]["evidenceIds"][0]
        status, ev = self.request("GET", f"/api/lessons/{lesson_id}/evidence/{ev_id}")
        self.assertEqual(status, 200)
        self.assertEqual(set(ev), {"id", "kind", "evidenceType", "confidence", "source"})
        self.assertEqual(set(ev["source"]), {"program", "function", "address", "instruction",
                                             "reference", "excerpt"})
        self.assertEqual(os.listdir(os.path.join(self.tmp, "jobs")), [],
                         "the input copy is removed after processing")

    def test_renamed_executable_is_refused_after_upload(self):
        status, body = self.upload(b"\x7fELF" + b"\x00" * 400)
        self.assertEqual(status, 422)
        self.assertEqual(body["code"], "not-gzf")
        self.assertEqual(os.listdir(os.path.join(self.tmp, "jobs")), [])

    def test_upload_limits(self):
        status, body = self.reserve(gzf.MAX_GZF_BYTES + 1)
        self.assertEqual((status, body["code"]), (413, "too-large"))
        self.assertIsNone(self.state.ghidra.current(), "nothing reserved for a refused size")
        for bad in (0, -1, "10", True, None):
            with self.subTest(size=bad):
                status, _ = self.request("POST", "/api/ghidra/jobs/new", {"size": bad})
                self.assertIn(status, (400, 413))
        self.assertIsNone(self.state.ghidra.current())
        status, _ = self.upload(GZF, **{"Content-Type": "application/json"})
        self.assertEqual(status, 415)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest("POST", f"/api/ghidra/jobs/{'d' * 32}/upload", skip_host=True)
        conn.putheader("Host", f"127.0.0.1:{self.port}")
        conn.putheader("X-MWS-Token", "tok")
        conn.putheader("Content-Type", "application/octet-stream")
        conn.putheader("Content-Length", str(gzf.MAX_GZF_BYTES + 1))
        conn.endheaders()
        res = conn.getresponse()
        self.assertEqual(res.status, 413)
        conn.close()

    def test_json_body_limit_is_unchanged(self):
        self.assertEqual(api.MAX_BODY, 64 * 1024)
        status, _ = self.request("POST", "/api/ghidra/jobs/from-archive",
                                 b"{" + b" " * (api.MAX_BODY + 1) + b"}",
                                 {"Content-Type": "application/json"})
        self.assertEqual(status, 413)

    def test_docker_not_ready_refuses_before_reading(self):
        self.probe = {"docker": {"state": "docker-missing"}, "image": {"state": "unknown"}}
        status, body = self.upload(GZF)
        self.assertEqual(status, 409)
        self.assertEqual(body["code"], "docker-missing")
        self.probe = {"docker": READY["docker"], "image": {"state": "missing"}}
        status, body = self.upload(GZF)
        self.assertEqual(body["code"], "image-missing")

    def test_busy(self):
        job = self.state.ghidra.reserve("analyze", {})
        status, body = self.upload(GZF)
        self.assertEqual((status, body["code"]), (409, "busy"))
        self.state.ghidra.fail(job, "cancelled")

    def test_cancel_after_the_body_arrived_stops_before_analysis(self):
        """本文が届き終えて確認中のときに取り消しても、抽出も教材の保存も起きない。

        通信を切るだけでは、この段階のサーバー側の処理は止まらない。予約した
        ID で取り消せば、確認の直後に止まる。
        """
        ran = []
        self.runner = lambda *a, **k: ran.append(a) or fake_runner(*a, **k)
        checking = threading.Event()
        release = threading.Event()
        orig = intake.check_copy

        def slow_check(path):
            checking.set()
            release.wait(5)
            return orig(path)
        intake.check_copy = slow_check
        self.addCleanup(setattr, intake, "check_copy", orig)
        status, body = self.reserve(len(GZF))
        job_id = body["job"]["id"]
        result = {}
        t = threading.Thread(target=lambda: result.update(r=self.send_body(job_id, GZF)))
        t.start()
        self.assertTrue(checking.wait(5))
        status, _ = self.request("POST", f"/api/ghidra/jobs/{job_id}/cancel", {})
        self.assertEqual(status, 200)
        release.set()
        t.join(5)
        self.assertEqual(result["r"][0], 409)
        self.assertEqual(result["r"][1]["code"], "cancelled")
        self.assertEqual(self.state.ghidra.get(job_id).state, "cancelled")
        self.assertEqual(ran, [], "the container must not start")
        self.assertEqual(self.state.store.lessons(), [])
        self.assertEqual(os.listdir(os.path.join(self.tmp, "jobs")), [])

    def test_cancel_before_the_body_releases_the_reservation(self):
        status, body = self.reserve(len(GZF))
        job_id = body["job"]["id"]
        status, _ = self.request("POST", f"/api/ghidra/jobs/{job_id}/cancel", {})
        self.assertEqual(status, 200)
        self.assertEqual(self.state.ghidra.get(job_id).state, "cancelled")
        status, body = self.send_body(job_id, GZF)
        self.assertEqual((status, body["code"]), (409, "cancelled"))
        status, body = self.upload(GZF)
        self.assertEqual(status, 202, "the slot is free again")

    def test_abandoned_reservation_expires(self):
        self.state.ghidra.RESERVE_SECONDS = 0
        status, body = self.reserve(len(GZF))
        first = body["job"]["id"]
        time.sleep(0.01)
        status, body = self.reserve(len(GZF))
        self.assertEqual(status, 201, "a stale reservation must not hold the only slot")
        self.assertEqual(self.state.ghidra.get(first).error, "upload-timeout")
        status, body = self.send_body(first, GZF)
        self.assertEqual(status, 409)

    def test_a_reservation_takes_one_body_only(self):
        status, body = self.upload(GZF)
        job_id = body["job"]["id"]
        self.wait(job_id)
        status, body = self.send_body(job_id, GZF)
        self.assertEqual(status, 409)
        status, _ = self.send_body("e" * 32, GZF)
        self.assertEqual(status, 404)

    def test_token_host_and_capability_are_enforced(self):
        status, _ = self.upload(GZF, **{"X-MWS-Token": "wrong"})
        self.assertEqual(status, 403)
        status, _ = self.request("GET", "/api/ghidra/status", host="evil.example")
        self.assertEqual(status, 421)
        before = set(self.state.ghidra.jobs)
        status, _ = self.request("POST", "/api/ghidra/jobs/new", {"size": 10},
                                 {"Origin": "http://evil.example"})
        self.assertEqual(status, 403)
        status, _ = self.request("POST", "/api/ghidra/jobs/new", {"size": 10}, token="bad")
        self.assertEqual(status, 403)
        self.assertEqual(set(self.state.ghidra.jobs), before, "no reservation from a refused request")

    def test_student_cannot_use_any_ghidra_route(self):
        self.state.caps = set(api.ROLE_CAPS["student"])
        self.state.role = "student"
        jid = "a" * 32
        for method, path in (("GET", "/api/ghidra/status"), ("GET", f"/api/ghidra/jobs/{jid}"),
                             ("POST", f"/api/ghidra/jobs/{jid}/cancel"),
                             ("POST", "/api/ghidra/prepare"), ("POST", "/api/ghidra/jobs/new"),
                             ("POST", f"/api/ghidra/jobs/{jid}/upload"),
                             ("POST", "/api/ghidra/jobs/from-archive"),
                             ("POST", "/api/ghidra/jobs/sample"),
                             ("POST", "/api/lessons/gen-gzf-0123456789abcdef/delete")):
            with self.subTest(path=path):
                status, _ = self.request(method, path, {} if method == "POST" else None)
                self.assertEqual(status, 403)

    def test_unknown_job_and_malformed_ids(self):
        status, _ = self.request("GET", "/api/ghidra/jobs/" + "b" * 32)
        self.assertEqual(status, 404)
        status, _ = self.request("POST", f"/api/ghidra/jobs/{'b' * 32}/cancel", {})
        self.assertEqual(status, 409)
        status, _ = self.request("GET", "/api/ghidra/jobs/../../etc")
        self.assertEqual(status, 404)

    def test_cancel_only_touches_the_named_job(self):
        started = threading.Event()
        release = threading.Event()

        def slow(argv, env, **kw):
            started.set()
            kw["cancel"].wait(5)
            release.set()
            return gd.RunResult(None, cancelled=True)
        self.runner = slow
        status, body = self.upload(GZF)
        jid = body["job"]["id"]
        started.wait(5)
        status, _ = self.request("POST", f"/api/ghidra/jobs/{'c' * 32}/cancel", {})
        self.assertEqual(status, 409)
        self.assertFalse(release.is_set())
        status, _ = self.request("POST", f"/api/ghidra/jobs/{jid}/cancel", {})
        self.assertEqual(status, 200)
        self.assertEqual(self.wait(jid)["state"], "cancelled")

    def register(self, entries):
        path = self.zip_with(entries, name=f"r{time.monotonic_ns()}.zip")
        return path, self.state.store.record_archive(path, enumerate_zip(path))

    def test_from_archive_end_to_end(self):
        path, aid = self.register([("notes.txt", "x"), ("bin/game.gzf", GZF)])
        members = self.state.store.members(aid)
        ordinal = [m["name"] for m in members].index("bin/game.gzf")
        status, body = self.request("POST", "/api/ghidra/jobs/from-archive",
                                    {"archive": aid, "member": ordinal, "name": "bin/game.gzf"})
        self.assertEqual(status, 202, body)
        job = self.wait(body["job"]["id"])
        self.assertEqual(job["state"], "done")
        self.assertEqual(job["origin"]["member"], "bin/game.gzf")
        self.assertNotIn(self.tmp, json.dumps(job))

    def test_from_archive_refusals(self):
        path, aid = self.register([("bin/game.gzf", GZF)])
        status, body = self.request("POST", "/api/ghidra/jobs/from-archive",
                                    {"archive": aid, "member": 0, "name": "other.gzf"})
        self.assertEqual((status, body["code"]), (409, "zip-member-changed"))
        status, body = self.request("POST", "/api/ghidra/jobs/from-archive",
                                    {"archive": aid, "member": 7, "name": "bin/game.gzf"})
        self.assertEqual(status, 404)
        status, body = self.request("POST", "/api/ghidra/jobs/from-archive",
                                    {"archive": 999, "member": 0, "name": "x"})
        self.assertEqual(status, 404)
        # 登録後に ZIP が差し替えられた。
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("bin/game.gzf", fx.make_gzf(name="swapped"))
        status, body = self.request("POST", "/api/ghidra/jobs/from-archive",
                                    {"archive": aid, "member": 0, "name": "bin/game.gzf"})
        self.assertEqual((status, body["code"]), (409, "archive-changed"))

    def test_archive_rewritten_during_the_copy_is_not_used(self):
        """写している最中に同じファイル（同じ inode）が書き換えられた場合。

        記述子は inode を追うので、読み始める前の照合だけでは見えない。
        写し終えたあとの再照合で気づき、写しを使わないこと。
        """
        path, aid = self.register([("bin/game.gzf", GZF)])
        real = intake.copy_member

        def tampering(fh, member, dest, **kw):
            result = real(fh, member, dest, **kw)
            with open(path, "r+b") as out:   # 置き換えではなく上書き
                out.seek(0)
                out.write(b"X" * 16)
            return result
        intake.copy_member = tampering
        self.addCleanup(setattr, intake, "copy_member", real)
        status, body = self.request("POST", "/api/ghidra/jobs/from-archive",
                                    {"archive": aid, "member": 0, "name": "bin/game.gzf"})
        self.assertEqual((status, body["code"]), (409, "archive-changed"))
        self.assertEqual(os.listdir(os.path.join(self.tmp, "jobs")), [])

    def test_listing_and_preview_never_start_docker(self):
        calls = []
        self.runner = lambda *a, **k: calls.append(a) or fake_runner(*a, **k)
        path, aid = self.register([("bin/game.gzf", GZF)])
        self.request("GET", f"/api/archives/{aid}/members")
        self.request("GET", f"/api/archives/{aid}/members/0/preview")
        self.request("GET", f"/api/archives/{aid}/dataset")
        self.assertEqual(calls, [])
        self.assertIsNone(self.state.ghidra.current())

    def test_password_is_not_kept_anywhere(self):
        path, aid = self.register([("bin/game.gzf", GZF)])
        secret = "pw-" + "q" * 20
        status, body = self.request("POST", "/api/ghidra/jobs/from-archive",
                                    {"archive": aid, "member": 0, "name": "bin/game.gzf",
                                     "password": secret})
        job = self.wait(body["job"]["id"])
        self.assertNotIn(secret, json.dumps(job))
        with open(os.path.join(self.tmp, "m.sqlite3"), "rb") as fh:
            self.assertNotIn(secret.encode(), fh.read())
        self.assertNotIn(secret, json.dumps(self.state.store.events(100)))

    def test_delete_lesson(self):
        status, body = self.upload(GZF)
        lesson_id = self.wait(body["job"]["id"])["lessonId"]
        status, _ = self.request("POST", f"/api/lessons/{lesson_id}/delete", {})
        self.assertEqual(status, 200)
        status, _ = self.request("GET", f"/api/lessons/{lesson_id}")
        self.assertEqual(status, 404)
        status, _ = self.request("POST", f"/api/lessons/{lesson_id}/delete", {})
        self.assertEqual(status, 404)
        # ログ教材は、この経路では消せない（ルートの形が合わない）。
        status, _ = self.request("POST", "/api/lessons/gen-1/delete", {})
        self.assertEqual(status, 404)

    def test_status_reports_pinned_versions_and_limits(self):
        status, body = self.request("GET", "/api/ghidra/status")
        self.assertEqual(status, 200)
        self.assertEqual(body["pinned"]["ghidraVersion"], "12.1.4")
        self.assertEqual(body["limits"]["maxGzfBytes"], gzf.MAX_GZF_BYTES)
        self.assertNotIn(self.tmp, json.dumps(body))


if __name__ == "__main__":
    unittest.main(verbosity=2)
