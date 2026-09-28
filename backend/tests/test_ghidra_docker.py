"""Docker の接続先確認・固定コマンド・実行の上限・ジョブ管理のテスト。

Docker 自体は使わない。CLI の応答は偽の runner で、実行の上限は本物の子プロセス
（python -c）で確かめる。実コンテナでの確認は README の手順で別に行う。
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ghidra_docker as gd  # noqa: E402
import ghidra_fixtures as fx  # noqa: E402
import ghidra_jobs as jobs  # noqa: E402


def proc(rc=0, out=b"", err=b""):
    return SimpleNamespace(returncode=rc, stdout=out, stderr=err)


class FakeRunner:
    """argv の先頭数語で応答を決める偽の subprocess.run。呼ばれた argv を記録する。"""

    def __init__(self, table):
        self.table = table
        self.calls = []

    def __call__(self, argv, **kw):
        self.calls.append((list(argv), kw.get("env")))
        for key, value in self.table.items():
            if tuple(argv[1:1 + len(key)]) == key:
                return value(argv) if callable(value) else value
        return proc(1, b"", b"unexpected")


def version_ok(arch="arm64"):
    return proc(0, json.dumps({"Server": {"Os": "linux", "Arch": arch,
                                          "Version": "28.0.0"}}).encode())


class SocketDir(unittest.TestCase):
    def setUp(self):
        # AF_UNIX のパス長制限（macOS は 104 バイト）に収まる短い場所を使う。
        self.tmp = tempfile.mkdtemp(prefix="mws", dir="/tmp")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.sock_path = os.path.join(self.tmp, "d.sock")
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.bind(self.sock_path)
        self.addCleanup(self.sock.close)
        self.fake_docker = os.path.join(self.tmp, "docker")
        with open(self.fake_docker, "w") as fh:
            fh.write("#!/bin/sh\nexit 1\n")
        os.chmod(self.fake_docker, 0o755)
        self.environ = {"PATH": self.tmp, "HOME": self.tmp}


class TestEndpoint(SocketDir):
    def test_local_unix_socket_is_accepted(self):
        self.assertEqual(gd.check_endpoint("unix://" + self.sock_path),
                         "unix://" + self.sock_path)

    def test_remote_endpoints_are_refused(self):
        for ep in ("tcp://127.0.0.1:2375", "tcp://10.0.0.5:2376", "ssh://user@host",
                   "http://localhost:2375", "https://example.test", "fd://"):
            with self.subTest(ep=ep):
                with self.assertRaises(gd.DockerProblem) as ctx:
                    gd.check_endpoint(ep)
                self.assertEqual(ctx.exception.code, "docker-remote")

    def test_unverifiable_local_endpoints_are_refused(self):
        regular = os.path.join(self.tmp, "file")
        open(regular, "w").close()
        for ep in ("unix://" + regular, "unix://relative/path", "unix:///a/../b",
                   "", "unix://" + self.sock_path + "\n"):
            with self.subTest(ep=ep):
                with self.assertRaises(gd.DockerProblem):
                    gd.check_endpoint(ep)

    def test_named_pipe_only_on_windows(self):
        self.assertEqual(gd.check_endpoint("npipe:////./pipe/docker_engine", "win32"),
                         "npipe:////./pipe/docker_engine")
        with self.assertRaises(gd.DockerProblem):
            gd.check_endpoint("npipe:////./pipe/docker_engine", "darwin")


class TestResolve(SocketDir):
    def test_docker_host_pointing_away_is_refused_without_touching_it(self):
        runner = FakeRunner({})
        env = dict(self.environ, DOCKER_HOST="tcp://192.0.2.1:2375")
        with self.assertRaises(gd.DockerProblem) as ctx:
            gd.resolve(env, runner=runner)
        self.assertEqual(ctx.exception.code, "docker-remote")
        self.assertEqual(runner.calls, [], "nothing is sent to a remote endpoint")

    def test_remote_context_is_refused(self):
        runner = FakeRunner({("context", "inspect"): proc(0, b'"ssh://me@builder"')})
        with self.assertRaises(gd.DockerProblem) as ctx:
            gd.resolve(self.environ, runner=runner)
        self.assertEqual(ctx.exception.code, "docker-remote")

    def test_local_context_is_pinned_for_every_later_command(self):
        runner = FakeRunner({
            ("context", "inspect"): proc(0, json.dumps("unix://" + self.sock_path).encode()),
            ("version",): version_ok(),
        })
        env = dict(self.environ, DOCKER_CONTEXT="desktop-linux",
                   DOCKER_TLS_VERIFY="1", BUILDX_BUILDER="cloud-x")
        envi = gd.resolve(env, runner=runner)
        self.assertEqual(envi.server_arch, "arm64")
        _, version_env = runner.calls[-1]
        self.assertEqual(version_env["DOCKER_HOST"], "unix://" + self.sock_path)
        for leaked in ("DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "BUILDX_BUILDER"):
            self.assertNotIn(leaked, version_env)

    def test_daemon_states_are_classified(self):
        cases = {
            b"Cannot connect to the Docker daemon. Is the docker daemon running?": "docker-not-running",
            b"permission denied while trying to connect": "docker-permission",
            b"something else": "docker-unavailable",
        }
        for err, code in cases.items():
            with self.subTest(code=code):
                runner = FakeRunner({("version",): proc(1, b"", err)})
                env = dict(self.environ, DOCKER_HOST="unix://" + self.sock_path)
                with self.assertRaises(gd.DockerProblem) as ctx:
                    gd.resolve(env, runner=runner)
                self.assertEqual(ctx.exception.code, code)

    def test_windows_containers_and_other_cpus_are_refused(self):
        env = dict(self.environ, DOCKER_HOST="unix://" + self.sock_path)
        runner = FakeRunner({("version",): proc(0, json.dumps(
            {"Server": {"Os": "windows", "Arch": "amd64"}}).encode())})
        with self.assertRaises(gd.DockerProblem) as ctx:
            gd.resolve(env, runner=runner)
        self.assertEqual(ctx.exception.code, "docker-not-linux")
        runner = FakeRunner({("version",): version_ok("s390x")})
        with self.assertRaises(gd.DockerProblem) as ctx:
            gd.resolve(env, runner=runner)
        self.assertEqual(ctx.exception.code, "docker-arch-unsupported")

    def test_missing_cli(self):
        orig = gd.DOCKER_CANDIDATES
        gd.DOCKER_CANDIDATES = ()
        self.addCleanup(setattr, gd, "DOCKER_CANDIDATES", orig)
        with self.assertRaises(gd.DockerProblem) as ctx:
            gd.resolve({"PATH": "/nonexistent"})
        self.assertEqual(ctx.exception.code, "docker-missing")


def envi(arch="arm64"):
    return gd.Environment("/usr/bin/docker", "unix:///tmp/x.sock",
                          {"DOCKER_HOST": "unix:///tmp/x.sock"}, "linux", arch, "28")


JOB = "0123456789abcdef0123456789abcdef"
OWNER = "fedcba9876543210"
SESSION = "1111222233334444"


class TestRunArgv(unittest.TestCase):
    def argv(self, **kw):
        base = dict(job_id=JOB, owner=OWNER, session=SESSION,
                    input_dir="/state/ghidra-jobs/x/input", uid=501, gid=20)
        base.update(kw)
        return gd.run_argv(envi(), **base)

    def test_isolation_flags_are_all_present(self):
        a = self.argv()
        for flag in ("--rm", "--network=none", "--cap-drop=ALL",
                     "--security-opt=no-new-privileges", "--read-only", "--pull=never",
                     "--log-driver=none"):
            self.assertIn(flag, a)
        self.assertEqual(a[a.index("--user") + 1], "501:20")
        self.assertEqual(a[a.index("--memory") + 1], gd.LIMITS["memory"])
        self.assertEqual(a[a.index("--memory-swap") + 1], gd.LIMITS["memory"])
        self.assertEqual(a[a.index("--pids-limit") + 1], str(gd.LIMITS["pids"]))
        self.assertIn("--cpus", a)
        tmpfs = a[a.index("--tmpfs") + 1]
        self.assertIn("size=", tmpfs)
        self.assertIn("noexec", tmpfs)
        self.assertEqual(a[-1], gd.image_ref(), "the image is the fixed one, last")

    def test_dangerous_options_never_appear(self):
        text = " ".join(self.argv())
        for banned in ("--privileged", "--network=host", "--net=host", "seccomp=unconfined",
                       "-p ", "--publish", "docker.sock", "--pid=host", "--ipc=host",
                       "--entrypoint", "--cap-add", "--device", "--volumes-from", ":latest"):
            self.assertNotIn(banned, text)

    def test_only_the_job_input_is_shared_and_read_only(self):
        a = self.argv()
        mounts = [a[i + 1] for i, x in enumerate(a) if x in ("--mount", "-v", "--volume")]
        self.assertEqual(mounts, ["type=bind,source=/state/ghidra-jobs/x/input,target=/input,readonly"])

    def test_no_shell_and_no_command_after_the_image(self):
        a = self.argv()
        self.assertNotIn("sh", a)
        self.assertNotIn("-c", a)
        self.assertEqual(a.index(gd.image_ref()), len(a) - 1)

    def test_labels_identify_owner_and_job(self):
        a = self.argv()
        labels = [a[i + 1] for i, x in enumerate(a) if x == "--label"]
        self.assertIn(f"{gd.LABEL_APP}={gd.LABEL_APP_VALUE}", labels)
        self.assertIn(f"{gd.LABEL_OWNER}={OWNER}", labels)
        self.assertIn(f"{gd.LABEL_JOB}={JOB}", labels)
        self.assertIn(f"{gd.LABEL_SESSION}={SESSION}", labels)
        self.assertEqual(a[a.index("--name") + 1], gd.NAME_PREFIX + JOB)

    def test_root_and_unsafe_paths_and_ids_are_refused(self):
        for kw in ({"uid": 0}, {"input_dir": "/a,b/input"}, {"input_dir": "rel/input"},
                   {"input_dir": "/a=b"}, {"job_id": "x; rm -rf /"}, {"owner": "../"},
                   {"session": "x"}):
            with self.subTest(kw=kw):
                with self.assertRaises(ValueError):
                    self.argv(**kw)

    def test_diagnostics_only_when_asked(self):
        self.assertNotIn("MWS_DIAG=1", self.argv())
        self.assertIn("MWS_DIAG=1", self.argv(diag=True))


class TestBuild(unittest.TestCase):
    def test_build_is_local_and_never_pushes(self):
        a = gd.build_argv(envi("amd64"))
        self.assertEqual(a[1:3], ["buildx", "build"])
        self.assertEqual(a[a.index("--builder") + 1], "default")
        self.assertIn("--load", a)
        self.assertEqual(a[a.index("--platform") + 1], "linux/amd64")
        self.assertNotIn("--push", a)
        self.assertEqual(a[-1], gd.CONTEXT_DIR)

    def test_non_local_builder_is_refused(self):
        for driver, ok in (("docker", True), ("docker-container", False),
                           ("cloud", False), ("remote", False)):
            with self.subTest(driver=driver):
                runner = FakeRunner({("buildx", "inspect"): proc(
                    0, f"Name: default\nDriver:        {driver}\n".encode())})
                if ok:
                    self.assertEqual(gd.check_local_builder(envi(), runner=runner), "docker")
                else:
                    with self.assertRaises(gd.DockerProblem) as ctx:
                        gd.check_local_builder(envi(), runner=runner)
                    self.assertEqual(ctx.exception.code, "builder-not-local")

    def test_build_context_is_only_the_fixed_files(self):
        on_disk = sorted(os.listdir(gd.CONTEXT_DIR))
        self.assertEqual(on_disk, sorted(gd.CONTEXT_FILES))
        with open(os.path.join(gd.CONTEXT_DIR, ".dockerignore")) as fh:
            ignore = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        self.assertEqual(ignore[0], "*")

    def test_image_tag_follows_the_context(self):
        self.assertTrue(gd.image_ref().startswith(f"{gd.IMAGE_REPO}:{gd.GHIDRA_VERSION}-"))
        self.assertNotIn("latest", gd.image_ref())


class TestImageState(unittest.TestCase):
    def labels(self, **over):
        labels = {
            "org.mws.ghidra.version": gd.GHIDRA_VERSION,
            "org.mws.ghidra.zip-sha256": gd.GHIDRA_ZIP_SHA256,
            "org.mws.script.sha256": gd.script_sha256(),
            "org.mws.entry.sha256": gd.entry_sha256(),
            "org.mws.context": gd.context_digest(),
        }
        labels.update(over)
        return labels

    def state(self, labels, arch="arm64", ls=b""):
        info = {"Id": "sha256:" + "1" * 64, "Architecture": arch, "Os": "linux",
                "Config": {"Labels": labels}}
        runner = FakeRunner({("image", "inspect"): proc(0, json.dumps(info).encode()),
                             ("image", "ls"): proc(0, ls)})
        return gd.image_state(envi(), runner=runner)["state"]

    def test_ready_only_when_every_label_matches(self):
        self.assertEqual(self.state(self.labels()), "ready")
        self.assertEqual(self.state(self.labels(**{"org.mws.script.sha256": "0" * 64})), "outdated")
        self.assertEqual(self.state(self.labels(**{"org.mws.ghidra.version": "11.0"})), "outdated")
        self.assertEqual(self.state(self.labels(), arch="amd64"), "outdated")

    def test_missing_and_outdated(self):
        gone = proc(1, b"", b"Error: No such image: mws-ghidra-static:x")
        runner = FakeRunner({("image", "inspect"): gone, ("image", "ls"): proc(0, b"")})
        self.assertEqual(gd.image_state(envi(), runner=runner)["state"], "missing")
        runner = FakeRunner({("image", "inspect"): gone,
                             ("image", "ls"): proc(0, b"mws-ghidra-static:old\n")})
        self.assertEqual(gd.image_state(envi(), runner=runner)["state"], "outdated")

    def test_a_failed_query_is_unknown_not_missing(self):
        """接続が切れただけで「準備が必要」と案内しない。"""
        runner = FakeRunner({("image", "inspect"): proc(1, b"", b"error during connect")})
        self.assertEqual(gd.image_state(envi(), runner=runner)["state"], "unknown")
        runner = FakeRunner({("image", "inspect"): proc(1, b"", b"No such image: x"),
                             ("image", "ls"): proc(1, b"", b"error during connect")})
        self.assertEqual(gd.image_state(envi(), runner=runner)["state"], "unknown")


class TestCleanup(unittest.TestCase):
    def test_only_owned_containers_are_removed(self):
        runner = FakeRunner({
            ("ps",): proc(0, b"a" * 64 + b"\told0000old00000\n" + b"b" * 64
                          + b"\t\nnot-an-id\tx\n"),
            ("rm",): proc(0),
        })
        n = gd.remove_owned(envi(), OWNER, runner=runner)
        self.assertEqual(n, 2)
        ps = runner.calls[0][0]
        self.assertIn(f"label={gd.LABEL_APP}={gd.LABEL_APP_VALUE}", ps)
        self.assertIn(f"label={gd.LABEL_OWNER}={OWNER}", ps)
        rm = runner.calls[1][0]
        self.assertEqual(rm[1:3], ["rm", "-f"])
        self.assertEqual(rm[3:], ["a" * 64, "b" * 64])
        for argv, _ in runner.calls:
            self.assertNotIn("prune", argv)

    def test_containers_of_the_current_session_are_kept(self):
        """回収が遅れて、今回の起動で始めたコンテナと並んでも、それは消さない。"""
        runner = FakeRunner({
            ("ps",): proc(0, b"a" * 64 + b"\t" + SESSION.encode() + b"\n"
                          + b"b" * 64 + b"\t9999888877776666\n"),
            ("rm",): proc(0),
        })
        n = gd.remove_owned(envi(), OWNER, keep_session=SESSION, runner=runner)
        self.assertEqual(n, 1)
        self.assertEqual(runner.calls[-1][0][3:], ["b" * 64])

    def test_a_failed_listing_is_not_an_empty_one(self):
        """docker ps の失敗を「取り残しなし」と取り違えない。"""
        runner = FakeRunner({("ps",): proc(1, b"", b"error during connect: EOF")})
        with self.assertRaises(gd.DockerProblem):
            gd.owned_containers(envi(), OWNER, runner=runner)
        with self.assertRaises(gd.DockerProblem):
            gd.remove_owned(envi(), OWNER, runner=runner)

        def slow(argv, **kw):
            raise subprocess.TimeoutExpired(argv, 1)
        with self.assertRaises(gd.DockerProblem):
            gd.owned_containers(envi(), OWNER, runner=slow)

    def test_a_failed_removal_is_reported(self):
        runner = FakeRunner({("ps",): proc(0, b"a" * 64 + b"\told0000old00000\n"),
                             ("rm",): proc(1, b"", b"Cannot connect to the Docker daemon")})
        with self.assertRaises(gd.DockerProblem):
            gd.remove_owned(envi(), OWNER, runner=runner)

    def test_container_state_separates_absent_from_unknown(self):
        cases = [
            (proc(0, b"abc\n"), "present"),
            (proc(1, b"", b"Error: No such container: mws-ghidra-x"), "absent"),
            (proc(1, b"", b"error during connect: connection reset"), None),
            (proc(1, b"", b""), None),
        ]
        for result, expected in cases:
            with self.subTest(expected=expected):
                runner = FakeRunner({("container", "inspect"): result})
                self.assertEqual(gd.container_state(envi(), "mws-ghidra-x", runner=runner),
                                 expected)

        def slow(argv, **kw):
            raise subprocess.TimeoutExpired(argv, 1)
        self.assertIsNone(gd.container_state(envi(), "mws-ghidra-x", runner=slow))

    def test_stop_targets_only_the_named_job(self):
        runner = FakeRunner({("kill",): proc(0), ("rm",): proc(0)})
        gd.stop_container(envi(), JOB, runner=runner)
        self.assertEqual([c[0][1:] for c in runner.calls],
                         [["kill", gd.NAME_PREFIX + JOB], ["rm", "-f", gd.NAME_PREFIX + JOB]])

    def test_reason_code_is_the_only_text_taken_from_stderr(self):
        self.assertEqual(gd.reason_code(b"noise\nMWS-REASON: not-gzf rc=1\n"), "not-gzf")
        self.assertIsNone(gd.reason_code(b"Exception: <script>alert(1)</script>"))
        self.assertIsNone(gd.reason_code(b"MWS-REASON: ../../etc"))


PY = sys.executable


class TestRunProcess(unittest.TestCase):
    def run_py(self, code, **kw):
        base = dict(deadline=time.monotonic() + 10, cancel=threading.Event(),
                    max_stdout=1024 * 1024, max_stderr=1024)
        base.update(kw)
        return gd.run_process([PY, "-c", code], dict(os.environ), **base)

    def test_pipes_are_closed_afterwards(self):
        """止めた場合も含め、記述子が残り続けないこと。

        閉じ忘れても、ガベージコレクタがいずれ閉じるので記述子の数だけでは
        見えにくい。閉じ忘れを知らせる ResourceWarning が出ないことで確かめる。
        """
        import gc
        import warnings
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            for _ in range(3):
                self.run_py("print(1)")
                self.run_py("import time; time.sleep(30)", deadline=time.monotonic() + 0.2)
            gc.collect()
        leaks = [w for w in caught if issubclass(w.category, ResourceWarning)]
        self.assertEqual(leaks, [], [str(w.message) for w in leaks])

    def test_normal_output_is_captured(self):
        r = self.run_py("import sys; sys.stdout.write('{}'); sys.stderr.write('e')")
        self.assertEqual((r.returncode, r.stdout, r.stderr), (0, b"{}", b"e"))

    def test_deadline_stops_the_process_and_calls_on_stop_first(self):
        order = []
        r = self.run_py("import time; time.sleep(30)",
                        deadline=time.monotonic() + 0.5, on_stop=lambda: order.append("stop"))
        self.assertTrue(r.timed_out)
        self.assertEqual(order, ["stop"])
        self.assertLess(r.seconds, 15)

    def test_cancel_stops_the_process(self):
        cancel = threading.Event()
        threading.Timer(0.3, cancel.set).start()
        r = self.run_py("import time; time.sleep(30)", cancel=cancel)
        self.assertTrue(r.cancelled)

    def test_stdout_over_the_limit_is_cut(self):
        r = self.run_py("import sys,time\nwhile True: sys.stdout.write('x'*65536); sys.stdout.flush()",
                        max_stdout=100_000)
        self.assertEqual(r.overflow, "stdout")
        self.assertLessEqual(len(r.stdout), 100_000)

    def test_stderr_over_the_limit_is_cut(self):
        r = self.run_py("import sys\nwhile True: sys.stderr.write('y'*4096); sys.stderr.flush()",
                        max_stderr=10_000)
        self.assertEqual(r.overflow, "stderr")


class FakeDocker:
    """JobManager に渡す偽物一式。"""

    def __init__(self, *, result=None, image="ready", problem=None):
        self.result = result
        self.image = image
        self.problem = problem
        self.argv = None
        self.stopped = []
        self.removed = 0

    def resolver(self):
        if self.problem:
            raise gd.DockerProblem(self.problem)
        return envi()

    def image_state(self, _envi):
        return {"state": self.image, "ref": gd.image_ref(), "id": "sha256:" + "2" * 64,
                "arch": "arm64"}

    def run_process(self, argv, env, **kw):
        self.argv = argv
        self.kw = kw
        r = self.result
        if callable(r):
            r = r(kw)
        return r

    def stop(self, _envi, job_id):
        self.stopped.append(job_id)

    def remove_owned(self, _envi, owner, keep_session=None):
        self.removed += 1
        self.kept = keep_session
        return 3


class TestJobManager(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.saved = []

    def manager(self, fake, uid=501):
        return jobs.JobManager(
            os.path.join(self.tmp, "jobs"), OWNER, sink=self.saved.append,
            resolver=fake.resolver, image_state=fake.image_state,
            run_process=fake.run_process, stop_container=fake.stop,
            remove_owned=fake.remove_owned, check_builder=lambda e: "docker",
            uid=uid, gid=20)

    def start(self, m, sha=fx.PROGRAM_SHA, origin=None):
        job = m.reserve("analyze", origin or {"kind": "upload", "name": "x.gzf"})
        d = m.make_input_dir(job)
        with open(os.path.join(d, "input.gzf"), "wb") as fh:
            fh.write(b"x")
        m.start_analysis(job, sha, 1)
        m.threads[job.id].join(10)
        return job

    def test_success_saves_a_lesson_and_removes_the_work_data(self):
        fake = FakeDocker(result=gd.RunResult(0, fx.facts_bytes(), b"", seconds=1.0))
        m = self.manager(fake)
        job = self.start(m)
        self.assertEqual(job.state, "done", job.error)
        self.assertEqual(self.saved[0]["id"], job.lesson_id)
        self.assertFalse(os.path.exists(m.job_dir(job)))
        self.assertEqual(fake.kw["max_stdout"], gd.MAX_STDOUT)
        self.assertLessEqual(fake.kw["deadline"] - time.monotonic(), gd.RUN_DEADLINE)

    def test_the_file_name_never_reaches_the_command(self):
        fake = FakeDocker(result=gd.RunResult(0, fx.facts_bytes(), b""))
        m = self.manager(fake)
        evil = "$(touch /tmp/pwned); `id` | sh -c 'x' && ExtractStaticFacts.java"
        self.start(m, origin={"kind": "upload", "name": evil})
        self.assertNotIn(evil, " ".join(fake.argv))
        for part in ("$(", "`", "|", "&&"):
            self.assertFalse(any(part in a for a in fake.argv), part)

    def test_container_failures_become_fixed_codes(self):
        cases = [
            (b"MWS-REASON: version-unsupported rc=1\nStack trace with /Users/me", "version-unsupported"),
            (b"MWS-REASON: something-new rc=1", "container-failed"),
            (b"raw java exception text", "container-failed"),
        ]
        for err, code in cases:
            with self.subTest(code=code):
                fake = FakeDocker(result=gd.RunResult(3, b"", err))
                job = self.start(self.manager(fake))
                self.assertEqual(job.error, code)
                body = json.dumps(job.public())
                self.assertNotIn("Stack trace", body)
                self.assertNotIn("/Users/me", body)
                self.assertNotIn("raw java", body)

    def test_bad_output_is_not_adopted(self):
        for out, code in ((b"{", "output-invalid"),
                          (fx.facts_bytes(sha="00" * 32), "hash-mismatch")):
            with self.subTest(code=code):
                fake = FakeDocker(result=gd.RunResult(0, out, b""))
                job = self.start(self.manager(fake))
                self.assertEqual(job.error, code)
                self.assertEqual(self.saved, [])

    def test_timeout_and_overflow_stop_the_container(self):
        for result, code in ((gd.RunResult(None, timed_out=True), "timeout"),
                             (gd.RunResult(None, overflow="stdout"), "output-too-large"),
                             (gd.RunResult(None, cancelled=True), "cancelled")):
            with self.subTest(code=code):
                fake = FakeDocker(result=result)
                m = self.manager(fake)
                job = self.start(m)
                self.assertEqual(job.error, code)
                self.assertIn(job.id, fake.stopped)
                self.assertFalse(os.path.exists(m.job_dir(job)))

    def test_cancel_reaches_the_runner(self):
        started = threading.Event()

        def slow(kw):
            started.set()
            kw["cancel"].wait(5)
            return gd.RunResult(None, cancelled=kw["cancel"].is_set())
        fake = FakeDocker(result=slow)
        m = self.manager(fake)
        job = m.reserve("analyze", {})
        m.make_input_dir(job)
        m.start_analysis(job, fx.PROGRAM_SHA, 1)
        started.wait(5)
        self.assertTrue(m.cancel(job.id))
        m.threads[job.id].join(5)
        self.assertEqual(job.state, "cancelled")
        self.assertFalse(m.cancel(job.id), "a finished job cannot be cancelled again")

    def test_only_one_job_at_a_time(self):
        m = self.manager(FakeDocker())
        job = m.reserve("analyze", {})
        with self.assertRaises(jobs.Busy):
            m.reserve("analyze", {})
        with self.assertRaises(jobs.Busy):
            m.reserve("prepare")
        m.fail(job, "cancelled")
        m.reserve("analyze", {})

    def test_no_questions_is_a_reasoned_failure(self):
        doc = fx.facts_doc(stringRefs=[], calls=[], externals=[])
        doc["functions"][1].update(thunk=False, thunkTarget=None)
        fake = FakeDocker(result=gd.RunResult(0, json.dumps(doc).encode(), b""))
        job = self.start(self.manager(fake))
        self.assertEqual(job.error, "no-questions")
        self.assertTrue(job.public()["error"]["reasons"])

    def test_root_is_refused(self):
        fake = FakeDocker(result=gd.RunResult(0, fx.facts_bytes(), b""))
        job = self.start(self.manager(fake, uid=0))
        self.assertEqual(job.error, "root-refused")
        self.assertIsNone(fake.argv)

    def test_image_must_be_ready(self):
        for image, code in (("missing", "image-missing"), ("outdated", "image-outdated"),
                            ("unknown", "docker-unavailable")):
            fake = FakeDocker(image=image)
            job = self.start(self.manager(fake))
            self.assertEqual(job.error, code)
            self.assertIsNone(fake.argv)

    def test_recover_removes_leftovers_and_owned_containers(self):
        fake = FakeDocker()
        m = self.manager(fake)
        stale = os.path.join(m.root, "a" * 32, "input")
        os.makedirs(stale)
        other = os.path.join(m.root, "keep-me")
        os.makedirs(other)
        out = m.recover()
        self.assertEqual(out, {"dirs": 1, "containers": 3})
        self.assertFalse(os.path.exists(os.path.dirname(stale)))
        self.assertTrue(os.path.exists(other), "only job-shaped names are removed")

    def test_recovery_keeps_this_session_and_runs_before_jobs(self):
        fake = FakeDocker(result=gd.RunResult(0, fx.facts_bytes(), b""))
        m = self.manager(fake)
        m.recover_containers()
        self.assertEqual(fake.kept, m.session)
        self.start(m)
        self.assertIn(f"{gd.LABEL_SESSION}={m.session}", fake.argv)
        with self.assertRaises(RuntimeError):
            m.recover_dirs()   # 受付を始めたあとに呼ぶと、今回の入力を消しかねない

    def test_recover_without_docker_does_not_fail(self):
        m = self.manager(FakeDocker(problem="docker-missing"))
        self.assertEqual(m.recover()["containers"], 0)

    def test_public_view_has_no_paths(self):
        fake = FakeDocker(result=gd.RunResult(0, fx.facts_bytes(), b""))
        m = self.manager(fake)
        job = self.start(m)
        self.assertNotIn(self.tmp, json.dumps(job.public()))

    def test_every_error_code_has_a_message(self):
        codes = set(jobs.MESSAGES)
        for code in ("docker-missing", "docker-remote", "not-gzf", "timeout", "cancelled",
                     "image-missing", "no-questions", "password-required", "zip-aes"):
            self.assertIn(code, codes)
        self.assertEqual(jobs.message("nonsense"), jobs.MESSAGES["internal"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
