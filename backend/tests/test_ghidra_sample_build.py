"""開発者用のサンプル作成（ghidra/sample/build_sample.py）のテスト。

Docker は使わない。接続先の確認・固定引数・上限・停止処理が、アプリ本体と
同じ部品で効いていることを確かめる。
"""

import os
import sys
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "ghidra", "sample"))

import build_sample as bs  # noqa: E402
import ghidra_docker as gd  # noqa: E402

ENV = gd.Environment("/usr/bin/docker", "unix:///tmp/x.sock",
                     {"DOCKER_HOST": "unix:///tmp/x.sock"}, "linux", "arm64", "28")
RID = "0123456789abcdef0123456789abcdef"


def flags(argv, name):
    return [argv[i + 1] for i, a in enumerate(argv) if a == name]


class TestSampleBuild(unittest.TestCase):
    def test_remote_docker_is_refused_before_anything_runs(self):
        called = []

        def remote():
            raise gd.DockerProblem("docker-remote")
        rc = bs.main(resolver=remote, run_process=lambda *a, **k: called.append(a))
        self.assertEqual(rc, 2)
        self.assertEqual(called, [])

    def test_compile_container_is_limited(self):
        a = bs.compile_argv(ENV, run_id=RID, owner="0" * 16, src_dir="/w/src")
        self.assertEqual(flags(a, "--memory"), [bs.COMPILE_LIMITS["memory"]])
        self.assertEqual(flags(a, "--memory-swap"), [bs.COMPILE_LIMITS["memory"]])
        self.assertEqual(flags(a, "--pids-limit"), [str(bs.COMPILE_LIMITS["pids"])])
        self.assertTrue(flags(a, "--cpus"))
        self.assertIn("--cap-drop=ALL", a)
        self.assertIn("--security-opt=no-new-privileges", a)
        self.assertIn(gd.BASE_IMAGE, a, "the base image is pinned by digest")
        self.assertIn("type=bind,source=/w/src,target=/src,readonly", flags(a, "--mount"))
        self.assertEqual(a[-1], bs.COMPILE_SCRIPT, "the command is the fixed script")

    def test_compile_container_gets_no_writable_host_directory(self):
        """root のコンテナにホストの領域を書かせない（Linux で root 所有のファイルが残る）。"""
        a = bs.compile_argv(ENV, run_id=RID, owner="0" * 16, src_dir="/w/src")
        self.assertEqual(flags(a, "--mount"), ["type=bind,source=/w/src,target=/src,readonly"])
        self.assertFalse(flags(a, "-v") or flags(a, "--volume"))
        self.assertTrue(bs.COMPILE_SCRIPT.startswith("exec 3>&1 1>&2; "),
                        "only the tar stream may reach stdout")
        self.assertTrue(bs.COMPILE_SCRIPT.endswith("tar -C /work -cf - termmines toolchain.txt >&3"))

    def tar(self, entries):
        import io
        import tarfile
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            for name, data, kind in entries:
                info = tarfile.TarInfo(name)
                if kind == "sym":
                    info.type = tarfile.SYMTYPE
                    info.linkname = "/etc/passwd"
                    tf.addfile(info)
                else:
                    info.size = len(data)
                    info.uid = 0            # コンテナの root が作ったもの
                    info.mode = 0o755
                    tf.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    def test_compile_output_is_written_as_the_host_user_without_exec_bits(self):
        import tempfile
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d, True)
        bs.unpack_compile_output(self.tar([("termmines", b"\x7fELF..", "reg"),
                                           ("toolchain.txt", b"gcc 13\n", "reg")]), d)
        for name in ("termmines", "toolchain.txt"):
            st = os.stat(os.path.join(d, name))
            self.assertEqual(st.st_uid, os.getuid(), "owned by the host user, not root")
            self.assertEqual(st.st_mode & 0o777, 0o644, "no exec bits even if the tar said 0755")

    def test_unexpected_compile_output_is_refused(self):
        import tempfile
        cases = [
            [("termmines", b"x", "reg")],                                         # 足りない
            [("termmines", b"x", "reg"), ("toolchain.txt", b"y", "reg"), ("extra", b"z", "reg")],
            [("../termmines", b"x", "reg"), ("toolchain.txt", b"y", "reg")],     # 名前が違う
            [("termmines", b"", "sym"), ("toolchain.txt", b"y", "reg")],          # リンク
            [("termmines", b"x" * (bs.COMPILE_OUTPUTS["termmines"] + 1), "reg"),
             ("toolchain.txt", b"y", "reg")],                                    # 大きすぎる
        ]
        for entries in cases:
            with self.subTest(entries=[e[0] for e in entries]):
                d = tempfile.mkdtemp()
                self.addCleanup(__import__("shutil").rmtree, d, True)
                with self.assertRaises(bs.BuildError):
                    bs.unpack_compile_output(self.tar(entries), d)
        with self.assertRaises(bs.BuildError):
            bs.unpack_compile_output(b"not a tar", tempfile.mkdtemp())

    def test_analysis_container_matches_the_app_isolation(self):
        a = bs.analyze_argv(ENV, run_id=RID, owner="0" * 16, bin_dir="/w/bin",
                            out_dir="/w/out", uid=501, gid=20)
        for flag in ("--network=none", "--read-only", "--cap-drop=ALL",
                     "--security-opt=no-new-privileges", "--pull=never", "--log-driver=none"):
            self.assertIn(flag, a)
        self.assertEqual(flags(a, "--memory"), [gd.LIMITS["memory"]])
        self.assertEqual(flags(a, "--pids-limit"), [str(gd.LIMITS["pids"])])
        self.assertEqual(flags(a, "--user"), ["501:20"])
        mounts = flags(a, "--mount")
        self.assertIn("type=bind,source=/w/bin,target=/in,readonly", mounts)
        self.assertTrue(any(m.endswith("target=/tools,readonly") for m in mounts))
        self.assertNotIn("--privileged", a)
        self.assertIn(gd.image_ref(), a)
        with self.assertRaises(bs.BuildError):
            bs.analyze_argv(ENV, run_id=RID, owner="0" * 16, bin_dir="/w/bin",
                            out_dir="/w/out", uid=0, gid=0)
        with self.assertRaises(bs.BuildError):
            bs.analyze_argv(ENV, run_id=RID, owner="0" * 16, bin_dir="/w,x",
                            out_dir="/w/out", uid=501, gid=20)

    def test_labels_are_not_the_apps_so_recovery_leaves_them_alone(self):
        a = bs.compile_argv(ENV, run_id=RID, owner="0" * 16, src_dir="/w/s")
        self.assertIn(f"{gd.LABEL_APP}={bs.LABEL_VALUE}", flags(a, "--label"))
        self.assertNotEqual(bs.LABEL_VALUE, gd.LABEL_APP_VALUE)

    def test_timeout_and_cancel_stop_the_container(self):
        stopped = []
        orig = gd.stop_container
        gd.stop_container = lambda envi, rid: stopped.append(rid)
        self.addCleanup(setattr, gd, "stop_container", orig)
        for result in (gd.RunResult(None, timed_out=True), gd.RunResult(None, cancelled=True)):
            seen = {}

            def fake(argv, env, **kw):
                seen.update(kw)
                kw["on_stop"]()
                return result
            with self.assertRaises(bs.BuildError):
                bs.run(ENV, ["docker"], RID, 60, threading.Event(), run_process=fake)
            self.assertIs(seen["deadline"] > 0, True)
            self.assertIn(RID, stopped)
            self.assertEqual(seen.get("max_stdout"), 4 * 1024**2)

    def test_commands_use_the_pinned_local_endpoint(self):
        seen = {}

        def fake(argv, env, **kw):
            seen["env"] = env
            return gd.RunResult(0)
        bs.run(ENV, ["docker"], RID, 60, threading.Event(), run_process=fake)
        self.assertEqual(seen["env"]["DOCKER_HOST"], "unix:///tmp/x.sock")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestLiveCheckJudgement(unittest.TestCase):
    """実コンテナ確認の合否。観測できなかった項目は合格にしない。"""

    def setUp(self):
        import ghidra_live_check as live
        self.judge = live.judge
        self.good = {
            "run": {"state": "done"},
            "lesson": {"questionCounts": {"string": 1, "call": 1, "external": 1}},
            "inputUnchanged": True, "jobDirRemoved": True, "inspect": "ok",
            "processObservations": 12, "unexpectedExecutables": [],
            "resources": {"memPeakMiB": 900}, "leftoverContainers": 0,
            "cancel": {"state": "cancelled", "containerObserved": True, "runningAtCancel": True,
                       "containerRemoved": True, "jobDirRemoved": True},
        }

    def test_all_observed_passes(self):
        self.assertTrue(all(v == "確認済み" for v in self.judge(self.good).values()))

    def test_no_process_observation_is_unconfirmed(self):
        report = dict(self.good, processObservations=0)
        self.assertEqual(self.judge(report)["対象が起動していない（プロセス観測）"], "未確認")

    def test_cancel_before_the_container_ran_is_unconfirmed(self):
        for change in ({"containerObserved": False}, {"runningAtCancel": False}):
            report = dict(self.good, cancel=dict(self.good["cancel"], **change))
            self.assertEqual(self.judge(report)["キャンセルで停止・削除"], "未確認")

    def test_unobserved_inspect_and_resources_are_unconfirmed(self):
        report = dict(self.good, inspect="未確認（コンテナを観測できなかった）",
                      resources="未測定（docker stats を取得できなかった）")
        checks = self.judge(report)
        self.assertEqual(checks["コンテナの設定（inspect）"], "未確認")
        self.assertEqual(checks["資源使用の実測"], "未確認")

    def test_failed_docker_queries_are_unconfirmed_not_passed(self):
        """問い合わせの失敗を「削除済み」「取り残しなし」と扱わない。"""
        report = dict(self.good, leftoverContainers="未確認（一覧を取得できなかった）",
                      cancel=dict(self.good["cancel"], containerRemoved=None))
        checks = self.judge(report)
        self.assertEqual(checks["コンテナの取り残しなし"], "未確認")
        self.assertEqual(checks["キャンセルで停止・削除"], "未確認")
        report = dict(self.good, cancel=dict(self.good["cancel"], containerRemoved=False))
        self.assertEqual(self.judge(report)["キャンセルで停止・削除"], "不合格")

    def test_a_missing_question_kind_fails(self):
        report = dict(self.good, lesson={"questionCounts": {"string": 2, "call": 0, "external": 1}})
        self.assertEqual(self.judge(report)["教材の完成（3 種類の設問）"], "不合格")


class TestLiveCheckProcessAllowlist(unittest.TestCase):
    """プロセス観測の許可一覧が、固定の処理と食い違わないこと。"""

    def setUp(self):
        import ghidra_live_check as live
        self.live = live

    def test_the_normal_extraction_processes_are_not_flagged(self):
        # エントリポイントが入力を /tmp へ写している最中に観測した場合も正常。
        seen = ["/bin/sh", "/opt/zip2learn/bin/run-extract.sh", "cp", "/usr/bin/cp", "mkdir",
                "/opt/ghidra/support/analyzeHeadless", "/opt/ghidra/support/launch.sh",
                "/opt/java/openjdk/bin/java", "bash", "grep", "tail", "cat"]
        self.assertEqual(self.live.unexpected_executables(seen), [])

    def test_target_like_processes_are_flagged(self):
        seen = ["/input/input.gzf", "/tmp/zip2learn/in/input.gzf", "/tmp/x/termmines", "termmines",
                "gdb", "qemu-x86_64", "/opt/java/openjdk/bin/java"]
        self.assertEqual(self.live.unexpected_executables(seen),
                         sorted(set(seen) - {"/opt/java/openjdk/bin/java"}))

    def test_every_command_in_the_entrypoint_is_allowed(self):
        """エントリポイントに処理を足したのに許可一覧へ足し忘れる、を防ぐ。"""
        import re
        with open(os.path.join(REPO, "ghidra", "image", "run-extract.sh"), encoding="utf-8") as fh:
            # 引用符の中（grep のパターンや文言）はコマンドではないので取り除く。
            lines = [re.sub(r'"[^"]*"|\'[^\']*\'', '""', l.split("#", 1)[0]) for l in fh]
        builtins = {"if", "then", "fi", "elif", "else", "set", "umask", "echo", "exit", "export",
                    "reason", "return", "for", "do", "done", "case", "esac", "in", "local", "[",
                    "]", "true", "false", "shift", "printf"}
        commands = set()
        for line in lines:
            for part in re.split(r"\|\||&&|\||;|\$\(|\bthen\b|\belse\b|\bif\b|\{", line):
                word = part.strip().split(" ", 1)[0]
                if re.fullmatch(r"[a-z][a-z0-9_.-]*", word) and word not in builtins:
                    commands.add(word)
        commands.discard("reason()")
        missing = sorted(c for c in commands if c not in self.live.ALLOWED_EXE)
        self.assertEqual(missing, [], "add these to ALLOWED_EXE in ghidra_live_check.py")
        self.assertIn("cp", commands, "the input copy uses cp")
