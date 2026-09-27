"""処理イメージのエントリポイント（run-extract.sh）を、偽の Ghidra で動かすテスト。

Ghidra も Docker も使わない。イメージ内の固定パスだけを一時ディレクトリへ
置き換えた写しを /bin/sh で動かし、偽の analyzeHeadless の終わり方ごとに、
標準出力（JSON）・終了コード・理由符号を確かめる。
"""

import os
import shutil
import subprocess
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ENTRY = os.path.join(REPO, "ghidra", "image", "run-extract.sh")

# 偽の analyzeHeadless。-postScript ExtractStaticFacts.java <入力> <出力> の出力へ
# 書き、FAKE_MODE に応じて終わる。受け取った引数も記録する。
FAKE = r"""#!/bin/sh
printf '%s\n' "$@" > "$FAKE_ARGS"
out=""
seen=0
for a in "$@"; do
  if [ "$seen" = 2 ]; then out="$a"; seen=3; fi
  if [ "$seen" = 1 ]; then seen=2; fi
  if [ "$a" = "ExtractStaticFacts.java" ]; then seen=1; fi
done
case "$FAKE_MODE" in
  ok) printf '{"ok":true}' > "$out"; exit 0 ;;
  crash-after-output) printf '{"ok":true}' > "$out"; echo "java.lang.OutOfMemoryError"; exit 1 ;;
  fail-no-output) echo "No load spec found for import file"; exit 1 ;;
  zero-no-output) exit 0 ;;
  symlink-output) ln -s /etc/hosts "$out"; exit 0 ;;
esac
"""


class TestEntrypoint(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        support = os.path.join(self.tmp, "ghidra", "support")
        os.makedirs(support)
        fake = os.path.join(support, "analyzeHeadless")
        with open(fake, "w") as fh:
            fh.write(FAKE)
        os.chmod(fake, 0o755)
        os.makedirs(os.path.join(self.tmp, "input"))
        self.input = os.path.join(self.tmp, "input", "input.gzf")
        with open(self.input, "wb") as fh:
            fh.write(b"x")
        with open(ENTRY, encoding="utf-8") as fh:
            script = fh.read()
        script = script.replace("IN=/input/input.gzf", f"IN={self.input}")
        script = script.replace("WORK=/tmp/mws", f"WORK={self.tmp}/work")
        self.script = os.path.join(self.tmp, "run.sh")
        with open(self.script, "w") as fh:
            fh.write(script)

    def run_mode(self, mode, *args):
        env = {"PATH": "/usr/bin:/bin", "HOME": os.path.join(self.tmp, "home"),
               "GHIDRA_HOME": os.path.join(self.tmp, "ghidra"), "FAKE_MODE": mode,
               "FAKE_ARGS": os.path.join(self.tmp, "args.txt")}
        return subprocess.run(["/bin/sh", self.script, *args], env=env,
                               capture_output=True, timeout=30)

    def test_success_needs_exit_zero_and_output(self):
        r = self.run_mode("ok")
        self.assertEqual((r.returncode, r.stdout), (0, b'{"ok":true}'))
        self.assertEqual(r.stderr, b"")

    def test_crash_after_writing_output_is_a_failure(self):
        r = self.run_mode("crash-after-output")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, b"", "a partial success must not reach stdout")
        self.assertIn(b"MWS-REASON: out-of-memory", r.stderr)

    def test_known_failures_get_fixed_reason_codes(self):
        r = self.run_mode("fail-no-output")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(b"MWS-REASON: not-gzf", r.stderr)
        r = self.run_mode("zero-no-output")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(b"MWS-REASON: extract-failed", r.stderr)

    def test_symlinked_output_is_not_followed(self):
        r = self.run_mode("symlink-output")
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn(b"localhost", r.stdout)

    def test_ghidra_output_never_reaches_stdout(self):
        r = self.run_mode("fail-no-output")
        self.assertNotIn(b"No load spec", r.stdout + r.stderr)

    def test_arguments_are_refused(self):
        r = self.run_mode("ok", "--extra")
        self.assertEqual(r.returncode, 64)
        self.assertIn(b"MWS-REASON: bad-invocation", r.stderr)

    def test_fixed_arguments_reach_ghidra(self):
        self.run_mode("ok")
        with open(os.path.join(self.tmp, "args.txt")) as fh:
            args = fh.read().split("\n")
        for flag in ("-loader", "GzfLoader", "-noanalysis", "-readOnly", "-postScript",
                     "ExtractStaticFacts.java"):
            self.assertIn(flag, args)
        self.assertNotIn("-preScript", args)


if __name__ == "__main__":
    unittest.main(verbosity=2)
