"""対象を実行する経路が無いことを、固定ファイルの中身から見張るテスト。

このテストは人の監査の代わりではなく、監査した状態から黙って崩れないための
見張りである。抽出スクリプト・エントリポイント・Dockerfile・Python 側の
起動経路を読み、禁止した API や引数が入っていないこと、必須の引数が
そろっていることを確かめる。
"""

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ghidra_docker as gd  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
IMAGE = os.path.join(REPO, "ghidra", "image")


def read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as fh:
        return fh.read()


def code_only(text: str, comment: str) -> str:
    """コメント行を除いた本文。説明文の中の単語で誤検知しないように。"""
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(comment) or stripped.startswith("*") or stripped.startswith("/*"):
            continue
        out.append(line.split(" " + comment, 1)[0] if comment == "#" else line)
    return "\n".join(out)


class TestExtractionScript(unittest.TestCase):
    SCRIPT = code_only(read("ghidra", "image", "ExtractStaticFacts.java"), "//")

    #: 対象の実行・エミュレーション・デバッガ・元検体の書き出し・自動解析・
    #: Program への書き込み・外部プログラムの起動につながる API。
    BANNED = (
        "Emulator", "PcodeEmulator", "EmulatorHelper", "Pcode", "Debugger", "TraceRmi",
        "ghidra.debug", "ghidra.trace", "ProcessBuilder", "Runtime", ".exec(",
        "Exporter", "OriginalFile", "BinaryExporter", "GzfExporter",
        "runScript", "analyzeAll", "AutoAnalysisManager", "analyzeChanges",
        "startTransaction", "setBytes", "createFunction", "clearListing", "save(",
        "getMemory", ".getBytes()", "DecompInterface", "System.load", "loadLibrary",
        "ScriptEngine", "Class.forName", "URLClassLoader", "Socket", "URL(",
        "HttpClient", "Files.delete", "deleteIfExists",
    )

    def test_no_execution_emulation_debugger_or_export_api(self):
        for token in self.BANNED:
            with self.subTest(token=token):
                self.assertNotIn(token, self.SCRIPT)

    def test_reads_only_the_listed_records(self):
        for needed in ("getFunctions(", "getExternalFunctions(", "DefinedStringIterator",
                       "getReferencesTo(", "getFlowType(", "isComputed("):
            self.assertIn(needed, self.SCRIPT)

    def test_references_are_limited_to_the_emitted_records(self):
        """一覧を打ち切っても、一覧の外を参照する記録を書かない（#6 の見張り）。"""
        s = self.SCRIPT
        self.assertIn("Set<String> emitted", s)
        self.assertIn("emitted.contains(functionId(fn))", s)      # 文字列参照の参照元
        self.assertIn("emitted.contains(targetId)", s)             # 呼び出し先
        self.assertIn("emitted.contains(functionId(thunked))", s)  # thunk の行き先
        self.assertIn("thunkTargets.get(targetId)", s)             # resolvedTarget は同じ値
        self.assertIn("new LinkedHashSet<>()", s)                  # 打ち切りの印は重複させない
        # 書き出す前に集合を確定している（関数を書き出す前に外部関数を集めている）。
        self.assertLess(s.index("allExternals"), s.index('j.key("functions")'))

    def test_clipping_does_not_split_surrogate_pairs(self):
        self.assertIn("Character.isHighSurrogate", self.SCRIPT)

    def test_versions_match_the_python_side(self):
        self.assertIn(f'SCRIPT_VERSION = "{gd.SCRIPT_VERSION}"', self.SCRIPT)
        self.assertIn('SCHEMA = "mws-ghidra-static/1"', self.SCRIPT)

    def test_output_is_written_atomically_without_following_links(self):
        self.assertIn("CREATE_NEW", self.SCRIPT)
        self.assertIn("NOFOLLOW_LINKS", self.SCRIPT)
        self.assertIn("ATOMIC_MOVE", self.SCRIPT)


class TestEntrypoint(unittest.TestCase):
    RAW = read("ghidra", "image", "run-extract.sh")
    SH = code_only(RAW, "#")

    def test_fixed_headless_arguments(self):
        for flag in ("-import \"$COPY\"", "-loader GzfLoader", "-noanalysis", "-readOnly",
                     "-deleteProject", "-scriptPath /opt/mws/scripts",
                     "-postScript ExtractStaticFacts.java"):
            with self.subTest(flag=flag):
                self.assertIn(flag, self.SH)
        self.assertEqual(self.SH.count("-postScript"), 1)

    def test_nothing_else_is_run(self):
        for banned in ("-preScript", "-process", "eval ", "exec ", "$@", "$*", "$1",
                       "curl", "wget", "java -jar", "gdb", "qemu", "chmod +x", "./",
                       "-analysisTimeoutPerFile", "-overwrite", "-commit"):
            with self.subTest(banned=banned):
                self.assertNotIn(banned, self.SH)

    def test_refuses_arguments_and_symlinked_input(self):
        self.assertIn('if [ "$#" -ne 0 ]', self.SH)
        self.assertIn('[ -L "$IN" ]', self.SH)

    def test_success_requires_ghidra_to_exit_cleanly(self):
        self.assertIn('if [ "$rc" -eq 0 ] && [ -f "$OUT" ]', self.SH)

    def test_only_the_json_goes_to_stdout(self):
        self.assertIn('>"$WORK/headless.out" 2>&1', self.SH)
        self.assertEqual(len(re.findall(r'\bcat "\$OUT"', self.SH)), 1)


class TestDockerfile(unittest.TestCase):
    DF = read("ghidra", "image", "Dockerfile")

    def test_everything_is_pinned(self):
        froms = re.findall(r"^FROM\s+(\S+)", self.DF, re.M)
        self.assertEqual(froms, [gd.BASE_IMAGE])
        self.assertRegex(froms[0], r"@sha256:[0-9a-f]{64}$")
        self.assertNotIn(":latest", self.DF)
        self.assertIn(f"--checksum=sha256:{gd.GHIDRA_ZIP_SHA256}", self.DF)
        self.assertIn(gd.GHIDRA_ZIP, self.DF)
        self.assertIn(f'org.mws.ghidra.version="{gd.GHIDRA_VERSION}"', self.DF)

    def test_no_unpinned_downloads_or_package_installs(self):
        body = code_only(self.DF, "#")
        for banned in ("apt-get", "apk add", "pip install", "curl", "wget", "| sh", "npm "):
            self.assertNotIn(banned, body)

    def test_runs_as_non_root_with_the_fixed_entrypoint(self):
        self.assertRegex(self.DF, r"(?m)^USER 65532:65532$")
        self.assertIn('ENTRYPOINT ["/opt/mws/bin/run-extract.sh"]', self.DF)
        self.assertNotIn("CMD", code_only(self.DF, "#"))


class TestPythonLaunchPath(unittest.TestCase):
    MODULES = ("ghidra_docker.py", "ghidra_jobs.py", "ghidra_api.py", "ghidra_intake.py",
               "gzf.py", "static_facts.py", "static_lesson.py")

    def test_no_shell_eval_or_extractall(self):
        for name in self.MODULES:
            src = code_only(read("backend", name), "#")
            for banned in ("shell=True", "os.system", "os.popen", "eval(", "exec(",
                           "pickle", "extractall", "--privileged", "marshal"):
                with self.subTest(module=name, banned=banned):
                    self.assertNotIn(banned, src)

    def test_container_is_started_only_from_the_fixed_builder(self):
        uses = [n for n in self.MODULES if "run_argv(" in read("backend", n)]
        self.assertEqual(sorted(uses), ["ghidra_docker.py", "ghidra_jobs.py"])
        api = code_only(read("backend", "ghidra_api.py"), "#")
        for banned in ("subprocess", "Popen", "run_process", "build_argv"):
            self.assertNotIn(banned, api)


class TestRepositoryHygiene(unittest.TestCase):
    GITIGNORE = read(".gitignore")

    def test_real_data_protection_is_kept(self):
        lines = [l.strip() for l in self.GITIGNORE.splitlines()]
        for rule in ("*.gzf", "*.vir", "samples/", ".mws-state/", ".local-validation/",
                     "docs/Ghidra静的解析教材_Docker連携_実装指示書.md"):
            self.assertIn(rule, lines)

    def test_only_the_audited_sample_is_excepted(self):
        exceptions = [l.strip() for l in self.GITIGNORE.splitlines()
                      if l.strip().startswith("!")]
        self.assertTrue(all(e == "!ghidra/sample/termmines.gzf" for e in exceptions),
                        exceptions)

    def test_public_docs_do_not_link_the_private_instructions(self):
        for name in ("README.md", "THIRD_PARTY_NOTICES.md"):
            path = os.path.join(REPO, name)
            if os.path.exists(path):
                self.assertNotIn("Docker連携_実装指示書", read(name))


if __name__ == "__main__":
    unittest.main(verbosity=2)
