"""build_sample.py — 開発者用。同梱サンプル termmines.gzf を作り直す。

    python3 ghidra/sample/build_sample.py

利用者は実行する必要がない（できあがった GZF をリポジトリに同梱している）。
手順の意味と記録は PROVENANCE.md にある。

アプリ本体と同じ部品（backend/ghidra_docker.py）で Docker を使う。

  * 接続先は、この PC の UNIX ソケット（Windows は名前付きパイプ）と確かめられた
    ものだけ。DOCKER_HOST や docker context がリモートを指していれば、何も
    送らずに止まる。以後のコマンドは、確かめた接続先に固定した環境で動かす。
  * 引数は固定の構造から組み、シェル文字列への連結は使わない。
  * どちらのコンテナにも、メモリ・CPU・PID 数の上限と、全体の時間制限を付ける。
    時間切れ・Ctrl+C では、名前を付けたコンテナを止めて消してから終わる。
  * ラベルはアプリの処理コンテナと別の値にする。アプリの起動時の回収が、
    作成中のサンプルのコンテナを止めることはない。

手順:
  1. 監査済みの termmines.c を、固定したハッシュで照合する。
  2. 使い捨てのコンテナ（固定 digest の Ubuntu 24.04、linux/amd64）で gcc により
     コンパイルする。パッケージの取得に通信を使うのはこの段階だけ。できた
     プログラムは起動しない。ホストに出したら実行属性を外す。
  3. アプリの処理イメージ（Ghidra 12.1.4）で、ネットワークなし・読み取り専用・
     権限を落とした状態で取り込みと自動解析を行い、GZF として書き出す。
  4. GZF を中身から確かめ、ハッシュを sample.json に、部品の版を toolchain.txt に記録する。
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import shutil
import signal
import stat
import sys
import tarfile
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "backend"))

import ghidra_docker as gd  # noqa: E402
import gzf  # noqa: E402

SRC_SHA256 = "a30710cc0ff4e1e8136ec2164c235e201a969672cf6f5a5aceea95d81d6e13d2"
TOOLS_DIR = os.path.join(HERE, "tools")
#: アプリの処理コンテナ（ghidra-static）とは別のラベル値。
LABEL_VALUE = "ghidra-sample-build"
COMPILE_DEADLINE = 20 * 60
ANALYZE_DEADLINE = 20 * 60
COMPILE_LIMITS = {"memory": "2g", "cpus": "2", "pids": 512}
MAX_ELF_BYTES = 16 * 1024**2
MAX_TEXT_BYTES = 64 * 1024

#: コンパイル用コンテナで動かす固定のコマンド。外からの値は一切埋め込まない。
#:
#: 成果物はホストの領域へ書かず、標準出力へ tar で流す。コンテナは root で動く
#: ので、bind mount へ書くと、通常の Linux の Docker Engine では root 所有の
#: ファイルになり、ホストの利用者が属性を直せない（Docker Desktop では所有者が
#: 付け替えられるので表に出ない）。標準出力で受け取り、ホスト側で検査して
#: ホストの利用者として書き出せば、どの環境でも所有権の問題が起きない。
#: 標準出力を tar だけにするため、最初にそれ以外の出力を標準エラーへ回す。
COMPILE_SCRIPT = (
    "exec 3>&1 1>&2; "
    "export DEBIAN_FRONTEND=noninteractive; "
    "apt-get update -qq; "
    "apt-get install -y -qq --no-install-recommends gcc libc6-dev libncurses-dev >/dev/null; "
    "mkdir -p /work; "
    "gcc -O0 -o /work/termmines /src/termmines.c -lncurses -lpthread; "
    "{ gcc --version | head -n 1; "
    "echo 'gcc -O0 -o termmines termmines.c -lncurses -lpthread (linux/amd64, not stripped)'; "
    "dpkg-query -W -f='${Package} ${Version} ${Architecture}\\n' "
    "gcc libc6-dev libncurses-dev libncurses6 libtinfo6 libc6; } > /work/toolchain.txt; "
    "chmod 0644 /work/termmines /work/toolchain.txt; "
    "tar -C /work -cf - termmines toolchain.txt >&3"
)
#: コンパイルの成果物として受け取るもの（名前と大きさの上限）。これ以外は受け取らない。
COMPILE_OUTPUTS = {"termmines": 16 * 1024**2, "toolchain.txt": 64 * 1024}


class BuildError(Exception):
    pass


def _safe_dir(path: str) -> str:
    if not os.path.isabs(path) or any(c in path for c in ",=\0\n"):
        raise BuildError("unsafe directory path for a bind mount")
    return path


def _labels(owner: str, run_id: str) -> list[str]:
    return ["--label", f"{gd.LABEL_APP}={LABEL_VALUE}",
            "--label", f"{gd.LABEL_OWNER}={owner}",
            "--label", f"{gd.LABEL_JOB}={run_id}"]


def compile_argv(envi: gd.Environment, *, run_id: str, owner: str,
                 src_dir: str) -> list[str]:
    """コンパイル用コンテナ。パッケージ取得のため通信は使うが、上限を付ける。

    ホストの領域は、ソースを読み取り専用で渡すだけ。成果物は標準出力で受け取る。
    """
    return [
        envi.docker, "run", "--rm",
        "--name", gd.container_name(run_id),
        *_labels(owner, run_id),
        "--platform", "linux/amd64",
        "--memory", COMPILE_LIMITS["memory"],
        "--memory-swap", COMPILE_LIMITS["memory"],
        "--cpus", COMPILE_LIMITS["cpus"],
        "--pids-limit", str(COMPILE_LIMITS["pids"]),
        "--security-opt=no-new-privileges",
        # apt と dpkg に要る権限だけを残す。
        "--cap-drop=ALL", "--cap-add=CHOWN", "--cap-add=DAC_OVERRIDE",
        "--cap-add=FOWNER", "--cap-add=SETUID", "--cap-add=SETGID",
        "--log-driver=none",
        "--stop-timeout", "5",
        "--mount", f"type=bind,source={_safe_dir(src_dir)},target=/src,readonly",
        gd.BASE_IMAGE,
        "sh", "-eu", "-c", COMPILE_SCRIPT,
    ]


def analyze_argv(envi: gd.Environment, *, run_id: str, owner: str, bin_dir: str,
                 out_dir: str, uid: int, gid: int) -> list[str]:
    """解析用コンテナ。アプリの処理コンテナと同じ隔離と上限で動かす。"""
    if uid <= 0:
        raise BuildError("refusing to run as root")
    return [
        envi.docker, "run", "--rm",
        "--name", gd.container_name(run_id),
        *_labels(owner, run_id),
        "--pull=never",
        "--network=none",
        "--user", f"{uid}:{gid}",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--read-only",
        "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={gd.LIMITS['tmp']},mode=1777",
        "--memory", gd.LIMITS["memory"],
        "--memory-swap", gd.LIMITS["memory"],
        "--cpus", gd.LIMITS["cpus"],
        "--pids-limit", str(gd.LIMITS["pids"]),
        "--ulimit", f"nofile={gd.LIMITS['nofile']}:{gd.LIMITS['nofile']}",
        "--ulimit", "core=0",
        "--log-driver=none",
        "--stop-timeout", "5",
        # Ghidra の起動部品は HOME が既にあることを前提にする。tmpfs の /tmp を使う。
        "--env", "HOME=/tmp",
        "--env", "GHIDRA_HEADLESS_JAVA_OPTIONS=-Duser.name=mws -XX:-UsePerfData",
        "--mount", f"type=bind,source={_safe_dir(bin_dir)},target=/in,readonly",
        "--mount", f"type=bind,source={_safe_dir(TOOLS_DIR)},target=/tools,readonly",
        "--mount", f"type=bind,source={_safe_dir(out_dir)},target=/out",
        "--entrypoint", "/opt/ghidra/support/analyzeHeadless",
        gd.image_ref(),
        # 一時プロジェクトの置き場所は既存でなければならない。tmpfs の /tmp を使う。
        "/tmp", "sample", "-import", "/in/termmines", "-max-cpu", "2",
        "-scriptPath", "/tools", "-postScript", "ExportGzf.java", "/out/termmines.gzf",
        "-deleteProject",
    ]


def run(envi: gd.Environment, argv: list[str], run_id: str, deadline_s: int,
        cancel: threading.Event, run_process=gd.run_process) -> gd.RunResult:
    """1 つのコンテナを、期限・キャンセル・出力上限付きで動かす。"""
    result = run_process(
        argv, envi.env, deadline=time.monotonic() + deadline_s, cancel=cancel,
        max_stdout=4 * 1024**2, max_stderr=4 * 1024**2,
        on_stop=lambda: gd.stop_container(envi, run_id),
    )
    if result.cancelled or result.timed_out or result.overflow:
        gd.stop_container(envi, run_id)
        raise BuildError("cancelled" if result.cancelled else
                         "timed out" if result.timed_out else "output over the limit")
    if result.returncode != 0:
        tail = (result.stderr + result.stdout)[-4000:].decode("utf-8", "replace")
        raise BuildError(f"container failed (exit {result.returncode}):\n{tail}")
    return result


def unpack_compile_output(data: bytes, dest_dir: str) -> None:
    """コンパイル用コンテナの標準出力（tar）から、決まった 2 つだけを書き出す。

    tar の中の名前はパスに使わない（照合にだけ使う）。通常ファイルでないもの、
    余分なもの、足りないもの、上限を超えるものは受け取らない。書き出しは
    ホストの利用者として、固定名・0644・既存ファイルは上書きしない形で行う。
    """
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
            members = tf.getmembers()
            if sorted(m.name for m in members) != sorted(COMPILE_OUTPUTS):
                raise BuildError("unexpected compile output")
            for m in members:
                limit = COMPILE_OUTPUTS[m.name]
                if not m.isreg() or not 0 < m.size <= limit:
                    raise BuildError(f"{m.name}: not a regular file of an allowed size")
                src = tf.extractfile(m)
                body = src.read(limit + 1) if src else b""
                if len(body) != m.size:
                    raise BuildError(f"{m.name}: size mismatch")
                fd = os.open(os.path.join(dest_dir, m.name),
                             os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
                with os.fdopen(fd, "wb") as out:
                    out.write(body)
    except (tarfile.TarError, EOFError) as exc:
        raise BuildError(f"compile output is not a tar stream: {type(exc).__name__}") from None


def _regular(path: str, limit: int) -> None:
    try:
        st = os.lstat(path)
    except OSError:
        # Ghidra はスクリプトが失敗しても終了コード 0 で終わることがある。
        # 出力が無いことで失敗に気づくので、ここで整った失敗にする。
        raise BuildError(f"{os.path.basename(path)} was not produced") from None
    if not stat.S_ISREG(st.st_mode):
        raise BuildError(f"{os.path.basename(path)} is not a regular file")
    if st.st_size <= 0 or st.st_size > limit:
        raise BuildError(f"{os.path.basename(path)} has an unexpected size")


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def main(resolver=gd.resolve, run_process=gd.run_process) -> int:
    try:
        envi = resolver()
    except gd.DockerProblem as exc:
        print(f"Docker を使えません（{exc.code}）。ローカルの Docker 以外では実行しません。",
              file=sys.stderr)
        return 2
    image = gd.image_state(envi)
    if image.get("state") != "ready":
        print("処理イメージがありません。アプリの「処理環境を準備する」を先に実行してください。",
              file=sys.stderr)
        return 2
    if _sha256(os.path.join(HERE, "termmines.c")) != SRC_SHA256:
        print("termmines.c が監査済みのものと一致しません。", file=sys.stderr)
        return 2

    owner = gd.owner_id(HERE)
    cancel = threading.Event()
    previous = signal.signal(signal.SIGINT, lambda *_: cancel.set())
    work = tempfile.mkdtemp(prefix="mws-sample-")
    ids = []
    try:
        src, bindir, out = (os.path.join(work, d) for d in ("src", "bin", "out"))
        for d in (src, bindir, out):
            os.mkdir(d, 0o755)
        # 解析用コンテナは --user でホストの利用者として動くので、out へ書ける。
        shutil.copyfile(os.path.join(HERE, "termmines.c"), os.path.join(src, "termmines.c"))

        started = time.monotonic()
        run_id = secrets.token_hex(16)
        ids.append(run_id)
        result = run(envi, compile_argv(envi, run_id=run_id, owner=owner, src_dir=src),
                     run_id, COMPILE_DEADLINE, cancel, run_process)
        compile_s = time.monotonic() - started
        # ホストの利用者として、実行属性の無い 0644 で書き出す（起動しない）。
        unpack_compile_output(result.stdout, bindir)
        elf = os.path.join(bindir, "termmines")
        _regular(elf, MAX_ELF_BYTES)
        _regular(os.path.join(bindir, "toolchain.txt"), MAX_TEXT_BYTES)
        if os.stat(elf).st_mode & 0o111:
            raise BuildError("the compiled program must not be executable on the host")

        started = time.monotonic()
        run_id = secrets.token_hex(16)
        ids.append(run_id)
        run(envi, analyze_argv(envi, run_id=run_id, owner=owner, bin_dir=bindir, out_dir=out,
                               uid=os.getuid(), gid=os.getgid()),
            run_id, ANALYZE_DEADLINE, cancel, run_process)
        analyze_s = time.monotonic() - started
        produced = os.path.join(out, "termmines.gzf")
        _regular(produced, gzf.MAX_GZF_BYTES)
        with open(produced, "rb") as fh:
            gzf.inspect_file(fh, os.fstat(fh.fileno()).st_size)

        target = os.path.join(HERE, "termmines.gzf")
        tmp = target + ".part"
        shutil.copyfile(produced, tmp)
        os.chmod(tmp, 0o644)
        os.replace(tmp, target)
        gzf_sha, elf_sha = _sha256(target), _sha256(elf)
        with open(os.path.join(bindir, "toolchain.txt"), encoding="utf-8") as fh:
            toolchain = fh.read()
        with open(os.path.join(HERE, "toolchain.txt"), "w", encoding="utf-8") as fh:
            fh.write(toolchain)
            fh.write(f"termmines (ELF, not executed): {elf_sha}\n")
            fh.write(f"ghidra image: {gd.image_ref()} {image.get('id', '')}\n")
            fh.write(f"docker server: {envi.server_version} {envi.server_arch}\n")
        with open(os.path.join(HERE, "sample.json"), encoding="utf-8") as fh:
            manifest = json.load(fh)
        manifest["sha256"] = gzf_sha
        manifest["executableSha256"] = elf_sha
        with open(os.path.join(HERE, "sample.json"), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        print(json.dumps({"termmines.gzf": gzf_sha, "elf": elf_sha,
                          "compileSeconds": round(compile_s, 1),
                          "analyzeSeconds": round(analyze_s, 1)}, indent=2))
        return 0
    except BuildError as exc:
        print(f"サンプルを作れませんでした: {exc}", file=sys.stderr)
        return 1
    finally:
        for run_id in ids:
            gd.stop_container(envi, run_id)
        signal.signal(signal.SIGINT, previous)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
