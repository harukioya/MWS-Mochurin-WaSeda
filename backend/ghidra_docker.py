"""ghidra_docker.py — ローカルの Docker だけを使って、固定のコマンドを動かす。

このモジュールの責務は三つに限る。

  1. 接続先の確認。Docker CLI が向いている先（DOCKER_HOST、有効な context）を
     調べ、この PC の中の UNIX ソケット（Windows では名前付きパイプ）と
     確かめられた場合だけ使う。TCP・SSH・確認できない接続は断る。以後の
     すべてのコマンドは、確かめた接続先を DOCKER_HOST に固定して実行する。
  2. 固定コマンドの組み立て。引数は下の定数と、アプリが自分で作った値
     （ジョブ ID・ジョブ専用ディレクトリ・uid/gid）だけから作る。HTTP の
     要求からイメージ名・エントリポイント・スクリプト・マウント先・オプションを
     受け取る経路は無い。シェルは通さず、argv の配列で渡す。
  3. 実行と後始末。出力と時間に上限を設け、キャンセル・期限切れでは自分が
     名前とラベルを付けたコンテナだけを止める。ユーザーの他のコンテナや
     イメージには触れない（prune などの広い削除はしない）。

ここで起動するのは Docker CLI と、開発側が用意した固定イメージだけである。
入力ファイルの中にあるプログラム・スクリプトを動かす経路は、このモジュールにも
イメージにも無い。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTEXT_DIR = os.path.join(REPO_ROOT, "ghidra", "image")
#: build context に入れるファイル。これ以外はディレクトリにあっても使わない
#: （.dockerignore でも同じものだけを通す）。
CONTEXT_FILES = (".dockerignore", "Dockerfile", "ExtractStaticFacts.java", "run-extract.sh")
SCRIPT_FILE = "ExtractStaticFacts.java"
ENTRY_FILE = "run-extract.sh"

# ---- 固定した版（Dockerfile と揃える）------------------------------------
GHIDRA_VERSION = "12.1.4"
GHIDRA_ZIP = "ghidra_12.1.4_PUBLIC_20260921.zip"
GHIDRA_ZIP_SHA256 = "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db"
BASE_IMAGE = (
    "eclipse-temurin:21.0.12.1_1-jdk-noble"
    "@sha256:d1eb0297924c2d5a37ba7042a59ae84a3487e086b077ac054019a423767d4311"
)
SCRIPT_VERSION = "1.0.0"
IMAGE_REPO = "mws-ghidra-static"

# ---- 処理コンテナの資源上限 ----------------------------------------------
LIMITS = {
    "memory": "4g",        # JVM ヒープ 2G + /tmp の tmpfs 分を含む
    "cpus": "2",
    "pids": 256,
    "tmp": "1536m",        # /tmp（作業用 tmpfs）。Ghidra の展開・一時ファイル
    "nofile": 4096,
}
#: 標準出力（抽出 JSON）と標準エラー（理由符号）の上限。
MAX_STDOUT = 32 * 1024**2
MAX_STDERR = 64 * 1024
#: 1 回の抽出にかける時間の上限。コンテナ起動・JVM・スクリプトの
#: コンパイル・読み込み・抽出のすべてを含む（analysisTimeoutPerFile では
#: 全体を縛れないため、ここで管理する）。
RUN_DEADLINE = 600
#: 初回準備（ベースイメージと Ghidra の取得・展開）にかける時間の上限。
BUILD_DEADLINE = 45 * 60
#: 状態確認に使う短いコマンドの上限。
PROBE_TIMEOUT = 15

LABEL_APP = "org.mws.app"
LABEL_APP_VALUE = "ghidra-static"
LABEL_OWNER = "org.mws.owner"
LABEL_JOB = "org.mws.job"
#: サーバーの起動ごとに変わる値。起動時の回収で、前回以前のコンテナと、
#: 今回の起動で動き始めたコンテナを取り違えないために使う。
LABEL_SESSION = "org.mws.session"
NAME_PREFIX = "mws-ghidra-"

JOB_ID = re.compile(r"[0-9a-f]{32}")
OWNER = re.compile(r"[0-9a-f]{16}")
SESSION = re.compile(r"[0-9a-f]{16}")

#: Docker Desktop が PATH を通していない起動方法でも見つけられるように。
DOCKER_CANDIDATES = (
    "/usr/local/bin/docker",
    "/opt/homebrew/bin/docker",
    "/usr/bin/docker",
    os.path.expanduser("~/.docker/bin/docker"),
    "/Applications/Docker.app/Contents/Resources/bin/docker",
)

#: Docker CLI へ引き継ぐ環境変数。接続先・TLS・builder の指定は引き継がない。
_ENV_KEEP = (
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR",
    "SYSTEMROOT", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
    "DOCKER_CONFIG",
)


class DockerProblem(Exception):
    """Docker を使えない理由。`code` は画面へ出す固定の符号。"""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(detail or code)
        self.code = code


@dataclass
class Environment:
    """確かめ終えたローカルの Docker。"""

    docker: str
    endpoint: str
    env: dict
    server_os: str = ""
    server_arch: str = ""
    server_version: str = ""
    builder_driver: str = ""


# ---------------------------------------------------------------------------
# 固定したファイルと版
# ---------------------------------------------------------------------------

def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def script_sha256() -> str:
    return _file_sha256(os.path.join(CONTEXT_DIR, SCRIPT_FILE))


def entry_sha256() -> str:
    return _file_sha256(os.path.join(CONTEXT_DIR, ENTRY_FILE))


def context_digest() -> str:
    """build context の内容の指紋。イメージのタグとラベルに使う。

    固定ファイルを 1 バイトでも変えればタグが変わるので、古いイメージを
    黙って使い続けることがない（画面では「作り直しが必要」と出る）。
    """
    h = hashlib.sha256()
    for name in sorted(CONTEXT_FILES):
        h.update(name.encode())
        h.update(b"\0")
        h.update(_file_sha256(os.path.join(CONTEXT_DIR, name)).encode())
        h.update(b"\0")
    return h.hexdigest()


def image_ref() -> str:
    return f"{IMAGE_REPO}:{GHIDRA_VERSION}-{context_digest()[:12]}"


def owner_id(state_dir: str) -> str:
    """この導入先を表すラベル値。再起動しても同じで、別の導入先とは重ならない。"""
    real = os.path.realpath(state_dir)
    return hashlib.sha256(real.encode("utf-8", "surrogateescape")).hexdigest()[:16]


def pinned() -> dict:
    """画面・README・教材に出す固定版の一覧。"""
    return {
        "ghidraVersion": GHIDRA_VERSION,
        "ghidraZip": GHIDRA_ZIP,
        "ghidraZipSha256": GHIDRA_ZIP_SHA256,
        "baseImage": BASE_IMAGE,
        "scriptVersion": SCRIPT_VERSION,
        "scriptSha256": script_sha256(),
        "entrySha256": entry_sha256(),
        "contextDigest": context_digest(),
        "imageRef": image_ref(),
    }


# ---------------------------------------------------------------------------
# 接続先の確認
# ---------------------------------------------------------------------------

def find_docker(environ=None) -> str | None:
    environ = os.environ if environ is None else environ
    found = shutil.which("docker", path=environ.get("PATH"))
    if found:
        return found
    for cand in DOCKER_CANDIDATES:
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def check_endpoint(endpoint: str, platform: str | None = None) -> str:
    """ローカルと確かめられる接続先なら正規化して返す。それ以外は DockerProblem。

    許すのは次の二つだけ。
      * unix:///絶対パス で、そのパスが実在する UNIX ソケットであること
      * Windows の npipe:////./pipe/名前
    tcp://・ssh://・http(s)://・fd:// など、それ以外はすべて断る。
    tcp://127.0.0.1 も断る。ポートを開けている時点で同じ PC の別ユーザーや
    転送設定を通じて届き得るうえ、TLS の有無をここで判断しきれないため。
    """
    platform = sys.platform if platform is None else platform
    if not isinstance(endpoint, str) or not endpoint or len(endpoint) > 1024:
        raise DockerProblem("docker-endpoint-unknown")
    if any(c in endpoint for c in "\0\n\r"):
        raise DockerProblem("docker-endpoint-unknown")
    if endpoint.startswith("unix://"):
        path = endpoint[len("unix://"):]
        if not path.startswith("/") or "/../" in path + "/":
            raise DockerProblem("docker-endpoint-unknown")
        try:
            st = os.stat(path)
        except OSError:
            raise DockerProblem("docker-not-running", "socket missing") from None
        if not stat.S_ISSOCK(st.st_mode):
            raise DockerProblem("docker-endpoint-unknown", "not a socket")
        return "unix://" + path
    if endpoint.startswith("npipe://") and platform == "win32":
        if not re.fullmatch(r"npipe:////\./pipe/[A-Za-z0-9_.-]{1,128}", endpoint):
            raise DockerProblem("docker-endpoint-unknown")
        return endpoint
    raise DockerProblem("docker-remote", endpoint.split("://", 1)[0][:16])


def command_env(environ, endpoint: str, docker: str) -> dict:
    """Docker CLI へ渡す環境。接続先は確かめたものに固定する。"""
    env = {k: environ[k] for k in _ENV_KEEP if k in environ}
    # 資格情報ヘルパー（docker-credential-*）は CLI と同じ場所にあることが多い。
    bindir = os.path.dirname(docker)
    env["PATH"] = bindir + os.pathsep + env.get("PATH", "/usr/bin:/bin")
    env["DOCKER_HOST"] = endpoint
    env["DOCKER_CLI_HINTS"] = "false"
    env["BUILDX_NO_DEFAULT_ATTESTATIONS"] = "1"
    return env


def _run(argv, env, timeout=PROBE_TIMEOUT, runner=subprocess.run):
    return runner(
        argv, env=env, stdin=subprocess.DEVNULL, capture_output=True,
        timeout=timeout, check=False,
    )


def _classify_cli_error(stderr: str) -> str:
    text = stderr.lower()
    if "permission denied" in text:
        return "docker-permission"
    if ("cannot connect" in text or "is the docker daemon running" in text
            or "no such file or directory" in text or "connection refused" in text
            or "error during connect" in text):
        return "docker-not-running"
    return "docker-unavailable"


def resolve(environ=None, runner=subprocess.run) -> Environment:
    """使ってよいローカル Docker を確かめて返す。だめなら DockerProblem。"""
    environ = dict(os.environ if environ is None else environ)
    docker = find_docker(environ)
    if docker is None:
        raise DockerProblem("docker-missing")

    raw = environ.get("DOCKER_HOST")
    if raw:
        endpoint = raw.strip()
    else:
        # 有効な context の接続先。DOCKER_CONTEXT があればそれが使われる。
        probe_env = {k: environ[k] for k in _ENV_KEEP + ("DOCKER_CONTEXT",) if k in environ}
        probe_env["PATH"] = os.path.dirname(docker) + os.pathsep + probe_env.get("PATH", "")
        try:
            proc = _run([docker, "context", "inspect", "--format",
                         "{{json .Endpoints.docker.Host}}"], probe_env, runner=runner)
        except (OSError, subprocess.TimeoutExpired):
            raise DockerProblem("docker-unavailable", "context inspect failed") from None
        if proc.returncode != 0:
            raise DockerProblem("docker-endpoint-unknown", "context inspect")
        try:
            endpoint = json.loads(proc.stdout.decode("utf-8", "replace").strip() or '""')
        except json.JSONDecodeError:
            raise DockerProblem("docker-endpoint-unknown", "context json") from None
    endpoint = check_endpoint(endpoint)
    env = command_env(environ, endpoint, docker)

    try:
        proc = _run([docker, "version", "--format", "{{json .}}"], env, runner=runner)
    except (OSError, subprocess.TimeoutExpired):
        raise DockerProblem("docker-not-running", "version timed out") from None
    info = None
    try:
        info = json.loads(proc.stdout.decode("utf-8", "replace") or "null")
    except json.JSONDecodeError:
        info = None
    server = (info or {}).get("Server") if isinstance(info, dict) else None
    if proc.returncode != 0 or not isinstance(server, dict):
        raise DockerProblem(_classify_cli_error(proc.stderr.decode("utf-8", "replace")))
    server_os = str(server.get("Os") or "")
    arch = str(server.get("Arch") or "")
    if server_os != "linux":
        raise DockerProblem("docker-not-linux", server_os[:16])
    if arch not in ("amd64", "arm64"):
        raise DockerProblem("docker-arch-unsupported", arch[:16])
    return Environment(docker, endpoint, env, server_os, arch,
                       str(server.get("Version") or "")[:32])


# ---------------------------------------------------------------------------
# イメージ
# ---------------------------------------------------------------------------

def image_state(envi: Environment, runner=subprocess.run) -> dict:
    """固定イメージの状態。missing / outdated / ready。

    ready と言うのは、タグが今の build context の指紋と一致し、ラベルの
    Ghidra 版・スクリプトの指紋・CPU の種類が期待どおりのときだけ。
    """
    ref = image_ref()
    try:
        proc = _run([envi.docker, "image", "inspect", "--format", "{{json .}}", ref],
                    envi.env, runner=runner)
    except (OSError, subprocess.TimeoutExpired):
        return {"state": "unknown", "ref": ref}
    if proc.returncode == 0:
        try:
            info = json.loads(proc.stdout.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            return {"state": "unknown", "ref": ref}
        labels = ((info.get("Config") or {}).get("Labels") or {}) if isinstance(info, dict) else {}
        ok = (
            labels.get("org.mws.ghidra.version") == GHIDRA_VERSION
            and labels.get("org.mws.ghidra.zip-sha256") == GHIDRA_ZIP_SHA256
            and labels.get("org.mws.script.sha256") == script_sha256()
            and labels.get("org.mws.entry.sha256") == entry_sha256()
            and labels.get("org.mws.context") == context_digest()
            and info.get("Architecture") == envi.server_arch
            and info.get("Os") == "linux"
        )
        if ok:
            return {"state": "ready", "ref": ref, "id": str(info.get("Id") or "")[:80],
                    "arch": info.get("Architecture")}
        return {"state": "outdated", "ref": ref}
    # 「イメージが無い」と Docker が答えた場合だけ missing / outdated とする。
    # 接続が切れただけで「準備が必要」と案内すると、要らない再取得を促してしまう。
    err = proc.stderr.decode("utf-8", "replace").lower()
    if "no such image" not in err and "no such object" not in err:
        return {"state": "unknown", "ref": ref}
    # 同じリポジトリ名の古いタグがあるか（作り直しの案内に使う）。
    try:
        ls = _run([envi.docker, "image", "ls", "--format", "{{.Repository}}:{{.Tag}}",
                   "--filter", f"reference={IMAGE_REPO}"], envi.env, runner=runner)
    except (OSError, subprocess.TimeoutExpired):
        return {"state": "unknown", "ref": ref}
    if ls.returncode != 0:
        return {"state": "unknown", "ref": ref}
    return {"state": "outdated" if ls.stdout.strip() else "missing", "ref": ref}


def check_local_builder(envi: Environment, runner=subprocess.run) -> str:
    """ビルドが手元の Docker で行われることを確かめる。

    `docker build` は、利用者が別の builder（クラウド builder を含む）を既定に
    していると、そちらへ送られる。`--builder default` を明示し、その driver が
    ローカルの `docker` であることを確かめてから使う。
    """
    try:
        proc = _run([envi.docker, "buildx", "inspect", "default"], envi.env, runner=runner)
    except (OSError, subprocess.TimeoutExpired):
        raise DockerProblem("buildx-missing") from None
    if proc.returncode != 0:
        raise DockerProblem("buildx-missing")
    m = re.search(r"^Driver:\s+(\S+)", proc.stdout.decode("utf-8", "replace"), re.M)
    driver = m.group(1) if m else ""
    if driver != "docker":
        raise DockerProblem("builder-not-local", driver[:32])
    envi.builder_driver = driver
    return driver


def build_argv(envi: Environment) -> list[str]:
    """初回準備のビルドコマンド。ローカル builder・この PC の CPU 向けだけ。"""
    return [
        envi.docker, "buildx", "build",
        "--builder", "default",
        "--load",
        "--platform", f"linux/{envi.server_arch}",
        "--provenance=false",
        "--sbom=false",
        "--progress=plain",
        "--tag", image_ref(),
        "--build-arg", f"MWS_SCRIPT_SHA256={script_sha256()}",
        "--build-arg", f"MWS_ENTRY_SHA256={entry_sha256()}",
        "--label", f"org.mws.context={context_digest()}",
        "--file", os.path.join(CONTEXT_DIR, "Dockerfile"),
        CONTEXT_DIR,
    ]


# ---------------------------------------------------------------------------
# 処理コンテナ
# ---------------------------------------------------------------------------

def container_name(job_id: str) -> str:
    if not JOB_ID.fullmatch(job_id):
        raise ValueError("bad job id")
    return NAME_PREFIX + job_id


def run_argv(envi: Environment, *, job_id: str, owner: str, session: str, input_dir: str,
             uid: int, gid: int, diag: bool = False) -> list[str]:
    """抽出コンテナの起動コマンド。すべて固定値とアプリが作った値から組む。

    共有するホスト領域は、ジョブ専用の入力ディレクトリ 1 つだけで、読み取り
    専用。出力は標準出力で受け取るので、書き込み可能なホスト領域は渡さない。
    """
    if (not JOB_ID.fullmatch(job_id) or not OWNER.fullmatch(owner)
            or not SESSION.fullmatch(session)):
        raise ValueError("bad identifiers")
    if not isinstance(uid, int) or not isinstance(gid, int) or uid <= 0 or gid < 0:
        # root のまま動かさない。呼び出し側で断る。
        raise ValueError("refusing to run the container as root")
    if not os.path.isabs(input_dir) or any(c in input_dir for c in ",=\0\n"):
        # --mount の値はカンマ区切り。パスにカンマが入ると別の指定に化ける。
        raise ValueError("unsafe input directory path")
    argv = [
        envi.docker, "run",
        "--rm",
        "--name", container_name(job_id),
        "--label", f"{LABEL_APP}={LABEL_APP_VALUE}",
        "--label", f"{LABEL_OWNER}={owner}",
        "--label", f"{LABEL_JOB}={job_id}",
        "--label", f"{LABEL_SESSION}={session}",
        "--pull=never",
        "--network=none",
        "--user", f"{uid}:{gid}",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--read-only",
        "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={LIMITS['tmp']},mode=1777",
        "--memory", LIMITS["memory"],
        "--memory-swap", LIMITS["memory"],
        "--cpus", LIMITS["cpus"],
        "--pids-limit", str(LIMITS["pids"]),
        "--ulimit", f"nofile={LIMITS['nofile']}:{LIMITS['nofile']}",
        "--ulimit", "core=0",
        "--log-driver=none",
        "--stop-timeout", "5",
        "--mount", f"type=bind,source={input_dir},target=/input,readonly",
        "--workdir", "/tmp",
    ]
    if diag:
        argv += ["--env", "MWS_DIAG=1"]
    argv.append(image_ref())
    return argv


@dataclass
class RunResult:
    returncode: int | None
    stdout: bytes = b""
    stderr: bytes = b""
    cancelled: bool = False
    timed_out: bool = False
    overflow: str = ""          # "stdout" / "stderr"
    seconds: float = 0.0
    extra: dict = field(default_factory=dict)


def _pump(stream, sink: bytearray, limit: int, over: threading.Event):
    try:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            if len(sink) + len(chunk) > limit:
                sink.extend(chunk[: max(0, limit - len(sink))])
                over.set()
                # 上限を超えても読み続けて捨てる。止めると子が書き込みで詰まる。
                continue
            sink.extend(chunk)
    except (OSError, ValueError):
        pass


def run_process(argv: list[str], env: dict, *, deadline: float,
                cancel: threading.Event, max_stdout: int, max_stderr: int,
                on_stop=None, popen=subprocess.Popen, clock=time.monotonic) -> RunResult:
    """コマンドを 1 つ動かし、期限・キャンセル・出力上限を守らせる。

    止めるときは、まず `on_stop`（コンテナの停止）を呼び、次に CLI 自身を
    止める。CLI だけを止めてもコンテナは動き続けるため、順番が逆だと
    取り残しが出る。
    """
    started = clock()
    proc = popen(
        argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, start_new_session=True,
    )
    out, err = bytearray(), bytearray()
    out_over, err_over = threading.Event(), threading.Event()
    threads = [
        threading.Thread(target=_pump, args=(proc.stdout, out, max_stdout, out_over), daemon=True),
        threading.Thread(target=_pump, args=(proc.stderr, err, max_stderr, err_over), daemon=True),
    ]
    for t in threads:
        t.start()
    result = RunResult(None)
    while True:
        try:
            rc = proc.wait(timeout=0.2)
            result.returncode = rc
            break
        except subprocess.TimeoutExpired:
            pass
        reason = None
        if cancel.is_set():
            reason = "cancelled"
        elif clock() > deadline:
            reason = "timeout"
        elif out_over.is_set():
            reason = "stdout"
        elif err_over.is_set():
            reason = "stderr"
        if reason:
            if on_stop is not None:
                try:
                    on_stop()
                except Exception:  # noqa: BLE001 - 後始末は最後まで続ける
                    pass
            _terminate(proc)
            result.returncode = proc.returncode
            if reason == "cancelled":
                result.cancelled = True
            elif reason == "timeout":
                result.timed_out = True
            else:
                result.overflow = reason
            break
    for t in threads:
        t.join(timeout=5)
    # パイプの記述子を閉じる。ジョブのたびに残ると、長く動かすうちに尽きる。
    for stream in (proc.stdout, proc.stderr):
        try:
            stream.close()
        except (OSError, ValueError):
            pass
    if out_over.is_set() and not result.overflow:
        result.overflow = "stdout"
    if err_over.is_set() and not result.overflow:
        result.overflow = "stderr"
    result.stdout = bytes(out)
    result.stderr = bytes(err)
    result.seconds = clock() - started
    return result


def _terminate(proc) -> None:
    for sig, wait in ((signal.SIGTERM, 5), (signal.SIGKILL, 5)):
        if proc.poll() is not None:
            return
        try:
            if hasattr(os, "killpg"):
                os.killpg(proc.pid, sig)
            else:  # pragma: no cover - Windows
                proc.kill()
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            proc.wait(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue


def stop_container(envi: Environment, job_id: str, runner=subprocess.run) -> None:
    """自分が付けた名前のコンテナだけを止めて消す。"""
    name = container_name(job_id)
    for argv in ([envi.docker, "kill", name], [envi.docker, "rm", "-f", name]):
        try:
            _run(argv, envi.env, runner=runner)
        except (OSError, subprocess.TimeoutExpired):
            pass


def container_state(envi: Environment, name: str, runner=subprocess.run) -> str | None:
    """名前を付けたコンテナが "present" か "absent" か。確かめられなければ None。

    inspect の終了コードが 0 以外でも、それだけでは「無い」とは言えない
    （Docker との接続が切れた、応答が遅れた、でも同じ終わり方をする）。
    Docker が「そのコンテナは無い」と答えた場合だけ absent とする。
    """
    try:
        proc = _run([envi.docker, "container", "inspect", "--format", "{{.Id}}", name],
                    envi.env, runner=runner)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode == 0 and proc.stdout.strip():
        return "present"
    err = proc.stderr.decode("utf-8", "replace").lower()
    if proc.returncode != 0 and ("no such container" in err or "no such object" in err):
        return "absent"
    return None


def owned_containers(envi: Environment, owner: str, *, keep_session: str | None = None,
                     runner=subprocess.run) -> list[str]:
    """この導入先が起動した処理コンテナの ID。アプリと導入先のラベルが一致するものだけ。

    `keep_session` を渡すと、そのセッション（今回の起動）のコンテナは除く。
    問い合わせに失敗したときは DockerProblem を送出する。空の一覧を返すと、
    「取り残しは無い」と区別がつかなくなるため。
    """
    if not OWNER.fullmatch(owner) or (keep_session is not None
                                      and not SESSION.fullmatch(keep_session)):
        raise ValueError("bad owner or session")
    try:
        proc = _run([envi.docker, "ps", "-a", "--no-trunc",
                     "--filter", f"label={LABEL_APP}={LABEL_APP_VALUE}",
                     "--filter", f"label={LABEL_OWNER}={owner}",
                     "--format", "{{.ID}}\t{{.Label \"" + LABEL_SESSION + "\"}}"],
                    envi.env, runner=runner)
    except (OSError, subprocess.TimeoutExpired):
        raise DockerProblem("docker-unavailable", "container listing timed out") from None
    if proc.returncode != 0:
        raise DockerProblem(_classify_cli_error(proc.stderr.decode("utf-8", "replace")),
                            "container listing failed")
    ids = []
    for line in proc.stdout.decode("ascii", "replace").splitlines():
        cid, _, session = line.partition("\t")
        cid, session = cid.strip(), session.strip()
        if not re.fullmatch(r"[0-9a-f]{12,64}", cid):
            continue
        if keep_session is not None and session == keep_session:
            continue
        ids.append(cid)
    return ids


def remove_owned(envi: Environment, owner: str, *, keep_session: str | None = None,
                 runner=subprocess.run) -> int:
    """前回以前の異常終了で残った、自分の処理コンテナを消す。他には触れない。

    今回の起動で動き始めたコンテナ（`keep_session`）は消さない。回収が
    Docker の応答待ちで遅れても、その間に受け付けた新しい処理を止めない。
    """
    ids = owned_containers(envi, owner, keep_session=keep_session, runner=runner)
    if ids:
        try:
            proc = _run([envi.docker, "rm", "-f", *ids], envi.env, runner=runner)
        except (OSError, subprocess.TimeoutExpired):
            raise DockerProblem("docker-unavailable", "container removal timed out") from None
        if proc.returncode != 0:
            raise DockerProblem(_classify_cli_error(proc.stderr.decode("utf-8", "replace")),
                                "container removal failed")
    return len(ids)


_REASON = re.compile(rb"MWS-REASON: ([a-z-]{1,40})")


def reason_code(stderr: bytes) -> str | None:
    """エントリポイントが出した固定の理由符号。それ以外の文字列は使わない。"""
    m = _REASON.search(stderr or b"")
    return m.group(1).decode("ascii") if m else None
