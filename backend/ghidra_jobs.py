"""ghidra_jobs.py — GZF からの教材生成と、処理環境の準備を 1 件ずつ動かす。

同時に動かすのは 1 件だけ（抽出でも準備でも）。待ち行列は持たず、動いて
いる間の新しい依頼は「処理中」として断る。受信中の入力もこの 1 枠に数える
ので、未処理の入力がディスクに溜まることはない。

作業データの寿命:

  * 入力のコピー `.mws-state/ghidra-jobs/<job>/input/input.gzf` は、抽出が
    終わった時点（成功・失敗・キャンセル・期限切れのどれでも）で消す。
  * Ghidra の一時プロジェクトと抽出 JSON はコンテナ内の tmpfs にしかなく、
    コンテナの終了とともに消える（--rm）。
  * サーバーが異常終了した場合は、次の起動時に `recover()` がジョブ用
    ディレクトリを消し、自分のラベルが付いた処理コンテナだけを止めて消す。
  * 教材に採用した根拠・版・ハッシュだけがローカル DB に残る。

利用者に返すのは固定の理由符号と、それに対応する固定の文言だけ。コンテナの
生のエラー文字列・ファイルの中身・手元の絶対パスは返さない。
"""

from __future__ import annotations

import os
import secrets
import shutil
import sys
import threading
import time
from dataclasses import dataclass, field

import ghidra_docker as gd
import static_facts
import static_lesson

#: 画面に出す段階名。
PHASES = {
    "receiving": "ファイルを受け取っています",
    "checking": "ファイル確認中",
    "reading": "Ghidra で読み取り中",
    "building": "教材生成中",
    "preparing": "処理環境を準備しています",
    "done": "完了しました",
    "failed": "失敗しました",
    "cancelled": "キャンセルしました",
}
FINAL = {"done", "failed", "cancelled"}

#: 理由符号 → 利用者向けの文言と、次にできること。生のエラーは入れない。
MESSAGES = {
    "busy": "別の処理が進行中です。終わってからもう一度実行してください。",
    "docker-missing": "Docker が見つかりません。Docker Desktop（または Linux の Docker Engine）を導入して起動してから、状態を確認し直してください。既存のログ教材は Docker なしで使えます。",
    "docker-not-running": "Docker が起動していないか、応答していません。Docker Desktop を起動してから、状態を確認し直してください。",
    "docker-permission": "Docker への接続が許可されていません。Docker を使える利用者でアプリを起動してください。",
    "docker-remote": "Docker の接続先がこの PC の外（TCP・SSH など）を向いています。安全のため、ローカルの Docker 以外では処理しません。DOCKER_HOST や docker context を、この PC の Docker に戻してください。",
    "docker-endpoint-unknown": "Docker の接続先を確かめられませんでした。ローカルの Docker だと確認できない接続は使いません。",
    "docker-not-linux": "Docker が Linux コンテナを動かす設定になっていません。Linux コンテナへ切り替えてください。",
    "docker-arch-unsupported": "この CPU の種類（amd64 / arm64 以外）には対応していません。",
    "docker-unavailable": "Docker の状態を確かめられませんでした。Docker を再起動してから、もう一度確認してください。",
    "buildx-missing": "Docker の buildx が使えないため、処理環境を準備できません。Docker Desktop を使うか、buildx を導入してください。",
    "builder-not-local": "既定の builder がローカルではありません。処理環境の準備はこの PC の Docker でだけ行います。",
    "image-missing": "処理環境がまだ準備されていません。先に「処理環境を準備する」を実行してください。",
    "image-outdated": "処理環境が古い版です。「処理環境を準備する」で作り直してください。",
    "prepare-failed": "処理環境の準備に失敗しました。通信状況と空きディスク容量を確かめてから、もう一度実行してください。",
    "prepare-timeout": "処理環境の準備が時間内に終わりませんでした。通信状況を確かめてから、もう一度実行してください。",
    "root-refused": "アプリが管理者（root）として動いています。安全のため、通常の利用者で起動し直してください。",
    "path-unsafe": "アプリの置き場所のパスにカンマ等の記号が含まれるため、Docker へ安全に受け渡せません。別の場所に置いてください。",
    "too-large": "ファイルが大きすぎます。上限（64 MB）以下の GZF を使ってください。",
    "too-large-unpacked": "展開後のデータベースが上限（512 MB）を超えるため、処理しません。",
    "empty": "空のファイルです。",
    "not-gzf": "Ghidra の GZF ファイルとして読めませんでした。拡張子だけを .gzf にしたファイルや、壊れたファイルは処理しません。",
    "not-program": "この GZF はプログラムの解析データではありません（データ型アーカイブ等）。",
    "version-unsupported": "この GZF は、固定している Ghidra の版では読めない形式です。",
    "language-unsupported": "この GZF のプロセッサ定義を、固定している Ghidra の版が持っていません。",
    "ratio": "圧縮率が極端なため、処理しません。",
    "crc": "ファイルの検査値が一致しません。壊れている可能性があります。",
    "upload-incomplete": "ファイルを最後まで受け取れませんでした。もう一度送ってください。",
    "upload-timeout": "ファイルの受け取りが時間内に終わりませんでした。",
    "disk-full": "ディスクの空きが足りません。空きを作ってから、もう一度実行してください。",
    "timeout": "処理が時間内（10 分）に終わりませんでした。GZF が大きすぎる可能性があります。",
    "cancelled": "キャンセルしました。作業データは削除済みです。",
    "out-of-memory": "処理中にメモリが足りなくなりました。GZF が大きすぎる可能性があります。",
    "workspace-full": "コンテナ内の作業領域が足りなくなりました。GZF が大きすぎる可能性があります。",
    "container-failed": "Ghidra での読み取りに失敗しました。",
    "extract-failed": "Ghidra での読み取りに失敗しました。解析情報が壊れている可能性があります。",
    "script-failed": "保存済み情報の抽出中にエラーが起きました。",
    "output-missing": "抽出結果が空でした。",
    "output-too-large": "抽出結果が上限を超えたため、採用しませんでした。",
    "output-invalid": "抽出結果の形式が正しくないため、採用しませんでした。",
    "output-incomplete": "抽出結果が途中で切れていたため、採用しませんでした。",
    "schema-unsupported": "抽出結果の版に対応していません。処理環境を作り直してください。",
    "hash-mismatch": "抽出結果が、送ったファイルのものと一致しませんでした。採用しません。",
    "tool-mismatch": "抽出に使われた Ghidra またはスクリプトの版が、固定した版と一致しませんでした。処理環境を作り直してください。",
    "no-questions": "根拠の揃う設問を作れませんでした。",
    "password-required": "この ZIP の項目は暗号化されています。パスワードを入力してください。",
    "password-rejected": "パスワードが合いませんでした。もう一度入力してください。",
    "zip-aes": "AES 方式で暗号化された ZIP には対応していません。",
    "zip-symlink": "この項目はシンボリックリンクです。読み取りません。",
    "zip-unsafe-name": "この項目の名前（絶対パス・.. ・制御文字など）または種類が危険なため、読み取りません。",
    "zip-nested-too-deep": "入れ子になった ZIP は 1 段までしか対応していません。",
    "zip-ambiguous": "同じ名前の入れ子 ZIP が複数あり、どの中身か決められないため、読み取りません。",
    "zip-member-missing": "選んだ項目が ZIP の中に見つかりませんでした。ZIP を読み取り直してください。",
    "zip-member-changed": "ZIP の目録が読み込んだときと食い違っています。ZIP を読み取り直してください。",
    "zip-damaged": "ZIP を読み取れませんでした。壊れている可能性があります。",
    "archive-changed": "この ZIP ファイルは読み込み後に変更されています。もう一度読み取ってから実行してください。",
    "budget": "読み取り量の上限を超えたため、中断しました。",
    "sample-missing": "同梱のサンプル GZF が見つかりません。",
    "internal": "内部エラーが起きました。作業データは削除済みです。",
}


def image_problem(state: str | None) -> str:
    """準備済みでないイメージの状態を、理由符号にする。

    確かめられなかった（unknown）ものを「未準備」と言うと、要らない再準備を
    促してしまう。Docker の状態を確かめ直すよう案内する。
    """
    return {"outdated": "image-outdated", "missing": "image-missing"}.get(
        state or "", "docker-unavailable")


def message(code: str) -> str:
    return MESSAGES.get(code, MESSAGES["internal"])


class Busy(Exception):
    pass


@dataclass
class Job:
    id: str
    kind: str                    # "analyze" / "prepare"
    state: str
    created: float
    updated: float
    origin: dict = field(default_factory=dict)
    input_sha256: str = ""
    input_bytes: int = 0
    error: str = ""
    reasons: list = field(default_factory=list)
    lesson_id: str = ""
    summary: dict = field(default_factory=dict)
    cancel: threading.Event = field(default_factory=threading.Event)
    seconds: float = 0.0
    #: 受信中のキャンセルで呼ぶ。待っている読み取りを終わらせる（接続の受信を止める）。
    interrupt: object = None
    #: 受付を担う要求が付いているか。ブラウザからの送信は、先に予約して ID を
    #: 返し（未接続）、本文の要求が来た時点で付く。未接続のままの予約は、
    #: キャンセルされればその場で、放置されれば期限で解放する。
    attached: bool = True

    def public(self) -> dict:
        body = {
            "id": self.id,
            "kind": self.kind,
            "state": self.state,
            "phase": PHASES.get(self.state, self.state),
            "final": self.state in FINAL,
            "elapsed": round(time.time() - self.created, 1),
            "origin": dict(self.origin),
        }
        if self.input_sha256:
            body["inputSha256"] = self.input_sha256
            body["inputBytes"] = self.input_bytes
        if self.error:
            body["error"] = {"code": self.error, "message": message(self.error),
                             "reasons": list(self.reasons)}
        if self.lesson_id:
            body["lessonId"] = self.lesson_id
            body["summary"] = dict(self.summary)
        if self.seconds:
            body["seconds"] = round(self.seconds, 1)
        return body


class JobManager:
    """1 件ずつ動かす。テストでは resolver / runner / sink を差し替える。"""

    KEEP_FINISHED = 8
    #: 予約してから本文の送信が始まるまで待つ時間。
    RESERVE_SECONDS = 30

    def __init__(self, root: str, owner: str, *, sink, sample_lookup=None,
                 resolver=gd.resolve, image_state=gd.image_state,
                 run_process=gd.run_process, stop_container=gd.stop_container,
                 check_builder=gd.check_local_builder, remove_owned=gd.remove_owned,
                 uid=None, gid=None, log=None):
        self.root = root
        self.owner = owner
        self.sink = sink
        self.sample_lookup = sample_lookup or (lambda sha: None)
        self.resolver = resolver
        self.image_state = image_state
        self.run_process = run_process
        self.stop_container = stop_container
        self.check_builder = check_builder
        self.remove_owned = remove_owned
        self.uid = os.getuid() if uid is None and hasattr(os, "getuid") else uid
        self.gid = os.getgid() if gid is None and hasattr(os, "getgid") else gid
        self.log = log or (lambda kind, detail: None)
        #: この起動の識別子。コンテナのラベルに付け、起動時の回収で使う。
        self.session = secrets.token_hex(8)
        self.lock = threading.Lock()
        self.jobs: dict[str, Job] = {}
        self.active: Job | None = None
        self.threads: dict[str, threading.Thread] = {}

    # -- lifecycle --------------------------------------------------------
    def recover(self) -> dict:
        """起動時の後始末（テスト・手動用に両方をまとめて行う）。"""
        return {"dirs": self.recover_dirs(), "containers": self.recover_containers()}

    def recover_dirs(self) -> int:
        """前回の作業データを消す。受付を始める前に、同期して呼ぶこと。

        受付と並行して動かすと、今回のジョブの入力まで消しかねない。ローカルの
        ディレクトリを消すだけなので速く、Docker の状態にも左右されない。
        """
        with self.lock:
            if self.jobs:
                raise RuntimeError("recover_dirs must run before any job is accepted")
            removed = 0
            os.makedirs(self.root, mode=0o700, exist_ok=True)
            for name in os.listdir(self.root):
                if gd.JOB_ID.fullmatch(name):
                    shutil.rmtree(os.path.join(self.root, name), ignore_errors=True)
                    removed += 1
            return removed

    def recover_containers(self) -> int:
        """前回以前の起動で残った、自分の処理コンテナを消す。

        Docker の応答待ちで時間がかかることがあるので、別スレッドで動かして
        よい。今回の起動のコンテナはセッションのラベルで除くので、その間に
        受け付けた処理を止めることはない。
        """
        try:
            envi = self.resolver()
            return self.remove_owned(envi, self.owner, keep_session=self.session)
        except gd.DockerProblem:
            return 0  # Docker が無い・止まっている。既存機能はそのまま使える。
        except Exception:  # noqa: BLE001 - 起動を止めない
            return 0

    def reserve(self, kind: str, origin: dict | None = None, *,
                attached: bool = True) -> Job:
        """処理枠を確保する。`attached=False` は、本文を後から別の要求で送る予約。"""
        with self.lock:
            self._expire_stale_locked()
            if self.active is not None and self.active.state not in FINAL:
                raise Busy()
            now = time.time()
            job = Job(secrets.token_hex(16), kind,
                      "preparing" if kind == "prepare" else "receiving",
                      now, now, origin=dict(origin or {}), attached=attached)
            self.jobs[job.id] = job
            self.active = job
            self._trim()
            return job

    def _expire_stale_locked(self) -> None:
        """本文が来ないまま期限を過ぎた予約を解放する。self.lock を持って呼ぶ。"""
        job = self.active
        if (job is not None and job.state == "receiving" and not job.attached
                and time.time() - job.created > self.RESERVE_SECONDS):
            self.fail(job, "upload-timeout")

    def attach(self, job: Job) -> bool:
        """予約に本文の要求を付ける。キャンセル済み・期限切れ・付け済みなら False。

        cancel と同じ lock の中で判定するので、「付いた直後にキャンセルされた」
        場合は cancel 側が受信の打ち切りへ回り、「キャンセルされた直後に付こう
        とした」場合はここで断る。どちらの順でも、取り消しが抜け落ちない。
        """
        with self.lock:
            self._expire_stale_locked()
            if job.attached or job.state != "receiving" or job.cancel.is_set():
                return False
            job.attached = True
            job.updated = time.time()
            return True

    def _trim(self) -> None:
        finished = [j for j in self.jobs.values() if j.state in FINAL]
        finished.sort(key=lambda j: j.updated)
        for j in finished[: max(0, len(finished) - self.KEEP_FINISHED)]:
            self.jobs.pop(j.id, None)

    def get(self, job_id: str) -> Job | None:
        return self.jobs.get(job_id)

    def current(self) -> Job | None:
        with self.lock:
            self._expire_stale_locked()
        return self.active

    def job_dir(self, job: Job) -> str:
        return os.path.join(self.root, job.id)

    def input_dir(self, job: Job) -> str:
        return os.path.join(self.job_dir(job), "input")

    def make_input_dir(self, job: Job) -> str:
        os.makedirs(self.root, mode=0o700, exist_ok=True)
        os.mkdir(self.job_dir(job), 0o700)
        os.mkdir(self.input_dir(job), 0o700)
        return self.input_dir(job)

    def _set(self, job: Job, state: str) -> None:
        job.state = state
        job.updated = time.time()

    def fail(self, job: Job, code: str, reasons: list | None = None) -> None:
        # 作業データを消してから終了状態にする。終了と見えた時点で、次の依頼が
        # 始まってもよい状態（一時ファイルが残っていない状態）にしておく。
        self._cleanup(job)
        job.error = code
        job.reasons = list(reasons or [])
        self._set(job, "cancelled" if code == "cancelled" else "failed")

    def _cleanup(self, job: Job) -> None:
        shutil.rmtree(self.job_dir(job), ignore_errors=True)

    def cancel(self, job_id: str) -> bool:
        job = self.jobs.get(job_id)
        with self.lock:
            if job is None or job.state in FINAL:
                return False
            # 受信・確認中は要求を処理しているスレッドが、読み取り中は
            # run_process が、この印を見て止まる（コンテナも止めてから抜ける）。
            job.cancel.set()
            detached = job.state == "receiving" and not job.attached
        if detached:
            # 本文の要求がまだ来ていない予約。待つ相手がいないので、ここで解放する。
            self.fail(job, "cancelled")
            return True
        # 受信中は、届かないデータを待って止まっていることがあるので、
        # 受信そのものを打ち切らせる。
        hook = job.interrupt
        if callable(hook):
            try:
                hook()
            except Exception:  # noqa: BLE001 - キャンセルは最後まで続ける
                pass
        return True

    def release_stranded(self, job: Job) -> None:
        """受付の途中で取り残されたジョブを、失敗として後始末する。

        抽出スレッドへ渡す前（receiving / checking）に受付が抜けた場合だけ
        働く。渡し終えたもの・すでに終えたものには何もしない。
        """
        with self.lock:
            stranded = job.state in ("receiving", "checking")
        if stranded:
            self.fail(job, "cancelled" if job.cancel.is_set() else (job.error or "internal"))

    # -- 抽出 ------------------------------------------------------------
    def start_analysis(self, job: Job, sha256: str, size: int) -> None:
        job.input_sha256 = sha256
        job.input_bytes = size
        self._set(job, "reading")
        t = threading.Thread(target=self._analyze, args=(job,), daemon=True,
                             name=f"ghidra-{job.id[:8]}")
        self.threads[job.id] = t
        t.start()

    def _analyze(self, job: Job) -> None:
        try:
            self._analyze_inner(job)
        except Exception as exc:  # noqa: BLE001 - 失敗は固定の符号で返す
            if os.environ.get("MWS_GHIDRA_DEBUG") == "1":
                print(f"[ghidra] internal error: {type(exc).__name__}", file=sys.stderr)
            self.fail(job, "internal")

    def _analyze_inner(self, job: Job) -> None:
        if job.cancel.is_set():
            return self.fail(job, "cancelled")
        if not self.uid:
            return self.fail(job, "root-refused")
        try:
            envi = self.resolver()
        except gd.DockerProblem as exc:
            return self.fail(job, exc.code)
        image = self.image_state(envi)
        if image.get("state") != "ready":
            return self.fail(job, image_problem(image.get("state")))
        try:
            argv = gd.run_argv(envi, job_id=job.id, owner=self.owner, session=self.session,
                               input_dir=os.path.realpath(self.input_dir(job)),
                               uid=self.uid, gid=self.gid,
                               diag=os.environ.get("MWS_GHIDRA_DEBUG") == "1")
        except ValueError:
            return self.fail(job, "path-unsafe")

        result = self.run_process(
            argv, envi.env, deadline=time.monotonic() + gd.RUN_DEADLINE,
            cancel=job.cancel, max_stdout=gd.MAX_STDOUT, max_stderr=gd.MAX_STDERR,
            on_stop=lambda: self.stop_container(envi, job.id),
        )
        job.seconds = result.seconds
        # 入力のコピーは、ここで役目を終える。以後は読み直さない。
        self._cleanup(job)
        if result.cancelled:
            self.stop_container(envi, job.id)
            return self.fail(job, "cancelled")
        if result.timed_out:
            self.stop_container(envi, job.id)
            return self.fail(job, "timeout")
        if result.overflow:
            self.stop_container(envi, job.id)
            return self.fail(job, "output-too-large")
        if result.returncode != 0:
            code = gd.reason_code(result.stderr) or "container-failed"
            if os.environ.get("MWS_GHIDRA_DEBUG") == "1":
                # 開発者が明示したときだけ、手元の端末に診断を出す。利用者の
                # 画面・API・ログには出さない。
                print(result.stderr[-6000:].decode("utf-8", "replace"), file=sys.stderr)
            return self.fail(job, code if code in MESSAGES else "container-failed")

        self._set(job, "building")
        try:
            facts = static_facts.parse(
                result.stdout, expected_sha256=job.input_sha256,
                expected_ghidra=gd.GHIDRA_VERSION, expected_script=gd.SCRIPT_VERSION,
            )
        except static_facts.FactsInvalid as exc:
            return self.fail(job, exc.code if exc.code in MESSAGES else "output-invalid")
        try:
            lesson = static_lesson.build(
                facts,
                image={"imageRef": image.get("ref", ""), "imageId": image.get("id", ""),
                       "arch": image.get("arch", envi.server_arch),
                       "scriptSha256": gd.script_sha256(), "baseImage": gd.BASE_IMAGE},
                origin=job.origin,
                sample=self.sample_lookup(job.input_sha256),
            )
        except static_lesson.NoQuestions as exc:
            return self.fail(job, "no-questions", exc.reasons)
        if job.cancel.is_set():
            return self.fail(job, "cancelled")
        self.sink(lesson)
        job.lesson_id = lesson["id"]
        job.summary = {
            "title": lesson["title"],
            "questions": sum(len(s["quizzes"]) for s in lesson["stages"]),
            "questionCounts": lesson["static"]["questionCounts"],
            "skipped": lesson["static"]["skipped"],
            "truncated": lesson["static"]["truncated"],
            "sample": bool(lesson["static"].get("sample")),
        }
        self._set(job, "done")
        self.log("ghidra-lesson", f"{lesson['id']} {job.input_sha256[:12]}")

    # -- 準備 ------------------------------------------------------------
    def start_prepare(self, job: Job) -> None:
        t = threading.Thread(target=self._prepare, args=(job,), daemon=True,
                             name=f"ghidra-prepare-{job.id[:8]}")
        self.threads[job.id] = t
        t.start()

    def _prepare(self, job: Job) -> None:
        try:
            self._prepare_inner(job)
        except Exception:  # noqa: BLE001
            self.fail(job, "internal")

    def _prepare_inner(self, job: Job) -> None:
        try:
            envi = self.resolver()
            self.check_builder(envi)
        except gd.DockerProblem as exc:
            return self.fail(job, exc.code)
        result = self.run_process(
            gd.build_argv(envi), envi.env,
            deadline=time.monotonic() + gd.BUILD_DEADLINE, cancel=job.cancel,
            max_stdout=4 * 1024**2, max_stderr=4 * 1024**2,
        )
        job.seconds = result.seconds
        if result.cancelled:
            return self.fail(job, "cancelled")
        if result.timed_out:
            return self.fail(job, "prepare-timeout")
        if result.returncode != 0:
            text = (result.stderr + result.stdout)[-8000:].decode("utf-8", "replace")
            if os.environ.get("MWS_GHIDRA_DEBUG") == "1":
                print(text, file=sys.stderr)
            code = "disk-full" if "no space left" in text.lower() else "prepare-failed"
            return self.fail(job, code)
        image = self.image_state(envi)
        if image.get("state") != "ready":
            return self.fail(job, "prepare-failed")
        job.summary = {"imageRef": image.get("ref"), "imageId": image.get("id"),
                       "arch": image.get("arch")}
        self._set(job, "done")
        self.log("ghidra-prepare", f"{image.get('ref')} {str(image.get('id'))[:19]}")
