"""ghidra_live_check.py — 実コンテナでの受け入れ確認（任意・Docker が必要）。

    python3 backend/tests/ghidra_live_check.py [--save-fixture]

自動テスト（unittest）には含めない。手元の Docker と、準備済みの処理イメージを
前提に、同梱サンプルを本番と同じ部品で処理し、次を確かめて結果を表示する。

  1. サンプル GZF → 固定コマンドのコンテナ → JSON の検証 → 教材、が完了する。
     文字列参照・直接呼び出し・外部関数の設問がそれぞれ 1 問以上できる。
  2. 元の入力ファイルが変わっていない。
  3. 動いているコンテナの設定を docker inspect で確かめる（ネットワーク、マウント、
     ユーザー、権限、読み取り専用、上限、ログ、ラベル）。
  4. 処理中のコンテナのプロセスを docker top で繰り返し観測し、対象プログラムや
     入力のパスが実行ファイルとして現れないことを確かめる（観測できるのは、
     観測した間隔の範囲だけ。短命なプロセスを取りこぼす可能性はある）。
  5. docker stats でメモリと CPU の使用量を測る。
  6. キャンセルすると、コンテナが止まって消え、作業データも消える。

`--save-fixture` を付けると、抽出 JSON を tests/fixtures/ghidra/termmines-facts.json に
保存する（「事前抽出」と明記した回帰用の固定データ。本物の受け入れ確認の代わりにはしない）。
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import ghidra_api  # noqa: E402
import ghidra_docker as gd  # noqa: E402
import ghidra_intake as intake  # noqa: E402
import ghidra_jobs as jobs  # noqa: E402

FIXTURE = os.path.join(HERE, "fixtures", "ghidra", "termmines-facts.json")
#: 固定の処理（エントリポイント run-extract.sh と Ghidra の起動スクリプト）が
#: 動かすコマンド。エントリポイントに処理を足したら、ここにも足すこと
#: （test_ghidra_sample_build が、エントリポイントの呼ぶコマンドとの食い違いを見張る）。
ALLOWED_EXE = {"sh", "dash", "bash", "java", "run-extract.sh", "analyzeHeadless",
               "launch.sh", "mkdir", "cp", "cat", "grep", "tail", "dirname", "readlink",
               "uname", "sed", "tr", "cut", "head", "basename", "expr", "env", "which",
               "id", "ls", "sort", "awk", "test", "["}


def unexpected_executables(argv0s) -> list[str]:
    """観測したプロセスの実行ファイルのうち、固定の処理のものでないもの。

    入力・作業領域（/input、/tmp）に置かれたものが実行ファイルとして現れたら、
    名前に関わらず想定外とする（対象のプログラムや写しが起動した疑い）。
    """
    return sorted(p for p in set(argv0s)
                  if p.startswith(("/input", "/tmp")) or os.path.basename(p) not in ALLOWED_EXE)


def sh(argv, env, timeout=30):
    return subprocess.run(argv, env=env, capture_output=True, timeout=timeout, check=False)


def sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


class Observer(threading.Thread):
    """処理中のコンテナを見張る。inspect・top・stats を集める。"""

    def __init__(self, envi, job_id):
        super().__init__(daemon=True)
        self.envi = envi
        self.cname = gd.container_name(job_id)
        self.stop = threading.Event()
        self.inspect = None
        self.processes: set[str] = set()
        self.argv0: set[str] = set()
        self.mem_peak = 0.0
        self.cpu_peak = 0.0
        self.seen = threading.Event()
        #: docker top / stats が実際に成功した回数。0 なら観測できていない。
        self.top_ok = 0
        self.stats_ok = 0

    def run(self):
        d = self.envi.docker
        while not self.stop.is_set():
            if self.inspect is None:
                r = sh([d, "inspect", self.cname], self.envi.env)
                if r.returncode == 0:
                    self.inspect = json.loads(r.stdout)[0]
                    self.seen.set()
            if self.inspect is not None:
                # docker top は出力に PID の列が無いと失敗する（"Couldn't find PID field"）。
                top = sh([d, "top", self.cname, "-eo", "pid,comm,args"], self.envi.env)
                if top.returncode == 0:
                    self.top_ok += 1
                    for line in top.stdout.decode("utf-8", "replace").splitlines()[1:]:
                        parts = line.split(None, 2)
                        if len(parts) >= 2:
                            self.processes.add(parts[1])
                            if len(parts) > 2:
                                self.argv0.add(parts[2].split()[0])
                st = sh([d, "stats", "--no-stream", "--format", "{{json .}}", self.cname],
                        self.envi.env)
                if st.returncode == 0 and st.stdout.strip():
                    self.stats_ok += 1
                    try:
                        row = json.loads(st.stdout)
                        mem = row.get("MemUsage", "0MiB").split("/")[0].strip()
                        self.mem_peak = max(self.mem_peak, _mib(mem))
                        self.cpu_peak = max(self.cpu_peak, float(row.get("CPUPerc", "0%").rstrip("%") or 0))
                    except (ValueError, json.JSONDecodeError):
                        pass
            time.sleep(0.3)


def _mib(text: str) -> float:
    units = {"B": 1 / 1024**2, "KiB": 1 / 1024, "kB": 1 / 1024, "MiB": 1, "MB": 1,
             "GiB": 1024, "GB": 1024}
    for u in sorted(units, key=len, reverse=True):
        if text.endswith(u):
            return float(text[: -len(u)]) * units[u]
    return 0.0


def check_inspect(info, uid, gid, input_dir) -> list[str]:
    problems = []
    hc = info["HostConfig"]
    cfg = info["Config"]

    def need(cond, what):
        if not cond:
            problems.append(what)

    need(hc.get("NetworkMode") == "none", "network is not none")
    need(set((info.get("NetworkSettings") or {}).get("Networks") or {}) <= {"none"}, "attached to a network")
    need(hc.get("Privileged") is False, "privileged")
    need(hc.get("ReadonlyRootfs") is True, "root fs is writable")
    need(hc.get("CapDrop") == ["ALL"] or hc.get("CapDrop") == ["all"], f"cap drop {hc.get('CapDrop')}")
    need(not hc.get("CapAdd"), "caps added")
    need(any("no-new-privileges" in o for o in hc.get("SecurityOpt") or []), "no-new-privileges missing")
    need(hc.get("Memory") == 4 * 1024**3, f"memory {hc.get('Memory')}")
    need(hc.get("MemorySwap") == 4 * 1024**3, f"memory swap {hc.get('MemorySwap')}")
    need(hc.get("NanoCpus") == 2 * 10**9, f"cpus {hc.get('NanoCpus')}")
    need(hc.get("PidsLimit") == gd.LIMITS["pids"], f"pids {hc.get('PidsLimit')}")
    need((hc.get("LogConfig") or {}).get("Type") == "none", "log driver")
    need(not hc.get("PortBindings"), "ports published")
    need((hc.get("PidMode") or "") == "" and (hc.get("IpcMode") or "private") in ("private", "none", ""),
         "shared pid/ipc")
    need(cfg.get("User") == f"{uid}:{gid}", f"user {cfg.get('User')}")
    tmpfs = hc.get("Tmpfs") or {}
    need(list(tmpfs) == ["/tmp"] and "noexec" in tmpfs["/tmp"], f"tmpfs {tmpfs}")
    mounts = info.get("Mounts") or []
    need(len(mounts) == 1, f"{len(mounts)} mounts")
    if mounts:
        m = mounts[0]
        need(m.get("Type") == "bind" and m.get("Destination") == "/input"
             and m.get("RW") is False, f"mount {m}")
        need(os.path.realpath(m.get("Source", "")) == os.path.realpath(input_dir)
             or m.get("Source", "").endswith(os.path.relpath(input_dir, "/")), "mount source")
    labels = cfg.get("Labels") or {}
    need(labels.get(gd.LABEL_APP) == gd.LABEL_APP_VALUE, "app label")
    need(cfg.get("Entrypoint") == ["/opt/zip2learn/bin/run-extract.sh"], f"entrypoint {cfg.get('Entrypoint')}")
    need(not cfg.get("Cmd"), f"cmd {cfg.get('Cmd')}")
    return problems


def main() -> int:
    save_fixture = "--save-fixture" in sys.argv
    report: dict = {"checkedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    try:
        envi = gd.resolve()
    except gd.DockerProblem as exc:
        print(f"Docker を使えません: {exc.code} — {jobs.message(exc.code)}")
        return 2
    image = gd.image_state(envi)
    report["docker"] = {"arch": envi.server_arch, "version": envi.server_version,
                        "endpoint": envi.endpoint.split("://")[0]}
    report["image"] = image
    if image.get("state") != "ready":
        print("処理イメージが準備されていません。アプリの「処理環境を準備する」を先に実行してください。")
        return 2
    sample = ghidra_api.load_sample()
    if not sample or not sample.get("available"):
        print("同梱サンプル（ghidra/sample/termmines.gzf）がありません。")
        return 2
    before = sha256(sample["path"])
    report["sample"] = {"sha256": before, "matchesManifest": before == sample.get("sha256")}

    tmp = tempfile.mkdtemp(prefix="zip2learn-live-")
    saved = []
    captured = {}
    real_run = gd.run_process

    def capture(argv, env, **kw):
        result = real_run(argv, env, **kw)
        captured["stdout"] = result.stdout
        captured["seconds"] = result.seconds
        return result

    manager = jobs.JobManager(os.path.join(tmp, "jobs"), gd.owner_id(tmp),
                              sink=saved.append, sample_lookup=ghidra_api.sample_lookup,
                              run_process=capture)
    try:
        # ---- 1〜5: 処理を最後まで ----
        job = manager.reserve("analyze", {"kind": "sample", "name": "termmines"})
        dest = os.path.join(manager.make_input_dir(job), "input.gzf")
        with open(sample["path"], "rb") as src:
            sha, size = intake.receive_upload(src, os.path.getsize(sample["path"]), dest,
                                              cancel=job.cancel, deadline=time.monotonic() + 60)
        intake.check_copy(dest)
        obs = Observer(envi, job.id)
        obs.start()
        t0 = time.monotonic()
        manager.start_analysis(job, sha, size)
        manager.threads[job.id].join(gd.RUN_DEADLINE + 30)
        obs.stop.set()
        obs.join(5)
        report["run"] = {"state": job.state, "error": job.error, "reasons": job.reasons,
                         "seconds": round(time.monotonic() - t0, 1),
                         "containerSeconds": round(captured.get("seconds", 0), 1)}
        if job.state == "done":
            lesson = saved[0]
            report["lesson"] = {"id": lesson["id"],
                                "questionCounts": lesson["static"]["questionCounts"],
                                "counts": lesson["static"]["counts"],
                                "truncated": lesson["static"]["truncated"],
                                "skipped": lesson["static"]["skipped"]}
            if save_fixture and captured.get("stdout"):
                os.makedirs(os.path.dirname(FIXTURE), exist_ok=True)
                doc = json.loads(captured["stdout"])
                with open(FIXTURE, "w", encoding="utf-8") as fh:
                    json.dump({"_note": "事前抽出。ghidra_live_check.py --save-fixture が"
                               "実コンテナの出力をそのまま保存したもの。受け入れ確認の代わりにはしない。",
                               "_image": image, "facts": doc}, fh, ensure_ascii=False, indent=1)
                    fh.write("\n")
                report["fixture"] = os.path.relpath(FIXTURE, os.path.dirname(os.path.dirname(HERE)))
        report["inputUnchanged"] = sha256(sample["path"]) == before
        report["jobDirRemoved"] = not os.path.exists(manager.job_dir(job))
        report["inspect"] = ("未確認（コンテナを観測できなかった）" if obs.inspect is None else
                             check_inspect(obs.inspect, os.getuid(), os.getgid(),
                                           manager.input_dir(job)) or "ok")
        report["processObservations"] = obs.top_ok
        report["processes"] = sorted(obs.processes)
        report["unexpectedExecutables"] = unexpected_executables(obs.argv0)
        report["resources"] = ({"memPeakMiB": round(obs.mem_peak), "cpuPeakPercent": obs.cpu_peak,
                                "samples": obs.stats_ok}
                               if obs.stats_ok else "未測定（docker stats を取得できなかった）")
        try:
            report["leftoverContainers"] = len(gd.owned_containers(envi, manager.owner))
        except gd.DockerProblem:
            # 問い合わせの失敗は「取り残しなし」ではない。
            report["leftoverContainers"] = "未確認（一覧を取得できなかった）"

        # ---- 6: キャンセル ----
        job2 = manager.reserve("analyze", {"kind": "sample", "name": "termmines"})
        dest = os.path.join(manager.make_input_dir(job2), "input.gzf")
        with open(sample["path"], "rb") as src:
            sha, size = intake.receive_upload(src, os.path.getsize(sample["path"]), dest,
                                              cancel=job2.cancel, deadline=time.monotonic() + 60)
        obs2 = Observer(envi, job2.id)
        obs2.start()
        manager.start_analysis(job2, sha, size)
        observed = obs2.seen.wait(60)
        time.sleep(2)
        running = sh([envi.docker, "inspect", "-f", "{{.State.Running}}",
                      gd.container_name(job2.id)], envi.env)
        running_at_cancel = observed and running.returncode == 0 and running.stdout.strip() == b"true"
        manager.cancel(job2.id)
        manager.threads[job2.id].join(60)
        obs2.stop.set()
        time.sleep(1)
        # Docker が「無い」と答えた場合だけ削除済み。問い合わせの失敗は未確認。
        state = gd.container_state(envi, gd.container_name(job2.id))
        gone = None if state is None else state == "absent"
        report["cancel"] = {"state": job2.state, "containerObserved": observed,
                            "runningAtCancel": running_at_cancel,
                            "containerRemoved": gone,
                            "jobDirRemoved": not os.path.exists(manager.job_dir(job2))}
    finally:
        try:
            gd.remove_owned(envi, manager.owner)
        except Exception:  # noqa: BLE001
            pass
        shutil.rmtree(tmp, ignore_errors=True)

    report["checks"] = checks = judge(report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    ok = all(v == "確認済み" for v in checks.values())
    print("\n受け入れ確認:", "合格" if ok else "不合格（未確認の項目を含む）")
    return 0 if ok else 1


def judge(report: dict) -> dict:
    """項目ごとに「確認済み」「不合格」「未確認」を決める。

    観測できなかったものは合格にしない。たとえば docker top が一度も成功して
    いなければ、異常なプロセスが見つからなかったことは何の証拠にもならない。
    キャンセルも、動いているコンテナを取り消して止まったことを見た場合だけ
    確認済みとする（起動前に取り消しただけでは、停止を確かめたことにならない）。
    """
    run = report.get("run", {})
    counts = report.get("lesson", {}).get("questionCounts") or {}
    cancel = report.get("cancel", {})
    inspect = report.get("inspect")

    def verdict(observed: bool, passed: bool) -> str:
        if not observed:
            return "未確認"
        return "確認済み" if passed else "不合格"

    return {
        "教材の完成（3 種類の設問）": verdict(
            run.get("state") is not None,
            run.get("state") == "done" and len(counts) == 3
            and all(v >= 1 for v in counts.values())),
        "入力が変わっていない": verdict("inputUnchanged" in report, bool(report.get("inputUnchanged"))),
        "作業データの削除": verdict("jobDirRemoved" in report, bool(report.get("jobDirRemoved"))),
        "コンテナの設定（inspect）": verdict(isinstance(inspect, (str, list)) and inspect != ""
                                        and not str(inspect).startswith("未確認"),
                                        inspect == "ok"),
        "対象が起動していない（プロセス観測）": verdict(
            report.get("processObservations", 0) > 0, not report.get("unexpectedExecutables")),
        "資源使用の実測": verdict(isinstance(report.get("resources"), dict), True),
        "コンテナの取り残しなし": verdict(isinstance(report.get("leftoverContainers"), int),
                                   report.get("leftoverContainers") == 0),
        "キャンセルで停止・削除": verdict(
            bool(cancel.get("containerObserved")) and bool(cancel.get("runningAtCancel"))
            and cancel.get("containerRemoved") is not None,
            cancel.get("state") == "cancelled" and cancel.get("containerRemoved") is True
            and bool(cancel.get("jobDirRemoved"))),
    }


if __name__ == "__main__":
    sys.exit(main())
