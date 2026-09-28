// ghidra.js — Ghidra のファイル（.gzf）から演習を作る画面。
//
// 利用者がするのは、ファイルを選んで「演習を作成する」を押すところまで。
// Ghidra の起動や JSON の書き出しは求めない。処理はこの PC の Docker の中で、
// サーバーが固定のコマンドだけを使って行う。対象プログラムは実行しない。
//
// ファイル選択の accept は補助にすぎない（本当の確認はサーバーが中身で行う）。
// ブラウザから絶対パスは受け取らない。ファイルの中身だけを送る。
//
// サーバーからの文字列（ファイル名・プログラム名・理由）はすべて textContent と
// visible() で描く。

import { visible } from './evidence.js';

const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
};

function token() {
  const meta = document.querySelector('meta[name="mws-token"]');
  return meta ? meta.content : '';
}

/** 応答を JSON で読む。失敗しても {error, code} の形に揃えて返す。 */
async function call(path, options = {}) {
  let res;
  try {
    res = await fetch(path, {
      ...options,
      headers: { 'Content-Type': 'application/json', 'X-MWS-Token': token(), ...(options.headers || {}) },
    });
  } catch (err) {
    if (err && err.name === 'AbortError') {
      return { ok: false, status: 0, aborted: true, body: { error: '送信を取り消しました。' } };
    }
    return { ok: false, status: 0, body: { error: 'サーバーに接続できません。python3 backend/api.py で起動しているか確かめてください。' } };
  }
  const body = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, body };
}

const DOCKER_TEXT = {
  ready: 'この PC の Docker に接続できました。',
};

const IMAGE_TEXT = {
  ready: '処理環境は準備済みです。',
  missing: '処理環境がまだありません。最初に一度だけ準備が必要です。',
  outdated: '処理環境が古い版です。作り直してください。',
  unknown: '処理環境の状態を確かめられませんでした。',
};

const PHASE_ORDER = ['receiving', 'checking', 'reading', 'building', 'done'];
const PHASE_LABEL = {
  receiving: 'ファイルを受け取る',
  checking: 'ファイル確認中',
  reading: 'Ghidra で読み取り中',
  building: '教材生成中',
  done: '完了',
};

function homeNav() {
  const nav = el('div', 'navbtns navbtns--home');
  const home = el('button', 'btn btn-ghost', '← ホームに戻る');
  home.type = 'button';
  home.addEventListener('click', () => {
    location.hash = '#/';
  });
  nav.append(home);
  return nav;
}

const mb = (n) => `${Math.round(n / 1024 / 1024)} MB`;

/**
 * @param {HTMLElement} mount
 * @param {{poll?: number}} [opts] poll はテスト用に待ち時間を縮めるためのもの
 */
export async function renderGhidra(mount, opts = {}) {
  const pollMs = opts.poll || 1000;
  mount.textContent = '';

  const hero = el('section', 'hero');
  const h1 = el('h1', null, 'Ghidra ファイルから演習を作る');
  h1.tabIndex = -1;
  hero.append(h1);
  hero.append(
    el('p', null,
      'Ghidra で解析して保存した .gzf ファイルから、保存済みの解析情報（関数・命令・文字列・参照）を読み出し、根拠付きの設問を作ります。対象のプログラムは実行しません。')
  );
  mount.append(hero);
  mount.append(homeNav());
  h1.focus({ preventScroll: true });

  const statusPanel = el('section', 'panel');
  const inputPanel = el('section', 'panel');
  const jobPanel = el('section', 'panel');
  jobPanel.setAttribute('role', 'status');
  jobPanel.setAttribute('aria-live', 'polite');
  jobPanel.hidden = true;
  mount.append(statusPanel, jobPanel, inputPanel);

  let status = null;

  // ---- 状態 ---------------------------------------------------------------
  const loadStatus = async (refresh) => {
    statusPanel.textContent = '';
    statusPanel.append(el('div', 'panel__label', '処理環境'));
    statusPanel.append(el('p', 'muted', '確認しています…'));
    const r = await call(`/api/ghidra/status${refresh ? '?refresh=1' : ''}`);
    if (!statusPanel.isConnected) return null;
    if (!r.ok) {
      statusPanel.textContent = '';
      statusPanel.append(el('div', 'panel__label', '処理環境'));
      statusPanel.append(
        el('p', 'feedback is-bad',
          r.status === 403
            ? 'この権限では Ghidra ファイルからの演習作成は使えません。教材を配った人の側で作成してください。'
            : r.body.error || '状態を取得できませんでした。')
      );
      inputPanel.hidden = true;
      return null;
    }
    status = r.body;
    drawStatus();
    drawInput();
    if (status.job && !status.job.final) watch(status.job);
    return status;
  };

  const drawStatus = () => {
    const d = status.docker || {};
    const img = status.image || {};
    const pin = status.pinned || {};
    statusPanel.textContent = '';
    statusPanel.append(el('div', 'panel__label', '処理環境'));

    const dockerOk = d.state === 'ready';
    statusPanel.append(
      el('div', dockerOk ? 'claims__item' : 'member__warn',
        dockerOk
          ? `✓ ${DOCKER_TEXT.ready}（${visible(d.arch || '')}・Docker ${visible(d.version || '')}）`
          : `⚠ ${visible(d.message || d.state || '')}`)
    );
    if (dockerOk) {
      const imgOk = img.state === 'ready';
      statusPanel.append(
        el('div', imgOk ? 'claims__item' : 'member__warn',
          `${imgOk ? '✓' : '⚠'} ${IMAGE_TEXT[img.state] || IMAGE_TEXT.unknown}`)
      );
      // 準備を勧めるのは、Docker が「イメージが無い／古い」と答えたときだけ。
      // 確かめられなかった（unknown）ときは、確認し直しを案内する。
      if (img.state === 'unknown') {
        statusPanel.append(
          el('p', 'muted', 'Docker からの応答を確かめられませんでした。Docker が動いているか確かめて、「状態を確認し直す」を押してください。')
        );
      }
      if ((img.state === 'missing' || img.state === 'outdated') && status.canPrepare) {
        statusPanel.append(
          el('p', 'muted',
            `初回の準備では、固定したベースイメージ（JDK 21）と Ghidra ${visible(pin.ghidraVersion || '')} の公式配布物（約 570 MB）をインターネットから取得し、この PC の Docker の中で処理環境を組み立てます。数 GB の空きディスクと、回線によっては十数分かかります。取得したファイルのチェックサムは固定値と照合します。`)
        );
        const nav = el('div', 'navbtns navbtns--wrap');
        const prep = el('button', 'btn btn-primary', '処理環境を準備する');
        prep.type = 'button';
        prep.addEventListener('click', async () => {
          prep.disabled = true;
          const r = await call('/api/ghidra/prepare', { method: 'POST', body: '{}' });
          if (!statusPanel.isConnected) return;
          if (r.ok && r.body.job) {
            watch(r.body.job);
          } else {
            prep.disabled = false;
            statusPanel.append(el('p', 'feedback is-bad', visible(r.body.error || '開始できませんでした。')));
          }
        });
        nav.append(prep);
        statusPanel.append(nav);
      }
    } else if (d.state === 'docker-missing' || d.state === 'docker-not-running') {
      statusPanel.append(
        el('p', 'muted',
          'Docker Desktop（Mac / Windows）または Docker Engine（Linux）を導入・起動してから、下の「状態を確認し直す」を押してください。Docker が無くても、ログからの演習作成はこれまでどおり使えます。')
      );
    }

    const again = el('button', 'btn btn-ghost btn-sm', '状態を確認し直す');
    again.type = 'button';
    again.addEventListener('click', () => loadStatus(true));
    const nav2 = el('div', 'navbtns navbtns--wrap');
    nav2.append(again);
    statusPanel.append(nav2);

    // 固定している版。何で処理したのかを、後から確かめられるように。
    const fold = document.createElement('details');
    fold.className = 'fold';
    const head = document.createElement('summary');
    head.className = 'fold__head';
    head.textContent = '固定している版と上限';
    fold.append(head);
    const dl = el('dl', 'factlist');
    const lim = status.limits || {};
    [
      ['Ghidra', `${pin.ghidraVersion || ''}（${pin.ghidraZip || ''}）`],
      ['Ghidra 配布物の SHA-256', pin.ghidraZipSha256 || ''],
      ['ベースイメージ', pin.baseImage || ''],
      ['抽出スクリプト', `${pin.scriptVersion || ''}（SHA-256 ${pin.scriptSha256 || ''}）`],
      ['処理イメージ', img.id ? `${pin.imageRef || ''}（${img.id}）` : pin.imageRef || ''],
      ['GZF の上限', lim.maxGzfBytes ? `${mb(lim.maxGzfBytes)}（展開後 ${mb(lim.maxUnpackedBytes)}）` : ''],
      ['1 回の処理時間の上限', lim.runSeconds ? `${lim.runSeconds} 秒` : ''],
    ].forEach(([k, v]) => {
      dl.append(el('dt', 'factlist__key', k));
      dl.append(el('dd', 'factlist__value mono', visible(String(v))));
    });
    fold.append(dl);
    statusPanel.append(fold);
  };

  // ---- 入力 ---------------------------------------------------------------
  const drawInput = () => {
    inputPanel.textContent = '';
    inputPanel.hidden = false;
    inputPanel.append(el('div', 'panel__label', 'GZF ファイルを選ぶ'));
    const ready = status.docker.state === 'ready' && status.image.state === 'ready';
    const lim = status.limits || {};
    inputPanel.append(
      el('p', null,
        `Ghidra の File → Export Program で「Ghidra Zip File」形式にしたもの、またはプロジェクトから保存した .gzf を選んでください。解析済み（Analyze を実行して保存した）ものが必要です。上限は ${lim.maxGzfBytes ? mb(lim.maxGzfBytes) : '64 MB'} です。`)
    );
    inputPanel.append(
      el('p', 'muted',
        'ファイルはこの PC の中だけで処理し、外部の解析サーバーへは送りません。処理のための一時的なコピーは、終わりしだい削除します。作った教材（採用した根拠・版・ハッシュ）はこの PC のデータベースに保存されます。')
    );

    const row = el('div', 'browser__bar');
    const input = el('input', 'text-input');
    input.type = 'file';
    input.accept = '.gzf';
    input.id = 'ghidra-file';
    const label = el('label', 'muted', 'GZF ファイル：');
    label.setAttribute('for', input.id);
    row.append(label, input);
    inputPanel.append(row);

    const nav = el('div', 'navbtns navbtns--wrap');
    const go = el('button', 'btn btn-primary', '演習を作成する');
    go.type = 'button';
    go.disabled = !ready;
    nav.append(go);

    const sample = status.sample || {};
    let trySample = null;
    if (sample.available) {
      trySample = el('button', 'btn btn-ghost', `同梱サンプル（${visible(sample.name || '')}）で試す`);
      trySample.type = 'button';
      trySample.disabled = !ready;
      nav.append(trySample);
    }
    inputPanel.append(nav);
    if (sample.available && sample.note) {
      inputPanel.append(el('p', 'muted', visible(sample.note)));
    }
    if (!ready) {
      inputPanel.append(
        el('p', 'member__warn', '⚠ 処理環境の準備ができるまで、演習は作成できません。')
      );
    }

    const out = el('div');
    inputPanel.append(out);
    const fail = (text) => {
      out.textContent = '';
      out.append(el('p', 'feedback is-bad', visible(text)));
    };

    go.addEventListener('click', async () => {
      const file = input.files && input.files[0];
      if (!file) {
        fail('ファイルを選んでください。');
        input.focus();
        return;
      }
      if (lim.maxGzfBytes && file.size > lim.maxGzfBytes) {
        fail(`ファイルが大きすぎます（上限 ${mb(lim.maxGzfBytes)}）。`);
        return;
      }
      out.textContent = '';
      go.disabled = true;
      if (trySample) trySample.disabled = true;
      const enable = () => {
        go.disabled = false;
        if (trySample) trySample.disabled = false;
      };

      // 先に処理枠を予約し、取り消しに使うジョブ ID を受け取ってから本文を送る。
      // 通信を切るだけでは、本文が届き終えて確認中・応答待ちのときにサーバー側の
      // 処理が止まらないため、キャンセルはこの ID の取り消しと通信の中断を両方行う。
      const rsv = await call('/api/ghidra/jobs/new', {
        method: 'POST',
        body: JSON.stringify({ name: file.name, size: file.size }),
      });
      if (!inputPanel.isConnected) return;
      if (!rsv.body.job || rsv.body.job.final) {
        enable();
        jobPanel.hidden = true;
        fail(rsv.body.error || '開始できませんでした。');
        return;
      }
      const job = rsv.body.job;
      const controller = typeof AbortController === 'function' ? new AbortController() : null;
      let cancelled = false;
      showSending(file.name, async () => {
        cancelled = true;
        await call(`/api/ghidra/jobs/${encodeURIComponent(job.id)}/cancel`, {
          method: 'POST',
          body: '{}',
        });
        if (controller) controller.abort();
      });
      const r = await call(`/api/ghidra/jobs/${encodeURIComponent(job.id)}/upload`, {
        method: 'POST',
        body: file,
        signal: controller ? controller.signal : undefined,
        headers: { 'Content-Type': 'application/octet-stream' },
      });
      if (!inputPanel.isConnected) return;
      enable();
      if (cancelled) {
        // 取り消しが間に合ったかどうかは、サーバー側の最終状態で示す。
        watch({ ...job, final: false });
        return;
      }
      if (r.body.job && !r.aborted) {
        watch(r.body.job);
      } else {
        jobPanel.hidden = true;
        fail(r.body.error || '送信できませんでした。');
      }
    });

    if (trySample) {
      trySample.addEventListener('click', async () => {
        trySample.disabled = true;
        go.disabled = true;
        const r = await call('/api/ghidra/jobs/sample', { method: 'POST', body: '{}' });
        if (!inputPanel.isConnected) return;
        trySample.disabled = false;
        go.disabled = false;
        if (r.body.job) watch(r.body.job);
        else fail(r.body.error || '開始できませんでした。');
      });
    }
  };

  const showSending = (name, abort) => {
    jobPanel.hidden = false;
    jobPanel.textContent = '';
    jobPanel.append(el('div', 'panel__label', '処理の状況'));
    jobPanel.append(el('p', null, `${visible(name)} を送っています…`));
    if (abort) {
      const nav = el('div', 'navbtns navbtns--wrap');
      const stop = el('button', 'btn btn-ghost', 'キャンセル');
      stop.type = 'button';
      stop.addEventListener('click', () => {
        stop.disabled = true;
        abort();
      });
      nav.append(stop);
      jobPanel.append(nav);
    }
  };

  // ---- 進捗 ---------------------------------------------------------------
  let watching = null;
  const watch = (job) => {
    watching = job.id;
    drawJob(job);
    const tick = async () => {
      if (!jobPanel.isConnected || watching !== job.id) return;
      const r = await call(`/api/ghidra/jobs/${encodeURIComponent(job.id)}`);
      // 画面を離れた後の応答は、どこにも描かない。
      if (!jobPanel.isConnected || watching !== job.id) return;
      if (!r.ok || !r.body.job) return;
      drawJob(r.body.job);
      if (!r.body.job.final) setTimeout(tick, pollMs);
      else if (r.body.job.kind === 'prepare') loadStatus(true);
    };
    if (!job.final) setTimeout(tick, pollMs);
  };

  /**
   * 実行中を示す 3 つの点。動きは CSS（.working-dots）で付け、動きを減らす
   * 設定では止まった点になる。読み上げには出さない（段階の文言と
   * aria-current で伝わる）。
   */
  const workingDots = () => {
    const dots = el('span', 'working-dots');
    dots.setAttribute('aria-hidden', 'true');
    dots.append(el('span'), el('span'), el('span'));
    return dots;
  };

  // 前回描いたジョブと段階。同じ段階のままなら、経過秒数だけを書き換える。
  // 毎回作り直すと、点のアニメーションが取り直しのたびに最初から始まって
  // 途切れて見えるうえ、押した「キャンセル」も押せる状態に戻ってしまう。
  let drawn = null;

  const drawJob = (job) => {
    if (drawn && drawn.id === job.id && drawn.state === job.state && !job.final
        && drawn.elapsed.isConnected) {
      drawn.elapsed.textContent = drawn.text(job);
      return;
    }
    drawn = null;
    jobPanel.hidden = false;
    jobPanel.textContent = '';
    jobPanel.append(el('div', 'panel__label', job.kind === 'prepare' ? '処理環境の準備' : '処理の状況'));

    const origin = job.origin || {};
    if (origin.kind === 'upload') jobPanel.append(el('p', 'muted mono', visible(origin.name || '')));
    if (origin.kind === 'archive') {
      jobPanel.append(el('p', 'muted mono', `${visible(origin.archiveName || '')} :: ${visible(origin.member || '')}`));
    }
    if (origin.kind === 'sample') jobPanel.append(el('p', 'muted', `同梱サンプル: ${visible(origin.name || '')}`));

    let elapsed = null;
    let text = null;
    if (job.kind === 'prepare') {
      text = (j) => `${visible(j.phase)}（${Math.round(j.elapsed)} 秒経過）`;
      const line = el('p', job.state === 'failed' ? 'feedback is-bad' : 'muted');
      if (!job.final) line.append(workingDots());
      elapsed = el('span', null, text(job));
      line.append(elapsed);
      jobPanel.append(line);
    } else {
      const steps = el('ol', 'bullets');
      const at = PHASE_ORDER.indexOf(job.state);
      PHASE_ORDER.forEach((p, i) => {
        const running = i === at && !job.final;
        let mark = '・';
        if (job.state === 'done' || (at >= 0 && i < at)) mark = '✓';
        const li = el('li', null);
        // 実行中の段階は、矢印の代わりに動く 3 つの点で示す。
        if (running) li.append(workingDots(), el('span', null, PHASE_LABEL[p]));
        else li.textContent = `${mark} ${PHASE_LABEL[p]}`;
        if (running) li.setAttribute('aria-current', 'step');
        steps.append(li);
      });
      jobPanel.append(steps);
      if (!job.final) {
        text = (j) => `${visible(j.phase)}…（${Math.round(j.elapsed)} 秒経過）`;
        elapsed = el('p', 'muted', text(job));
        jobPanel.append(elapsed);
      }
    }
    if (!job.final && elapsed) drawn = { id: job.id, state: job.state, elapsed, text };

    if (!job.final) {
      const nav = el('div', 'navbtns navbtns--wrap');
      const stop = el('button', 'btn btn-ghost', 'キャンセル');
      stop.type = 'button';
      stop.addEventListener('click', async () => {
        stop.disabled = true;
        stop.textContent = '止めています…';
        await call(`/api/ghidra/jobs/${encodeURIComponent(job.id)}/cancel`, { method: 'POST', body: '{}' });
      });
      nav.append(stop);
      jobPanel.append(nav);
      return;
    }

    if (job.state === 'done' && job.kind === 'prepare') {
      jobPanel.append(el('p', 'feedback is-ok', '処理環境を準備しました。'));
      return;
    }
    if (job.state === 'done') {
      const s = job.summary || {};
      const c = s.questionCounts || {};
      jobPanel.append(el('p', 'feedback is-ok', `演習ができました：${visible(s.title || '')}`));
      jobPanel.append(
        el('p', null,
          `設問 ${s.questions || 0} 問（文字列の参照 ${c.string || 0}・直接呼び出し ${c.call || 0}・外部関数 ${c.external || 0}）。自動生成した下書きです。使う前に内容を確認してください。`)
      );
      (s.skipped || []).forEach((t) => jobPanel.append(el('div', 'member__warn', `⚠ ${visible(t)}`)));
      if ((s.truncated || []).length) {
        jobPanel.append(el('div', 'member__warn', '⚠ 上限に達したため、一部の記録を読み出していません。'));
      }
      const nav = el('div', 'navbtns navbtns--wrap');
      const start = el('button', 'btn btn-primary', '演習を始める');
      start.type = 'button';
      start.addEventListener('click', () => {
        location.hash = `#/lesson/${job.lessonId}`;
      });
      nav.append(start);
      jobPanel.append(nav);
      start.focus({ preventScroll: true });
      return;
    }

    const err = job.error || {};
    jobPanel.append(el('p', 'feedback is-bad', visible(err.message || job.phase)));
    (err.reasons || []).forEach((t) => jobPanel.append(el('div', 'member__warn', `⚠ ${visible(t)}`)));
    jobPanel.append(
      el('p', 'muted', '作業用のコピーは削除済みです。設定や安全のための制限を緩める必要はありません。ファイルや状態を確かめてから、もう一度試してください。')
    );
  };

  await loadStatus(false);
}
