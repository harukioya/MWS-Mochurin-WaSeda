// inspect.js — the archive inspector: inventory, per-member triage, hexdump.
//
// Answers the learner's real question for every file: *can the operating
// system run this, and how do we know?* Everything shown here comes from the
// local backend, which reads archive metadata and a bounded prefix of each
// member. Nothing is extracted, downloaded, or executed.
//
// All text is set with textContent. Member names come from inside archives and
// are attacker-controlled strings; they are never interpolated into markup.

// Bidirectional controls reverse how a name renders: `payroll<RLO>gnp.exe`
// displays as `payrollexe.png`. CSS isolation stops the reorder leaking into
// the surrounding row, but it does NOT neutralise it inside the name, so the
// controls are escaped to visible sentinels before display.
const BIDI = /[\u202A-\u202E\u2066-\u2069\u200E\u200F]/g;
const showBidi = (s) =>
  String(s).replace(BIDI, (c) => `<U+${c.codePointAt(0).toString(16).toUpperCase()}>`);
const hasBidi = (s) => BIDI.test(String(s));

const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
};

/** The backend injects this into index.html at serve time. */
function token() {
  const meta = document.querySelector('meta[name="mws-token"]');
  return meta ? meta.content : '';
}

async function api(path, options) {
  const res = await fetch(path, {
    ...options,
    headers: { 'Content-Type': 'application/json', 'X-MWS-Token': token() },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `要求に失敗しました (${res.status})`);
  }
  return res.json();
}

/** Map a verdict to a severity class. Anything runnable reads as danger. */
const SEVERITY = {
  'inert-data': 'is-ok',
  container: 'is-neutral',
  script: 'is-bad',
  'document-with-active-content': 'is-bad',
  'shortcut-or-launcher': 'is-bad',
  'native-executable': 'is-bad',
  'bytecode-archive': 'is-bad',
  'sample-bearing': 'is-bad',
  unknown: 'is-bad',
  'opaque-encrypted': 'is-warn',
  'unsupported-container': 'is-warn',
  'forensic-image': 'is-warn',
};

// Plain-language answers. These state what was actually CHECKED, not a promise
// of safety: "safe to open" would be a claim the classifier has not earned,
// and BUILD-CONTRACT rule 8 makes an unearned reassurance a defect.
const PLAIN = {
  'inert-data': '実行可能な構造は見つかりませんでした',
  container: '書庫です。中身を確認してください',
  script: 'スクリプトです。実行権限がなくても、対応する実行環境があれば動作します',
  'document-with-active-content': '開いたときに動作する内容を含み得ます',
  'shortcut-or-launcher': '開くと別のプログラムを起動します',
  'native-executable': '基本ソフトが直接実行できるプログラムです',
  'bytecode-archive': 'Java などの実行環境の上で動作します',
  'sample-bearing': '検体の元のバイト列を含んでおり、道具を使えば復元できます',
  unknown: '種別を特定できません。プログラムと同等に扱います',
  'opaque-encrypted': '暗号化されており、中身を確認できません',
  'unsupported-container': '未対応の形式のため開けません。安全とは見なしません',
  'forensic-image': 'ディスクイメージまたはメモリイメージです。プログラムを含み得ます',
};

/** Display names for backend role keys. The key itself is never changed. */
const ROLE_LABEL = { student: '受講者', instructor: '指導者' };

/** Display names for archive verification states. */
const STATUS_LABEL = { ok: '検証済み', changed: '変更あり', missing: '見つかりません' };

function verdictBadge(verdict) {
  const badge = el('span', `verdict ${SEVERITY[verdict] || 'is-warn'}`, verdict);
  badge.title = PLAIN[verdict] || verdict;
  return badge;
}

// ---------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------

export async function renderInspect(mount) {
  mount.textContent = '';

  const hero = el('section', 'hero');
  hero.append(el('div', 'eyebrow', '検査'));
  const h1 = el('h1', null, 'この書庫には何が入っているか');
  h1.tabIndex = -1;
  hero.append(h1);
  hero.append(
    el(
      'p',
      null,
      '書庫内の各項目について、その種別と、基本ソフトが実行できる形式かどうかを判定します。'
    )
  );
  mount.append(hero);
  h1.focus({ preventScroll: true });

  const status = el('div', 'panel');
  mount.append(status);
  const list = el('div', 'home-grid');
  mount.append(list);

  try {
    const [{ role, claims }, { archives }] = await Promise.all([
      api('/api/status'),
      api('/api/archives'),
    ]);
    renderClaims(status, role, claims);
    if (!archives.length) {
      renderScanPrompt(list, mount);
      return;
    }
    archives.forEach((a) => list.append(archiveCard(a)));
  } catch (err) {
    status.textContent = '';
    status.append(el('div', 'panel__label', 'サーバー側に接続できません'));
    status.append(
      el(
        'p',
        'muted',
        '検査機能にはサーバー側の起動が必要です。次のコマンドで起動してください: python3 backend/api.py'
      )
    );
  }
}

/** State exactly what the integrity check does and does not cover. */
function renderClaims(mount, role, claims) {
  mount.textContent = '';
  mount.append(
    el('div', 'panel__label', `完全性の点検 · 権限: ${ROLE_LABEL[role] || role}`)
  );

  const yes = el('div', 'claims');
  yes.append(el('div', 'claims__head is-ok', '検出できるもの'));
  claims.detects.forEach((c) => yes.append(el('div', 'claims__item', c)));
  mount.append(yes);

  const no = el('div', 'claims');
  no.append(el('div', 'claims__head is-bad', '検出できないもの'));
  claims.doesNotDetect.forEach((c) => no.append(el('div', 'claims__item', c)));
  mount.append(no);

  const nav = el('div', 'navbtns');
  const run = el('button', 'btn btn-ghost btn-sm', '完全性を再点検');
  run.type = 'button';
  const out = el('div', 'claims');
  run.addEventListener('click', async () => {
    run.disabled = true;
    run.textContent = 'ハッシュ値を計算中…';
    try {
      const { results } = await api('/api/verify', { method: 'POST', body: '{}' });
      out.textContent = '';
      const when = new Date().toLocaleTimeString();
      out.append(el('div', 'claims__head is-ok', `${when} に点検しました`));
      results.forEach((r) => {
        out.append(
          el('div', r.ok ? 'claims__item' : 'member__warn',
             `${r.ok ? '✓' : '⚠'} ${r.path.split('/').pop()} — ${r.detail}`)
        );
      });
      if (!results.length) out.append(el('div', 'claims__item', '点検対象の書庫はまだありません。'));
    } catch (err) {
      out.textContent = '';
      out.append(el('div', 'member__warn', err.message));
    } finally {
      run.disabled = false;
      run.textContent = '完全性を再点検';
    }
  });
  nav.append(run);
  mount.append(nav);
  mount.append(out);
}

function renderScanPrompt(list, mount) {
  list.remove();
  const panel = el('div', 'panel');
  panel.append(el('div', 'panel__label', '登録済みの書庫はありません'));
  panel.append(
    el('p', 'muted', '.zip ファイルのあるフォルダを指定して登録してください。')
  );
  const input = el('input', 'text-input');
  input.type = 'text';
  input.placeholder = '~/zip ファイルのあるフォルダのパス';
  input.setAttribute('aria-label', '登録するフォルダ');
  panel.append(input);

  const nav = el('div', 'navbtns');
  const go = el('button', 'btn btn-primary', 'このフォルダを登録');
  go.type = 'button';
  go.addEventListener('click', async () => {
    go.disabled = true;
    go.textContent = '読み込み中…';
    try {
      await api('/api/scan', { method: 'POST', body: JSON.stringify({ dir: input.value }) });
      renderInspect(mount);
    } catch (err) {
      go.disabled = false;
      go.textContent = 'このフォルダを登録';
      const msg = el('p', 'feedback is-bad', err.message);
      panel.append(msg);
    }
  });
  nav.append(go);
  panel.append(nav);
  mount.append(panel);
}

function archiveCard(a) {
  const card = el('button', 'lesson-card');
  card.type = 'button';
  const name = a.path.split('/').pop();
  card.setAttribute('aria-label', `${name} を検査`);
  card.append(el('span', 'lesson-card__tag', `${a.members} 項目`));
  card.append(el('div', 'lesson-card__title', name));
  card.append(el('p', 'lesson-card__desc mono', `sha256 ${a.sha256.slice(0, 24)}…`));
  const meta = el('div', 'lesson-card__meta');
  meta.append(el('span', null, `${(a.size / 1e6).toFixed(1)} MB`));
  meta.append(el('span', null, STATUS_LABEL[a.last_status] || a.last_status));
  card.append(meta);
  card.addEventListener('click', () => {
    location.hash = `#/inspect/${a.id}`;
  });
  return card;
}

// ---------------------------------------------------------------------------
// Member list + preview
// ---------------------------------------------------------------------------

export async function renderArchive(mount, archiveId) {
  mount.textContent = '';

  const page = el('div', 'player');
  mount.append(page);

  const head = el('div', 'stage-head');
  const title = el('h2', 'stage-name', '書庫の内容');
  title.tabIndex = -1;
  head.append(title);
  page.append(head);

  const back = el('button', 'btn btn-ghost', '検査画面に戻る');
  back.type = 'button';
  back.addEventListener('click', () => {
    location.hash = '#/inspect';
  });

  let members;
  try {
    const [membersRes, { archives }] = await Promise.all([
      api(`/api/archives/${encodeURIComponent(archiveId)}/members`),
      api('/api/archives'),
    ]);
    members = membersRes.members;
    const match = archives.find((a) => String(a.id) === String(archiveId));
    if (!match) {
      const panel = el('div', 'panel');
      panel.append(el('div', 'panel__label', '書庫が見つかりません'));
      panel.append(el('p', 'muted', `id ${archiveId} の書庫は登録されていません。`));
      page.append(panel);
      const nav = el('div', 'navbtns');
      nav.append(back);
      page.append(nav);
      return;
    }
    title.textContent = match.path.split('/').pop();
  } catch (err) {
    const panel = el('div', 'panel');
    panel.append(el('div', 'panel__label', '読み込めませんでした'));
    panel.append(el('p', 'muted', err.message));
    page.append(panel);
    const nav = el('div', 'navbtns');
    nav.append(back);
    page.append(nav);
    return;
  }

  const unrecognised = members.filter((m) => m.verdict === 'unknown').length;
  const runnable = members.filter(
    (m) => SEVERITY[m.verdict] === 'is-bad' && m.verdict !== 'unknown'
  ).length;
  // Blocked is the wider set: anything not plainly inert, plus anything inert
  // whose NAME is hostile. Reporting only "runnable" would understate it.
  const blocked = members.filter(
    (m) => m.verdict !== 'inert-data' || m.warnings
  ).length;

  const summary = el('div', 'panel');
  summary.append(el('div', 'panel__label', '概要'));
  const line =
    `全 ${members.length} 項目。` +
    `実行され得るもの ${runnable} 件、` +
    `種別を特定できないもの ${unrecognised} 件（プログラムと同等に扱います）、` +
    `書き出しを遮断したもの ${blocked} 件。`;
  summary.append(el('p', null, line));
  summary.append(
    el(
      'p',
      'muted',
      '遮断: 実行され得る、読み取れない、または名前が細工されているため、ディスクへ書き出しません。'
    )
  );
  page.append(summary);
  title.focus({ preventScroll: true });

  const table = el('div', 'member-list');
  members.forEach((m) => table.append(memberRow(m, archiveId)));
  page.append(table);

  const nav = el('div', 'navbtns');
  nav.append(back);

  const gen = el('button', 'btn btn-primary', 'このログから課を作成');
  gen.type = 'button';
  const genOut = el('div', 'panel');
  genOut.hidden = true;
  gen.addEventListener('click', async () => {
    gen.disabled = true;
    gen.textContent = 'ログを読み込み中…';
    genOut.textContent = '';
    genOut.hidden = false;
    try {
      const r = await api('/api/generate', {
        method: 'POST',
        body: JSON.stringify({ archive: Number(archiveId) }),
      });
      genOut.append(el('div', 'panel__label', '課を作成しました'));
      genOut.append(
        el('p', null,
           `全 ${r.stages} 段階、観測事象 ${r.events} 件、うち ATT&CK 技術を付与したもの ${r.tagged} 件。`)
      );
      const open = el('button', 'btn btn-primary', '課を開く');
      open.type = 'button';
      open.addEventListener('click', () => {
        location.hash = `#/lesson/${r.id}`;
      });
      const row = el('div', 'navbtns');
      row.append(open);
      genOut.append(row);
    } catch (err) {
      genOut.append(el('div', 'panel__label', '課を作成できませんでした'));
      genOut.append(el('p', 'muted', err.message));
    } finally {
      gen.disabled = false;
      gen.textContent = 'このログから課を作成';
    }
  });
  nav.append(gen);
  page.append(nav);
  page.append(genOut);
}

function memberRow(m, archiveId) {
  const row = el('div', 'member');
  const bar = el('div', 'member__bar');
  bar.append(verdictBadge(m.verdict));

  const nameEl = el('div', 'member__name mono');
  nameEl.textContent = showBidi(m.name);
  bar.append(nameEl);
  bar.append(el('span', 'member__size mono', `${m.size} B`));
  row.append(bar);

  row.append(el('div', 'member__kind', m.kind));
  row.append(el('div', 'member__plain', PLAIN[m.verdict] || ''));

  if (hasBidi(m.name)) {
    row.append(
      el(
        'div',
        'member__warn',
        '⚠ この名前には双方向制御文字が含まれています（上では <U+…> と表示）。表示上の並びが実際のバイト列と異なります。'
      )
    );
  }

  if (m.warnings) {
    m.warnings.split('\n').filter(Boolean).forEach((w) => {
      row.append(el('div', 'member__warn', `⚠ ${showBidi(w)}`));
    });
  }

  const toggle = el('button', 'btn btn-ghost btn-sm', '先頭バイトを表示');
  toggle.type = 'button';
  const holder = el('div', 'hexdump');
  holder.hidden = true;
  // A scrollable region is unreachable by keyboard without a tabindex.
  holder.tabIndex = 0;
  holder.setAttribute('role', 'region');
  holder.setAttribute('aria-label', 'この項目の先頭バイト');
  toggle.setAttribute('aria-expanded', 'false');
  toggle.addEventListener('click', async () => {
    if (!holder.hidden) {
      holder.hidden = true;
      toggle.setAttribute('aria-expanded', 'false');
      toggle.textContent = '先頭バイトを表示';
      return;
    }
    toggle.disabled = true;
    try {
      const data = await api(
        `/api/archives/${encodeURIComponent(archiveId)}/members/${encodeURIComponent(m.idx)}/preview`
      );
      holder.textContent = '';
      if (data.note) holder.append(el('div', 'hexdump__note', data.note));
      data.rows.forEach((r) => {
        const line = el('div', 'hexdump__row');
        line.append(el('span', 'hexdump__off', r.offset));
        line.append(el('span', 'hexdump__hex', r.hex));
        line.append(el('span', 'hexdump__txt', r.text));
        holder.append(line);
      });
      holder.hidden = false;
      toggle.setAttribute('aria-expanded', 'true');
      toggle.textContent = '表示を閉じる';
    } catch (err) {
      holder.textContent = err.message;
      holder.hidden = false;
    } finally {
      toggle.disabled = false;
    }
  });
  row.append(toggle);
  row.append(holder);
  return row;
}
