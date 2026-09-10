// inspect.js — ZIPファイルの中身を調べる画面。
//
// 画面は二つ。
//   1. 一覧 … 読み込んだZIPファイルを並べる
//   2. 中身 … 一つのZIPに入っているファイルを、危険度で分けて見せる
//
// 表示する文字はすべて textContent で入れる。ファイル名はZIPの中から来るため、
// 細工されている前提で扱う。

// 表示順を入れ替える制御文字は `payroll<RLO>gnp.exe` を `payrollexe.png` に
// 見せる。CSS の分離だけでは名前の内側までは戻せないので、目に見える形に
// 置き換えてから表示する。
const BIDI = /[‪-‮⁦-⁩‎‏]/g;
const showBidi = (s) =>
  String(s).replace(BIDI, (c) => `<U+${c.codePointAt(0).toString(16).toUpperCase()}>`);
const hasBidi = (s) => BIDI.test(String(s));

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

async function api(path, options) {
  const res = await fetch(path, {
    ...options,
    headers: { 'Content-Type': 'application/json', 'X-MWS-Token': token() },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `通信に失敗しました（${res.status}）`);
  }
  return res.json();
}

// ---------------------------------------------------------------------------
// 判定の見せ方
// ---------------------------------------------------------------------------

/** 危険度。安全と言い切れるものだけ is-ok。 */
const SEVERITY = {
  'inert-data': 'is-ok',
  container: 'is-neutral',
  script: 'is-bad',
  'document-with-active-content': 'is-bad',
  'document-passive': 'is-ok',
  'metadata-sidecar': 'is-warn',
  'shortcut-or-launcher': 'is-bad',
  'native-executable': 'is-bad',
  'bytecode-archive': 'is-bad',
  'sample-bearing': 'is-bad',
  unknown: 'is-bad',
  'opaque-encrypted': 'is-warn',
  'unsupported-container': 'is-warn',
  'forensic-image': 'is-warn',
};

/** 札に出す短い言葉。判定のキーは変えない。 */
const LABEL = {
  'inert-data': '安全',
  container: '圧縮ファイル',
  script: 'スクリプト',
  'document-with-active-content': '文書（動作あり）',
  'document-passive': '文書',
  'metadata-sidecar': '付随情報',
  'shortcut-or-launcher': 'ショートカット',
  'native-executable': '実行ファイル',
  'bytecode-archive': '実行ファイル',
  'sample-bearing': '検体を含む',
  unknown: '不明',
  'opaque-encrypted': '暗号化',
  'unsupported-container': '未対応の形式',
  'forensic-image': 'ディスクイメージ',
};

/** 何のファイルで、どう扱えばよいかを一文で。 */
const PLAIN = {
  'inert-data': 'そのまま開いても、これ自体が動き出すことはありません。',
  container: '中に別のファイルが入っています。開く前に中身を確かめてください。',
  script: '文字で書かれた命令です。二重クリックしなくても、処理系に渡せば動きます。',
  'document-with-active-content': '開いたときに何かを動かす指定が、実際に含まれています。',
  'document-passive': '読み取った範囲には、開いた時に動作する指定は見当たりませんでした。',
  'metadata-sidecar': 'macOS が作る付随情報です。本体ではありません。中に別の内容が隠されている場合があり、そこまでは確かめられません。',
  'shortcut-or-launcher': '開くと、別のプログラムを呼び出します。',
  'native-executable': 'そのまま動くプログラムです。',
  'bytecode-archive': 'Java などの実行環境の上で動くプログラムです。',
  'sample-bearing': '解析用の道具で開くと、元の検体そのものを取り出せます。',
  unknown: '何のファイルか判別できませんでした。安全と確かめられないため、プログラムと同じ扱いにしています。',
  'opaque-encrypted': 'パスワードが掛かっていて、中身を確かめられませんでした。',
  'unsupported-container': 'この圧縮形式にはまだ対応しておらず、中身を確かめられていません。',
  'forensic-image': 'ディスクや記憶内容を写し取ったものです。中にプログラムが含まれ得ます。',
};

function verdictBadge(verdict) {
  const badge = el(
    'span',
    `verdict ${SEVERITY[verdict] || 'is-warn'}`,
    LABEL[verdict] || verdict
  );
  badge.title = PLAIN[verdict] || '';
  return badge;
}

// 三つに分ける。数の多い低リスクを畳めるようにするため。
const bucketOf = (m) => {
  if (m.warnings) return 'care';
  const sev = SEVERITY[m.verdict];
  if (sev === 'is-bad') return 'care';
  if (sev === 'is-warn') return 'unchecked';
  return 'ok';
};

// ---------------------------------------------------------------------------
// 一覧の画面
// ---------------------------------------------------------------------------

export async function renderInspect(mount) {
  mount.textContent = '';

  const hero = el('section', 'hero');
  const h1 = el('h1', null, 'ZIPファイルの中身を調べる');
  h1.tabIndex = -1;
  hero.append(h1);
  hero.append(
    el(
      'p',
      null,
      '解凍する前に、中に何が入っているかを一覧で確かめられます。危険なファイルをそれと知らずに開いてしまう前に、種類と扱い方を把握するための画面です。'
    )
  );
  mount.append(hero);
  h1.focus({ preventScroll: true });

  try {
    const [{ role, claims }, { archives }] = await Promise.all([
      api('/api/status'),
      api('/api/archives'),
    ]);

    if (!archives.length) {
      mount.append(renderScanPrompt(mount));
      return;
    }

    mount.append(el('h2', null, '読み込み済みのZIPファイル'));
    mount.append(el('p', 'muted', '見たいものを選んでください。'));
    const list = el('div', 'home-grid');
    archives.forEach((a) => list.append(archiveCard(a)));
    mount.append(list);

    const status = el('div', 'panel');
    renderClaims(status, role, claims);
    mount.append(status);
  } catch (err) {
    const panel = el('div', 'panel');
    panel.append(el('div', 'panel__label', 'サーバーに接続できません'));
    panel.append(
      el('p', null, 'この画面を使うには、手元でサーバーを動かしておく必要があります。')
    );
    panel.append(el('p', 'mono', 'python3 backend/api.py'));
    mount.append(panel);
  }
}

/** 読み込んだZIPが後から書き換えられていないかの見張り。 */
function renderClaims(mount, role, claims) {
  mount.textContent = '';
  mount.append(el('div', 'panel__label', '読み込んだZIPファイルの見張り'));
  mount.append(
    el(
      'p',
      null,
      '読み込んだ時点の内容を控えておき、後から書き換えられていないかを照合します。'
    )
  );

  const yes = el('div', 'claims');
  yes.append(el('div', 'claims__head is-ok', 'できること'));
  claims.detects.forEach((c) => yes.append(el('div', 'claims__item', c)));
  mount.append(yes);

  const no = el('div', 'claims');
  no.append(el('div', 'claims__head is-bad', 'できないこと'));
  claims.doesNotDetect.forEach((c) => no.append(el('div', 'claims__item', c)));
  mount.append(no);

  const nav = el('div', 'navbtns');
  const run = el('button', 'btn btn-ghost btn-sm', '今すぐ照合する');
  run.type = 'button';
  const out = el('div', 'claims');
  run.addEventListener('click', async () => {
    run.disabled = true;
    run.textContent = '照合しています…';
    try {
      const { results } = await api('/api/verify', { method: 'POST', body: '{}' });
      out.textContent = '';
      out.append(
        el('div', 'claims__head is-ok', `${new Date().toLocaleTimeString()} に照合しました`)
      );
      results.forEach((r) =>
        out.append(
          el(
            'div',
            r.ok ? 'claims__item' : 'member__warn',
            `${r.ok ? '✓' : '⚠'} ${r.path.split('/').pop()} — ${r.detail}`
          )
        )
      );
      if (!results.length) {
        out.append(el('div', 'claims__item', 'まだ何も読み込んでいません。'));
      }
    } catch (err) {
      out.textContent = '';
      out.append(el('div', 'member__warn', err.message));
    } finally {
      run.disabled = false;
      run.textContent = '今すぐ照合する';
    }
  });
  nav.append(run);
  mount.append(nav);
  mount.append(out);
}

function renderScanPrompt(mount) {
  const panel = el('div', 'panel');
  panel.append(
    el('div', 'panel__label', 'まず、調べたいZIPファイルの置き場所を教えてください')
  );
  panel.append(
    el(
      'p',
      null,
      'ZIPファイルが入っているフォルダの場所を書いて、下の押しボタンを押してください。ZIPは開かずに、中の目録だけを読み取ります。'
    )
  );
  const input = el('input', 'text-input');
  input.type = 'text';
  input.placeholder = '例）~/Documents/mws-data';
  input.setAttribute('aria-label', 'ZIPファイルが入っているフォルダの場所');
  panel.append(input);

  const nav = el('div', 'navbtns');
  const go = el('button', 'btn btn-primary', '中身を読み取る');
  go.type = 'button';
  go.addEventListener('click', async () => {
    go.disabled = true;
    go.textContent = '読み取っています…';
    try {
      await api('/api/scan', { method: 'POST', body: JSON.stringify({ dir: input.value }) });
      renderInspect(mount);
    } catch (err) {
      go.disabled = false;
      go.textContent = '中身を読み取る';
      panel.append(el('p', 'feedback is-bad', err.message));
    }
  });
  nav.append(go);
  panel.append(nav);
  return panel;
}

function archiveCard(a) {
  const card = el('button', 'lesson-card');
  card.type = 'button';
  const name = a.path.split('/').pop();
  card.setAttribute('aria-label', `${name} の中身を見る`);
  card.append(el('span', 'lesson-card__tag', `${a.members} 個のファイル`));
  card.append(el('div', 'lesson-card__title', name));
  const meta = el('div', 'lesson-card__meta');
  meta.append(el('span', null, `${(a.size / 1e6).toFixed(1)} MB`));
  meta.append(el('span', null, a.last_status === 'ok' ? '照合済み' : '要確認'));
  card.append(meta);
  card.addEventListener('click', () => {
    location.hash = `#/inspect/${a.id}`;
  });
  return card;
}

// ---------------------------------------------------------------------------
// 中身の画面
// ---------------------------------------------------------------------------

export async function renderArchive(mount, archiveId) {
  mount.textContent = '';
  const page = el('div', 'player');
  mount.append(page);

  const title = el('h1', null, '読み込んでいます…');
  title.tabIndex = -1;
  page.append(title);

  const back = el('button', 'btn btn-ghost', '一覧に戻る');
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
      title.textContent = '見つかりません';
      page.append(el('p', null, 'そのZIPファイルは読み込まれていません。'));
      const nav = el('div', 'navbtns');
      nav.append(back);
      page.append(nav);
      return;
    }
    title.textContent = match.path.split('/').pop();
  } catch (err) {
    title.textContent = '読み込めませんでした';
    page.append(el('p', null, err.message));
    const nav = el('div', 'navbtns');
    nav.append(back);
    page.append(nav);
    return;
  }

  const care = members.filter((m) => bucketOf(m) === 'care');
  const unchecked = members.filter((m) => bucketOf(m) === 'unchecked');
  const safe = members.filter((m) => bucketOf(m) === 'ok');

  const lead = care.length
    ? `このZIPには ${members.length} 個のファイルが入っています。そのうち ${care.length} 個は、開く前に注意が必要です。`
    : `このZIPには ${members.length} 個のファイルが入っています。注意が必要なものはありませんでした。`;
  page.append(el('p', null, lead));
  title.focus({ preventScroll: true });

  // 注意が要るものは最初から開いて見せる。
  if (care.length) {
    page.append(el('h2', null, `注意が必要なファイル（${care.length} 個）`));
    page.append(el('p', 'muted', '何のファイルで、なぜ注意が要るのかを一件ずつ示します。'));
    const table = el('div', 'member-list');
    care.forEach((m) => table.append(memberRow(m, archiveId)));
    page.append(table);
  }

  // 中身を確かめられなかったもの。危険とは限らないが、安全とも言えない。
  if (unchecked.length) {
    page.append(fold(
      `中身を確かめられなかったファイル（${unchecked.length} 個）`,
      'パスワードが掛かっている、または未対応の形式です。危険と決まったわけではありませんが、安全とも言えません。',
      unchecked, archiveId
    ));
  }

  // 低リスクのものは畳んでおく。数が多く、一件ずつ見る必要がないため。
  if (safe.length) {
    const kinds = [...new Set(safe.map((m) => m.kind))].slice(0, 4).join('・');
    page.append(fold(
      `そのまま開いて問題のないファイル（${safe.length} 個）`,
      `${kinds} など。これら自体が動き出すことはありません。`,
      safe, archiveId
    ));
  }

  const nav = el('div', 'navbtns');
  nav.append(back);

  const gen = el('button', 'btn btn-primary', 'このZIPのログから演習を作る');
  gen.type = 'button';
  const genOut = el('div', 'panel');
  genOut.hidden = true;
  gen.addEventListener('click', async () => {
    gen.disabled = true;
    gen.textContent = 'ログを読んでいます…';
    genOut.textContent = '';
    genOut.hidden = false;
    try {
      const r = await api('/api/generate', {
        method: 'POST',
        body: JSON.stringify({ archive: Number(archiveId) }),
      });
      genOut.append(el('div', 'panel__label', '演習ができました'));
      genOut.append(el('p', null, `${r.stages} 段階・${r.events} 件の記録から作りました。`));
      const open = el('button', 'btn btn-primary', '演習を開く');
      open.type = 'button';
      open.addEventListener('click', () => {
        location.hash = `#/lesson/${r.id}`;
      });
      const row = el('div', 'navbtns');
      row.append(open);
      genOut.append(row);
    } catch (err) {
      genOut.append(el('div', 'panel__label', '演習を作れませんでした'));
      genOut.append(el('p', null, err.message));
    } finally {
      gen.disabled = false;
      gen.textContent = 'このZIPのログから演習を作る';
    }
  });
  nav.append(gen);
  page.append(nav);
  page.append(genOut);
}

/** 畳める一覧。件数が多く、一件ずつ読む必要がないものに使う。 */
function fold(headText, note, items, archiveId) {
  const box = document.createElement('details');
  box.className = 'fold';
  const head = document.createElement('summary');
  head.className = 'fold__head';
  head.textContent = headText;
  box.append(head);
  box.append(el('p', 'muted', note));
  const table = el('div', 'member-list');
  items.forEach((m) => table.append(memberRow(m, archiveId)));
  box.append(table);
  return box;
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
        '⚠ 名前に表示順を入れ替える文字が含まれています。上では <U+…> に置き換えて表示しています。見た目の拡張子と実際の拡張子が違う場合があります。'
      )
    );
  }
  if (m.warnings) {
    m.warnings
      .split('\n')
      .filter(Boolean)
      .forEach((w) => row.append(el('div', 'member__warn', `⚠ ${showBidi(w)}`)));
  }

  const toggle = el('button', 'btn btn-ghost btn-sm', '先頭のデータを見る');
  toggle.type = 'button';
  toggle.setAttribute('aria-expanded', 'false');
  const holder = el('div', 'hexdump');
  holder.hidden = true;
  holder.tabIndex = 0;
  holder.setAttribute('role', 'region');
  holder.setAttribute('aria-label', 'このファイルの先頭のデータ');
  toggle.addEventListener('click', async () => {
    if (!holder.hidden) {
      holder.hidden = true;
      toggle.setAttribute('aria-expanded', 'false');
      toggle.textContent = '先頭のデータを見る';
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
      toggle.textContent = '閉じる';
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
