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

/** ホームへ戻る導線。どの画面からでも抜けられるように、必ず一つは置く。 */
function homeNav() {
  const nav = el('div', 'navbtns navbtns--home');
  const home = el('button', 'btn btn-ghost', '← ホームに戻る');
  home.type = 'button';
  home.setAttribute('aria-label', 'ホームに戻る');
  home.addEventListener('click', () => {
    location.hash = '#/';
  });
  nav.append(home);
  return nav;
}

/**
 * @param {HTMLElement} mount
 * @param {string} [notice] 直前の読み取り結果など、再描画後に伝えたいこと。
 */
export async function renderInspect(mount, notice) {
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
  // 戻る導線は、この後の通信が失敗しても残るように先に置く。
  mount.append(homeNav());
  h1.focus({ preventScroll: true });

  if (notice) {
    mount.append(el('div', 'feedback is-ok', notice));
  }

  let role;
  let claims;
  let archives;
  let canScan = false;
  try {
    const [status, list] = await Promise.all([api('/api/status'), api('/api/archives')]);
    // 応答を待つ間に別の画面へ移られていたら、ここから先は描かない。
    // ルーターが器ごと差し替えているので書いても見えないが、続きの通信まで
    // 無駄に走らせない。
    if (!mount.isConnected) return;
    role = status.role;
    claims = status.claims;
    archives = list.archives;
    canScan = (status.capabilities || []).includes('scan');
  } catch (err) {
    if (!mount.isConnected) return;
    const panel = el('div', 'panel');
    panel.append(el('div', 'panel__label', 'サーバーに接続できません'));
    panel.append(
      el('p', null, 'この画面を使うには、手元でサーバーを動かしておく必要があります。')
    );
    panel.append(el('p', 'mono', 'python3 backend/api.py'));
    mount.append(panel);
    return;
  }

  // 読み取りの入口は常に出しておく。以前はまだ一件も読み込んでいないときだけ
  // 表示していたため、一度読み取ったあとは二つ目のZIPを追加できなかった。
  //
  // ただし読み取る権限がないとき（student）は出さない。出しても操作はすべて
  // 403 になり、拒否の赤字を読ませるだけで終わるため。
  if (canScan) {
    await renderScanPrompt(mount, archives.length > 0);
  } else if (!archives.length) {
    mount.append(
      el(
        'p',
        'muted center',
        'まだZIPファイルが読み込まれていません。読み込みは、この教材を配った人の側で行います。'
      )
    );
  }

  if (archives.length) {
    mount.append(el('h2', null, '読み込み済みのZIPファイル'));
    mount.append(el('p', 'muted', '見たいものを選んでください。'));
    const list = el('div', 'home-grid');
    archives.forEach((a) => list.append(archiveCard(a)));
    mount.append(list);

    const status = el('div', 'panel');
    renderClaims(status, role, claims);
    mount.append(status);
  }

  mount.append(homeNav());
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

/**
 * ZIPを読み取る入口。一件も読み込んでいないときは最初の案内として、すでに
 * 読み込んでいるときは「別のZIPを追加する」欄として、同じものを使う。
 * @param {HTMLElement} mount
 * @param {boolean} hasArchives すでに読み込み済みのZIPがあるか
 */
async function renderScanPrompt(mount, hasArchives) {
  const panel = el('div', 'panel');
  panel.append(
    el(
      'div',
      'panel__label',
      hasArchives
        ? '別のZIPファイルを読み込む'
        : 'まず、調べたいZIPファイルの置き場所を教えてください'
    )
  );
  panel.append(
    el(
      'p',
      null,
      'ZIPファイルが入っているフォルダを選んでください。ZIPは開かずに、中の目録だけを読み取ります。'
    )
  );

  // ---- フォルダ選択はページの中で完結させる -------------------------------
  // OSのダイアログは別アプリの窓なので、ブラウザを全画面にしていると macOS が
  // 別のスペースへ切り替えてしまい、開いていた画面から引き剥がされる。ここで
  // 描けば、全画面のままひとつの窓の中で選び終えられる。
  const browser = el('div', 'browser');
  panel.append(browser);

  // ---- 手入力とOSダイアログは畳んでおく（逃げ道） ------------------------
  const manual = document.createElement('details');
  manual.className = 'fold';
  const manualHead = document.createElement('summary');
  manualHead.className = 'fold__head';
  manualHead.textContent = 'パスを直接入力する / OSの選択画面を使う';
  manual.append(manualHead);

  const input = el('input', 'text-input');
  input.type = 'text';
  input.placeholder = '例）~/Documents/mws-data';
  input.setAttribute('aria-label', 'ZIPファイルが入っているフォルダの場所');
  manual.append(input);

  const manualNav = el('div', 'navbtns navbtns--wrap');
  const go = el('button', 'btn btn-ghost', 'このパスを読み取る');
  go.type = 'button';
  manualNav.append(go);
  const pick = el('button', 'btn btn-ghost', 'OSの選択画面を開く');
  pick.type = 'button';
  pick.setAttribute('aria-label', 'OS標準のフォルダ選択画面を開く');
  manualNav.append(pick);
  manual.append(manualNav);
  manual.append(
    el(
      'p',
      'muted',
      'OSの選択画面は別アプリの窓として開きます。ブラウザを全画面にしていると、別のスペースへ切り替わります。'
    )
  );
  panel.append(manual);

  // 結果を出す場所。押すたびに差し替えるので、積み上がらない。
  const out = el('div');
  panel.append(out);

  const clear = () => {
    out.textContent = '';
  };
  const fail = (text) => {
    clear();
    out.append(el('p', 'feedback is-bad', text));
  };
  const note = (text) => {
    clear();
    out.append(el('p', 'muted', text));
  };

  // ---- ページ内フォルダ選択 ---------------------------------------------
  // 続けて別のフォルダを押すと要求が重なる。応答の戻る順は要求した順とは限ら
  // ないので、最後に要求したものだけを採用する。これがないと、遅れて返った
  // 古い応答が、今見ているフォルダの一覧を上書きする。
  let browseSeq = 0;

  /** 一覧を描き直す。dir を省略するとホームから始める。 */
  const openDir = async (dir) => {
    const seq = ++browseSeq;
    browser.textContent = '';
    browser.append(el('p', 'muted', '読み込んでいます…'));
    let d;
    try {
      d = await api('/api/browse', {
        method: 'POST',
        body: JSON.stringify({ dir: dir || '' }),
      });
    } catch (err) {
      if (seq !== browseSeq || !browser.isConnected) return;
      browser.textContent = '';
      browser.append(el('p', 'feedback is-bad', err.message));
      return;
    }
    // 追い越された、または画面から離れた。描かずに捨てる。
    if (seq !== browseSeq || !browser.isConnected) return;
    browser.textContent = '';

    // 近道。探し始める場所は数えるほどしかない。
    const quick = el('div', 'browser__quick');
    (d.shortcuts || []).forEach((s) => {
      const b = el('button', 'btn btn-ghost btn-sm', s.name);
      b.type = 'button';
      b.addEventListener('click', () => openDir(s.path));
      quick.append(b);
    });
    browser.append(quick);

    // いまどこにいるか。
    const bar = el('div', 'browser__bar');
    const up = el('button', 'btn btn-ghost btn-sm', '↑ 上へ');
    up.type = 'button';
    up.disabled = !d.parent;
    up.setAttribute('aria-label', '一つ上のフォルダへ');
    up.addEventListener('click', () => openDir(d.parent));
    bar.append(up);
    bar.append(el('div', 'browser__path mono', d.path));
    browser.append(bar);

    if (d.error) {
      browser.append(el('div', 'member__warn', `⚠ ${d.error}`));
    }

    // 中のフォルダ。ZIPを持つものが一目で分かるようにする。
    const list = el('div', 'browser__list');
    list.setAttribute('role', 'group');
    list.setAttribute('aria-label', 'フォルダの一覧');
    d.entries.forEach((e) => {
      const row = el('button', 'browser__row');
      row.type = 'button';
      const countLabel = e.zipsPartial
        ? `ZIP ${e.zips} 個以上`
        : e.zips && `ZIP ${e.zips} 個`;
      row.setAttribute(
        'aria-label',
        countLabel ? `${e.name} を開く（${countLabel}）` : `${e.name} を開く`
      );
      row.append(el('span', 'browser__icon', '📁'));
      row.append(el('span', 'browser__name', e.name));
      // 子フォルダの件数はサーバー側で打ち切られることがある。打ち切られた
      // 数をそのまま出すと過少に見え、0 のときは「無い」と誤読させるので、
      // 確定していないことが分かる形にする。
      if (e.zipsPartial) {
        row.append(
          el('span', 'browser__count', e.zips ? `ZIP ${e.zips}+` : 'ZIP ?')
        );
      } else if (e.zips) {
        row.append(el('span', 'browser__count', `ZIP ${e.zips}`));
      }
      row.addEventListener('click', () => openDir(e.path));
      list.append(row);
    });
    if (!d.entries.length) {
      list.append(el('p', 'muted', 'この中にフォルダはありません。'));
    }
    browser.append(list);
    if (d.truncated) {
      browser.append(
        el('p', 'muted', 'フォルダが多いため、一部だけ表示しています。')
      );
    }

    // いまのフォルダを読み取る。ZIPの有無を押す前に伝える。
    const act = el('div', 'navbtns navbtns--wrap');
    const take = el(
      'button',
      d.zips ? 'btn btn-primary' : 'btn btn-ghost',
      d.zips ? `このフォルダを読み取る（ZIP ${d.zips} 個）` : 'このフォルダにZIPはありません'
    );
    take.type = 'button';
    take.disabled = !d.zips;
    take.addEventListener('click', () => scan(d.path));
    act.append(take);
    browser.append(act);
  };

  /** 読み取りを実行して、結果に応じて画面を進めるか、その場で理由を出す。 */
  const scan = async (dir) => {
    clear();
    pick.disabled = true;
    go.disabled = true;
    go.textContent = '読み取っています…';
    try {
      const { scanned, subdirs } = await api('/api/scan', {
        method: 'POST',
        body: JSON.stringify({ dir }),
      });
      const read = scanned.filter((s) => !s.skipped);
      const skipped = scanned.filter((s) => s.skipped);

      // 一件も読めなかったときに黙って再描画すると、押しても何も起きていない
      // ように見える。理由をその場に出して、画面はそのままにしておく。
      if (!read.length) {
        fail('このフォルダには、読み取れるZIPファイルがありませんでした。');
        out.append(el('p', 'muted mono', dir));
        skipped.forEach((s) =>
          out.append(el('div', 'member__warn', `⚠ ${s.name} — ${s.skipped}`))
        );
        // 一つ上のフォルダを選んでしまった場合の行き止まりを避ける。
        if (subdirs && subdirs.length) {
          out.append(
            el('p', null, 'この中の次のフォルダにZIPファイルがあります。')
          );
          const list = el('div', 'navbtns navbtns--wrap');
          subdirs.forEach((d) => {
            const b = el(
              'button',
              'btn btn-ghost btn-sm',
              `${d.name}（${d.zips} 個）`
            );
            b.type = 'button';
            b.setAttribute('aria-label', `${d.name} を読み取る`);
            b.addEventListener('click', () => scan(d.path));
            list.append(b);
          });
          out.append(list);
        }
        return;
      }

      let notice = `${read.length} 個のZIPファイルを読み取りました。`;
      if (skipped.length) {
        notice += `（${skipped.length} 個は読み取れませんでした）`;
      }
      await renderInspect(mount, notice);
    } catch (err) {
      fail(err.message);
    } finally {
      pick.disabled = false;
      go.disabled = false;
      go.textContent = 'このパスを読み取る';
    }
  };

  pick.addEventListener('click', async () => {
    clear();
    pick.disabled = true;
    pick.textContent = '選択画面を開いています…';
    let picked;
    try {
      picked = await api('/api/choose-dir', { method: 'POST', body: '{}' });
    } catch (err) {
      fail(err.message);
      return;
    } finally {
      pick.disabled = false;
      pick.textContent = 'フォルダを選ぶ…';
    }

    // 取り消しは失敗ではない。何も言わずに元の状態へ戻す。
    if (picked.cancelled) return;

    // 選択画面が使えない環境。責めずに手入力へ誘導する。
    if (picked.unavailable) {
      manual.open = true;
      note('この環境ではフォルダ選択画面を開けませんでした。下にパスを直接入力してください。');
      input.focus();
      return;
    }

    // 選んだ場所を手入力欄にも残す。選び直すときに打ち直さずに済む。
    input.value = picked.dir;
    await scan(picked.dir);
  });

  go.addEventListener('click', async () => {
    const dir = input.value.trim();
    if (!dir) {
      fail('フォルダの場所を入力してください。');
      input.focus();
      return;
    }
    await scan(dir);
  });

  // 最初のフォルダ一覧を取りに行く前に、panel を画面へ入れておく。openDir は
  // 「離脱済みなら描かない」を isConnected で判断するので、未接続のまま呼ぶと
  // 初回の一覧が描かれないまま「読み込んでいます…」で止まる。
  mount.append(panel);

  // 最初はホームから。押しボタンを一つ挟まず、開いた時点で選べる状態にする。
  await openDir();
}

function archiveCard(a) {
  const card = el('button', 'lesson-card');
  card.type = 'button';
  // 同じ名前のZIPが別のフォルダにあることは珍しくない（配布物の控えなど）。
  // 名前だけを出すと一覧で見分けが付かないので、入っているフォルダも添える。
  const parts = a.path.split('/');
  const name = parts.pop();
  const folder = parts.pop() || '';
  card.setAttribute(
    'aria-label',
    folder ? `${folder} フォルダの ${name} の中身を見る` : `${name} の中身を見る`
  );
  card.append(el('span', 'lesson-card__tag', `${a.members} 個のファイル`));
  card.append(el('div', 'lesson-card__title', name));
  if (folder) {
    card.append(el('p', 'lesson-card__desc mono', `${folder}/`));
  }
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
