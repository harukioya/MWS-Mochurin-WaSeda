// intro.js — 調査導入画面と、初心者向けの用語説明。
//
// 自動生成した演習をいきなり第1段階から始めると、「何のログを、何のために
// 読むのか」が分からないまま設問に入ることになる。ここで先に、扱うログ、
// 対象の端末、この演習で学ぶこと、そして自動生成の下書きであることを示す。
//
// 分からない項目は推測で埋めない。ホストが取れなければ「記録からは分かり
// ません」と書く。埋めてしまうと、根拠のない情報が教材の一部に見える。

import { visible } from './evidence.js';
import { profileLine, profileOfLesson } from './profile.js';

const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
};

/** 外部を開かずに読める用語集。初めての人が、画面の中だけで用語の意味を確かめられるようにする。 */
const GLOSSARY = [
  ['ログ', '機器やソフトが「何が起きたか」を1行ずつ書き留めた記録です。あとから読み返すために残されます。'],
  ['証拠', 'この教材では、ログのある1行そのものを指します。どのファイルの何行目かまで示せるものだけを証拠と呼びます。'],
  ['プロセス', '実行中のプログラム1つ分のことです。ログには、どの実行ファイルが起動したかが残ります。'],
  ['親プロセス', 'そのプロセスを起動した側のプロセスです。「誰が動かしたのか」をたどる手がかりになります。'],
  ['ファイル書き込み', 'ディスク上にファイルが作られた、または内容が変えられたことです。中身より「どこに置かれたか」が意味を持ちます。'],
  ['プロキシ', '端末と外部の間に立って通信を中継する機器です。どの端末がどこへ繋いだかが記録に残ります。'],
  ['IPアドレス', 'ネットワーク上の住所にあたる番号です。プロキシの記録では、行の先頭が要求元の端末を指します。'],
  ['MITRE ATT&CK', '攻撃の手口を分類した、世界的に使われている一覧です。この教材では、根拠を説明できる場合にだけ対応付けます。'],
  ['観測された事実', 'ログの1行に直接書かれていることです。読めばそのまま確かめられます。'],
  ['複数記録からの関連付け', '2つ以上の記録を突き合わせて分かることです。たとえば「どちらが先に記録されたか」。'],
  ['仮説／未確定事項', '可能性はあるが、手元の記録だけでは断定できないことです。断定せずに残しておきます。'],
];

/** 静的解析の教材で出てくる言葉。 */
const STATIC_GLOSSARY = [
  ['静的解析', 'プログラムを動かさずに、中身（命令やデータ）を読んで調べることです。この教材はこれだけを行います。'],
  ['Ghidra', '米国 NSA が公開している解析ツールです。プログラムを命令や関数に分けて表示し、その結果を保存できます。'],
  ['GZF', 'Ghidra が解析結果を 1 つのファイルにまとめて保存する形式です。この教材は、その中に保存済みの記録だけを読みます。'],
  ['アドレス', 'プログラムの中の位置を表す番号です。命令・文字列・関数は、それぞれアドレスで区別されます。'],
  ['アドレス空間', 'アドレスの種類です。プログラム本体は ram、外から取り込む関数は EXTERNAL のように分かれます。'],
  ['命令', 'CPU が実行する 1 つ 1 つの操作です。この教材では、読むだけで実行はしません。'],
  ['関数', 'ひとまとまりの処理です。入口のアドレスで呼び出されます。'],
  ['参照', 'ある命令が、どのアドレスのデータや関数を指しているかを Ghidra が記録したものです。'],
  ['定義済み文字列', 'プログラム内で文字列として定義されたデータです。メッセージや書式などが入っています。'],
  ['直接呼び出し', '行き先のアドレスが命令に書かれている呼び出しです。記録から行き先を一意に決められます。'],
  ['間接呼び出し', 'レジスタやメモリの値で行き先が決まる呼び出しです。動かさないと行き先が分からないことがあるため、この教材では扱いません。'],
  ['thunk', '別の関数へそのまま飛ぶだけの小さな関数です。外部関数を呼ぶときの中継によく使われます。'],
  ['外部関数', '共有ライブラリなど、このプログラムの外にある関数です。名前だけでは用途や悪性は決まりません。'],
];

/** 用語集。details なので既定では畳まれ、キーボードだけで開ける。 */
export function glossary(entries = GLOSSARY) {
  const box = document.createElement('details');
  box.className = 'fold';
  const head = document.createElement('summary');
  head.className = 'fold__head';
  head.textContent = 'はじめての方へ — この演習で出てくる言葉';
  box.append(head);
  box.append(
    el('p', 'muted', '外部の説明を開かなくても、ここだけで意味が分かるようにしてあります。')
  );
  const list = el('dl', 'glossary');
  entries.forEach(([term, meaning]) => {
    list.append(el('dt', 'glossary__term', term));
    list.append(el('dd', 'glossary__desc', meaning));
  });
  box.append(list);
  return box;
}

/** 値が無いときに、推測ではなくその旨を返す。 */
const orUnknown = (values, fallback) =>
  Array.isArray(values) && values.length ? values : [fallback];

/**
 * 調査導入画面。
 * @param {HTMLElement} mount
 * @param {object} lesson
 * @param {() => void} onStart 「調査を始める」で呼ばれる
 */
export function renderIntroduction(mount, lesson, onStart) {
  mount.textContent = '';
  const intro = lesson.introduction || {};
  if (intro.kind === 'static') return renderStaticIntroduction(mount, lesson, onStart);
  const report = lesson.report || {};

  const page = el('div', 'player');
  mount.append(page);

  const head = el('div', 'stage-head');
  const title = el('h1', 'stage-name', visible(lesson.title || '調査演習'));
  title.tabIndex = -1;
  head.append(title);
  page.append(head);

  // 自動生成の下書きであることを、最初に、畳まずに出す。
  if ((intro.status || (lesson.dataset || {}).draft) !== undefined) {
    const draft = intro.status === 'draft' || (lesson.dataset || {}).draft;
    if (draft) {
      page.append(
        el('div', 'feedback is-bad',
          '⚠ これはログから自動生成した下書きです。内容を確認のうえ使ってください。')
      );
    }
  }

  const ds = intro.dataset || {};
  // データセット形式と、それを自動で判定したのか利用者が指定したのか。
  // データセット画面・最終レポートと同じ 1 行を出す（profile.js）。教材を
  // 後から見た人が、その形式を誰が決めたのかを取り違えないようにするため。
  const profile = profileOfLesson(lesson);
  if (profile) {
    page.append(el('p', 'muted', profileLine(profile)));
  }

  page.append(
    el('p', null,
      intro.scenario ||
      '記録されたログを読み、何が起きたのかを段階を追って確かめます。')
  );

  // ---- 概要 ----
  const facts = el('div', 'panel');
  facts.append(el('div', 'panel__label', 'この演習について'));
  const rows = [
    ['使用するログ', orUnknown(intro.logTypes, '取得できませんでした').join('、')],
    ['対象ホスト', orUnknown(intro.hosts, '記録からは分かりません').join('、')],
    ['段階の数', `${(lesson.stages || []).length} 段階`],
    ['所要時間の目安', intro.estimatedMinutes ? `およそ ${intro.estimatedMinutes} 分` : '取得できませんでした'],
  ];
  const table = el('dl', 'factlist');
  rows.forEach(([k, v]) => {
    table.append(el('dt', 'factlist__key', k));
    table.append(el('dd', 'factlist__value', visible(String(v))));
  });
  facts.append(table);
  page.append(facts);

  // ---- 学ぶこと ----
  const aims = orUnknown(intro.objectives, null).filter(Boolean);
  if (aims.length) {
    const box = el('div', 'panel');
    box.append(el('div', 'panel__label', 'この演習で学ぶこと'));
    const ul = el('ul', 'bullets');
    aims.forEach((a) => ul.append(el('li', null, visible(a))));
    box.append(ul);
    page.append(box);
  }

  // ---- 読み取りの制約 ----
  //
  // 教材が不完全なら、始める前に言う。終わってから言われても、どの判断が
  // その影響を受けたのか分からない。
  const limits = [];
  if (ds.truncated) limits.push('上限に達したため、一部のログを最後まで読んでいません。');
  if (ds.unreadable) limits.push(`${ds.unreadable} 件の問題ログを読み取れませんでした。`);
  // 「読み取れなかった」と「読む仕組みが無い」は直し方が違うので分けて言う。
  if (ds.unsupported) {
    limits.push(
      `${ds.unsupported} 件の問題ログは、分類はできましたが専用の解析に対応していないため、` +
      'この教材の材料にしていません。'
    );
  }
  if (ds.unrecognized) {
    limits.push(
      `${ds.unrecognized} 件のログは、登録済みのどのパーサーでも形式を判別できず、` +
      'この教材の材料になっていません。'
    );
  }
  if (ds.incomplete && !limits.length) limits.push('読み取れなかったログがあります。');
  if (limits.length) {
    const box = el('div', 'panel');
    box.append(el('div', 'panel__label', 'この教材の制約'));
    limits.forEach((t) => box.append(el('div', 'member__warn', `⚠ ${t}`)));
    page.append(box);
  }

  page.append(glossary());

  // ---- 導線 ----
  const nav = el('div', 'navbtns');
  const back = el('button', 'btn btn-ghost', '演習一覧へ戻る');
  back.type = 'button';
  back.addEventListener('click', () => {
    location.hash = '#/';
  });
  nav.append(back);

  const start = el('button', 'btn btn-primary', '調査を始める');
  start.type = 'button';
  start.addEventListener('click', onStart);
  nav.append(start);
  page.append(nav);

  title.focus({ preventScroll: true });
  return { start, report };
}

/** 静的解析の教材で使う用語集。 */
export function staticGlossary() {
  return glossary(STATIC_GLOSSARY);
}

function token() {
  const meta = document.querySelector('meta[name="mws-token"]');
  return meta ? meta.content : '';
}

/**
 * 静的解析の教材の導入画面。
 *
 * ログ教材の「対象ホスト」「使用するログ」は、ここには無い。代わりに、何を
 * どの版で読んだのか（入力のハッシュ・固定したツールの版）と、実行して
 * いないことを最初に示す。
 */
function renderStaticIntroduction(mount, lesson, onStart) {
  const intro = lesson.introduction || {};
  const meta = intro.static || lesson.static || {};
  const program = meta.program || {};
  const input = meta.input || {};
  const tool = meta.tool || {};
  const counts = meta.questionCounts || {};
  const origin = meta.origin || {};

  const page = el('div', 'player');
  mount.append(page);
  const head = el('div', 'stage-head');
  const title = el('h1', 'stage-name', visible(lesson.title || '静的解析演習'));
  title.tabIndex = -1;
  head.append(title);
  page.append(head);

  if (intro.status === 'draft') {
    page.append(
      el('div', 'feedback is-bad',
        '⚠ これは Ghidra の保存済み解析情報から自動生成した下書きです。内容を確認のうえ使ってください。')
    );
  }
  page.append(
    el('div', 'feedback is-ok',
      '対象のプログラムは実行していません。GZF に保存されていた解析結果（関数・命令・文字列・参照）を読み出しただけです。')
  );
  if (meta.sample) {
    page.append(el('p', 'muted', visible(meta.sample.note || '')));
  }
  page.append(el('p', null, visible(intro.scenario || '')));

  const originText = {
    upload: `ブラウザで選んだファイル（${visible(origin.name || '')}）`,
    archive: `ZIP の中の項目（${visible(origin.archiveName || '')} :: ${visible(origin.member || '')}）`,
    sample: `同梱サンプル（${visible(origin.name || '')}）`,
  }[origin.kind] || '記録なし';

  const facts = el('div', 'panel');
  facts.append(el('div', 'panel__label', 'この演習について'));
  const rows = [
    ['対象プログラム', program.name],
    ['実行ファイル形式', program.executableFormat || '記録なし'],
    ['プロセッサ・コンパイラ仕様', `${program.languageId || ''} / ${program.compilerSpecId || ''}`],
    ['読み込み基準アドレス', program.imageBase],
    ['入力元', originText],
    ['入力 GZF の SHA-256', input.sha256],
    ['元の実行ファイルの SHA-256（GZF に保存された値）', program.storedExecutableSha256 || '記録なし'],
    ['Ghidra の版 / 抽出スクリプトの版', `${tool.ghidraVersion || ''} / ${tool.scriptVersion || ''}`],
    ['処理イメージ', `${tool.imageRef || ''} ${tool.imageId ? `（${tool.imageId}）` : ''}`],
    ['設問', `文字列の参照 ${counts.string || 0} 問・直接呼び出し ${counts.call || 0} 問・外部関数 ${counts.external || 0} 問`],
    ['所要時間の目安', intro.estimatedMinutes ? `およそ ${intro.estimatedMinutes} 分` : '取得できませんでした'],
  ];
  const table = el('dl', 'factlist');
  rows.forEach(([k, v]) => {
    table.append(el('dt', 'factlist__key', k));
    table.append(el('dd', 'factlist__value mono', visible(String(v == null ? '' : v))));
  });
  facts.append(table);
  facts.append(
    el('p', 'muted',
      '入力 GZF のハッシュは送ったファイルそのものの値で、元の実行ファイルのハッシュ（Ghidra が解析時に保存した値）とは別物です。')
  );
  page.append(facts);

  const aims = Array.isArray(intro.objectives) ? intro.objectives.filter(Boolean) : [];
  if (aims.length) {
    const box = el('div', 'panel');
    box.append(el('div', 'panel__label', 'この演習で学ぶこと'));
    const ul = el('ul', 'bullets');
    aims.forEach((a) => ul.append(el('li', null, visible(a))));
    box.append(ul);
    page.append(box);
  }

  const limits = [];
  if ((meta.truncated || []).length) {
    limits.push('上限に達したため、一部の記録を読み出していません。完全な一覧ではありません。');
  }
  (meta.skipped || []).forEach((t) => limits.push(`設問を作れなかった種類があります — ${t}`));
  if (limits.length) {
    const box = el('div', 'panel');
    box.append(el('div', 'panel__label', 'この教材の制約'));
    limits.forEach((t) => box.append(el('div', 'member__warn', `⚠ ${visible(t)}`)));
    page.append(box);
  }

  page.append(staticGlossary());

  const nav = el('div', 'navbtns');
  const back = el('button', 'btn btn-ghost', '演習一覧へ戻る');
  back.type = 'button';
  back.addEventListener('click', () => {
    location.hash = '#/';
  });
  nav.append(back);
  const start = el('button', 'btn btn-primary', '演習を始める');
  start.type = 'button';
  start.addEventListener('click', onStart);
  nav.append(start);
  page.append(nav);

  // 教材の削除。二段階にして、押し間違いで消えないようにする。
  const del = document.createElement('details');
  del.className = 'fold';
  const delHead = document.createElement('summary');
  delHead.className = 'fold__head';
  delHead.textContent = 'この教材を削除する';
  del.append(delHead);
  del.append(el('p', 'muted', 'この PC のデータベースから、この教材（採用した根拠・版・ハッシュ）を削除します。元の GZF には影響しません。'));
  const delNav = el('div', 'navbtns navbtns--wrap');
  const confirmDel = el('button', 'btn btn-ghost btn-sm', '削除する');
  confirmDel.type = 'button';
  const delOut = el('div');
  confirmDel.addEventListener('click', async () => {
    confirmDel.disabled = true;
    let ok = false;
    let msg = '削除できませんでした。';
    try {
      const res = await fetch(`/api/lessons/${encodeURIComponent(lesson.id)}/delete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-MWS-Token': token() },
        body: '{}',
      });
      ok = res.ok;
      if (!ok) {
        const body = await res.json().catch(() => ({}));
        msg = body.error || msg;
      }
    } catch (err) {
      msg = 'サーバーに接続できません。';
    }
    if (!delOut.isConnected) return;
    if (ok) {
      location.hash = '#/';
      return;
    }
    confirmDel.disabled = false;
    delOut.textContent = '';
    delOut.append(el('p', 'feedback is-bad', visible(msg)));
  });
  delNav.append(confirmDel);
  del.append(delNav, delOut);
  page.append(del);

  title.focus({ preventScroll: true });
  return { start, report: lesson.report || {} };
}
