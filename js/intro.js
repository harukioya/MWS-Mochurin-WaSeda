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

/** 外部を開かずに読める用語集。仕様書 1 節の必須項目を満たす。 */
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

/** 用語集。details なので既定では畳まれ、キーボードだけで開ける。 */
export function glossary() {
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
  GLOSSARY.forEach(([term, meaning]) => {
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
