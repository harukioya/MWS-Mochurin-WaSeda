// test_ui_report.mjs — 導入画面と最終調査レポートの回帰テスト。
//
// 本物の player.js / quiz.js / recap.js / intro.js を最小の DOM シムで動かす。
// ブラウザは使わないので、確かめられるのは「何をどう組み立てたか」までで、
// 実際の見た目やスクロールの体感は見ていない。
//
// 実データは使わない。架空の端末名と RFC 5737 の文書用アドレスだけ。
//
//   node backend/tests/test_ui_report.mjs

import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

// ---------------------------------------------------------------------------
class El {
  constructor(tag) {
    this.tag = tag;
    this.children = [];
    this.attrs = {};
    this._text = '';
    this._on = {};
    this.parent = null;
    this._root = false;
    this.classList = {
      add: (c) => { this.className = (this.className ? this.className + ' ' : '') + c; },
    };
  }
  _adopt(c) {
    if (c.parent) c.parent.children = c.parent.children.filter((x) => x !== c);
    c.parent = this;
    return c;
  }
  set textContent(v) {
    this.children.forEach((c) => (c.parent = null));
    this._text = String(v);
    this.children = [];
  }
  get textContent() {
    return this.children.length
      ? this.children.map((c) => c.textContent).join('')
      : this._text;
  }
  appendChild(c) { this.children.push(this._adopt(c)); return c; }
  append(...cs) { cs.forEach((c) => this.children.push(this._adopt(c))); }
  replaceChildren(...cs) {
    this.children.forEach((c) => (c.parent = null));
    this._text = '';
    this.children = cs.map((c) => this._adopt(c));
  }
  setAttribute(k, v) { this.attrs[k] = v; }
  addEventListener(t, f) { (this._on[t] || (this._on[t] = [])).push(f); }
  click() { return Promise.all((this._on.click || []).map((f) => f())); }
  focus() { globalThis.__focused = this; }
  scrollIntoView() { globalThis.__scrolled = this; }
  get isConnected() {
    let n = this;
    while (n) { if (n._root) return true; n = n.parent; }
    return false;
  }
  find(pred, acc = []) {
    if (pred(this)) acc.push(this);
    this.children.forEach((c) => c.find(pred, acc));
    return acc;
  }
  cls(name) {
    return this.find((e) => String(e.className).split(' ').includes(name));
  }
  button(re) {
    return this.find((e) => e.tag === 'button' && re.test(e.textContent))[0];
  }
}

const app = new El('main');
app._root = true;
function byId(node, id) {
  if (node.id === id) return node;
  for (const c of node.children) { const r = byId(c, id); if (r) return r; }
  return null;
}
globalThis.document = {
  createElement: (t) => new El(t),
  getElementById: (id) => (id === 'app' ? app : byId(app, id)),
  querySelector: () => null,
  addEventListener() {}, removeEventListener() {},
};
globalThis.window = { scrollTo() {}, dispatchEvent() {}, addEventListener() {} };
globalThis.location = { hash: '' };
globalThis.HashChangeEvent = class {};

// ---------------------------------------------------------------------------
const EV_A = 'ev-aaaaaaaaaaaaaaaaaaaaaaaa';
const EV_B = 'ev-bbbbbbbbbbbbbbbbbbbbbbbb';

const src = (member, line, excerpt) => ({
  archivePath: `case/DFIR/logs.zip :: ${member}`, member, line, excerpt,
});

/** フェーズ3の形。導入・時系列・ATT&CK・未確定事項を持つ。 */
function lesson(overrides = {}) {
  const base = {
    id: 'gen-test',
    title: 'テスト演習',
    introduction: {
      scenario: '記録を読み、何が起きたかを確かめます。',
      logTypes: ['InfoTrace Mark II（端末の記録）'],
      hosts: ['WS99'],
      objectives: ['記録された事実と解釈を区別する'],
      status: 'draft',
      estimatedMinutes: 9,
      dataset: { year: 2022, label: 'MWS Cup 2022 DFIR', truncated: true, unreadable: 2 },
    },
    evidence: {
      [EV_A]: { id: EV_A, kind: 'process', confidence: 'observed',
                source: src('logs/ws99.log', 3, 'psPath="C:\\W\\cmd.exe"') },
      [EV_B]: { id: EV_B, kind: 'file', confidence: 'observed',
                source: src('logs/ws99.log', 8, 'path="C:\\Users\\a\\x.dat"') },
    },
    report: {
      timeline: [
        { timestamp: '10/05/2022 14:00:01.000 +0900', timeKnown: true,
          title: 'WS99: cmd.exe を起動', status: 'observed',
          member: 'logs/ws99.log', line: 3, evidenceIds: [EV_A] },
        { timestamp: '時刻不明', timeKnown: false,
          title: 'WS99: x.dat に書き込み', status: 'observed',
          member: 'logs/ws99.log', line: 8, evidenceIds: [EV_B] },
      ],
      techniques: [
        { id: 'T1059.003', name: 'Windows Command Shell',
          reason: '起動したプログラムがコマンドシェルだと psPath にあります。',
          evidenceIds: [EV_A], ruleVersion: '2026-09-mws-1',
          confidence: 'high', status: 'observed' },
      ],
      unknowns: [
        { topic: '記録の順序と出来事の順序', detail: '記録の前後は因果を意味しません。' },
        { topic: '読み取りの打ち切り', detail: '一部のログを最後まで読んでいません。' },
      ],
      nextInvestigations: ['親プロセスを確認する'],
    },
    stages: [
      {
        id: 'endpoint', name: '端末', intro: '',
        events: [
          { type: 'process', detail: 'WS99: cmd.exe を起動', evidenceIds: [EV_A] },
          { type: 'file', detail: 'WS99: x.dat に書き込み', evidenceIds: [EV_B] },
        ],
        quiz: null, quizzes: [],
      },
    ],
  };
  const q1 = {
    id: 'q1', type: 'single_choice', category: 'log-reading',
    q: '問い1', options: ['あ', 'い'], correct: 1, explain: '解説1',
    evidenceIds: [EV_A], nextInvestigation: '親プロセスを確認する',
  };
  const q2 = {
    id: 'q2', type: 'single_choice', category: 'correlation',
    q: 'どちらが先に記録されましたか。', options: ['A が先', 'B が先'],
    correct: 0, explain: '記録の順序です。引き起こした、とは言えません。',
    evidenceIds: [EV_A, EV_B], status: 'correlated',
  };
  base.stages[0].quizzes = [q1, q2];
  base.stages[0].quiz = q1;
  return { ...base, ...overrides };
}

/** フェーズ1以前の形。導入もレポートも無い。 */
function oldLesson() {
  return {
    id: 'gen-old', title: '旧',
    recap: { summary: '旧形式のまとめ', chain: [
      { stage: '段階', name: '端末', desc: '観測 1 件。',
        attck: [{ id: 'T1059.003', name: 'Shell' }] },
    ] },
    stages: [{
      id: 's', name: '段階', intro: '',
      events: [{ type: 'process', detail: '何か' }],
      quiz: { q: '問い', options: ['あ', 'い'], correct: 1, explain: '解説' },
    }],
  };
}

const results = [];
async function test(name, fn) {
  try { await fn(); results.push(['ok', name]); }
  catch (e) { results.push(['NG', name, e.message]); }
}

const { renderLesson } = await import(REPO + '/js/player.js');

function stubFetch(obj, delay = 0) {
  globalThis.fetch = async () => {
    if (delay) await new Promise((r) => setTimeout(r, delay));
    return { ok: true, json: async () => obj, status: 200 };
  };
}

async function open(obj) {
  stubFetch(obj);
  const view = document.createElement('div');
  app.replaceChildren(view);
  await renderLesson(view, obj.id);
  return view;
}

/** 導入 → 全設問へ回答 → 振り返り、まで進める。 */
async function playThrough(view, answers) {
  const start = view.button(/調査を始める/);
  if (start) await start.click();
  for (const pick of answers) {
    const options = view.cls('option');
    await options[pick].click();
    const next = view.button(/次の設問へ/);
    if (next) await next.click();
  }
  const cont = view.button(/振り返りへ|次へ/);
  if (cont) await cont.click();
}

// ---------------------------------------------------------------------------
await test('導入画面が出て、そこから調査を始められる', async () => {
  const view = await open(lesson());
  const text = view.textContent;
  assert.ok(text.includes('MWS Cup 2022 DFIR'), '年度と課題名');
  assert.ok(text.includes('自動生成した下書き'), '下書きであることを明示');
  assert.ok(text.includes('InfoTrace Mark II'), '使用するログ種別');
  assert.ok(text.includes('WS99'), '対象ホスト');
  assert.ok(text.includes('9 分'), '所要時間の目安');
  assert.ok(text.includes('この演習で学ぶこと'), '学ぶこと');
  assert.equal(view.cls('option').length, 0, 'まだ設問は出ていない');

  await view.button(/調査を始める/).click();
  assert.ok(view.cls('option').length > 0, '調査が始まる');
});

await test('導入に読み取りの制約が出る', async () => {
  const view = await open(lesson());
  const text = view.textContent;
  assert.ok(text.includes('最後まで読んでいません'), 'truncated');
  assert.ok(text.includes('2 件の問題ログを読み取れませんでした'), 'unreadable');
});

await test('用語説明がキーボードで開ける', async () => {
  const view = await open(lesson());
  const fold = view.find((e) => e.tag === 'details' &&
    /はじめての方へ/.test(e.textContent))[0];
  assert.ok(fold, '用語集がある');
  const summary = fold.find((e) => e.tag === 'summary')[0];
  assert.ok(summary, 'summary なのでキーボードで開閉できる');
  const body = fold.textContent;
  for (const term of ['ログ', '証拠', '親プロセス', 'プロキシ',
                      'MITRE ATT&CK', '観測された事実', '仮説']) {
    assert.ok(body.includes(term), `用語 ${term}`);
  }
});

await test('導入のない旧形式はそのまま第1段階から始まる', async () => {
  const view = await open(oldLesson());
  assert.equal(view.button(/調査を始める/), undefined, '導入は出さない');
  assert.ok(view.cls('option').length > 0, 'すぐ設問が出る');
});

await test('得点は設問単位で、カテゴリ別も出る', async () => {
  const view = await open(lesson());
  await playThrough(view, [1, 1]);   // q1 正解 / q2 不正解
  const heading = app.find((e) => e.tag === 'h1' && /正解/.test(e.textContent))[0];
  assert.equal(heading.textContent, '正解 1 / 2', heading.textContent);
  const scores = app.cls('scorelist')[0];
  assert.ok(scores, '段階別・カテゴリ別の表がある');
  const all = app.cls('scorelist').map((s) => s.textContent).join(' ');
  assert.ok(all.includes('ログの意味を読む'), 'カテゴリ名');
  assert.ok(all.includes('二つの証拠を関連付ける'), 'カテゴリ名');
});

await test('時系列が根拠付きで出る', async () => {
  const view = await open(lesson());
  await playThrough(view, [1, 0]);
  const rows = app.cls('timeline__row');
  assert.equal(rows.length, 2);
  const text = rows.map((r) => r.textContent).join(' ');
  assert.ok(text.includes('10/05/2022 14:00:01.000 +0900'), '原文の時刻');
  assert.ok(text.includes('時刻不明'), '読めなかったものも残す');
  assert.ok(text.includes('logs/ws99.log'), '出典');
  assert.ok(text.includes('3 行目'), '行番号');
  assert.ok(text.includes('観測された事実'), '状態を文言で');
  assert.ok(
    app.textContent.includes('引き起こした'),
    '記録の順序と因果を区別する断りがある'
  );
});

await test('ATT&CK に理由と根拠と規則版が出る', async () => {
  const view = await open(lesson());
  await playThrough(view, [1, 0]);
  const card = app.cls('technique')[0];
  assert.ok(card, 'ATT&CK の欄がある');
  const text = card.textContent;
  assert.ok(text.includes('T1059.003'), 'Technique ID');
  assert.ok(text.includes('psPath にあります'), '日本語の対応理由');
  assert.ok(text.includes('2026-09-mws-1'), '規則の版');
  assert.ok(text.includes('確信度'), '確信度');
  assert.ok(text.includes('観測された事実'), '状態');
  assert.ok(card.button(/根拠ログを見る/), '根拠への導線');
});

await test('未確定事項と追加調査が出る', async () => {
  const view = await open(lesson());
  await playThrough(view, [1, 0]);
  const text = app.textContent;
  assert.ok(text.includes('断定できなかったこと'));
  assert.ok(text.includes('記録の順序と出来事の順序'));
  assert.ok(text.includes('読み取りの打ち切り'), 'truncated が反映される');
  assert.ok(text.includes('次に調べるとよいこと'));
  assert.ok(text.includes('親プロセスを確認する'));
});

await test('間違えた問題だけが復習対象になる', async () => {
  const view = await open(lesson());
  await playThrough(view, [1, 1]);   // q1 正解 / q2 不正解
  const reviews = app.cls('review');
  assert.equal(reviews.length, 1, '間違えた 1 問だけ');
  assert.ok(reviews[0].textContent.includes('どちらが先に記録されましたか'));
  assert.ok(!reviews[0].textContent.includes('問い1'), '正解した問題は出さない');
});

await test('復習ボタンで該当段階へ戻れ、得点が二重加算されない', async () => {
  const view = await open(lesson());
  await playThrough(view, [1, 1]);
  assert.equal(
    app.find((e) => e.tag === 'h1' && /正解/.test(e.textContent))[0].textContent,
    '正解 1 / 2'
  );
  const back = app.button(/この段階へ戻って解き直す/);
  assert.ok(back, '復習の導線が押せる');
  await back.click();
  assert.ok(view.cls('option').length > 0, '段階へ戻った');

  // 戻って正解し直しても、同じ問題は数え直さない。
  await view.cls('option')[1].click();
  const next = view.button(/次の設問へ/);
  if (next) await next.click();
  await view.cls('option')[0].click();
  await view.button(/振り返りへ|次へ/).click();
  assert.equal(
    app.find((e) => e.tag === 'h1' && /正解/.test(e.textContent))[0].textContent,
    '正解 1 / 2',
    '二重加算されない'
  );
});

await test('複数証拠の問題は両方の根拠を見せる', async () => {
  const view = await open(lesson());
  const start = view.button(/調査を始める/);
  await start.click();
  await view.cls('option')[1].click();
  await view.button(/次の設問へ/).click();
  await view.cls('option')[0].click();
  const jumps = view.find((e) => e.tag === 'button' && /根拠ログを見る/.test(e.textContent));
  assert.equal(jumps.length, 2, '2 件の根拠それぞれへ飛べる');
  const cards = view.cls('evidence__excerpt').map((e) => e.textContent).join(' ');
  assert.ok(cards.includes('cmd.exe'), '1 件目の原文');
  assert.ok(cards.includes('x.dat'), '2 件目の原文');
});

await test('証拠カードの DOM ID が重複しない', async () => {
  const view = await open(lesson());
  await playThrough(view, [1, 0]);
  const ids = app.find((e) => e.id).map((e) => e.id);
  assert.equal(new Set(ids).size, ids.length, `重複: ${ids}`);
});

await test('ATT&CK ゼロ・時系列ゼロ・設問ゼロでも白画面にならない', async () => {
  const bare = lesson({
    report: { timeline: [], techniques: [], unknowns: [], nextInvestigations: [] },
  });
  bare.stages[0].quizzes = [];
  bare.stages[0].quiz = null;
  bare.stages[0].note = 'この段階では、問題を作るための根拠が不足しています。';
  const view = await open(bare);
  await view.button(/調査を始める/).click();
  assert.ok(view.textContent.includes('根拠が不足'), '理由を説明する');
  const cont = view.button(/振り返りへ|次へ/);
  assert.ok(cont, '設問ゼロでも先へ進める');
  await cont.click();
  const text = app.textContent;
  assert.ok(text.includes('正解 0 / 0'), '得点は 0/0');
  assert.ok(text.includes('推測で手法を当てはめていません'), 'ATT&CK ゼロの説明');
  assert.ok(app.button(/もう一度/), '操作不能にならない');
});

await test('旧形式の recap.chain も表示できる', async () => {
  const view = await open(oldLesson());
  await view.cls('option')[0].click();
  await view.button(/振り返りへ|次へ/).click();
  const text = app.textContent;
  assert.ok(app.cls('kc-step').length > 0, 'キルチェーンが出る');
  assert.ok(text.includes('旧形式のまとめ'), 'summary');
  assert.ok(text.includes('T1059.003'), '旧形式の ATT&CK');
});

await test('レポートの任意フィールドが欠けても落ちない', async () => {
  const broken = lesson({ report: undefined, introduction: undefined });
  const view = await open(broken);
  assert.ok(view.cls('option').length > 0, '導入なしで始まる');
  await view.cls('option')[1].click();
  const next = view.button(/次の設問へ/);
  if (next) await next.click();
  await view.cls('option')[0].click();
  await view.button(/振り返りへ|次へ/).click();
  assert.ok(app.button(/演習の一覧に戻る/), 'レポートが描ける');
});

await test('レポートでも不可視文字が可視化される', async () => {
  const l = lesson();
  l.evidence[EV_A].source.member = 'logs/a\nb\tc.log';
  l.report.timeline[0].member = 'logs/a\nb\tc.log';
  const view = await open(l);
  await playThrough(view, [1, 0]);
  const row = app.cls('timeline__src')[0].textContent;
  assert.ok(!row.includes('\n'), '改行を残さない');
  assert.ok(!row.includes('\t'), 'タブを残さない');
  assert.ok(row.includes('<U+000A>') && row.includes('<U+0009>'), row);
});

await test('画面遷移後にフォーカスが移る', async () => {
  const view = await open(lesson());
  globalThis.__focused = null;
  await view.button(/調査を始める/).click();
  assert.ok(globalThis.__focused, '段階へ入るときにフォーカスする');
  await playThrough(view, [1, 0]);
  const heading = app.find((e) => e.tag === 'h1' && /正解/.test(e.textContent))[0];
  assert.equal(globalThis.__focused, heading, 'レポートの見出しへ移る');
});

// ---------------------------------------------------------------------------
// 「根拠ログを見る」が実際に効くか
//
// 以前は、ボタンを組み立てたことだけを確かめていた。レポート側のカードには
// id を付けていなかったので、押しても getElementById が null を返し、
// ハンドラは何もせずに戻っていた。組み立ての検査は、それを素通りさせる。
// ここでは必ず押して、移動先まで見る。

/** レポート内の全ジャンプボタン。 */
const jumpsIn = (node) => node.find(
  (e) => e.tag === 'button' && /根拠ログを見る/.test(e.textContent)
);

/**
 * 設問が指していない証拠を、時系列と ATT&CK にだけ足した教材。
 *
 * これが無いと検査が空回りする。既定の教材は EV_A と EV_B の両方が設問の
 * 根拠でもあるので、「回答が指したものだけ」を並べる実装でも、たまたま
 * すべての飛び先が揃ってしまう。レポート側だけが参照する証拠を 1 件
 * 混ぜて、集め漏れが表に出るようにする。
 */
const EV_C = 'ev-cccccccccccccccccccccccc';
function lessonWithReportOnlyEvidence() {
  const l = lesson();
  l.evidence[EV_C] = {
    id: EV_C, kind: 'registry', confidence: 'observed',
    source: src('logs/ws99.log', 21, 'path="HKCU\\...\\Run"'),
  };
  l.report.timeline.push({
    timestamp: '10/05/2022 14:00:30.000 +0900', timeKnown: true,
    timeComparable: true, title: 'WS99: Run キーを設定', status: 'observed',
    member: 'logs/ws99.log', line: 21, evidenceIds: [EV_C],
  });
  l.report.techniques.push({
    id: 'T1547.001', name: 'Registry Run Keys',
    reason: 'path がログオン時に自動実行される場所を指しています。',
    reasons: [{ reason: 'path がログオン時に自動実行される場所を指しています。',
                evidenceIds: [EV_C] }],
    evidenceIds: [EV_C], ruleVersion: '2026-09-mws-2',
    confidence: 'high', status: 'observed',
  });
  // 設問は EV_C を指さない。レポートだけが参照する証拠であること。
  for (const q of l.stages[0].quizzes) {
    assert.ok(!q.evidenceIds.includes(EV_C), '前提が崩れている');
  }
  return l;
}

await test('レポートの「根拠ログを見る」を押すと証拠カードへ移動する', async () => {
  const view = await open(lessonWithReportOnlyEvidence());
  await playThrough(view, [1, 0]);

  const buttons = jumpsIn(app);
  assert.ok(buttons.length > 0, 'レポートにジャンプボタンが無い');

  for (const btn of buttons) {
    globalThis.__scrolled = null;
    globalThis.__focused = null;
    await btn.click();
    assert.ok(globalThis.__scrolled, `押しても移動しない: ${btn.textContent}`);
    assert.equal(globalThis.__focused, globalThis.__scrolled,
      '移動先へフォーカスが移っていない');
    assert.ok(String(globalThis.__scrolled.className).includes('evidence'),
      '移動先が証拠カードでない');
    assert.ok(globalThis.__scrolled.isConnected, '移動先が頁から外れている');
  }
});

await test('レポートが指す証拠は、すべてレポート内にカードがある', async () => {
  const view = await open(lessonWithReportOnlyEvidence());
  await playThrough(view, [1, 0]);
  const anchored = new Set(
    app.find((e) => typeof e.id === 'string' && e.id.startsWith('ev-report-'))
       .map((e) => e.id)
  );
  assert.ok(anchored.size > 0, 'レポート用のアンカーが 1 つも無い');
  // EV_C は時系列と ATT&CK だけが指す。回答からは辿れない。
  for (const ident of [EV_A, EV_B, EV_C]) {
    assert.ok(anchored.has(`ev-report-${ident}`), `${ident} のカードが無い`);
  }
});

await test('同じ id のカードが 2 枚できない', async () => {
  const view = await open(lesson());
  await playThrough(view, [1, 0]);
  const ids = app.find((e) => typeof e.id === 'string' && e.id).map((e) => e.id);
  assert.equal(new Set(ids).size, ids.length, `id が重複している: ${ids}`);
});

await test('同じ手法でも理由が違えば、理由ごとに根拠を出す', async () => {
  const l = lesson();
  l.report.techniques = [{
    id: 'T1490', name: 'Inhibit System Recovery',
    reason: 'vssadmin の理由／bcdedit の理由',
    reasons: [
      { reason: 'vssadmin が復元用の控えを削除しています。', evidenceIds: [EV_A] },
      { reason: 'bcdedit が回復機能を無効化しています。', evidenceIds: [EV_B] },
    ],
    evidenceIds: [EV_A, EV_B], ruleVersion: '2026-09-mws-2',
    confidence: 'high', status: 'observed',
  }];
  const view = await open(l);
  await playThrough(view, [1, 0]);
  const card = app.cls('technique')[0];
  const reasons = card.cls('technique__reason').map((e) => e.textContent);
  assert.equal(reasons.length, 2, `理由が束ねられている: ${reasons}`);
  assert.ok(reasons[0].includes('vssadmin'), reasons[0]);
  assert.ok(reasons[1].includes('bcdedit'), reasons[1]);
  // それぞれの理由の直後に、その理由の根拠だけを指すボタンが並ぶ。
  const labels = jumpsIn(card).map((e) => e.textContent);
  assert.equal(labels.length, 2, labels);
  assert.ok(labels[0].includes('3 行目'), labels[0]);
  assert.ok(labels[1].includes('8 行目'), labels[1]);
});

await test('段階の設問が別の記録を指していても、飛び先がある', async () => {
  // 突き合わせの設問は、その段階の事象に無い記録を指すことがある。
  const l = lesson();
  l.stages[0].events = [
    { type: 'process', detail: 'WS99: cmd.exe を起動', evidenceIds: [EV_A] },
  ];
  const view = await open(l);
  await view.button(/調査を始める/).click();
  const anchored = new Set(
    view.find((e) => typeof e.id === 'string' && e.id.startsWith('ev-stage-'))
        .map((e) => e.id)
  );
  assert.ok(anchored.has(`ev-stage-${EV_B}`),
    '設問だけが指す記録のカードが出ていない');

  // 2 件目を指すのは 2 問目（突き合わせ）のほう。そこまで進める。
  await view.cls('option')[1].click();
  await view.button(/次の設問へ/).click();
  await view.cls('option')[0].click();
  const btn = jumpsIn(view).find((e) => /8 行目/.test(e.textContent));
  assert.ok(btn, '2 件目へのボタンが無い');
  globalThis.__scrolled = null;
  await btn.click();
  assert.ok(globalThis.__scrolled, '押しても移動しない');
  assert.equal(globalThis.__scrolled.id, `ev-stage-${EV_B}`);
});

await test('基準の揃わない時刻は、時系列の行にそう書く', async () => {
  const l = lesson();
  l.report.timeline[0].timeComparable = true;
  l.report.timeline[1].timeKnown = true;
  l.report.timeline[1].timestamp = '10/05/2022 01:00:00.000';
  l.report.timeline[1].timeComparable = false;
  const view = await open(l);
  await playThrough(view, [1, 0]);
  const marks = app.cls('timeline__basis');
  assert.equal(marks.length, 1, `印の数が合わない: ${marks.length}`);
  assert.equal(marks[0].textContent, '基準不明');
  const rows = app.cls('timeline__row');
  assert.ok(!rows[0].textContent.includes('基準不明') ||
            rows[1].textContent.includes('基準不明'),
    '基準の揃った行にまで印が付いている');
});

await test('新しい学習カテゴリが日本語で出る', async () => {
  const l = lesson();
  l.stages[0].quizzes[1].category = 'limits';
  const view = await open(l);
  await playThrough(view, [1, 0]);
  const text = app.textContent;
  assert.ok(text.includes('断定できない理由を説明する'), text.slice(0, 200));
  assert.ok(!text.includes('limits'), '内部のキーがそのまま出ている');
});

// ---------------------------------------------------------------------------
let bad = 0;
for (const [status, name, why] of results) {
  if (status === 'ok') console.log(`  ok   ${name}`);
  else { bad++; console.log(`  NG   ${name}\n       ${why}`); }
}
console.log(`\n${results.length - bad} / ${results.length} 成功`);
process.exit(bad ? 1 : 0);
