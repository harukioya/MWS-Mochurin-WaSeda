// test_ui_evidence.mjs — 証拠表示まわりのフロントエンド回帰テスト。
//
// 既存の検証と同じく、最小の DOM シムの上で本物の player.js / quiz.js を
// 動かす。ブラウザは使わないので、確かめられるのは「何をどう組み立てたか」
// までで、実際の見た目やスクロールの体感までは見ていない。
//
// 実データは使わない。架空の端末名と RFC 5737 の文書用アドレスだけ。
//
//   node backend/tests/test_ui_evidence.mjs

import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

// ---------------------------------------------------------------------------
// 最小の DOM
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
      add: (c) => {
        this.className = (this.className ? this.className + ' ' : '') + c;
      },
      remove: (c) => {
        this.className = String(this.className || '').split(' ').filter((x) => x && x !== c).join(' ');
      },
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
  // 正答率のリングは SVG。名前空間は見ないので、同じ El で足りる。
  createElementNS: (_ns, t) => new El(t),
  getElementById: (id) => (id === 'app' ? app : byId(app, id)),
  querySelector: () => null,
  addEventListener() {},
  removeEventListener() {},
};
globalThis.window = { scrollTo() {}, dispatchEvent() {}, addEventListener() {} };
globalThis.location = { hash: '' };
globalThis.HashChangeEvent = class {};

// ---------------------------------------------------------------------------
// fixture（架空データ）
// ---------------------------------------------------------------------------
const EV_A = 'ev-aaaaaaaaaaaaaaaaaaaaaaaa';
const EV_B = 'ev-bbbbbbbbbbbbbbbbbbbbbbbb';

// 出典も原文も細工されている前提。HTML、双方向制御、NUL を混ぜる。
const HOSTILE =
  '10/05/2022 14:00:01 com="WS99" <script>alert(1)</script> ' +
  'path="C:\\payroll\u202egnp.exe" nul=\u0000';

function lesson() {
  return {
    id: 'gen-test',
    title: 'テスト',
    evidence: {
      [EV_A]: {
        id: EV_A, kind: 'process', confidence: 'observed',
        source: {
          archivePath: 'case/logs.zip :: logs/ws99.log',
          member: 'logs/ws99.log', line: 12345, excerpt: HOSTILE,
        },
      },
      [EV_B]: {
        id: EV_B, kind: 'file', confidence: 'observed',
        source: {
          archivePath: 'case/logs.zip :: logs/ws99.log',
          member: 'logs/ws99.log', line: 12346, excerpt: '普通の行',
        },
      },
    },
    stages: [
      {
        id: 'endpoint', name: '端末', intro: '',
        events: [
          { type: 'process', detail: 'WS99 起動', evidenceIds: [EV_A] },
          { type: 'file', detail: 'WS99 書き込み', evidenceIds: [EV_B] },
        ],
        quiz: {
          id: 'q1', type: 'single_choice', q: '問い', options: ['あ', 'い'],
          correct: 1, explain: '解説', evidenceIds: [EV_A],
          nextInvestigation: '親プロセスを確認する',
        },
        quizzes: [
          {
            id: 'q1', type: 'single_choice', q: '問い', options: ['あ', 'い'],
            correct: 1, explain: '解説', evidenceIds: [EV_A],
            nextInvestigation: '親プロセスを確認する',
          },
          {
            id: 'q2', type: 'evidence_pick',
            learningObjective: '根拠を特定する',
            prompt: 'どの記録ですか。',
            options: [
              { label: 'logs/ws99.log の 12345 行目', evidenceId: EV_A },
              { label: 'logs/ws99.log の 12346 行目', evidenceId: EV_B },
            ],
            correct: 1, explanation: 'こちらです。', evidenceIds: [EV_B],
          },
        ],
      },
    ],
  };
}

/** 証拠を持たない、フェーズ1以前の形。 */
function oldLesson() {
  return {
    id: 'gen-old', title: '旧', stages: [
      {
        id: 's', name: '段階', intro: '',
        events: [{ type: 'process', detail: '何か' }],
        quiz: { q: '問い', options: ['あ', 'い'], correct: 1, explain: '解説' },
      },
    ],
  };
}

// ---------------------------------------------------------------------------
const results = [];
async function test(name, fn) {
  try { await fn(); results.push(['ok', name]); }
  catch (e) { results.push(['NG', name, e.message]); }
}

const { renderLesson } = await import(REPO + '/js/player.js');
const { renderQuiz } = await import(REPO + '/js/quiz.js');

function hintQuiz(overrides = {}, onAnswered = () => {}) {
  const view = document.createElement('div');
  app.replaceChildren(view);
  renderQuiz(view, {
    q: '起動したプログラムはどれですか。',
    options: ['ANSWER_VALUE', 'OTHER_VALUE'], correct: 0,
    explain: 'ANSWER_REVEALED_AFTER_RESPONSE',
    ...overrides,
  }, onAnswered);
  return view;
}

await test('ヒントは設問と選択肢の間に、閉じた標準の折りたたみで出る', async () => {
  const view = hintQuiz({ hint: 'psPath の末尾のファイル名を確認してください。' });
  const details = view.cls('quiz__hint')[0];
  assert.equal(details.tag, 'details');
  assert.equal(details.open, false);
  assert.equal(details.children[0].tag, 'summary');
  assert.equal(details.children[0].textContent, 'ヒントを見る');
  assert.match(view.cls('quiz__hint-body')[0].textContent, /psPath/);
  const quiz = view.cls('quiz')[0];
  assert.ok(quiz.children.indexOf(view.cls('quiz__q')[0]) < quiz.children.indexOf(details));
  assert.ok(quiz.children.indexOf(details) < quiz.children.indexOf(view.cls('options')[0]));
  assert.doesNotMatch(details.textContent, /ANSWER_VALUE|ANSWER_REVEALED/);
  assert.equal(view.cls('reveal').length, 0);
});

await test('ヒントの開閉は回答に数えず、開いても正解は正解のまま', async () => {
  const calls = [];
  const view = hintQuiz({ hint: '項目を確認してください。' }, (right) => calls.push(right));
  const details = view.cls('quiz__hint')[0];
  // DOM シムにはブラウザのネイティブ開閉がないので、open 状態だけを変える。
  details.open = true;
  details.open = false;
  details.open = true;
  assert.deepEqual(calls, []);
  assert.equal(view.cls('feedback').length, 0);
  assert.ok(view.cls('option').every((b) => !b.disabled));
  assert.match(details.textContent, /減点されません/);
  await view.cls('option')[0].click();
  await view.cls('option')[1].click();
  assert.deepEqual(calls, [true], '採点は回答時に一度だけ');
});

await test('ヒントのない旧教材と不正なヒント値には共通ヒントを出す', async () => {
  for (const hint of [undefined, null, '', '  ', {}, ['使わない']]) {
    const view = hintQuiz({ hint });
    assert.match(view.cls('quiz__hint-body')[0].textContent, /問題文が尋ねている対象/);
    assert.doesNotMatch(view.cls('quiz__hint')[0].textContent, /ANSWER_VALUE|ANSWER_REVEALED/);
    await view.cls('option')[0].click();
    assert.match(view.cls('feedback')[0].textContent, /正解/);
  }
});

await test('保存済み教材にも設問カテゴリに合った共通ヒントを出す', async () => {
  for (const [category, word] of [
    ['log-reading', 'ファイル名と行番号'], ['evidence', '証拠カード'],
    ['correlation', 'タイムゾーン'], ['attck', '引数'], ['limits', '推測'],
  ]) {
    const view = hintQuiz({ category });
    assert.ok(view.cls('quiz__hint-body')[0].textContent.includes(word));
  }
  assert.match(hintQuiz({ type: 'evidence_pick' }).cls('quiz__hint-body')[0].textContent, /証拠カード/);
  assert.match(hintQuiz({ category: 'constructor' }).cls('quiz__hint-body')[0].textContent, /問題文が尋ねている対象/);
});

await test('ヒントの HTML は実行せず、制御文字も可視化する', async () => {
  const view = hintQuiz({ hint: '<img src=x onerror=alert(1)>\u202e\u0000' });
  const body = view.cls('quiz__hint-body')[0];
  assert.match(body.textContent, /<img src=x/);
  assert.match(body.textContent, /<U\+202E>/);
  assert.match(body.textContent, /<U\+0000>/);
  assert.equal(body.children.length, 0);
});

await test('次の設問ではヒントが閉じ、新しい内容に切り替わる', async () => {
  const view = hintQuiz({ hint: '前のヒント' });
  view.cls('quiz__hint')[0].open = true;
  renderQuiz(view, {
    q: '次の問い', options: ['A', 'B'], correct: 0, hint: '次のヒント',
  }, () => {});
  assert.equal(view.cls('quiz__hint').length, 1);
  assert.equal(view.cls('quiz__hint')[0].open, false);
  assert.equal(view.cls('quiz__hint-body')[0].textContent, '次のヒント');
  assert.doesNotMatch(view.textContent, /前のヒント/);
});

// data.js の loadLesson は ESM なので差し替えられない。その下の fetch を
// 差し替えて、通信せずに任意の演習を読ませる。
function stubFetch(obj, delay = 0) {
  globalThis.fetch = async () => {
    if (delay) await new Promise((r) => setTimeout(r, delay));
    return { ok: true, json: async () => obj, status: 200 };
  };
}

await test('証拠カードが出典と行番号を表示する', async () => {
  stubFetch(lesson());
  const view = document.createElement('div');
  app.replaceChildren(view);
  await renderLesson(view, 'gen-test');
  const cards = view.cls('evidence');
  assert.equal(cards.length, 2, '事象ごとに 1 枚');
  const text = cards[0].textContent;
  assert.ok(text.includes('logs/ws99.log'), '出典ファイル名');
  assert.ok(text.includes('12345 行目'), '行番号');
  assert.ok(text.includes('記録から直接読める'), '状態を文言でも示す');
});

await test('原文の HTML が文字列として表示される', async () => {
  stubFetch(lesson());
  const view = document.createElement('div');
  app.replaceChildren(view);
  await renderLesson(view, 'gen-test');
  const pre = view.cls('evidence__excerpt')[0];
  // textContent へ入っているので、タグは要素ではなく文字として残る。
  assert.ok(pre.textContent.includes('<script>'), 'タグが文字として残る');
  assert.equal(pre.find((e) => e.tag === 'script').length, 0, '要素化しない');
});

await test('双方向制御文字と NUL が可視化される', async () => {
  stubFetch(lesson());
  const view = document.createElement('div');
  app.replaceChildren(view);
  await renderLesson(view, 'gen-test');
  const pre = view.cls('evidence__excerpt')[0].textContent;
  assert.ok(!pre.includes('\u202e'), '不可視のままにしない');
  assert.ok(pre.includes('<U+202E>'), '置き換えて見せる');
  assert.ok(!pre.includes('\u0000'), 'NUL を残さない');
  assert.ok(pre.includes('<U+0000>'));
});

await test('回答後に根拠と根拠ジャンプが出る', async () => {
  stubFetch(lesson());
  const view = document.createElement('div');
  app.replaceChildren(view);
  await renderLesson(view, 'gen-test');
  const options = view.cls('option');
  await options[0].click();
  assert.ok(view.cls('evidence-list').length >= 2, '回答後に根拠が並ぶ');
  const jump = view.find(
    (e) => e.tag === 'button' && /根拠ログを見る/.test(e.textContent)
  );
  assert.equal(jump.length, 1);
  assert.ok(/12345 行目/.test(jump[0].textContent), 'どの行かラベルで分かる');
});

await test('根拠ジャンプで対象へフォーカスが移る', async () => {
  stubFetch(lesson());
  const view = document.createElement('div');
  app.replaceChildren(view);
  await renderLesson(view, 'gen-test');
  await view.cls('option')[0].click();
  globalThis.__focused = null;
  globalThis.__scrolled = null;
  const jump = view.find(
    (e) => e.tag === 'button' && /根拠ログを見る/.test(e.textContent)
  )[0];
  await jump.click();
  assert.ok(globalThis.__scrolled, 'スクロールした');
  assert.ok(globalThis.__focused, 'フォーカスした');
  assert.equal(globalThis.__focused, globalThis.__scrolled, '同じカードへ');
  assert.ok(
    String(globalThis.__focused.className).includes('is-cited'),
    '見た目でも引用中と分かる'
  );
});

await test('evidence_pick へ回答できる', async () => {
  stubFetch(lesson());
  const view = document.createElement('div');
  app.replaceChildren(view);
  await renderLesson(view, 'gen-test');
  await view.cls('option')[0].click();
  const next = view.find(
    (e) => e.tag === 'button' && e.textContent === '次の設問へ'
  )[0];
  assert.ok(next, '次の設問へ進める');
  await next.click();
  const labels = view.cls('option__label').map((e) => e.textContent);
  assert.deepEqual(labels, [
    'logs/ws99.log の 12345 行目',
    'logs/ws99.log の 12346 行目',
  ]);
  await view.cls('option')[1].click();
  assert.ok(view.cls('feedback')[0].textContent.includes('正解'), '採点される');
});

await test('選択肢のラベルから正解が漏れない', async () => {
  stubFetch(lesson());
  const view = document.createElement('div');
  app.replaceChildren(view);
  await renderLesson(view, 'gen-test');
  await view.cls('option')[0].click();
  await view.find((e) => e.tag === 'button' && e.textContent === '次の設問へ')[0].click();
  const labels = view.cls('option__label').map((e) => e.textContent);
  // 空配列だと forEach が素通りして、検査したつもりになる。件数を先に固定する。
  assert.equal(labels.length, 2, '選択肢が描画されていること');
  // 出典と行番号だけ。長さや語彙で正解が分かる余地を残さない。
  labels.forEach((l) => assert.match(l, /^logs\/ws99\.log の \d+ 行目$/));
});

await test('証拠のない旧形式レッスンが従来どおり動く', async () => {
  stubFetch(oldLesson());
  const view = document.createElement('div');
  app.replaceChildren(view);
  await renderLesson(view, 'gen-old');
  assert.equal(view.cls('evidence').length, 0, '証拠カードは出さない');
  assert.equal(view.cls('event__source').length, 0, '出典も出さない');
  await view.cls('option')[0].click();
  assert.equal(
    view.find((e) => e.tag === 'button' && /根拠ログを見る/.test(e.textContent)).length,
    0,
    '根拠ジャンプを出さない'
  );
  assert.ok(view.cls('reveal').length, '解説は従来どおり出る');
  assert.ok(
    view.find((e) => e.tag === 'button' && /次へ|振り返りへ/.test(e.textContent)).length,
    '先へ進める'
  );
});

await test('画面離脱後の応答が別画面へ混入しない', async () => {
  stubFetch(lesson(), 60);
  const stale = document.createElement('div');
  app.replaceChildren(stale);
  const pending = renderLesson(stale, 'gen-test');
  // 応答を待つ間にルーターが器を差し替える。
  const fresh = document.createElement('div');
  app.replaceChildren(fresh);
  await pending;
  assert.equal(fresh.cls('evidence').length, 0, '新しい画面へ書かない');
  assert.equal(fresh.children.length, 0, '新しい画面は空のまま');
});

await test('同じ証拠の DOM id が重複しない', async () => {
  // 段階上部と回答後の 2 か所に同じ証拠が出る。両方へ id を付けると、
  // getElementById の行き先が実装任せになり、支援技術にとっても不正になる。
  stubFetch(lesson());
  const view = document.createElement('div');
  app.replaceChildren(view);
  await renderLesson(view, 'gen-test');
  await view.cls('option')[0].click();
  const ids = view.find((e) => e.id).map((e) => e.id);
  assert.equal(new Set(ids).size, ids.length, `id が重複: ${ids}`);
  // 飛び先は残っている。id は画面ごとに別の空間を持つ（演習の段階は
  // `stage`）。レポートは同じ証拠を `report` 側の id で持つので、両方が
  // 頁に出ても衝突しない。
  assert.ok(ids.includes('ev-stage-' + EV_A), ids.join(', '));
});

await test('得点が設問数と一致する', async () => {
  // 段階単位で 1 点にしていたため、端末段階に 2 問あると 4 問答えても
  // 「3/3」としか出せなかった。振り返りは「正解 X / Y」と読ませる。
  stubFetch(lesson());
  const view = document.createElement('div');
  app.replaceChildren(view);
  let seen = null;
  const recap = await import(REPO + '/js/recap.js');
  const realRecap = recap.renderRecap;
  await renderLesson(view, 'gen-test');

  // 設問1を正解、設問2を不正解にする。
  await view.cls('option')[1].click();          // q1 の正解は index 1
  await view.find((e) => e.tag === 'button' && e.textContent === '次の設問へ')[0].click();
  await view.cls('option')[0].click();          // q2 の正解は index 1 なので不正解

  const cont = view.find(
    (e) => e.tag === 'button' && /振り返りへ|次へ/.test(e.textContent)
  )[0];
  // recap は mount を置き換えるので、描画結果から得点表示を読む。
  await cont.click();
  const heading = app.find((e) => e.tag === 'h1' && /正解/.test(e.textContent))[0];
  assert.ok(heading, '振り返りに得点が出る');
  assert.equal(heading.textContent, '正解 1 / 2', heading.textContent);
  assert.ok(realRecap);
});

await test('設問のない旧形式は得点に数えない', async () => {
  const empty = {
    id: 'gen-empty', title: '空', stages: [
      { id: 's', name: '段階', intro: '', events: [{ type: 'process', detail: 'x' }] },
    ],
  };
  stubFetch(empty);
  const view = document.createElement('div');
  app.replaceChildren(view);
  await renderLesson(view, 'gen-empty');
  const cont = view.find(
    (e) => e.tag === 'button' && /振り返りへ/.test(e.textContent)
  )[0];
  assert.ok(cont, '設問が無くても先へ進める');
  await cont.click();
  const heading = app.find((e) => e.tag === 'h1' && /正解/.test(e.textContent))[0];
  // 以前はこうした段階が自動的に正解として加算されていた。
  assert.equal(heading.textContent, '正解 0 / 0', heading.textContent);
});

await test('出典名の改行とタブが、出る場所すべてで可視化される', async () => {
  // 証拠カードだけを見ていたため、イベント一覧の出典に未処理の値が残って
  // いても気づけなかった。表示に出る 3 か所をまとめて検査する。
  const l = lesson();
  l.evidence[EV_A].source.member = 'logs/a\nb\tc.log';
  stubFetch(l);
  const view = document.createElement('div');
  app.replaceChildren(view);
  await renderLesson(view, 'gen-test');

  const places = [
    ['証拠カード', view.cls('evidence__member')[0]],
    ['イベント一覧', view.cls('event__source')[0]],
  ];
  for (const [where, node] of places) {
    assert.ok(node, `${where} が描画されていること`);
    const text = node.textContent;
    assert.ok(!text.includes('\n'), `${where}: 改行を残さない`);
    assert.ok(!text.includes('\t'), `${where}: タブを残さない`);
    assert.ok(
      text.includes('<U+000A>') && text.includes('<U+0009>'),
      `${where}: ${JSON.stringify(text)}`
    );
  }

  // 回答後のジャンプボタンのラベルも同じ扱いであること。
  await view.cls('option')[0].click();
  const jump = view.find(
    (e) => e.tag === 'button' && /根拠ログを見る/.test(e.textContent)
  )[0];
  assert.ok(jump, 'ジャンプボタンがあること');
  assert.ok(!jump.textContent.includes('\n'), 'ジャンプ: 改行を残さない');
  assert.ok(!jump.textContent.includes('\t'), 'ジャンプ: タブを残さない');
});

// ---------------------------------------------------------------------------
let bad = 0;
for (const [status, name, why] of results) {
  if (status === 'ok') console.log(`  ok   ${name}`);
  else { bad++; console.log(`  NG   ${name}\n       ${why}`); }
}
console.log(`\n${results.length - bad} / ${results.length} 成功`);
process.exit(bad ? 1 : 0);
