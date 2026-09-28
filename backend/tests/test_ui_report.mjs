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
      remove: (c) => { this.className = String(this.className || '').split(' ').filter((x) => x && x !== c).join(' '); },
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
  focus(opts) { globalThis.__focused = this; globalThis.__focusOpts = opts; }
  scrollIntoView(opts) { globalThis.__scrolled = this; globalThis.__scrollOpts = opts; }
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
  // 正答率のリングは SVG。名前空間は見ないので、同じ El で足りる。
  createElementNS: (_ns, t) => new El(t),
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
  archivePath: `case/evidence/logs.zip :: ${member}`, member, line, excerpt,
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
      dataset: {
        profileId: 'example-incident', label: 'Example incident logs', edition: 'fixture v1',
        forced: false, truncated: true, unreadable: 2,
      },
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
  assert.ok(
    text.includes('データセット形式: Example incident logs（fixture v1）／自動で判定した形式'),
    'データセット形式と、誰が決めたか'
  );
  assert.ok(text.includes('自動生成した下書き'), '下書きであることを明示');
  assert.ok(text.includes('InfoTrace Mark II'), '使用するログ種別');
  assert.ok(text.includes('WS99'), '対象ホスト');
  assert.ok(text.includes('9 分'), '所要時間の目安');
  assert.ok(text.includes('この演習で学ぶこと'), '学ぶこと');
  assert.equal(view.cls('option').length, 0, 'まだ設問は出ていない');

  await view.button(/調査を始める/).click();
  assert.ok(view.cls('option').length > 0, '調査が始まる');
});

await test('導入と最終レポートに、同じデータセット形式の 1 行が出る', async () => {
  const obj = lesson();
  obj.introduction.dataset.forced = true;
  const view = await open(obj);
  const line = 'データセット形式: Example incident logs（fixture v1）／利用者が指定した形式';
  assert.ok(view.textContent.includes(line), '導入画面');
  await playThrough(view, obj.stages.map(() => 0));
  assert.ok(/正解 \d+ \/ \d+/.test(view.textContent), '最終レポートまで進んだ');
  assert.ok(view.textContent.includes(line), '最終レポート');
});

await test('edition が無いときは括弧ごと出さない', async () => {
  const obj = lesson();
  obj.introduction.dataset = { profileId: 'p', label: 'Example incident logs', forced: false };
  const view = await open(obj);
  const text = view.textContent;
  assert.ok(text.includes('データセット形式: Example incident logs／自動で判定した形式'));
  assert.ok(!text.includes('（）'), '空の括弧');
  assert.ok(!text.includes('Example incident logs（'), '中身の無い括弧');
});

await test('古い教材の year は表示に使わない（年度前提を持ち込まない）', async () => {
  const obj = lesson();
  obj.introduction.dataset = { year: 2022, label: 'Old dataset label', forced: false };
  const view = await open(obj);
  const text = view.textContent;
  assert.ok(text.includes('データセット形式: Old dataset label／自動で判定した形式'));
  assert.ok(!text.includes('年度'), '年度という言葉を出さない');
  assert.ok(!text.includes('2022）'), 'year を括弧で添えない');
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

// ---------------------------------------------------------------------------
// 回答後の視点
//
// 回答すると解説・根拠・「次へ」が下に足される。以前は「次へ」ボタンへ
// フォーカスを移していたため、ブラウザがそこまでスクロールし、自分の選択が
// 正解だったかを見るのに上へ戻る必要があった。視点は「設問 n/m」に固定する。
// ---------------------------------------------------------------------------
const quizPanelOf = (view) => view.cls('quiz-panel')[0];
const labelOf = (panel) => panel && panel.cls('panel__label')[0];

async function answerFirst(view, pick) {
  await view.button(/調査を始める/).click();
  globalThis.__scrolled = null;
  globalThis.__focusOpts = undefined;
  await view.cls('option')[pick].click();
}

await test('回答後、視点は「設問 n/m」のある設問の先頭へ合わせる', async () => {
  const view = await open(lesson());
  await answerFirst(view, 1);
  const panel = quizPanelOf(view);
  assert.ok(panel, '設問の区画がある');
  assert.equal(labelOf(panel).textContent, '設問 1/2');
  assert.equal(globalThis.__scrolled, panel, '設問の区画へスクロールする');
  assert.equal(globalThis.__scrollOpts.block, 'start', '区画の先頭で止める');
});

await test('回答後のフォーカス移動では、ページを動かさない', async () => {
  const view = await open(lesson());
  await answerFirst(view, 1);
  // キーボード利用者のためにフォーカスは「次の設問へ」へ移す。ただし
  // それで最下部まで流されないよう、位置は動かさない指定にする。
  assert.match(globalThis.__focused.textContent, /次の設問へ/);
  assert.deepEqual(globalThis.__focusOpts, { preventScroll: true });
});

await test('段階の最後の設問でも、視点は設問の先頭に残る', async () => {
  const view = await open(lesson());
  await answerFirst(view, 1);
  await view.button(/次の設問へ/).click();
  globalThis.__scrolled = null;
  await view.cls('option')[0].click();
  const panel = quizPanelOf(view);
  assert.equal(labelOf(panel).textContent, '設問 2/2');
  assert.equal(globalThis.__scrolled, panel, '「次へ」へ流されない');
  assert.match(globalThis.__focused.textContent, /次へ|振り返りへ/);
  assert.deepEqual(globalThis.__focusOpts, { preventScroll: true });
});

await test('「次の設問へ」で進んだときも、新しい設問の先頭を見せる', async () => {
  const view = await open(lesson());
  await answerFirst(view, 1);
  globalThis.__scrolled = null;
  await view.button(/次の設問へ/).click();
  const panel = quizPanelOf(view);
  assert.equal(globalThis.__scrolled, panel);
  assert.equal(labelOf(panel).textContent, '設問 2/2');
});

// ---------------------------------------------------------------------------
// 解答前に「問題の行」へ飛ぶ
//
// 「logs/ws99.log の 3 行目 について」のように問い文が行を名指ししている
// 設問では、答える前にその行のカードへ飛べる。問い文に書いてある行へ移る
// だけなので答えは漏れない。根拠を選ばせる設問では、先に飛べると答えそのもの
// になるので出さない。
// ---------------------------------------------------------------------------
const subjectButton = (view) => view.button(/^問題の行を見る/);

await test('行を名指しする設問は、解答前に「問題の行を見る」が出る', async () => {
  const view = await open(lesson());
  await view.button(/調査を始める/).click();
  const btn = subjectButton(view);
  assert.ok(btn, '解答前にボタンがある');
  assert.match(btn.textContent, /logs\/ws99\.log/);
  assert.equal(view.button(/^根拠ログを見る/), undefined, '根拠ボタンはまだ出さない');
});

await test('押すと、その行の証拠カードへ移動してフォーカスする', async () => {
  const view = await open(lesson());
  await view.button(/調査を始める/).click();
  globalThis.__scrolled = null;
  await subjectButton(view).click();
  const card = document.getElementById(`ev-stage-${EV_A}`);
  assert.ok(card, '飛び先のカードが解答前から頁にある');
  assert.equal(globalThis.__scrolled, card, 'カードへスクロールする');
  assert.equal(globalThis.__focused, card, 'カードへフォーカスを移す');
});

await test('飛んでも回答は始まらず、そのまま答えられる', async () => {
  const view = await open(lesson());
  await view.button(/調査を始める/).click();
  await subjectButton(view).click();
  assert.equal(view.textContent.includes('解説1'), false, '解説はまだ出ない');
  const options = view.cls('option');
  assert.ok(options.length && options.every((o) => !o.disabled), '選択肢は押せる');
});

await test('教材が明示した行を、根拠より優先して使う', async () => {
  const obj = lesson();
  obj.stages[0].quizzes[0].subjectEvidenceIds = [EV_B];
  const view = await open(obj);
  await view.button(/調査を始める/).click();
  assert.match(subjectButton(view).textContent, /8 行目/, '明示した EV_B の行');
});

await test('根拠を選ぶ設問では、解答前に飛べない（答えになるため）', async () => {
  const obj = lesson();
  const pick = {
    id: 'q-pick', type: 'evidence_pick', category: 'evidence',
    prompt: 'この判断を最も直接支えるログはどれですか。',
    options: [
      { label: 'logs/ws99.log の 3 行目', evidenceId: EV_A },
      { label: 'logs/ws99.log の 8 行目', evidenceId: EV_B },
    ],
    correct: 0, explain: '解説', evidenceIds: [EV_A],
    // 誤って付けてしまっても、画面側で出さない。
    subjectEvidenceIds: [EV_A],
  };
  obj.stages[0].quizzes = [pick];
  obj.stages[0].quiz = pick;
  const view = await open(obj);
  await view.button(/調査を始める/).click();
  assert.equal(subjectButton(view), undefined);
});

await test('行を名指ししない設問（関連付け）には出さない', async () => {
  const view = await open(lesson());
  await view.button(/調査を始める/).click();
  await view.cls('option')[1].click();
  await view.button(/次の設問へ/).click();
  // 2 問目は関連付けの設問。問い文は行を名指ししていない。
  assert.match(view.textContent, /どちらが先に記録されましたか/);
  assert.equal(subjectButton(view), undefined);
});

// ---------------------------------------------------------------------------
// 「下に示した記録は…」と書く設問は、解答前にその記録を設問の下へ出す
//
// 直した不具合: 問い文は「下に示した記録」と言うのに、記録は解答後にしか
// 出していなかった。段階の上に並ぶカードのどれが対象なのかも分からない。
// ---------------------------------------------------------------------------
const subjectBox = (view) =>
  view.find((e) => e.tag === 'div' && /^対象の記録/.test(e.textContent))[0];
const cardsIn = (box) => (box ? box.cls('evidence') : []);

async function reachSecondQuiz(view) {
  await view.button(/調査を始める/).click();
  await view.cls('option')[1].click();
  await view.button(/次の設問へ/).click();
}

await test('関連付けの設問は、見比べる二つの記録を解答前に出す', async () => {
  const view = await open(lesson());
  await reachSecondQuiz(view);
  assert.match(view.textContent, /どちらが先に記録されましたか/);
  const box = subjectBox(view);
  assert.ok(box, '「対象の記録」が解答前にある');
  assert.equal(cardsIn(box).length, 2, '二つとも出す');
  assert.ok(box.textContent.includes('3 行目') && box.textContent.includes('8 行目'));
  assert.ok(view.cls('option').every((o) => !o.disabled), 'まだ答えていない');
});

await test('対象の記録は、設問文より下・選択肢より上にある', async () => {
  const view = await open(lesson());
  await reachSecondQuiz(view);
  const quiz = view.cls('quiz')[0];
  const order = quiz.children.map((c) => c.className || '');
  const qAt = order.findIndex((c) => c.includes('quiz__q'));
  const subjAt = order.findIndex((c) => c.includes('quiz__subject'));
  const optAt = order.findIndex((c) => c.includes('options'));
  assert.ok(qAt < subjAt && subjAt < optAt, `並び: ${order.join(' / ')}`);
});

await test('解答後に同じ記録を二度並べない', async () => {
  const view = await open(lesson());
  await reachSecondQuiz(view);
  await view.cls('option')[0].click();
  const quiz = view.cls('quiz')[0];
  assert.equal(quiz.cls('evidence').length, 2, '対象の 2 枚だけ。根拠欄で複製しない');
  assert.ok(view.button(/^根拠ログを見る/), '根拠への移動は残す');
});

await test('手法の設問も、旧い教材（項目なし）で対象の記録を出す', async () => {
  const obj = lesson();
  const attck = {
    id: 'q-attck', type: 'single_choice', category: 'attck',
    prompt: '下に示した記録は、どの手法にあたりますか。',
    options: ['T1059.003 · Windows Command Shell', 'T1082 · System Information Discovery'],
    correct: 0, explain: '解説', evidenceIds: [EV_A],
  };
  obj.stages[0].quizzes = [attck];
  obj.stages[0].quiz = attck;
  const view = await open(obj);
  await view.button(/調査を始める/).click();
  const box = subjectBox(view);
  assert.ok(box, '項目が無くても、根拠を対象として出す');
  assert.equal(cardsIn(box).length, 1);
  assert.equal(view.button(/^問題の行を見る/), undefined, '行ジャンプとは別の出し方');
});

await test('解答前に出すカードは飛び先の id を持たない（id の重複を作らない）', async () => {
  const view = await open(lesson());
  await reachSecondQuiz(view);
  for (const card of cardsIn(subjectBox(view))) {
    assert.ok(!card.id, `設問内の複製に id が付いている: ${card.id}`);
  }
});

// ---------------------------------------------------------------------------
// 正答率のリング
// ---------------------------------------------------------------------------
const ringOf = () => app.cls('ring')[0];
const barOf = (ring) => ring && ring.find((e) => e.attrs.class === 'ring__bar')[0];

await test('得点の横に正答率のリングが出て、中央は % 表記', async () => {
  const view = await open(lesson());
  await playThrough(view, [1, 1]);   // 1 / 2
  const row = app.cls('recap__score')[0];
  assert.ok(row, '見出しとリングを並べる行がある');
  assert.ok(row.find((e) => e.tag === 'h1').length, '見出しは同じ行にある');
  const ring = ringOf();
  assert.ok(ring, 'リングがある');
  assert.equal(ring.cls('ring__label')[0].textContent, '50%');
});

await test('リングの弧の長さが正答率と一致する', async () => {
  const view = await open(lesson());
  await playThrough(view, [1, 1]);   // 1 / 2 → 50%
  const bar = barOf(ringOf());
  assert.ok(bar, '弧がある');
  // 円周を 100 と見なしているので、残す長さ = 100 - 正答率。
  assert.equal(bar.attrs.pathLength, '100');
  assert.equal(bar.attrs['stroke-dasharray'], '100');
  assert.equal(bar.attrs['stroke-dashoffset'], '50');
});

await test('読み上げでは円を「正答率 N%」の 1 枚として伝える', async () => {
  const view = await open(lesson());
  await playThrough(view, [1, 1]);
  const ring = ringOf();
  assert.equal(ring.attrs.role, 'img');
  assert.equal(ring.attrs['aria-label'], '正答率 50%');
  const svg = ring.find((e) => e.tag === 'svg')[0];
  assert.equal(svg.attrs['aria-hidden'], 'true', '中の図形は読ませない');
});

await test('全問正解は 100%、全問不正解は 0% で弧を描かない', async () => {
  let view = await open(lesson());
  await playThrough(view, [1, 0]);   // 両方正解
  assert.equal(ringOf().cls('ring__label')[0].textContent, '100%');
  assert.equal(barOf(ringOf()).attrs['stroke-dashoffset'], '0');

  view = await open(lesson());
  await playThrough(view, [0, 1]);   // 両方不正解
  assert.equal(ringOf().cls('ring__label')[0].textContent, '0%');
  // 端が丸いので、長さ 0 の弧でも点が残る。0% では弧そのものを置かない。
  assert.equal(barOf(ringOf()), undefined, '0% で点が残らない');
});

await test('得点の見出しは従来どおり「正解 X / Y」のまま', async () => {
  const view = await open(lesson());
  await playThrough(view, [1, 1]);
  const heading = app.find((e) => e.tag === 'h1' && /正解/.test(e.textContent))[0];
  assert.equal(heading.textContent, '正解 1 / 2', 'リングの % が見出しに混ざらない');
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
