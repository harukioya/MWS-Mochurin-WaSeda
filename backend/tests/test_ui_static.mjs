// test_ui_static.mjs — Ghidra 静的解析教材の画面の回帰テスト。
//
// 既存の UI テストと同じく、最小の DOM シムの上で本物の player.js / quiz.js /
// recap.js / ghidra.js を動かす。ブラウザは使わないので、確かめられるのは
// 「何をどう組み立てたか」まで。見た目・実際のファイル選択・スクロールの体感は
// 実ブラウザで別に確認する。
//
// 教材は、Python のビルダーが架空のゲームの静的事実から実際に作った出力
// （fixtures/ghidra/static-lesson.json）。実データは使わない。
//
//   node backend/tests/test_ui_static.mjs

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const FIXTURE = JSON.parse(fs.readFileSync(path.join(HERE, 'fixtures/ghidra/static-lesson.json'), 'utf8'));
const lessonCopy = () => JSON.parse(JSON.stringify(FIXTURE));

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
    this.hidden = false;
    this.disabled = false;
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
  insertBefore(c, ref) {
    this._adopt(c);
    const at = this.children.indexOf(ref);
    if (at < 0) this.children.push(c); else this.children.splice(at, 0, c);
    return c;
  }
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
  buttons(re) {
    return this.find((e) => e.tag === 'button' && re.test(e.textContent));
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
  createElementNS: (_ns, t) => new El(t),
  getElementById: (id) => (id === 'app' ? app : byId(app, id)),
  querySelector: () => null,
  addEventListener() {},
  removeEventListener() {},
};
globalThis.window = { scrollTo() {}, dispatchEvent() {}, addEventListener() {} };
globalThis.location = { hash: '' };
globalThis.HashChangeEvent = class {};

let lessonForFetch = null;
globalThis.fetch = async (url) => {
  if (String(url).startsWith('/api/lessons/') && lessonForFetch) {
    return { ok: true, status: 200, json: async () => lessonForFetch };
  }
  return { ok: false, status: 404, json: async () => ({}) };
};

const results = [];
async function test(name, fn) {
  try { await fn(); results.push(['ok', name]); }
  catch (e) { results.push(['NG', name, e.stack || e.message]); }
}

const allIds = (root) => root.find((e) => e.id).map((e) => e.id);
const quizzesOf = (l) => l.stages.flatMap((s) => s.quizzes);
const tick = () => new Promise((r) => setTimeout(r, 0));

const { renderLesson } = await import(REPO + '/js/player.js');
const { renderQuiz } = await import(REPO + '/js/quiz.js');
const { evidenceCard, sourceLabel } = await import(REPO + '/js/evidence.js');
const { renderGhidra } = await import(REPO + '/js/ghidra.js');

/** 導入画面から「演習を始める」まで進め、第 1 段階を描いた状態にする。 */
async function openLesson(lesson) {
  lessonForFetch = lesson;
  const view = document.createElement('div');
  app.replaceChildren(view);
  await renderLesson(view, lesson.id);
  return view;
}

// ---------------------------------------------------------------------------
await test('静的な証拠カードは「プログラム／関数／アドレス／命令・参照」を出し、行番号を出さない', async () => {
  const l = lessonCopy();
  const q = quizzesOf(l).find((x) => x.category === 'static-string');
  const item = l.evidence[q.subjectEvidenceIds[0]];
  const card = evidenceCard(item);
  const text = card.textContent;
  assert.match(text, /プログラム/);
  assert.match(text, /minigame/);
  assert.match(text, /関数/);
  assert.match(text, /ram:0010/);
  assert.match(text, /LEA RDI/);
  assert.match(text, /参照先: ram:0010/);
  assert.doesNotMatch(text, /行目/);
  assert.match(card.attrs['aria-label'], /ram:0010/);
  assert.match(sourceLabel(item), /ram:0010/);
  assert.doesNotMatch(sourceLabel(item), /行目|undefined/);
});

await test('GZF 由来の名前の HTML・双方向制御・NUL は、そのまま描かず見える形にする', async () => {
  const l = lessonCopy();
  const id = Object.keys(l.evidence)[0];
  const item = l.evidence[id];
  item.source.program = 'evil<img src=x onerror=alert(1)>‮gnp.exe\u0000';
  item.source.function = 'f‮x';
  const card = evidenceCard(item);
  assert.match(card.textContent, /<img src=x/);
  assert.match(card.textContent, /<U\+202E>/);
  assert.match(card.textContent, /<U\+0000>/);
  assert.doesNotMatch(card.textContent, /‮/);
  assert.equal(card.find((e) => e.tag === 'img').length, 0);
});

await test('導入画面で、実行していないこと・入力 GZF のハッシュ・固定版を示す', async () => {
  const l = lessonCopy();
  const view = await openLesson(l);
  const text = view.textContent;
  assert.match(text, /対象のプログラムは実行していません/);
  assert.match(text, /入力 GZF の SHA-256/);
  assert.match(text, new RegExp(l.static.input.sha256));
  assert.match(text, /元の実行ファイルの SHA-256（GZF に保存された値）/);
  assert.match(text, /12\.1\.4 \/ 1\.0\.0/);
  assert.match(text, /下書き/);
  assert.match(text, /静的解析/, 'static glossary');
  assert.doesNotMatch(text, /対象ホスト|使用するログ/);
  assert.equal(view.buttons(/演習を始める/).length, 1);
  assert.equal(view.buttons(/削除する/).length, 1);
});

await test('段階の見出しと記録は静的な言い方で、実行・観測を装わない', async () => {
  const l = lessonCopy();
  const view = await openLesson(l);
  await view.buttons(/演習を始める/)[0].click();
  const text = view.textContent;
  assert.match(text, /保存済みの解析情報（Ghidra）/);
  assert.doesNotMatch(text, /観測された挙動/);
  assert.match(text, /Ghidra が GZF に保存した次の記録/);
  assert.match(text, /命令/);
  assert.match(text, /文字列/);
});

await test('解答前の「問題の命令を見る」は答えを含まず、段階内の 1 枚へ飛ぶ', async () => {
  const l = lessonCopy();
  const view = await openLesson(l);
  await view.buttons(/演習を始める/)[0].click();
  const q = l.stages[0].quizzes[0];
  const answer = q.options[q.correct];
  const jump = view.buttons(/問題の命令を見る/);
  assert.equal(jump.length, 1);
  // 静的な根拠の出典は「関数 アドレス」で示す。ログの「行目」は出さない。
  assert.match(jump[0].textContent, /問題の命令を見る: \S+ ram:[0-9a-f]{8}/);
  assert.doesNotMatch(jump[0].textContent, /行目|undefined/);
  assert.ok(!jump[0].textContent.includes(answer.replace(/[「」]/g, '')));
  await jump[0].click();
  assert.equal(globalThis.__focused.id, `ev-stage-${q.subjectEvidenceIds[0]}`);
  const ids = allIds(view);
  assert.equal(new Set(ids).size, ids.length, 'DOM ids must be unique');
});

await test('段階的なヒントは 1 つずつ開き、最後で止まり、採点に影響しない', async () => {
  const l = lessonCopy();
  const q = quizzesOf(l)[0];
  const view = document.createElement('div');
  app.replaceChildren(view);
  const calls = [];
  renderQuiz(view, q, (ok) => calls.push(ok), l.evidence);
  const hint = view.cls('quiz__hint')[0];
  assert.match(hint.children[0].textContent, /全 3 段階/);
  assert.equal(view.cls('quiz__hint-body').length, 1);
  assert.match(view.cls('quiz__hint-body')[0].textContent, /^ヒント 1\/3/);
  const more = view.cls('quiz__hint-more')[0];
  await more.click();
  await more.click();
  assert.equal(view.cls('quiz__hint-body').length, 3);
  assert.match(view.cls('quiz__hint-body')[2].textContent, /^ヒント 3\/3/);
  assert.equal(more.disabled, true);
  await more.click();
  assert.equal(view.cls('quiz__hint-body').length, 3);
  assert.deepEqual(calls, []);
  assert.doesNotMatch(hint.textContent, /解説/);
  await view.cls('option')[q.correct].click();
  assert.deepEqual(calls, [true]);
});

await test('回答後の「根拠の記録を見る」は、段階内のカードへ飛ぶ', async () => {
  const l = lessonCopy();
  const view = await openLesson(l);
  await view.buttons(/演習を始める/)[0].click();
  const q = l.stages[0].quizzes[0];
  await view.cls('option')[(q.correct + 1) % q.options.length].click();
  assert.match(view.textContent, /不正解/);
  const jumps = view.buttons(/根拠の記録を見る/);
  assert.equal(jumps.length, q.evidenceIds.length);
  for (let i = 0; i < jumps.length; i++) {
    await jumps[i].click();
    assert.equal(globalThis.__focused.id, `ev-stage-${q.evidenceIds[i]}`);
  }
  const ids = allIds(view);
  assert.equal(new Set(ids).size, ids.length);
});

await test('次の設問へ進むと、前の設問の根拠の強調が消え、強調は常に 1 枚だけ', async () => {
  const l = lessonCopy();
  const view = await openLesson(l);
  await view.buttons(/演習を始める/)[0].click();
  const highlighted = () => view.cls('is-cited');
  const [q1, q2] = l.stages[0].quizzes;
  assert.ok(q2, 'the fixture has two questions in the first stage');

  await view.cls('option')[q1.correct].click();
  const jumps1 = view.buttons(/根拠の記録を見る/);
  await jumps1[0].click();
  assert.equal(highlighted().length, 1);
  await jumps1[1].click();
  assert.equal(highlighted().length, 1, 'jumping again moves the highlight, never adds a second');
  assert.equal(highlighted()[0].id, `ev-stage-${q1.evidenceIds[1]}`);

  await view.buttons(/次の設問へ/)[0].click();
  assert.equal(highlighted().length, 0, 'the previous answer must not stay highlighted');

  await view.cls('option')[q2.correct].click();
  await view.buttons(/根拠の記録を見る/)[0].click();
  assert.equal(highlighted().length, 1);
  assert.equal(highlighted()[0].id, `ev-stage-${q2.evidenceIds[0]}`);

  await view.buttons(/^次へ$/)[0].click();
  assert.equal(highlighted().length, 0, 'a new stage starts without highlights');
});

await test('得点の母数は設問数で、振り返りは静的な事実と限界を示す', async () => {
  const l = lessonCopy();
  const total = quizzesOf(l).length;
  const view = await openLesson(l);
  await view.buttons(/演習を始める/)[0].click();
  for (let s = 0; s < l.stages.length; s++) {
    for (let qi = 0; qi < l.stages[s].quizzes.length; qi++) {
      const q = l.stages[s].quizzes[qi];
      await view.cls('option')[q.correct].click();
      const next = view.buttons(/次の設問へ/);
      if (next.length) await next[0].click();
    }
    await view.buttons(/^(次へ|振り返りへ)$/)[0].click();
  }
  const text = view.textContent;
  assert.match(text, new RegExp(`正解 ${total} / ${total}`));
  assert.match(text, /静的に確認できた事実/);
  assert.doesNotMatch(text, /記録された順序/);
  assert.doesNotMatch(text, /MITRE ATT&CK との対応/);
  assert.match(text, /実行はしていません/);
  assert.match(text, /呼び出し命令と実際の呼び出し/);
  assert.match(text, /文字列の参照を読む|命令が参照する文字列を読む/);
  const jumps = view.buttons(/根拠の記録を見る/);
  assert.ok(jumps.length > 0);
  for (const j of jumps.slice(0, 5)) {
    await j.click();
    assert.match(globalThis.__focused.id, /^ev-report-/);
  }
  const ids = allIds(view);
  assert.equal(new Set(ids).size, ids.length);
});

// ---------------------------------------------------------------------------
// Ghidra 画面
// ---------------------------------------------------------------------------
const READY_STATUS = {
  docker: { state: 'ready', arch: 'arm64', version: '28.0.0' },
  image: { state: 'ready', ref: 'img', id: 'sha256:1' },
  pinned: { ghidraVersion: '12.1.4', ghidraZip: 'z.zip', ghidraZipSha256: 'aa', baseImage: 'b', scriptVersion: '1.0.0', scriptSha256: 'cc', imageRef: 'img' },
  limits: { maxGzfBytes: 64 * 1024 * 1024, maxUnpackedBytes: 512 * 1024 * 1024, runSeconds: 600 },
  job: null,
  sample: { available: true, name: 'termmines', note: 'マルウェアではなく解析練習用のゲームです。' },
  canPrepare: true,
};

function stubApi(routes) {
  const seen = [];
  globalThis.fetch = async (url, opts = {}) => {
    seen.push({ url: String(url), opts });
    for (const [re, fn] of routes) {
      if (re.test(String(url))) {
        const [status, body] = await fn(url, opts);
        return { ok: status >= 200 && status < 300, status, json: async () => body };
      }
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };
  return seen;
}

async function waitFor(pred, ms = 2000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (pred()) return;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error('condition not met');
}

await test('準備済みなら、.gzf の選択と作成ボタンとサンプルが使える', async () => {
  stubApi([[/\/api\/ghidra\/status/, async () => [200, READY_STATUS]]]);
  const view = document.createElement('div');
  app.replaceChildren(view);
  await renderGhidra(view, { poll: 5 });
  const input = view.find((e) => e.tag === 'input' && e.type === 'file')[0];
  assert.equal(input.accept, '.gzf');
  assert.equal(view.buttons(/演習を作成する/)[0].disabled, false);
  assert.equal(view.buttons(/同梱サンプル/).length, 1);
  assert.match(view.textContent, /マルウェアではなく解析練習用のゲーム/);
  assert.match(view.textContent, /外部の解析サーバーへは送りません/);
  assert.match(view.textContent, /12\.1\.4/);
});

await test('Docker が無ければ理由と戻り方を示し、作成ボタンは押せない', async () => {
  stubApi([[/\/api\/ghidra\/status/, async () => [200, {
    ...READY_STATUS,
    docker: { state: 'docker-missing', message: 'Docker が見つかりません。' },
    image: { state: 'unknown' },
  }]]]);
  const view = document.createElement('div');
  app.replaceChildren(view);
  await renderGhidra(view, { poll: 5 });
  assert.match(view.textContent, /Docker が見つかりません/);
  assert.match(view.textContent, /ログからの演習作成はこれまでどおり使えます/);
  assert.equal(view.buttons(/演習を作成する/)[0].disabled, true);
  assert.equal(view.buttons(/処理環境を準備する/).length, 0);
});

await test('処理環境が無ければ、準備ボタンを出し、ファイル処理とは分ける', async () => {
  const seen = stubApi([
    [/\/api\/ghidra\/status/, async () => [200, { ...READY_STATUS, image: { state: 'missing' } }]],
    [/\/api\/ghidra\/prepare/, async () => [202, { job: { id: 'p'.repeat(32), kind: 'prepare', state: 'preparing', phase: '処理環境を準備しています', final: false, elapsed: 0 } }]],
    [/\/api\/ghidra\/jobs\//, async () => [200, { job: { id: 'p'.repeat(32), kind: 'prepare', state: 'preparing', phase: '処理環境を準備しています', final: false, elapsed: 1 } }]],
  ]);
  const view = document.createElement('div');
  app.replaceChildren(view);
  await renderGhidra(view, { poll: 5 });
  assert.equal(view.buttons(/演習を作成する/)[0].disabled, true);
  assert.match(view.textContent, /インターネットから取得/);
  await view.buttons(/処理環境を準備する/)[0].click();
  assert.match(view.textContent, /処理環境を準備しています/);
  assert.ok(seen.some((s) => /\/prepare$/.test(s.url)));
  assert.ok(!seen.some((s) => /upload/.test(s.url)));
  app.replaceChildren(document.createElement('div')); // 画面を離れてポーリングを止める
});

await test('イメージの状態が分からないときは、準備ではなく確認し直しを案内する', async () => {
  stubApi([[/\/api\/ghidra\/status/, async () => [200, { ...READY_STATUS, image: { state: 'unknown' } }]]]);
  const view = document.createElement('div');
  app.replaceChildren(view);
  await renderGhidra(view, { poll: 5 });
  assert.equal(view.buttons(/処理環境を準備する/).length, 0);
  assert.match(view.textContent, /状態を確認し直す/);
  assert.equal(view.buttons(/演習を作成する/)[0].disabled, true);
});

await test('送信 → 進捗 → 完了 → 演習を始める', async () => {
  const id = 'a'.repeat(32);
  let polls = 0;
  const seen = stubApi([
    [/\/api\/ghidra\/status/, async () => [200, READY_STATUS]],
    [/\/api\/ghidra\/jobs\/new$/, async () => [201, { job: { id, kind: 'analyze', state: 'receiving', phase: 'ファイルを受け取っています', final: false, elapsed: 0, origin: { kind: 'upload', name: 'my game.gzf' } } }]],
    [/\/api\/ghidra\/jobs\/a+\/upload$/, async () => [202, { job: { id, kind: 'analyze', state: 'reading', phase: 'Ghidra で読み取り中', final: false, elapsed: 0, origin: { kind: 'upload', name: 'x.gzf' } } }]],
    [/\/api\/ghidra\/jobs\/a+$/, async () => {
      polls += 1;
      if (polls < 2) return [200, { job: { id, kind: 'analyze', state: 'building', phase: '教材生成中', final: false, elapsed: 1, origin: {} } }];
      return [200, { job: { id, kind: 'analyze', state: 'done', phase: '完了しました', final: true, elapsed: 2, origin: {}, lessonId: 'gen-gzf-0123456789abcdef', summary: { title: 'minigame — Ghidra 静的解析', questions: 5, questionCounts: { string: 2, call: 2, external: 1 }, skipped: [], truncated: [] } } }];
    }],
  ]);
  const view = document.createElement('div');
  app.replaceChildren(view);
  await renderGhidra(view, { poll: 5 });
  const input = view.find((e) => e.tag === 'input' && e.type === 'file')[0];
  input.files = [{ name: 'my game.gzf', size: 1234 }];
  await view.buttons(/演習を作成する/)[0].click();
  // 先に予約して ID を受け取り、その ID へ本文を送る。
  const rsv = seen.findIndex((s) => /\/jobs\/new$/.test(s.url));
  const up = seen.findIndex((s) => /\/jobs\/a+\/upload$/.test(s.url));
  assert.ok(rsv >= 0 && up > rsv, 'reserve first, then send the body');
  assert.deepEqual(JSON.parse(seen[rsv].opts.body), { name: 'my game.gzf', size: 1234 });
  assert.equal(seen[up].opts.headers['Content-Type'], 'application/octet-stream');
  assert.ok(!('path' in seen[up].opts), 'no host path is sent');
  await waitFor(() => view.buttons(/演習を始める/).length === 1);
  assert.match(view.textContent, /設問 5 問/);
  await view.buttons(/演習を始める/)[0].click();
  assert.equal(location.hash, '#/lesson/gen-gzf-0123456789abcdef');
});

await test('送信中のキャンセルは、サーバー側の取り消しと通信の中断を両方行う', async () => {
  const id = 'f'.repeat(32);
  let aborted = false;
  let cancelledOnServer = false;
  const seen = [];
  globalThis.fetch = async (url, opts = {}) => {
    url = String(url);
    seen.push(url);
    const reply = (status, body) => ({ ok: status < 300, status, json: async () => body });
    if (/\/api\/ghidra\/status/.test(url)) return reply(200, READY_STATUS);
    if (/\/jobs\/new$/.test(url)) {
      return reply(201, { job: { id, kind: 'analyze', state: 'receiving', phase: '', final: false, elapsed: 0, origin: {} } });
    }
    if (/\/cancel$/.test(url)) {
      assert.ok(url.includes(id), 'the reserved job is cancelled by id');
      cancelledOnServer = true;
      return reply(200, { job: {} });
    }
    if (/\/jobs\/f+$/.test(url)) {
      return reply(200, { job: { id, kind: 'analyze', state: 'cancelled', phase: 'キャンセルしました', final: true, elapsed: 1, origin: {}, error: { code: 'cancelled', message: 'キャンセルしました。作業データは削除済みです。', reasons: [] } } });
    }
    // 本文の送信は、取り消されるまで終わらない（本文は届き終えて応答待ちの状態）。
    return new Promise((_resolve, reject) => {
      opts.signal.addEventListener('abort', () => {
        aborted = true;
        const err = new Error('aborted');
        err.name = 'AbortError';
        reject(err);
      });
    });
  };
  const view = document.createElement('div');
  app.replaceChildren(view);
  await renderGhidra(view, { poll: 5 });
  const input = view.find((e) => e.tag === 'input' && e.type === 'file')[0];
  input.files = [{ name: 'big.gzf', size: 10 }];
  const sending = view.buttons(/演習を作成する/)[0].click();
  await waitFor(() => /big\.gzf を送っています/.test(view.textContent));
  await view.buttons(/^キャンセル$/)[0].click();
  await sending;
  assert.equal(cancelledOnServer, true, 'the server-side job is cancelled, not only the fetch');
  assert.equal(aborted, true);
  const cancelAt = seen.findIndex((u) => /\/cancel$/.test(u));
  assert.ok(cancelAt >= 0);
  // 取り消しが効いたかは、サーバー側の最終状態で示す。
  await waitFor(() => /キャンセルしました/.test(view.textContent));
  assert.equal(view.buttons(/演習を作成する/)[0].disabled, false);
});

await test('実行中の段階は動く 3 つの点で示し、取り直しで作り直さない', async () => {
  const id = '9'.repeat(32);
  let polls = 0;
  let release;
  const gate = new Promise((r) => { release = r; });
  stubApi([
    [/\/api\/ghidra\/status/, async () => [200, { ...READY_STATUS, job: { id, kind: 'analyze', state: 'reading', phase: 'Ghidra で読み取り中', final: false, elapsed: 1, origin: {} } }]],
    [/\/cancel$/, async () => [200, { job: {} }]],
    [/\/api\/ghidra\/jobs\/9+$/, async () => {
      polls += 1;
      if (polls < 3) return [200, { job: { id, kind: 'analyze', state: 'reading', phase: 'Ghidra で読み取り中', final: false, elapsed: 1 + polls, origin: {} } }];
      await gate;
      return [200, { job: { id, kind: 'analyze', state: 'done', phase: '完了しました', final: true, elapsed: 9, origin: {}, lessonId: 'gen-gzf-0123456789abcdef', summary: { title: 't', questions: 5, questionCounts: {}, skipped: [], truncated: [] } } }];
    }],
  ]);
  const view = document.createElement('div');
  app.replaceChildren(view);
  await renderGhidra(view, { poll: 5 });
  const dots = view.cls('working-dots');
  assert.equal(dots.length, 1, 'only the running step has the dots');
  assert.equal(dots[0].children.length, 3);
  assert.equal(dots[0].attrs['aria-hidden'], 'true');
  const li = dots[0].parent;
  assert.equal(li.attrs['aria-current'], 'step');
  assert.match(li.textContent, /Ghidra で読み取り中/);
  assert.doesNotMatch(li.parent.textContent, /→/, 'the arrow in the step list is replaced by the dots');
  // キャンセルを押してから取り直しが来ても、同じ点のまま・押した状態のまま。
  const stop = view.buttons(/キャンセル/)[0];
  await stop.click();
  await waitFor(() => polls >= 2);
  await tick();
  assert.equal(view.cls('working-dots')[0], dots[0], 'not rebuilt, so the animation does not restart');
  assert.equal(stop.disabled, true, 'the pressed cancel button stays pressed');
  assert.match(view.textContent, /[34] 秒経過/, 'elapsed time still updates');
  release();
  await waitFor(() => view.buttons(/演習を始める/).length === 1);
  assert.equal(view.cls('working-dots').length, 0, 'no dots once finished');
});

await test('処理環境の準備中も同じ点で示す', async () => {
  stubApi([[/\/api\/ghidra\/status/, async () => [200, { ...READY_STATUS, image: { state: 'missing' }, job: { id: '8'.repeat(32), kind: 'prepare', state: 'preparing', phase: '処理環境を準備しています', final: false, elapsed: 5, origin: {} } }]],
    [/\/api\/ghidra\/jobs\//, async () => new Promise(() => {})]]);
  const view = document.createElement('div');
  app.replaceChildren(view);
  await renderGhidra(view, { poll: 5 });
  assert.equal(view.cls('working-dots').length, 1);
  assert.match(view.textContent, /処理環境を準備しています（5 秒経過）/);
  app.replaceChildren(document.createElement('div'));
});

await test('失敗は固定の文言と理由で示し、生のエラーを出さない', async () => {
  const id = 'b'.repeat(32);
  stubApi([
    [/\/api\/ghidra\/status/, async () => [200, READY_STATUS]],
    [/\/api\/ghidra\/jobs\/sample/, async () => [202, { job: { id, kind: 'analyze', state: 'reading', phase: 'Ghidra で読み取り中', final: false, elapsed: 0, origin: {} } }]],
    [/\/api\/ghidra\/jobs\/b+$/, async () => [200, { job: { id, kind: 'analyze', state: 'failed', phase: '失敗しました', final: true, elapsed: 3, origin: {}, rawStderr: 'java.lang.Exception at /Users/someone', error: { code: 'no-questions', message: '根拠の揃う設問を作れませんでした。', reasons: ['文字列参照: 足りません<script>'] } } }]],
  ]);
  const view = document.createElement('div');
  app.replaceChildren(view);
  await renderGhidra(view, { poll: 5 });
  await view.buttons(/同梱サンプル/)[0].click();
  await waitFor(() => /根拠の揃う設問を作れませんでした/.test(view.textContent));
  assert.match(view.textContent, /文字列参照: 足りません<script>/);
  assert.match(view.textContent, /作業用のコピーは削除済み/);
  assert.match(view.textContent, /制限を緩める必要はありません/);
  assert.doesNotMatch(view.textContent, /java\.lang|\/Users\/someone/);
  assert.equal(view.find((e) => e.tag === 'script').length, 0);
  assert.equal(view.buttons(/演習を作成する/)[0].disabled, false, 'can retry');
});

await test('キャンセルと、画面を離れた後の応答', async () => {
  const id = 'c'.repeat(32);
  let cancelled = false;
  let release;
  const gate = new Promise((r) => { release = r; });
  stubApi([
    [/\/api\/ghidra\/status/, async () => [200, { ...READY_STATUS, job: { id, kind: 'analyze', state: 'reading', phase: 'Ghidra で読み取り中', final: false, elapsed: 1, origin: { kind: 'sample', name: 'termmines' } } }]],
    [/\/cancel$/, async () => { cancelled = true; return [200, { job: {} }]; }],
    [/\/api\/ghidra\/jobs\/c+$/, async () => { await gate; return [200, { job: { id, kind: 'analyze', state: 'cancelled', phase: 'キャンセルしました', final: true, elapsed: 2, origin: {}, error: { code: 'cancelled', message: 'キャンセルしました。作業データは削除済みです。', reasons: [] } } }]; }],
  ]);
  const view = document.createElement('div');
  app.replaceChildren(view);
  await renderGhidra(view, { poll: 5 });
  assert.match(view.textContent, /Ghidra で読み取り中/);
  await view.buttons(/キャンセル/)[0].click();
  assert.equal(cancelled, true);
  // ポーリングの応答が返る前に、別の画面へ移る。
  await new Promise((r) => setTimeout(r, 20));
  const other = document.createElement('div');
  other.append(document.createElement('p'));
  app.replaceChildren(other);
  release();
  await new Promise((r) => setTimeout(r, 30));
  assert.doesNotMatch(other.textContent, /キャンセルしました/);
  assert.equal(other.children.length, 1);
});

// ---------------------------------------------------------------------------
let failed = 0;
for (const [status, name, err] of results) {
  console.log(`${status} ${name}`);
  if (status !== 'ok') {
    failed += 1;
    console.log(`   ${err}`);
  }
}
console.log(`\n${results.length - failed}/${results.length} passed`);
if (failed) process.exit(1);
