// test_ui_dataset.mjs — データセット確認画面のフロントエンド回帰テスト。
//
// 既存の UI テストと同じく、最小の DOM シムの上で本物の inspect.js を動かす。
// ブラウザは使わないので、確かめられるのは「何をどう組み立てたか」までで、
// 実際の見た目、フォーカスの移り方、スクロールの体感までは見ていない。
// それらは人手のチェックリスト（docs/受け入れ確認チェックリスト.md）に残す。
//
// 実データは使わない。架空のデータセット形式・端末名と RFC 5737 の文書用アドレスだけ。
//
//   node backend/tests/test_ui_dataset.mjs

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
  setAttribute(k, v) { this.attrs[k] = v; }
  getAttribute(k) { return this.attrs[k]; }
  addEventListener(t, f) { (this._on[t] || (this._on[t] = [])).push(f); }
  async fire(t) { for (const f of this._on[t] || []) await f(); }
  focus() {}
  scrollIntoView() {}
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
  /** このノード以下の可読文字すべて。文言の有無を確かめるのに使う。 */
  get allText() {
    return this.find(() => true).map((e) => e._text).join('\n');
  }
}

const app = new El('main');
app._root = true;
globalThis.document = {
  createElement: (t) => new El(t),
  // 正答率のリングは SVG。名前空間は見ないので、同じ El で足りる。
  createElementNS: (_ns, t) => new El(t),
  getElementById: () => app,
  querySelector: () => null,
  addEventListener() {},
  removeEventListener() {},
};
globalThis.window = { scrollTo() {}, dispatchEvent() {}, addEventListener() {} };
globalThis.location = { hash: '' };

// ---------------------------------------------------------------------------
// fixture（架空データ）
// ---------------------------------------------------------------------------
const PROFILES = [
  { id: 'example-incident', label: 'Example incident logs', edition: 'fixture v1' },
  { id: 'example-nested', label: 'Example nested bundle', edition: '' },
  { id: 'example-mixed', label: 'Example mixed-format logs', edition: 'fixture v2' },
];
const LABELS = Object.fromEntries(PROFILES.map((p) => [p.id, p]));

const CHALLENGE = 'mixed-case/evidence/case.zip :: case/host01.log';
const WEBLOG = 'mixed-case/evidence/case.zip :: case/web/access.log';

function datasetReply(over = {}) {
  return {
    archive: 1,
    profileId: 'example-mixed',
    label: 'Example mixed-format logs',
    edition: 'fixture v2',
    metadata: {},
    confidence: 1,
    generic: false,
    forced: false,
    parsers: ['itm2', 'proxy'],
    parserLabels: ['InfoTrace Mark II（端末の記録）', 'Proxy（通信の記録）'],
    unknownParsers: [],
    counts: {},
    members: {
      challenge: [
        { name: CHALLENGE, size: 10, verdict: 'opaque-encrypted', encrypted: true },
        {
          name: WEBLOG, size: 10, verdict: 'opaque-encrypted', encrypted: true,
          unsupported: 'Web サーバーのアクセスログ',
        },
      ],
      baseline: [{ name: 'mixed-case/reference/baseline.zip :: WS02.log', size: 10, verdict: 'inert-data' }],
      narrative: [{ name: 'mixed-case/brief.pdf', size: 10, verdict: 'inert-data' }],
      tool: [{ name: 'mixed-case/tools.zip :: tools/sample.log', size: 10, verdict: 'inert-data' }],
      artifact: [], unrelated: [], unknown: [], ignore: [],
    },
    encryptedChallenge: 2,
    unsupported: [
      {
        name: WEBLOG,
        label: 'Web サーバーのアクセスログ',
        detail: '分類はできましたが、専用の解析に対応していません。',
      },
    ],
    profiles: PROFILES,
    profileErrors: [],
    passwordHint: true,
    warnings: [],
    ...over,
  };
}

const GENERIC = {
  profileId: null, label: 'プロファイル未特定（汎用解析）', edition: '', generic: true,
  confidence: 0,
  members: {
    challenge: [], baseline: [], narrative: [{ name: 'case/notes.md', size: 1, verdict: 'inert-data' }],
    tool: [], artifact: [], unrelated: [],
    unknown: [{ name: 'case/app.log', size: 1, verdict: 'inert-data' }], ignore: [],
  },
  unsupported: [], encryptedChallenge: 0, passwordHint: false,
};

const MEMBERS = [
  { idx: 0, name: CHALLENGE, size: 10, verdict: 'opaque-encrypted', kind: '暗号化' },
];

/** fetch のすり替え。要求された URL と本文を記録して、用意した応答を返す。 */
let calls = [];
let posts = [];
let datasetOverrides = {};
let baseOverride = {};
globalThis.fetch = async (url, options) => {
  calls.push(url);
  if (options && options.body) posts.push({ url, body: JSON.parse(options.body) });
  const reply = (body) => ({ ok: true, status: 200, json: async () => body });
  if (url.startsWith('/api/archives/1/dataset')) {
    // 本物のサーバーは、指定された id をそのまま `profileId` として返す
    // （`dataset.dataset_info`）。ここで常に自動判定の id を返すと、UI が
    // 「指定した形式」と「判定に使われた形式」を取り違えていても気づけない。
    const forced = /[?&]profileId=([^&]*)/.exec(url);
    let extra = { ...baseOverride };
    if (forced) {
      const id = decodeURIComponent(forced[1]);
      const p = LABELS[id] || {};
      extra = {
        ...extra, forced: true, generic: false, profileId: id,
        label: p.label || id, edition: p.edition || '',
        ...(datasetOverrides[id] || {}),
      };
    }
    return reply(datasetReply(extra));
  }
  if (url === '/api/archives/1/members') return reply({ members: MEMBERS });
  if (url === '/api/archives') return reply({ archives: [{ id: 1, path: '/tmp/case.zip' }] });
  if (url === '/api/generate') {
    // 本物のサーバーと同じ規則で `forced` を決める: `profileId` が来たら
    // 「利用者が指定した」、来なければ自動判定。旧名の `profile` は
    // 非推奨の互換として受け付けるが、新しい画面は送らない。
    const sent = JSON.parse((options && options.body) || '{}');
    const chosen = sent.profileId || sent.profile;
    const forced = Boolean(chosen && chosen !== 'auto');
    const p = LABELS[chosen] || LABELS['example-mixed'];
    return reply({
      id: 'gen-1', title: 'x', stages: 4, events: 20, tagged: 3,
      sources: [CHALLENGE],
      dataset: {
        profileId: p.id, label: p.label, edition: p.edition, generic: false,
        forced, challengeInputs: [CHALLENGE],
        baselineIdentified: ['mixed-case/reference/baseline.zip :: WS02.log'],
        truncated: true,
        unreadable: [{ name: 'x.log', reason: 'password-rejected', detail: 'パスワードが合いませんでした。' }],
        unsupported: [{ name: WEBLOG, label: 'Web サーバーのアクセスログ', detail: 'd' }],
        unrecognized: ['mixed-case/evidence/case.zip :: case/other.log'],
        unknownParsers: [],
        incomplete: true, draft: true,
      },
    });
  }
  throw new Error(`unexpected fetch: ${url}`);
};

const { renderArchive } = await import(path.join(REPO, 'js', 'inspect.js'));

// ---------------------------------------------------------------------------
let passed = 0;
const failures = [];
async function test(name, fn) {
  calls = [];
  posts = [];
  datasetOverrides = {};
  baseOverride = {};
  app.textContent = '';
  try {
    await fn();
    passed += 1;
    console.log(`  ok   ${name}`);
  } catch (err) {
    failures.push([name, err]);
    console.log(`  FAIL ${name}\n       ${err.message}`);
  }
}

async function screen() {
  const mount = new El('div');
  app.append(mount);
  await renderArchive(mount, '1');
  return mount;
}

async function generate(mount, label = '同梱の案内を使って読み取る') {
  const button = mount.find((e) => e._text === label)[0];
  assert.ok(button, `押しボタン「${label}」がありません`);
  await button.fire('click');
  const post = posts.find((p) => p.url === '/api/generate');
  assert.ok(post, '生成要求が送られていません');
  return post.body;
}

/**
 * 判定結果の見出し（形式名）。一覧側にも verdict の印（「暗号化」など）が
 * あるので、「誰が決めたか」と同じ行にある最初の要素を取る。
 */
function verdictName(mount) {
  const bar = mount.find((e) =>
    e.children.some((c) => /^(自動で判定した形式|利用者が指定した形式)$/.test(c._text))
  )[0];
  assert.ok(bar, '判定結果の見出しがありません');
  return bar.children[0].textContent;
}

/** 形式を選び直す。選ぶたびに欄ごと描き直されるので、毎回引き直す。 */
async function pickFormat(mount, value) {
  const select = mount.find((e) => e.tag === 'select')[0];
  assert.ok(select, 'データセット形式を選ぶ欄がありません');
  select.value = value;
  await select.fire('change');
}

// ---------------------------------------------------------------------------
// 判定した形式とプロファイル
// ---------------------------------------------------------------------------
await test('欄の見出しは汎用の言い方', async () => {
  const text = (await screen()).allText;
  assert.match(text, /データセットから教材を作る/);
});

await test('判定した形式・edition・プロファイル id・一致度が出る', async () => {
  const text = (await screen()).allText;
  assert.match(text, /Example mixed-format logs（fixture v2）/);
  assert.match(text, /example-mixed · 一致度 100%/);
});

await test('自動判定であることが言葉で分かる', async () => {
  const text = (await screen()).allText;
  assert.match(text, /自動で判定した形式/);
  assert.doesNotMatch(text, /利用者が指定した形式/);
  assert.match(text, /データセット形式: Example mixed-format logs（fixture v2）／自動で判定した形式/);
});

await test('利用者が指定したときは、そう表示される', async () => {
  const mount = await screen();
  await pickFormat(mount, 'example-incident');
  assert.match(mount.allText, /利用者が指定した形式/);
  assert.ok(
    calls.some((u) => u.includes('profileId=example-incident')),
    `指定が profileId で送られていません: ${calls.join(', ')}`
  );
  assert.ok(!calls.some((u) => /[?&]profile=/.test(u)), '旧名 profile を送っている');
});

await test('形式の選択肢に「自動で判定する」と全プロファイルが並ぶ', async () => {
  const mount = await screen();
  const select = mount.find((e) => e.tag === 'select')[0];
  const labels = select.children.map((o) => o.textContent);
  assert.equal(labels[0], '自動で判定する');
  assert.ok(labels.includes('Example incident logs（fixture v1）'));
  assert.ok(labels.includes('Example nested bundle'), 'edition が無ければ括弧を付けない');
  assert.ok(!labels.some((l) => l.includes('（）')));
});

await test('edition が無いときに空の括弧や区切りを出さない', async () => {
  baseOverride = { edition: '', label: 'Example mixed-format logs' };
  const mount = await screen();
  const text = mount.allText;
  assert.match(text, /データセット形式: Example mixed-format logs／自動で判定した形式/);
  assert.ok(!text.includes('（）'));
  // 判定結果の見出し。選択肢の一覧には edition 付きの同じ形式が並ぶので、
  // 全文ではなく見出しの 1 要素だけを見る。
  assert.equal(verdictName(mount), 'Example mixed-format logs');
});

await test('edition が null や未定義でも、空の括弧を出さない', async () => {
  for (const edition of [null, undefined]) {
    baseOverride = { edition, label: 'Example mixed-format logs' };
    app.textContent = '';
    const mount = await screen();
    assert.equal(verdictName(mount), 'Example mixed-format logs');
    assert.ok(!mount.allText.includes('（）'));
    assert.ok(!mount.allText.includes('null'));
    assert.ok(!mount.allText.includes('undefined'));
  }
});

await test('プロファイルが 0 件でも壊れず、汎用解析の案内が出る', async () => {
  baseOverride = { ...GENERIC, profiles: [] };
  const mount = await screen();
  const text = mount.allText;
  assert.equal(mount.find((e) => e.tag === 'select').length, 0, '空の選択欄を出さない');
  assert.match(text, /登録済みのデータセット形式（プロファイル）はありません/);
  assert.match(text, /プロファイル未特定（汎用解析）/);
  assert.match(text, /汎用解析で教材を作る/);
});

await test('読み込めなかったプロファイルを黙って捨てない', async () => {
  baseOverride = { profileErrors: [{ source: 'broken.json', reason: 'JSON として読めませんでした。' }] };
  const text = (await screen()).allText;
  assert.match(text, /読み込めなかったプロファイル（1 件）/);
  assert.match(text, /broken\.json — JSON として読めませんでした。/);
});

await test('未登録のパーサーをプロファイルが指定していたら、そう出る', async () => {
  baseOverride = { unknownParsers: ['no-such-format'] };
  const text = (await screen()).allText;
  assert.match(text, /no-such-format/);
  assert.match(text, /登録されていません/);
});

// ---------------------------------------------------------------------------
// 役割の内訳と対応範囲
// ---------------------------------------------------------------------------
await test('問題ログ・平常時ログ・案内・ツールがそれぞれ出る', async () => {
  const text = (await screen()).allText;
  assert.match(text, /問題ログ（本番）/);
  assert.match(text, /平常時・サンプルログ/);
  assert.match(text, /問題文・資料/);
  assert.match(text, /同梱ツール/);
});

await test('読み取れるログ形式が名前で分かり、任意形式に対応しないと言う', async () => {
  const text = (await screen()).allText;
  assert.match(text, /InfoTrace Mark II（端末の記録）/);
  assert.match(text, /Proxy（通信の記録）/);
  assert.match(text, /パーサーを追加しない限り対応しません/);
});

await test('分類済みだが専用解析が未対応のログが、無視されずに出る', async () => {
  const text = (await screen()).allText;
  assert.match(text, /分類はできたが専用解析が未対応のログ/);
  assert.match(text, /Web サーバーのアクセスログ/);
  assert.ok(text.includes(WEBLOG), '未対応ログの名前が出ていません');
});

await test('未対応のログは、役割の一覧でも役割を保ったまま印が付く', async () => {
  const mount = await screen();
  const marks = mount.find((e) => String(e._text).startsWith('専用解析なし：'));
  assert.equal(marks.length, 1, '未対応の印が付いていません');
  assert.match(mount.allText, /問題ログ（本番）（2 個）/);
});

await test('教材に使うのは、未対応を除いた本数だと書いてある', async () => {
  const text = (await screen()).allText;
  assert.match(text, /問題ログ 1 個だけです/);
  assert.match(text, /2 個のうち 1 個は専用解析が未対応/);
});

// ---------------------------------------------------------------------------
// 生成後の不完全性
// ---------------------------------------------------------------------------
await test('生成後、打ち切り・読み取り失敗・未対応・判別不能が別々に出る', async () => {
  const mount = await screen();
  await generate(mount);
  const text = mount.allText;
  assert.match(text, /読み取れなかった問題ログが 1 個あります/);
  assert.match(text, /専用解析が未対応のログが 1 個あります/);
  assert.match(text, /形式を判別できなかったログが 1 個あります/);
  assert.match(text, /上限に達したため、一部のログを最後まで読んでいません/);
  assert.match(text, /読み取れた分だけで作られています/);
});

await test('生成後も、何を材料にしたかが名前で残る', async () => {
  const mount = await screen();
  await generate(mount);
  assert.ok(mount.allText.includes(CHALLENGE));
  assert.match(mount.allText, /平常時ログ 1 個は、比較用として区別し/);
});

// ---------------------------------------------------------------------------
// 自動判定と強制指定が、生成後も食い違わないこと
//
// 生成要求へ自動判定の結果を毎回添えると、サーバーが「利用者が指定した」と
// 解釈する。データセット画面は「自動で判定した形式」と出し、同じ操作で
// 作った教材の導入画面は「利用者が指定」と出る、という食い違いになる。
// ---------------------------------------------------------------------------
await test('自動判定のときは、生成要求に profileId も profile も含めない', async () => {
  const body = await generate(await screen());
  assert.equal('profileId' in body, false, `送っています: ${JSON.stringify(body)}`);
  assert.equal('profile' in body, false, '旧名 profile を送っている');
  assert.equal(body.archive, 1);
});

await test('形式を指定したときは、選んだ ID を profileId で送る', async () => {
  const mount = await screen();
  await pickFormat(mount, 'example-incident');
  const body = await generate(mount);
  assert.equal(body.profileId, 'example-incident');
  assert.equal('profile' in body, false, '旧名 profile を送っている');
  assert.equal('year' in body, false);
});

await test('自動判定で作った教材は forced === false', async () => {
  const mount = await screen();
  await generate(mount);
  assert.match(mount.allText, /データセット形式: Example mixed-format logs（fixture v2）／自動で判定した形式/);
});

await test('形式を指定して作った教材は forced === true', async () => {
  const mount = await screen();
  await pickFormat(mount, 'example-incident');
  await generate(mount);
  assert.match(mount.allText, /データセット形式: Example incident logs（fixture v1）／利用者が指定した形式/);
});

await test('「自動で判定する」へ戻すと、profileId はまた送られなくなる', async () => {
  const mount = await screen();
  await pickFormat(mount, 'example-incident');
  await pickFormat(mount, '');
  assert.match(mount.allText, /自動で判定した形式/);
  const body = await generate(mount);
  assert.equal('profileId' in body, false);
});

// ---------------------------------------------------------------------------
// 汎用解析（プロファイル未特定）
// ---------------------------------------------------------------------------
await test('プロファイル未特定でも止めず、汎用解析で教材を作れる', async () => {
  baseOverride = GENERIC;
  const mount = await screen();
  const text = mount.allText;
  assert.match(text, /プロファイル未特定（汎用解析）/);
  assert.match(text, /区別できません/, '何ができないかを押す前に言う');
  const body = await generate(mount, '汎用解析で教材を作る');
  assert.deepEqual(body, { archive: 1 }, '汎用解析では形式も鍵も送らない');
});

// ---------------------------------------------------------------------------
// 明示指定が要る形式（Proxy）
// ---------------------------------------------------------------------------
await test('明示指定が要る形式は、指定したときだけ使うと書いてある', async () => {
  baseOverride = { ...GENERIC, parserLabels: ['InfoTrace Mark II（端末の記録）'],
    explicitOnlyLabels: ['Proxy（通信の記録）'] };
  const text = (await screen()).allText;
  assert.match(text, /Proxy（通信の記録） は、プロファイルで指定したときだけ使います/);
  assert.match(text, /通信の向きを決められない/);
});

await test('生成後、通信の向きを断定できないログを理由付きで出す', async () => {
  const mount = await screen();
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    const r = await realFetch(url, options);
    if (url !== '/api/generate') return r;
    const body = await r.json();
    body.dataset.explicitOnly = { 'mixed-case/evidence/case.zip :: case/other.log': ['proxy'] };
    return { ok: true, status: 200, json: async () => body };
  };
  try {
    await generate(mount);
  } finally {
    globalThis.fetch = realFetch;
  }
  const text = mount.allText;
  assert.match(text, /うち 1 個は、プロキシの記録と同じ形の行を含みます/);
  assert.match(text, /プロファイルの parsers に指定すると読み取ります/);
});

// ---------------------------------------------------------------------------
// 年度の前提が残っていないこと
// ---------------------------------------------------------------------------
await test('どの状態でも、画面の文言に年度が出ない', async () => {
  const texts = [];
  texts.push((await screen()).allText);
  baseOverride = GENERIC;
  texts.push((await screen()).allText);
  baseOverride = {};
  const mount = await screen();
  await pickFormat(mount, 'example-incident');
  await generate(mount);
  texts.push(mount.allText);
  for (const text of texts) {
    assert.ok(!text.includes('年度'), '年度という言葉が残っている');
    assert.ok(!text.includes('過去問'), '特定のデータセットを前提にした言い方');
  }
});

console.log(`\n${passed} / ${passed + failures.length} 成功`);
if (failures.length) process.exit(1);
