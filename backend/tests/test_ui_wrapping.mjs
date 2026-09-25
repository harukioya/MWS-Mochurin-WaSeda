// test_ui_wrapping.mjs — データ由来の文字列が枠から溢れないことの回帰テスト。
//
// なぜ要るか。画面に出る値の多くはログから来る。Windows のパス、URL、
// ハッシュ、レジストリキーは空白を含まない長い一続きの文字列で、CSS の
// 既定（overflow-wrap:normal）ではどこでも改行できない。`\` も `_` も
// UAX#14 の改行可能位置ではないので、幅に収まらなければそのまま枠の外へ出る。
//
// 実際に起きた不具合: 設問の選択肢に
// `C:\Users\demo\AppData\Roaming\Example\Cache\ABCDEFGHIJKLMNOPQRST.tmp`（架空）の
// ような値が出たとき、
// ハイフンを含む選択肢だけが折り返り、含まないものが画面右へはみ出した。
// `.option__label` に `min-width:0` はあったが折り返し規則が無かった。
// flex 項目は縮んでも、中の語は切れない。
//
// ここで確かめられるのは「規則が宣言されているか」までで、実際の描画では
// ない。本物のブラウザでの確認は docs/受け入れ確認チェックリスト.md に残す。
//
//   node backend/tests/test_ui_wrapping.mjs

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const CSS = fs.readFileSync(path.join(REPO, 'styles', 'design.css'), 'utf8');

/**
 * 1 つのセレクタに宣言されている中身を返す。
 * コメントを除いてから探すので、コメント中の例文に当たることはない。
 */
function rule(selector) {
  const body = CSS.replace(/\/\*[\s\S]*?\*\//g, '');
  const at = body.indexOf(`\n${selector}{`);
  if (at < 0) return null;
  const open = body.indexOf('{', at);
  return body.slice(open + 1, body.indexOf('}', open));
}

/** 長い一続きの値を折り返せる宣言があるか。 */
function wraps(decls) {
  return (
    /overflow-wrap\s*:\s*(anywhere|break-word)/.test(decls) ||
    /word-break\s*:\s*(break-all|break-word)/.test(decls) ||
    /white-space\s*:\s*pre-wrap/.test(decls)
  );
}

/**
 * データ由来の文字列を表示する要素。ここに挙げたものは、空白を含まない
 * 長い値を受け取っても溢れてはいけない。
 *
 * 新しく値を出す場所を作ったら、ここへ足すこと。足し忘れは「普段は平気
 * だが、長いパスが来た回だけ画面が壊れる」という形で出るので、実データで
 * 一度動かしただけでは見つからない。
 */
const VALUE_SURFACES = [
  ['.option__label', '設問の選択肢（パス、実行ファイル名、宛先）'],
  ['.event__detail', '観測事象の説明'],
  ['.evidence__member', '証拠の出典ファイル名'],
  ['.evidence__path', '証拠の論理パス（親 :: 子）'],
  ['.browser__name', 'フォルダ・ZIP 内の項目名'],
  ['.factlist__value', '導入画面の対象ホストやログ種別'],
  ['.timeline__title', '最終レポートの時系列の見出し'],
  ['.review__q', '復習一覧の設問文'],
  ['.quiz__hint-body', 'ヒント本文'],
];

const results = [];
function test(name, fn) {
  try {
    fn();
    results.push(['ok', name]);
  } catch (err) {
    results.push(['ng', name, err.message]);
  }
}

for (const [selector, what] of VALUE_SURFACES) {
  test(`${what} が折り返せる（${selector}）`, () => {
    const decls = rule(selector);
    assert.ok(decls !== null, `${selector} の規則が見つかりません`);
    assert.ok(
      wraps(decls),
      `${selector} に折り返し規則がありません。空白の無い長い値が枠から溢れます。`
    );
  });
}

test('選択肢は flex の中でも縮められる（min-width:0 がある）', () => {
  const decls = rule('.option__label');
  assert.match(
    decls, /min-width\s*:\s*0/,
    'flex 項目は既定で min-content より縮まないので、これが無いと折り返しても枠が広がる'
  );
});

test('選択肢の折り返しは break-all ではなく anywhere', () => {
  // 選択肢には散文も入る（「断定できない」「通信の記録が無い」など）。
  // break-all は普通の語の途中でも切るので、溢れるときだけ切る anywhere を使う。
  const decls = rule('.option__label');
  assert.match(decls, /overflow-wrap\s*:\s*anywhere/);
  assert.doesNotMatch(decls, /word-break\s*:\s*break-all/);
});

test('回答後の「✓ 正解」表示は途中で折り返さない', () => {
  // 値ではなく決まり文句なので、こちらは折り返させない側。
  const decls = rule('.option__label ~ .mono');
  assert.ok(decls !== null, '正解マーカーの規則が見つかりません');
  assert.match(decls, /white-space\s*:\s*nowrap/);
});

// ---------------------------------------------------------------------------
let bad = 0;
for (const [status, name, why] of results) {
  if (status === 'ok') console.log(`  ok   ${name}`);
  else { bad++; console.log(`  NG   ${name}\n       ${why}`); }
}
console.log(`\n${results.length - bad} / ${results.length} 成功`);
process.exit(bad ? 1 : 0);
