// evidence.js — 証拠カードの描画と、根拠への案内。
//
// 証拠の原文は ZIP の中から来る。細工されている前提で扱うので、
// innerHTML へは決して渡さず、必ず textContent で入れる。制御文字と双方向
// 制御文字はサーバー側で <U+XXXX> に置き換え済みだが、ここでも念のため同じ
// 処理をかける。表示側だけ、保存側だけ、のどちらか一方に頼らない。

// サーバー側 `evidence._UNSAFE` と同じ範囲。改行とタブも含める。ZIP の
// メンバー名には改行を入れられるので、残すと出典表示や読み上げラベルを
// 複数行に割られてしまう。
const BIDI_OR_CTRL =
  // eslint-disable-next-line no-control-regex
  /[\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c\u0000-\u001f\u007f-\u009f]/g;

/** 危ない文字を見える形へ。サーバー側 `evidence.visible()` と同じ考え方。 */
export const visible = (s) =>
  String(s == null ? '' : s).replace(
    BIDI_OR_CTRL,
    (c) => `<U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}>`
  );

/** 画面へ載せる 1 件あたりの上限。長い行で頁が壊れないようにする。
 *  サーバー側の上限（1000）と揃える。ここで先に切ると、設問の答えにあたる
 *  項目だけが画面から消えることがある。 */
const MAX_EXCERPT = 1000;

const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
};

const KIND_LABEL = {
  process: 'プロセス',
  file: 'ファイル',
  registry: 'レジストリ',
  network: '通信',
  // 静的な根拠（Ghidra の保存済み解析情報）
  instruction: '命令',
  string: '定義済み文字列',
  function: '関数',
  external: '外部関数',
};

const CONFIDENCE_LABEL = {
  observed: '記録から直接読める',
  correlated: '複数の記録を突き合わせた',
  hypothesis: '可能性はあるが未確定',
  stored: '保存済みの解析情報に記録されている',
};

/**
 * 静的な根拠か。ログの根拠（ファイル名と行番号）とは出典の形が違う。
 * 静的な根拠は「プログラム名／関数／アドレス／命令または参照関係」で示す。
 */
export const isStatic = (item) => !!item && item.evidenceType === 'static';

/** 出典を短く 1 行で。ジャンプボタンや事象の一覧で使う。 */
export function sourceLabel(item) {
  const src = (item && item.source) || {};
  if (isStatic(item)) {
    const who = src.function || src.program || '';
    return `${visible(who)} ${visible(src.address)}`.trim();
  }
  return `${visible(src.member)} ${src.line} 行目`;
}

/** 演習の証拠表。無い（旧形式）なら空を返す。 */
export function evidenceMap(lesson) {
  return (lesson && lesson.evidence) || {};
}

/**
 * DOM の id。証拠カードへ飛ぶときの宛先。
 *
 * `scope` は画面の別。演習の段階と最終レポートは別々に描かれ、同時に頁へ
 * 出ることはないが、id を共有していると「レポート側にはカードが無いのに
 * 段階側の id を探す」という状態になる。実際そうなっていて、レポートの
 * 「根拠ログを見る」は押しても何も起きなかった。画面ごとに別の id 空間を
 * 持たせ、その画面の中で飛び先が閉じるようにする。
 */
export const cardId = (ident, scope = 'stage') => `ev-${scope}-${ident}`;

/**
 * 証拠カードを 1 枚作る。
 *
 * 同じ証拠は 1 画面の中で、上部の一覧と回答後の再掲の 2 か所に出る。id を
 * 両方へ付けると同一頁に同じ id が 2 つできて、`getElementById()` の行き先が
 * 実装任せになるうえ、支援技術にとっても不正になる。飛び先になる方だけに
 * 付ける。
 *
 * @param {object} item サーバーが保存した証拠
 * @param {string} [note] この証拠が何を支えているか
 * @param {boolean} [anchor] ジャンプの飛び先にするか（既定は真）
 * @param {string} [scope] 画面の別。飛び先を探す側と必ず揃える。
 */
export function evidenceCard(item, note, anchor = true, scope = 'stage') {
  const card = el('div', 'evidence');
  if (anchor) card.id = cardId(item.id, scope);
  // 読み上げとキーボード操作のため、カード自体を到達可能にする。
  card.tabIndex = -1;
  card.setAttribute('role', 'group');

  const src = item.source || {};
  const label = KIND_LABEL[item.kind] || item.kind || '記録';
  if (isStatic(item)) return staticCard(card, item, label, note);
  card.setAttribute(
    'aria-label',
    `証拠 ${label}。出典 ${visible(src.member)} の ${src.line} 行目。`
  );

  const head = el('div', 'evidence__head');
  head.append(el('span', 'evidence__kind', label));
  // 状態は色だけで表さない。文言も必ず添える。
  const conf = el(
    'span',
    'evidence__confidence',
    CONFIDENCE_LABEL[item.confidence] || item.confidence || ''
  );
  head.append(conf);
  card.append(head);

  const where = el('div', 'evidence__where mono');
  where.append(el('span', 'evidence__member', visible(src.member)));
  where.append(el('span', 'evidence__line', `${src.line} 行目`));
  card.append(where);

  // 出典の完全な形（どの内側 ZIP か）。同名ログの取り違えを防ぐ。
  if (src.archivePath && src.archivePath !== src.member) {
    card.append(el('div', 'evidence__path mono', visible(src.archivePath)));
  }

  const raw = visible(src.excerpt);
  const body = el(
    'pre',
    'evidence__excerpt mono',
    raw.length > MAX_EXCERPT ? `${raw.slice(0, MAX_EXCERPT)}…` : raw
  );
  body.tabIndex = 0;
  body.setAttribute('role', 'region');
  body.setAttribute('aria-label', 'ログ原文の抜粋');
  card.append(body);

  if (note) card.append(el('p', 'evidence__note', note));
  return card;
}

/** 静的な根拠のカード。項目ごとに見出しを付けて並べる。 */
function staticCard(card, item, label, note) {
  const src = item.source || {};
  card.classList.add('evidence--static');
  const where = [visible(src.program), visible(src.function), visible(src.address)]
    .filter(Boolean)
    .join(' の ');
  card.setAttribute('aria-label', `証拠 ${label}。${where}。`);

  const head = el('div', 'evidence__head');
  head.append(el('span', 'evidence__kind', label));
  head.append(
    el('span', 'evidence__confidence', CONFIDENCE_LABEL[item.confidence] || item.confidence || '')
  );
  card.append(head);

  const dl = el('dl', 'factlist evidence__facts');
  const rows = [
    ['プログラム', src.program],
    ['関数', src.function],
    ['アドレス', src.address],
    ['命令', src.instruction],
    ['参照・記録', src.reference],
  ];
  rows.forEach(([k, v]) => {
    if (v == null || v === '') return;
    dl.append(el('dt', 'factlist__key', k));
    dl.append(el('dd', 'factlist__value mono', visible(v)));
  });
  card.append(dl);

  // 命令が無い記録（文字列・関数・外部関数）は、記録そのものを抜粋として出す。
  if (!src.instruction && src.excerpt) {
    const raw = visible(src.excerpt);
    const body = el('pre', 'evidence__excerpt mono', raw.length > MAX_EXCERPT ? `${raw.slice(0, MAX_EXCERPT)}…` : raw);
    body.tabIndex = 0;
    body.setAttribute('role', 'region');
    body.setAttribute('aria-label', '保存済みの記録');
    card.append(body);
  }
  if (note) card.append(el('p', 'evidence__note', note));
  return card;
}

/**
 * いま強調している証拠カード。強調は常に 1 枚だけにする。
 *
 * 以前は付けたまま外さなかったので、同じ段階で次の設問へ進んでも、前の
 * 設問の根拠が強調されたまま残り、どれが今の設問の根拠か分からなくなった。
 */
let citedCard = null;

/** 証拠カードの強調を外す。次の設問・段階へ移るときに呼ぶ。 */
export function clearCited() {
  if (citedCard) {
    citedCard.classList.remove('is-cited');
    citedCard = null;
  }
}

/**
 * 「根拠ログを見る」。回答後に、対応する証拠カードへ移動させる。
 *
 * 強調表示だけに頼らない。見出しとラベルでも位置が分かるようにし、移動後は
 * カードへフォーカスを移す。スクロールだけだと、キーボードと読み上げの利用者
 * には「どこへ着いたのか」が伝わらない。
 *
 * `text` はボタンの文言。解答前の「問題の行を見る」も同じ仕組みで飛ぶ。
 */
export function jumpButtons(ids, map, scope = 'stage', text = '根拠ログを見る') {
  const row = el('div', 'navbtns navbtns--wrap');
  const known = (ids || []).filter((i) => map[i]);
  if (!known.length) return null; // 旧形式の問題では出さない

  known.forEach((ident, i) => {
    const item = map[ident];
    const where = sourceLabel(item);
    const label =
      known.length > 1 ? `${text}（${i + 1}）: ${where}` : `${text}: ${where}`;
    const btn = el('button', 'btn btn-ghost btn-sm', label);
    btn.type = 'button';
    btn.addEventListener('click', () => {
      // 飛び先は同じ画面のアンカー付きカード。複製には id を付けていない
      // ので、ここで見つかるのは常に 1 枚だけになる。
      const card = document.getElementById(cardId(ident, scope));
      if (!card) return;
      card.scrollIntoView({ block: 'center', behavior: 'smooth' });
      clearCited();
      card.classList.add('is-cited');
      citedCard = card;
      card.focus({ preventScroll: true });
    });
    row.append(btn);
  });
  return row;
}

/**
 * 回答後に根拠そのものを並べる。段階上部まで戻らなくても読めるようにする。
 *
 * ここに出すのは複製なので id は付けない。飛び先は段階上部の 1 枚に保つ。
 */
export function citedEvidence(ids, map, note, title = '根拠となる記録') {
  const known = (ids || []).filter((i) => map[i]);
  if (!known.length) return null;
  const box = el('div', 'evidence-list');
  box.append(el('div', 'panel__label', title));
  known.forEach((ident) => box.append(evidenceCard(map[ident], note, false)));
  return box;
}
