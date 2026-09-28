// quiz.js — the answer-before-advance quiz component.
// Renders .quiz into `container`, locks on first answer, always reveals the
// correct option, shows feedback + explanation, then calls onAnswered(isCorrect).
// All lesson text is rendered with textContent (never innerHTML).

import { citedEvidence, jumpButtons, visible } from './evidence.js';

const KEYS = ['A', 'B', 'C', 'D', 'E', 'F'];

// 保存済みの教材にも、解説や正解を先に見せず使える共通ヒントを用意する。
const DEFAULT_HINT =
  'まず問題文が尋ねている対象と動作を整理し、上の記録や説明と選択肢を一つずつ照らし合わせてください。';
const CATEGORY_HINTS = {
  'log-reading': '問題文にあるファイル名と行番号の原文を確認してください。プログラム・端末・ファイル・通信先のうち何を尋ねているかを整理し、対応する項目を探します。',
  evidence: '選択肢の出典と行番号を上の証拠カードと照合し、主張している対象と動作を直接記録した行を探してください。同じ単語があるだけでは根拠になりません。',
  correlation: '二つの記録の日時とタイムゾーンを確認してください。比較できる時刻基準で前後を比べ、表示順や因果関係とは区別します。',
  attck: 'プログラムと引数、または設定された場所から、記録された動作を確認してください。手法の意味と照合し、目的は推測で補わないようにします。',
  limits: 'それぞれの選択肢を裏付ける項目が、原文にあるか確認してください。記録された事実と、目的や背景の推測を分けます。',
  'static-string': '命令の参照先アドレスと、定義済み文字列の記録のアドレスを照らし合わせてください。',
  'static-call': '呼び出し命令の行き先アドレスと、関数の入口アドレスを照らし合わせてください。',
  'static-external': '各記録のアドレス空間と登録先を確かめ、プログラムの外にある関数を探してください。',
};

/** Ghidra の保存済み解析情報から作った設問か。ボタンの言い方を変える。 */
const isStaticQuiz = (quiz) => /^static-/.test(String(quiz && quiz.category));

/**
 * 段階的なヒント。`hints` が配列で来た設問だけが持つ。
 *
 * 一度に全部を見せると、最後のヒントが答えの在りかをほぼ言ってしまう。
 * 1 つ目から順に開けるようにし、どこまで見たかを「ヒント n/m」で示す。
 */
function stagedHints(quiz) {
  return Array.isArray(quiz.hints)
    ? quiz.hints.filter((h) => typeof h === 'string' && h.trim())
    : [];
}

function hintText(quiz) {
  if (typeof quiz.hint === 'string' && quiz.hint.trim()) return quiz.hint;
  const categoryHint = CATEGORY_HINTS[quiz.category];
  return (typeof categoryHint === 'string' ? categoryHint : '')
    || (quiz.type === 'evidence_pick' ? CATEGORY_HINTS.evidence : DEFAULT_HINT);
}

/**
 * 選択肢を表示用の文字列にする。
 *
 * 旧来の単一選択では選択肢は文字列だが、`evidence_pick` では
 * `{label, evidenceId}` の形で来る。どちらでも壊れないようにする。
 */
function optionText(option) {
  if (option && typeof option === 'object') {
    return visible(option.label != null ? option.label : option.evidenceId);
  }
  return visible(option);
}

/**
 * 設問が対象にしている記録の証拠 id。解答前に見せてよいのはこれだけ。
 *
 * 対象の記録は、設問の種類によって二通りに出す。
 *   * 「○○ の N 行目 について」と問い文が行を名指しする設問（log-reading）
 *     → その行へ飛ぶボタン（`問題の行を見る`）
 *   * 「下に示した記録は…」と問い文が記録を示すと約束する設問
 *     （attck / limits / correlation）→ 問い文のすぐ下にカードを出す
 * どちらも、記録は「探させる答え」ではなく「読んで判断する材料」なので、
 * 解答前に見せても答えは漏れない。
 *
 * 教材側が `subjectEvidenceIds` で明示する。この項目が無い、以前に作った
 * 教材でも動くよう、上の種類に限っては根拠を充てる。これらの設問では
 * 根拠がそのまま対象の記録だからである。
 *
 * 根拠を選ばせる設問（evidence_pick）は、項目が付いていても空を返す。
 * そこで根拠を先に見せたら、答えを押す前に答えを見せることになる。
 */
const PRESENTS_RECORD = new Set(['attck', 'limits', 'correlation']);

function subjectIds(quiz) {
  if (quiz.type === 'evidence_pick') return [];
  if (Array.isArray(quiz.subjectEvidenceIds)) return quiz.subjectEvidenceIds;
  if (!Array.isArray(quiz.evidenceIds)) return [];
  if (quiz.category === 'log-reading') return quiz.evidenceIds.slice(0, 1);
  if (PRESENTS_RECORD.has(quiz.category)) return quiz.evidenceIds;
  return [];
}

/**
 * @param {HTMLElement} container  element to render into (cleared first)
 * @param {object} quiz            { q, options, correct, explain, hint?: string }
 * @param {(isCorrect:boolean)=>void} onAnswered  called once, after the first answer
 */
export function renderQuiz(container, quiz, onAnswered, evidence) {
  container.textContent = '';
  const map = evidence || {};

  // A lesson author can drop in a stage with no (or a malformed) quiz. Fail
  // soft: say so, and still hand control back so the stage isn't a dead end —
  // the caller only reveals "Continue" from this callback.
  //
  // 問い文は旧形式が `q`、根拠を選ぶ形式（`evidence_pick`）が `prompt`。
  // どちらか一方でも設問として成り立つ。`q` だけを必須にしていたため、
  // `prompt` だけを書いた設問が「設問がありません」になっていた。
  const question =
    typeof quiz?.q === 'string'
      ? quiz.q
      : typeof quiz?.prompt === 'string'
        ? quiz.prompt
        : null;
  if (!quiz || question === null || !Array.isArray(quiz.options) || quiz.options.length === 0) {
    const note = document.createElement('p');
    note.className = 'muted';
    note.textContent = 'この段階には設問がありません。上の挙動を読んで次へ進んでください。';
    container.appendChild(note);
    if (typeof onAnswered === 'function') onAnswered(false);
    return null;
  }

  const quizEl = document.createElement('div');
  quizEl.className = 'quiz';

  const promptText = question;

  if (quiz.learningObjective) {
    const aim = document.createElement('div');
    aim.className = 'quiz__aim';
    aim.textContent = `ねらい: ${quiz.learningObjective}`;
    quizEl.appendChild(aim);
  }

  const q = document.createElement('div');
  q.className = 'quiz__q';
  q.textContent = promptText;
  quizEl.appendChild(q);

  // 設問が対象にしている記録を、解答前から見せる（subjectIds の説明を参照）。
  //
  // 「下に示した記録は…」と書く設問で、その記録を解答後にしか出して
  // いなかった。問い文が約束したものが画面に無く、段階の上に並ぶカードの
  // どれが対象なのかも分からなかった。
  const subjectShown = PRESENTS_RECORD.has(quiz.category);
  const ids = subjectIds(quiz);
  const subject = subjectShown
    ? citedEvidence(ids, map, undefined, '対象の記録')
    : jumpButtons(ids, map, 'stage', isStaticQuiz(quiz) ? '問題の命令を見る' : '問題の行を見る');
  if (subject) {
    subject.classList.add('quiz__subject');
    quizEl.appendChild(subject);
  }

  // 根拠を選ぶ問題では、選択肢が「どのログか」を指す。何を比べるのかを
  // 先に言っておかないと、出典と行番号の羅列にしか見えない。
  if (quiz.type === 'evidence_pick') {
    const hint = document.createElement('p');
    hint.className = 'muted';
    hint.textContent =
      '下の記録のうち、この判断を最も直接支えているものを選んでください。回答後に原文を確認できます。';
    quizEl.appendChild(hint);
  }

  // details/summary の標準操作で、マウス・Enter・Spaceから開閉できる。
  // 採点や回答コールバックには繋げない。設問が変わるたび閉じた状態で作る。
  const hint = document.createElement('details');
  hint.className = 'quiz__hint';
  hint.open = false;
  const hintToggle = document.createElement('summary');
  hintToggle.className = 'quiz__hint-toggle';
  hintToggle.textContent = 'ヒントを見る';
  const steps = stagedHints(quiz);
  const hintBody = document.createElement('p');
  hintBody.className = 'quiz__hint-body';
  hintBody.textContent = visible(steps.length ? steps[0] : hintText(quiz));
  const hintNote = document.createElement('p');
  hintNote.className = 'quiz__hint-note';
  hintNote.textContent = 'ヒントを見ても減点されません。';
  hint.append(hintToggle, hintBody);
  if (steps.length > 1) {
    hintToggle.textContent = `ヒントを見る（全 ${steps.length} 段階）`;
    hintBody.textContent = `ヒント 1/${steps.length}: ${visible(steps[0])}`;
    let shown = 1;
    const more = document.createElement('button');
    more.type = 'button';
    more.className = 'btn btn-ghost btn-sm quiz__hint-more';
    more.textContent = '次のヒント';
    more.addEventListener('click', () => {
      if (shown >= steps.length) return;
      const p = document.createElement('p');
      p.className = 'quiz__hint-body';
      p.textContent = `ヒント ${shown + 1}/${steps.length}: ${visible(steps[shown])}`;
      hint.insertBefore(p, more);
      shown += 1;
      if (shown >= steps.length) {
        more.disabled = true;
        more.textContent = 'ヒントは以上です';
      }
      p.tabIndex = -1;
      p.focus({ preventScroll: true });
    });
    hint.append(more);
  }
  hint.append(hintNote);
  quizEl.appendChild(hint);

  const optionsEl = document.createElement('div');
  optionsEl.className = 'options';
  optionsEl.setAttribute('role', 'group');
  optionsEl.setAttribute('aria-label', '選択肢');

  const buttons = quiz.options.map((label, i) => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'option';

    const key = document.createElement('span');
    key.className = 'option__key';
    key.textContent = KEYS[i] || String(i + 1);
    key.setAttribute('aria-hidden', 'true');

    const text = document.createElement('span');
    text.className = 'option__label';
    text.textContent = optionText(label);

    btn.appendChild(key);
    btn.appendChild(text);
    btn.setAttribute('aria-label', `${KEYS[i] || i + 1}: ${optionText(label)}`);
    btn.addEventListener('click', () => answer(i));
    optionsEl.appendChild(btn);
    return btn;
  });

  quizEl.appendChild(optionsEl);
  container.appendChild(quizEl);

  let answered = false;

  function answer(chosen) {
    if (answered) return;
    answered = true;

    const isCorrect = chosen === quiz.correct;

    // Lock every option and paint the result. Correctness is also conveyed
    // non-visually (a text marker + aria-label) so it survives greyscale and
    // reaches screen readers — not by color alone (WCAG 1.4.1).
    buttons.forEach((btn, i) => {
      btn.disabled = true;
      const baseLabel = `${KEYS[i] || i + 1}: ${optionText(quiz.options[i])}`;
      if (i === quiz.correct) {
        btn.classList.add('is-correct');
        const mark = document.createElement('span');
        mark.className = 'mono faint';
        mark.textContent = '✓ 正解';
        btn.appendChild(mark);
        btn.setAttribute('aria-label', `${baseLabel}（正解）`);
      } else if (i === chosen && !isCorrect) {
        btn.classList.add('is-wrong');
        const mark = document.createElement('span');
        mark.className = 'mono faint';
        mark.textContent = '✗ あなたの選択';
        btn.appendChild(mark);
        btn.setAttribute('aria-label', `${baseLabel}（あなたの回答 — 不正解）`);
      }
    });

    // Feedback banner.
    const feedback = document.createElement('div');
    feedback.className = 'feedback ' + (isCorrect ? 'is-ok' : 'is-bad');
    feedback.setAttribute('role', 'status');

    const icon = document.createElement('span');
    icon.className = 'feedback__icon';
    icon.textContent = isCorrect ? '✓' : '✗';
    icon.setAttribute('aria-hidden', 'true');

    const msg = document.createElement('span');
    msg.textContent = isCorrect
      ? '正解です。'
      : '不正解です。正解は次のとおりです。';

    feedback.appendChild(icon);
    feedback.appendChild(msg);
    quizEl.appendChild(feedback);

    // Reveal / explanation.
    const reveal = document.createElement('div');
    reveal.className = 'reveal';

    const title = document.createElement('div');
    title.className = 'reveal__title';
    title.textContent = '解説';

    reveal.appendChild(title);
    // 解説も空行で段落を分ける。長い説明が一塊になると読み通されない。
    String(quiz.explain != null ? quiz.explain : quiz.explanation || '')
      .split(/\n{2,}/)
      .map((t) => t.trim())
      .filter(Boolean)
      .forEach((t) => {
        const para = document.createElement('p');
        para.textContent = t;
        reveal.appendChild(para);
      });
    quizEl.appendChild(reveal);

    // ---- 根拠 ----
    //
    // 正解でも不正解でも出す。間違えたときこそ「なぜそれが答えなのか」を
    // 実ログで確かめられる必要がある。証拠を持たない旧形式の問題では、
    // どちらも null が返るので何も足さない。
    // 対象の記録として解答前に同じカードを出してあれば、二度は並べない。
    const cited = subject && subjectShown ? null : citedEvidence(quiz.evidenceIds, map);
    if (cited) quizEl.appendChild(cited);

    const jump = jumpButtons(
      quiz.evidenceIds, map, 'stage',
      isStaticQuiz(quiz) ? '根拠の記録を見る' : '根拠ログを見る'
    );
    if (jump) quizEl.appendChild(jump);

    if (quiz.nextInvestigation) {
      const next = document.createElement('p');
      next.className = 'quiz__next';
      next.textContent = `次に確認すること: ${quiz.nextInvestigation}`;
      quizEl.appendChild(next);
    }

    document.removeEventListener('keydown', onKey);

    if (typeof onAnswered === 'function') onAnswered(isCorrect);
  }

  // Optional number-key shortcuts (1–4/6). Buttons already handle Enter/Space.
  function onKey(e) {
    // Self-clean: if the options were removed (learner navigated away or the
    // stage re-rendered without answering), unbind and bail so we never act on
    // detached buttons or stack listeners.
    if (!optionsEl.isConnected) {
      document.removeEventListener('keydown', onKey);
      return;
    }
    if (answered) return;
    if (e.altKey || e.ctrlKey || e.metaKey) return;
    const n = parseInt(e.key, 10);
    if (Number.isInteger(n) && n >= 1 && n <= buttons.length) {
      e.preventDefault();
      buttons[n - 1].focus();
      answer(n - 1);
    }
  }
  document.addEventListener('keydown', onKey);

  return quizEl;
}
