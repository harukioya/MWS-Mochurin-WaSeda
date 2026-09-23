// quiz.js — the answer-before-advance quiz component.
// Renders .quiz into `container`, locks on first answer, always reveals the
// correct option, shows feedback + explanation, then calls onAnswered(isCorrect).
// All lesson text is rendered with textContent (never innerHTML).

import { citedEvidence, jumpButtons, visible } from './evidence.js';

const KEYS = ['A', 'B', 'C', 'D', 'E', 'F'];

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
 * @param {HTMLElement} container  element to render into (cleared first)
 * @param {object} quiz            { q, options: string[], correct: number, explain: string }
 * @param {(isCorrect:boolean)=>void} onAnswered  called once, after the first answer
 */
export function renderQuiz(container, quiz, onAnswered, evidence) {
  container.textContent = '';
  const map = evidence || {};

  // A lesson author can drop in a stage with no (or a malformed) quiz. Fail
  // soft: say so, and still hand control back so the stage isn't a dead end —
  // the caller only reveals "Continue" from this callback.
  //
  // 問い文は旧形式が `q`、仕様書の `evidence_pick` が `prompt`。どちらか
  // 一方でも設問として成り立つ。`q` だけを必須にしていたため、仕様書どおり
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

  // 根拠を選ぶ問題では、選択肢が「どのログか」を指す。何を比べるのかを
  // 先に言っておかないと、出典と行番号の羅列にしか見えない。
  if (quiz.type === 'evidence_pick') {
    const hint = document.createElement('p');
    hint.className = 'muted';
    hint.textContent =
      '下の記録のうち、この判断を最も直接支えているものを選んでください。回答後に原文を確認できます。';
    quizEl.appendChild(hint);
  }

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
    const cited = citedEvidence(quiz.evidenceIds, map);
    if (cited) quizEl.appendChild(cited);

    const jump = jumpButtons(quiz.evidenceIds, map);
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
