// player.js — the stage-by-stage lesson player.
// Drives the lesson's stages one at a time: observe behavior -> quiz
// (answer before advancing) -> Continue. After the final stage, hands off
// to the kill-chain recap. All lesson data is rendered with textContent.

import { loadLesson } from './data.js';
import { renderQuiz } from './quiz.js';
import { renderRecap } from './recap.js';

// 事象の種別（データ側のキー）を、画面表示用の日本語に対応させる。
// データの値そのものは変更しない。
const EVENT_TYPE = {
  process: 'プロセス',
  file: 'ファイル',
  registry: 'レジストリ',
  network: '通信',
  api: 'API 呼び出し',
  import: '取り込み',
  string: '文字列',
};

const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
};

export async function renderLesson(mount, lessonId) {
  mount.textContent = '';

  let lesson;
  try {
    lesson = await loadLesson(lessonId);
  } catch (err) {
    const panel = el('div', 'panel');
    panel.appendChild(el('div', 'panel__label', '演習を読み込めませんでした'));
    panel.appendChild(el('p', 'muted', 'この演習は読み込めませんでした。一覧に戻って別の演習を選んでください。'));
    const back = el('button', 'btn btn-ghost', '演習の一覧に戻る');
    back.type = 'button';
    back.setAttribute('aria-label', '演習の一覧に戻る');
    back.addEventListener('click', () => { location.hash = '#/'; });
    const nav = el('div', 'navbtns');
    nav.appendChild(back);
    mount.appendChild(panel);
    mount.appendChild(nav);
    return;
  }

  const stages = Array.isArray(lesson.stages) ? lesson.stages : [];
  const total = stages.length;
  let correct = 0;

  const player = el('div', 'player');
  mount.appendChild(player);

  const renderStage = (index) => {
    player.textContent = '';
    const stage = stages[index];

    // --- Stage header: index pill, name, progress dots ---
    const head = el('div', 'stage-head');
    head.appendChild(el('span', 'stage-index', `段階 ${index + 1}/${total}`));
    const stageName = el('h2', 'stage-name', stage.name || '');
    // Focus target for this view: anchors keyboard focus and announces the new
    // stage to screen readers after the previous screen is torn down.
    stageName.tabIndex = -1;
    head.appendChild(stageName);

    const progress = el('div', 'progress');
    progress.setAttribute('role', 'img');
    progress.setAttribute('aria-label', `全 ${total} 段階中 ${index + 1} 段階目`);
    for (let i = 0; i < total; i++) {
      const dot = el('span', 'progress__dot');
      if (i < index) dot.classList.add('is-done');
      else if (i === index) dot.classList.add('is-current');
      progress.appendChild(dot);
    }
    head.appendChild(progress);
    player.appendChild(head);

    // --- Optional stage intro (friendly framing) ---
    if (stage.intro) {
      // 空行で段落を分ける。textContent は改行を潰すので、まとめて入れると
      // 説明が一続きの塊になって読みにくい。
      String(stage.intro)
        .split(/\n{2,}/)
        .map((t) => t.trim())
        .filter(Boolean)
        .forEach((t) => player.appendChild(el('p', 'muted', t)));
    }

    // --- Observed behavior panel ---
    const panel = el('div', 'panel');
    panel.appendChild(el('div', 'panel__label', '観測された挙動'));

    const list = el('div', 'event-list');
    (stage.events || []).forEach((event) => {
      const row = el('div', 'event');
      const t = String(event.type || '');
      row.appendChild(el('span', 'event__type', EVENT_TYPE[t] || t.toUpperCase()));

      const body = el('div', 'event__body');
      body.appendChild(el('div', 'event__detail', event.detail || ''));
      if (event.attck && event.attck.id) {
        const label = event.attck.name
          ? `${event.attck.id} · ${event.attck.name}`
          : event.attck.id;
        body.appendChild(el('span', 'event__attck', label));
      }
      row.appendChild(body);
      list.appendChild(row);
    });
    panel.appendChild(list);
    player.appendChild(panel);

    // --- Quiz (answer before advance) ---
    const quizPanel = el('div', 'panel');
    player.appendChild(quizPanel);

    // --- Nav: Back to lessons (always) + Continue (after answering) ---
    const nav = el('div', 'navbtns');

    const back = el('button', 'btn btn-ghost', '演習の一覧に戻る');
    back.type = 'button';
    back.setAttribute('aria-label', '演習の一覧に戻る');
    back.addEventListener('click', () => { location.hash = '#/'; });
    nav.appendChild(back);

    const isLast = index === total - 1;
    const cont = el('button', 'btn btn-primary', isLast ? '振り返りへ' : '次へ');
    cont.type = 'button';
    cont.hidden = true;
    cont.addEventListener('click', () => {
      if (isLast) {
        renderRecap(mount, lesson, { correct, total });
        window.scrollTo(0, 0);
      } else {
        renderStage(index + 1);
        window.scrollTo(0, 0);
      }
    });
    nav.appendChild(cont);
    player.appendChild(nav);

    // Render the quiz; reveal Continue once answered, count correct once.
    let answered = false;
    renderQuiz(quizPanel, stage.quiz, (isCorrect) => {
      if (!answered) {
        answered = true;
        if (isCorrect) correct++;
      }
      cont.hidden = false;
      cont.focus();
    });

    // Move focus to this stage's heading so keyboard/SR users land in the new
    // view rather than at <body> after the rebuild. preventScroll avoids
    // fighting the window.scrollTo(0, 0) the nav handlers perform.
    stageName.focus({ preventScroll: true });
  };

  if (total === 0) {
    renderRecap(mount, lesson, { correct: 0, total: 0 });
    return;
  }

  renderStage(0);
}
