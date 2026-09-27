// player.js — the stage-by-stage lesson player.
// Drives the lesson's stages one at a time: observe behavior -> quiz
// (answer before advancing) -> Continue. After the final stage, hands off
// to the kill-chain recap. All lesson data is rendered with textContent.

import { loadLesson } from './data.js';
import { renderQuiz } from './quiz.js';
import { renderRecap } from './recap.js';
import { clearCited, evidenceCard, evidenceMap, isStatic, sourceLabel, visible } from './evidence.js';
import { renderIntroduction } from './intro.js';

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
  // 静的解析の教材（Ghidra の保存済み解析情報）
  instruction: '命令',
  call: '呼び出し命令',
  function: '関数',
  external: '外部関数',
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
  const evidence = evidenceMap(lesson);
  // 静的解析の教材は「観測」ではなく、保存済みの記録を読む。実行したかの
  // ように見える言い方をしない。
  const staticLesson = lesson.kind === 'static';

  /** その段階の設問。旧形式は `quiz` が 1 つだけなので同じ形へ揃える。 */
  const quizzesOf = (stage) =>
    Array.isArray(stage.quizzes) && stage.quizzes.length
      ? stage.quizzes
      : stage.quiz
        ? [stage.quiz]
        : [];

  // 得点は設問単位で数える。段階ごとに 1 点としていたため、端末段階に設問が
  // 2 つある今の教材では、4 問答えても「3/3」としか出なかった。振り返りは
  // 「正解 X / Y」と読ませるので、Y は実際の設問数でなければならない。
  //
  // 設問を持たない段階（証拠が無く落とされた旧形式など）は、母数にも得点にも
  // 入れない。以前はそうした段階が自動的に正解として加算されていた。
  const questionTotal = stages.reduce((n, s) => n + quizzesOf(s).length, 0);
  let correct = 0;

  // 回答履歴。最終レポートの段階別・カテゴリ別得点と、間違えた問題の復習に
  // 使う。永続化はしない（今回の範囲外）。同じ問題を二度数えないよう、
  // 問題 ID を鍵にする。
  const answers = new Map();
  const record = (stage, quiz, isCorrect) => {
    const key = quiz.id || `${stage.id}:${quiz.q}`;
    if (answers.has(key)) return false;
    answers.set(key, {
      questionId: key,
      stageId: stage.id || '',
      stageName: stage.name || '',
      category: quiz.category || 'log-reading',
      correct: !!isCorrect,
      evidenceIds: quiz.evidenceIds || [],
      quiz,
    });
    return true;
  };

  const player = el('div', 'player');
  mount.appendChild(player);

  const renderStage = (index) => {
    clearCited();
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
    panel.appendChild(
      el('div', 'panel__label', staticLesson ? '保存済みの解析情報（Ghidra）' : '観測された挙動')
    );

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
      // 証拠があれば、その事象がどのログの何行目から来たのかを添える。
      // 旧形式の演習には evidenceIds が無いので、その場合は従来どおり。
      const cite = (event.evidenceIds || []).map((i) => evidence[i]).filter(Boolean)[0];
      if (cite && cite.source && !isStatic(cite)) {
        // 出典名も ZIP 由来なので、ここでも visible() を通す。証拠カードと
        // ジャンプボタンだけ処理していたため、未処理のデータが渡ってきた
        // 場合に、この一覧にだけ改行やタブが不可視のまま残っていた。
        const where = el(
          'span',
          'event__source mono',
          `${visible(cite.source.member)} : ${cite.source.line} 行目`
        );
        body.appendChild(where);
      } else if (cite && cite.source) {
        body.appendChild(el('span', 'event__source mono', sourceLabel(cite)));
      }
      row.appendChild(body);
      list.appendChild(row);
    });
    panel.appendChild(list);
    player.appendChild(panel);

    // --- 証拠カード ---
    //
    // 事象の一覧は短くまとめた説明で、原文ではない。根拠を確かめるための
    // 原文はここに置く。回答後の「根拠ログを見る」はこのカードへ飛ぶ。
    //
    // 事象が指すものだけでなく、この段階の設問が指すものも並べる。設問の
    // 根拠が別の段階の記録から来ることがあり、そのときカードが無いと
    // 「根拠ログを見る」が押しても何も起きないボタンになる。飛び先の有無を
    // 設問側で気にせずに済むよう、この段階が参照する証拠はここで全部出す。
    const cited = [];
    const addCite = (i) => {
      if (evidence[i] && !cited.includes(i)) cited.push(i);
    };
    (stage.events || []).forEach((event) =>
      (event.evidenceIds || []).forEach(addCite));
    quizzesOf(stage).forEach((quiz) => {
      (quiz.evidenceIds || []).forEach(addCite);
      (quiz.options || []).forEach((o) => {
        if (o && typeof o === 'object' && o.evidenceId) addCite(o.evidenceId);
      });
    });
    if (cited.length) {
      const evPanel = el('div', 'panel');
      evPanel.appendChild(el('div', 'panel__label', '根拠となった記録'));
      evPanel.appendChild(
        el('p', 'muted',
          staticLesson
            ? '上の各行は、Ghidra が GZF に保存した次の記録から読み取ったものです。'
            : '上の各行は、次のログの原文から読み取ったものです。')
      );
      const box = el('div', 'evidence-list');
      cited.forEach((i) => box.appendChild(evidenceCard(evidence[i])));
      evPanel.appendChild(box);
      player.appendChild(evPanel);
    }

    // --- Quiz (answer before advance) ---
    const quizPanel = el('div', 'panel quiz-panel');
    player.appendChild(quizPanel);

    // 回答した直後に、視点を設問の先頭（「設問 n/m」）へ合わせる。
    //
    // 回答後は解説・根拠・「次へ」が下に足される。以前は「次へ」ボタンへ
    // フォーカスを移していたので、ブラウザがそこまでスクロールし、自分の
    // 選択が正解だったかを確かめるには上へ戻る必要があった。フォーカスは
    // キーボード利用者のために移すが（preventScroll で位置は動かさない）、
    // 見せる位置は設問の先頭に固定する。
    const keepQuizInView = () => {
      const reduce =
        typeof window.matchMedia === 'function' &&
        window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      quizPanel.scrollIntoView({ block: 'start', behavior: reduce ? 'auto' : 'smooth' });
    };

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
        renderRecap(mount, lesson, {
          correct,
          total: questionTotal,
          answers: [...answers.values()],
          // 復習から段階へ戻れるようにする。得点は `answers` が鍵で
          // 重複を弾くので、戻って解き直しても二重加算されない。
          goToStage: (stageId) => {
            const at = stages.findIndex((s) => s.id === stageId);
            if (at < 0) return;
            // レポートは mount を丸ごと差し替えるので、player はもう外れて
            // いる。付け直してから段階を描かないと、どこにも表示されない。
            mount.textContent = '';
            mount.appendChild(player);
            renderStage(at);
            window.scrollTo(0, 0);
          },
        });
        window.scrollTo(0, 0);
      } else {
        renderStage(index + 1);
        window.scrollTo(0, 0);
      }
    });
    nav.appendChild(cont);
    player.appendChild(nav);

    // --- 設問 ---
    //
    // 新しい演習は 1 段階に複数の設問を持つ（`quizzes`）。旧形式は `quiz` が
    // 1 つだけなので、同じ形へ揃えてから順に出す。
    const quizzes = quizzesOf(stage);

    // 同じ設問を二重に数えないための記録。再描画や連打で加算されないように。
    const scored = new Set();

    const askFrom = (qi) => {
      if (qi >= quizzes.length) {
        if (!quizzes.length) {
          // 根拠が足りず設問を作れなかった段階。観測できた事実は上に出して
          // あるので、黙って飛ばさず理由を書いて先へ進めるようにする。
          quizPanel.appendChild(
            el('div', 'panel__label', 'この段階には設問がありません')
          );
          quizPanel.appendChild(
            el('p', 'muted',
              stage.note ||
              'この段階では、問題を作るための根拠が不足しています。上の記録を読んで次へ進んでください。')
          );
        }
        cont.hidden = false;
        // 位置は動かさない。フォーカス先へ飛ぶと、回答直後に最下部まで
        // 流されてしまう。見せる位置は呼び出し側が決める。
        cont.focus({ preventScroll: true });
        return;
      }
      // 前の設問の根拠の強調を外してから、次の設問を出す。
      clearCited();
      quizPanel.textContent = '';
      if (quizzes.length > 1) {
        quizPanel.appendChild(
          el('div', 'panel__label', `設問 ${qi + 1}/${quizzes.length}`)
        );
      }
      const holder = el('div');
      quizPanel.appendChild(holder);

      renderQuiz(
        holder,
        quizzes[qi],
        (isCorrect) => {
          if (!scored.has(qi)) {
            scored.add(qi);
            if (record(stage, quizzes[qi], isCorrect) && isCorrect) correct++;
          }
          if (qi + 1 < quizzes.length) {
            const nav2 = el('div', 'navbtns');
            const nextQ = el('button', 'btn btn-primary', '次の設問へ');
            nextQ.type = 'button';
            nextQ.addEventListener('click', () => {
              askFrom(qi + 1);
              keepQuizInView();
            });
            nav2.appendChild(nextQ);
            quizPanel.appendChild(nav2);
            nextQ.focus({ preventScroll: true });
          } else {
            askFrom(qi + 1);
          }
          keepQuizInView();
        },
        evidence
      );
    };
    askFrom(0);

    // Move focus to this stage's heading so keyboard/SR users land in the new
    // view rather than at <body> after the rebuild. preventScroll avoids
    // fighting the window.scrollTo(0, 0) the nav handlers perform.
    stageName.focus({ preventScroll: true });
  };

  if (total === 0) {
    renderRecap(mount, lesson, { correct: 0, total: 0, answers: [] });
    return;
  }

  // 自動生成した演習には導入がある。いきなり第1段階へ入ると、何のログを
  // 何のために読むのかが分からないまま設問に入ることになる。
  //
  // 旧形式（introduction が無い）は従来どおり第1段階から始める。導入が
  // 無いものに空の導入画面を出しても、何も伝わらない。
  if (lesson.introduction) {
    renderIntroduction(mount, lesson, () => {
      mount.textContent = '';
      mount.appendChild(player);
      renderStage(0);
      window.scrollTo(0, 0);
    });
    return;
  }

  renderStage(0);
}
