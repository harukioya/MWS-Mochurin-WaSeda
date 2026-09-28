// home.js — lesson picker (hero + grid of lesson cards).
// Renders from data/lessons/index.json via ./data.js. All colors/spacing come
// from styles/design.css classes only. Lesson text is set with textContent.

import { loadIndex, loadLesson } from './data.js';

/**
 * Render the home screen into the mount element (#app).
 * @param {HTMLElement} mount
 */
export async function renderHome(mount) {
  mount.textContent = '';

  // ---- Hero ---------------------------------------------------------------
  const hero = document.createElement('section');
  hero.className = 'hero';

  const eyebrow = document.createElement('div');
  eyebrow.className = 'eyebrow';
  eyebrow.textContent = 'Mochurin WaSeda · MWS Cup 2026';

  const h1 = document.createElement('h1');
  h1.textContent = 'マルウェアの挙動を段階ごとに読み解く';
  // Focus target for this view: anchors keyboard/SR focus after a route change
  // (e.g. "Back to lessons") instead of dropping the user at <body>.
  h1.tabIndex = -1;

  const intro = document.createElement('p');
  intro.textContent =
    '実際の攻撃を段階ごとに追い、挙動を読んで設問に答え、解説を確認します。最後に MITRE ATT&CK と対応付けて振り返ります。';

  // Entry point to the inspector. Kept next to the lessons because the two
  // halves answer the same question from different ends: the lessons explain
  // what malware does, the inspector explains what a file in front of you is.
  const cta = document.createElement('div');
  // Not .navbtns: that is space-between, which left-aligns a lone child inside
  // this centred hero.
  cta.className = 'hero-cta';
  const inspect = document.createElement('button');
  inspect.type = 'button';
  inspect.className = 'btn btn-ghost btn-lg';
  inspect.textContent = 'ZIPファイルの中身を調べる →';
  inspect.setAttribute('aria-label', 'ZIPファイルの中身を調べる画面を開く');
  inspect.addEventListener('click', () => {
    location.hash = '#/inspect';
  });
  cta.appendChild(inspect);

  // Ghidra で保存した .gzf から、静的解析の演習を作る入口。処理はこの PC の
  // Docker の中で行い、対象プログラムは実行しない（ghidra.js）。
  const ghidra = document.createElement('button');
  ghidra.type = 'button';
  ghidra.className = 'btn btn-ghost btn-lg';
  ghidra.textContent = 'Ghidraファイルから演習を作る →';
  ghidra.setAttribute('aria-label', 'Ghidraファイル（.gzf）から演習を作る画面を開く');
  ghidra.addEventListener('click', () => {
    location.hash = '#/ghidra';
  });
  cta.appendChild(ghidra);

  hero.append(eyebrow, h1, intro, cta);
  mount.appendChild(hero);
  h1.focus({ preventScroll: true });

  // ---- Grid ---------------------------------------------------------------
  const grid = document.createElement('div');
  grid.className = 'home-grid';
  mount.appendChild(grid);

  // 静的な演習と、ログから自動生成した演習の両方を集めてから判断する。
  // 以前はここで静的な一覧だけを見て、空なら早期に抜けていたため、自動生成
  // した演習があっても「まだありません」と表示されていた。
  const [staticLessons, generated] = await Promise.all([
    loadIndex().catch(() => null),
    fetch('/api/lessons')
      .then((r) => (r.ok ? r.json() : { lessons: [] }))
      .then((d) => d.lessons)
      // サーバーを動かしていない場合。静的な演習だけで成り立つので黙って続ける。
      .catch(() => []),
  ]);

  if (staticLessons === null && !generated.length) {
    grid.remove();
    renderMessage(mount, '演習の一覧を読み込めませんでした。ページを再読み込みしてください。');
    return;
  }

  const index = Array.isArray(staticLessons) ? staticLessons : [];

  if (!index.length && !generated.length) {
    grid.remove();
    renderMessage(
      mount,
      'まだ演習がありません。「ZIPファイルの中身を調べる」から、ログを含むZIPを読み込んで演習を作ってください。'
    );
    return;
  }

  generated.forEach((l) => {
    // 静的解析の教材（gen-gzf-）は、ログ教材と取り違えないよう言い分ける。
    const isStatic = /^gen-gzf-/.test(String(l.id));
    grid.appendChild(
      buildCard({
        id: l.id,
        title: l.title,
        tagline: isStatic
          ? 'Ghidra の保存済み解析情報から自動生成しました。使用前に内容を確認してください。'
          : 'ログから自動生成しました。使用前に内容を確認してください。',
        difficulty: isStatic ? '静的解析' : '自動生成',
        family: isStatic ? 'Ghidra' : l.source || 'DFIR',
      }).el
    );
  });

  index.forEach((item) => {
    const card = buildCard(item);
    grid.appendChild(card.el);

    // Enrich __meta with the stage count once the lesson is available.
    Promise.resolve()
      .then(() => loadLesson(item.id))
      .then((lesson) => {
        const n = lesson && Array.isArray(lesson.stages) ? lesson.stages.length : 0;
        if (n > 0) card.setStages(n);
      })
      .catch(() => {
        /* leave meta as family-only; a missing count is not worth an error */
      });
  });
}

/** Build one lesson card button. Returns { el, setStages }. */
function buildCard(item) {
  const el = document.createElement('button');
  el.className = 'lesson-card';
  el.type = 'button';

  const title = String(item.title || '無題の演習');
  el.setAttribute('aria-label', `演習を開始: ${title}`);

  const tag = document.createElement('span');
  tag.className = 'lesson-card__tag';
  tag.textContent = item.difficulty || '演習';

  const titleEl = document.createElement('div');
  titleEl.className = 'lesson-card__title';
  titleEl.textContent = title;

  const desc = document.createElement('p');
  desc.className = 'lesson-card__desc';
  desc.textContent = item.tagline || '';

  const meta = document.createElement('div');
  meta.className = 'lesson-card__meta';

  const familyEl = document.createElement('span');
  familyEl.textContent = item.family || 'マルウェア';

  const stagesEl = document.createElement('span');
  stagesEl.textContent = '';
  stagesEl.hidden = true;

  meta.append(familyEl, stagesEl);
  el.append(tag, titleEl, desc, meta);

  el.addEventListener('click', () => {
    location.hash = '#/lesson/' + item.id;
  });

  return {
    el,
    setStages(n) {
      stagesEl.textContent = `全 ${n} 段階`;
      stagesEl.hidden = false;
    },
  };
}

/** Render a friendly centered message into the mount. */
function renderMessage(mount, text) {
  const p = document.createElement('p');
  p.className = 'muted center';
  p.textContent = text;
  mount.appendChild(p);
}
