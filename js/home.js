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
  h1.textContent = 'See what malware actually does';
  // Focus target for this view: anchors keyboard/SR focus after a route change
  // (e.g. "Back to lessons") instead of dropping the user at <body>.
  h1.tabIndex = -1;

  const intro = document.createElement('p');
  intro.textContent =
    'Walk through a real attack one stage at a time — read each move, guess before you advance, then see it explained on the MITRE ATT&CK map. No samples ever run; every trace is a safe, synthetic teaching example.';

  hero.append(eyebrow, h1, intro);
  mount.appendChild(hero);
  h1.focus({ preventScroll: true });

  // ---- Grid ---------------------------------------------------------------
  const grid = document.createElement('div');
  grid.className = 'home-grid';
  mount.appendChild(grid);

  let index;
  try {
    index = await loadIndex();
  } catch (err) {
    grid.remove();
    renderMessage(mount, 'We could not load the lessons just now. Please refresh and try again.');
    return;
  }

  if (!Array.isArray(index) || index.length === 0) {
    grid.remove();
    renderMessage(mount, 'No lessons are available yet — check back soon!');
    return;
  }

  // Build cards immediately (fast, no stage count yet), then fill stage counts
  // as each lesson resolves so the grid never blocks on a slow load.
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

  const title = String(item.title || 'Untitled lesson');
  el.setAttribute('aria-label', `Start lesson: ${title}`);

  const tag = document.createElement('span');
  tag.className = 'lesson-card__tag';
  tag.textContent = item.difficulty || 'Lesson';

  const titleEl = document.createElement('div');
  titleEl.className = 'lesson-card__title';
  titleEl.textContent = title;

  const desc = document.createElement('p');
  desc.className = 'lesson-card__desc';
  desc.textContent = item.tagline || '';

  const meta = document.createElement('div');
  meta.className = 'lesson-card__meta';

  const familyEl = document.createElement('span');
  familyEl.textContent = item.family || 'Malware';

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
      stagesEl.textContent = n === 1 ? '1 stage' : `${n} stages`;
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
