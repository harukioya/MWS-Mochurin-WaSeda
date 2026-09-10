// recap.js — the MITRE ATT&CK kill-chain recap shown at the end of a lesson.
// Renders score + summary + kill-chain + actions. textContent only (never innerHTML).

/**
 * @param {HTMLElement} mount   the #app container
 * @param {object} lesson       the full lesson object (uses lesson.recap and lesson.id)
 * @param {{correct:number,total:number}} stats
 */
export function renderRecap(mount, lesson, stats) {
  const recap = lesson.recap || {};
  const correct = Number(stats && stats.correct) || 0;
  const total = Number(stats && stats.total) || 0;

  const root = document.createElement('section');
  root.className = 'recap';


  // ---- Actions ----
  const nav = document.createElement('div');
  nav.className = 'navbtns';

  const back = document.createElement('button');
  back.type = 'button';
  back.className = 'btn btn-ghost';
  back.textContent = '演習の一覧に戻る';
  back.setAttribute('aria-label', '演習の一覧に戻る');
  back.addEventListener('click', () => {
    location.hash = '#/';
  });
  nav.appendChild(back);

  const replay = document.createElement('button');
  replay.type = 'button';
  replay.className = 'btn btn-primary';
  replay.textContent = 'もう一度';
  replay.setAttribute('aria-label', 'この演習を最初からやり直す');
  replay.addEventListener('click', () => {
    const target = `#/lesson/${lesson.id}`;
    if (location.hash === target) {
      // Already on this lesson's hash — re-run the router to restart from stage 1.
      window.dispatchEvent(new HashChangeEvent('hashchange'));
    } else {
      location.hash = target;
    }
  });
  nav.appendChild(replay);

  root.appendChild(nav);

  mount.replaceChildren(root);

  // Move focus to the recap heading so keyboard/SR users land in the new view
  // instead of at <body> after the mount is replaced. preventScroll leaves the
  // caller's window.scrollTo(0, 0) in charge of scroll position.
  heading.focus({ preventScroll: true });
}
