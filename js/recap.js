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

  // ---- Score heading ----
  const eyebrow = document.createElement('p');
  eyebrow.className = 'eyebrow';
  eyebrow.textContent = 'Kill-chain recap';
  root.appendChild(eyebrow);

  const heading = document.createElement('h1');
  heading.textContent = `You scored ${correct} / ${total}`;
  // Focus target for this view (see below): anchors focus after the mount swap.
  heading.tabIndex = -1;
  root.appendChild(heading);

  // ---- Summary ----
  if (recap.summary) {
    const summary = document.createElement('p');
    summary.className = 'muted';
    summary.textContent = recap.summary;
    root.appendChild(summary);
  }

  // ---- Kill chain ----
  const chain = Array.isArray(recap.chain) ? recap.chain : [];
  const killchain = document.createElement('div');
  killchain.className = 'killchain';

  chain.forEach((step) => {
    const kc = document.createElement('div');
    kc.className = 'kc-step';

    const name = document.createElement('div');
    name.className = 'kc-step__name';
    name.textContent = step.stage ? `${step.stage}: ${step.name || ''}` : (step.name || '');
    kc.appendChild(name);

    if (step.desc) {
      const desc = document.createElement('p');
      desc.className = 'kc-step__desc';
      desc.textContent = step.desc;
      kc.appendChild(desc);
    }

    const techniques = Array.isArray(step.attck) ? step.attck : [];
    techniques.forEach((t) => {
      const badge = document.createElement('span');
      badge.className = 'attck-badge';
      badge.textContent = `${t.id} · ${t.name}`;
      kc.appendChild(badge);
    });

    killchain.appendChild(kc);
  });

  root.appendChild(killchain);

  // ---- Encouraging closing microcopy ----
  const closing = document.createElement('p');
  closing.className = 'muted center';
  closing.textContent = correct === total && total > 0
    ? 'Flawless read. You traced every move to its ATT&CK technique — that is exactly how analysts talk.'
    : 'Nicely done. Every stage you walked through is one more pattern you will recognise in the wild.';
  root.appendChild(closing);

  // ---- Actions ----
  const nav = document.createElement('div');
  nav.className = 'navbtns';

  const back = document.createElement('button');
  back.type = 'button';
  back.className = 'btn btn-ghost';
  back.textContent = 'Back to lessons';
  back.setAttribute('aria-label', 'Back to the lesson list');
  back.addEventListener('click', () => {
    location.hash = '#/';
  });
  nav.appendChild(back);

  const replay = document.createElement('button');
  replay.type = 'button';
  replay.className = 'btn btn-primary';
  replay.textContent = 'Replay';
  replay.setAttribute('aria-label', 'Replay this lesson from the start');
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
