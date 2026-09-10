// inspect.js — the archive inspector: inventory, per-member triage, hexdump.
//
// Answers the learner's real question for every file: *can the operating
// system run this, and how do we know?* Everything shown here comes from the
// local backend, which reads archive metadata and a bounded prefix of each
// member. Nothing is extracted, downloaded, or executed.
//
// All text is set with textContent. Member names come from inside archives and
// are attacker-controlled strings; they are never interpolated into markup.

// Bidirectional controls reverse how a name renders: `payroll<RLO>gnp.exe`
// displays as `payrollexe.png`. CSS isolation stops the reorder leaking into
// the surrounding row, but it does NOT neutralise it inside the name, so the
// controls are escaped to visible sentinels before display.
const BIDI = /[\u202A-\u202E\u2066-\u2069\u200E\u200F]/g;
const showBidi = (s) =>
  String(s).replace(BIDI, (c) => `<U+${c.codePointAt(0).toString(16).toUpperCase()}>`);
const hasBidi = (s) => BIDI.test(String(s));

const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
};

/** The backend injects this into index.html at serve time. */
function token() {
  const meta = document.querySelector('meta[name="mws-token"]');
  return meta ? meta.content : '';
}

async function api(path, options) {
  const res = await fetch(path, {
    ...options,
    headers: { 'Content-Type': 'application/json', 'X-MWS-Token': token() },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `Request failed (${res.status})`);
  }
  return res.json();
}

/** Map a verdict to a severity class. Anything runnable reads as danger. */
const SEVERITY = {
  'inert-data': 'is-ok',
  container: 'is-neutral',
  script: 'is-bad',
  'document-with-active-content': 'is-bad',
  'shortcut-or-launcher': 'is-bad',
  'native-executable': 'is-bad',
  'bytecode-archive': 'is-bad',
  'sample-bearing': 'is-bad',
  unknown: 'is-bad',
  'opaque-encrypted': 'is-warn',
  'unsupported-container': 'is-warn',
  'forensic-image': 'is-warn',
};

// Plain-language answers. These state what was actually CHECKED, not a promise
// of safety: "safe to open" would be a claim the classifier has not earned,
// and BUILD-CONTRACT rule 8 makes an unearned reassurance a defect.
const PLAIN = {
  'inert-data': 'No executable structure found in the bytes we read',
  container: 'An archive — look inside before trusting it',
  script: 'RUNS without an execute bit, via an interpreter',
  'document-with-active-content': 'Can carry content that runs when opened',
  'shortcut-or-launcher': 'Launches something else when opened',
  'native-executable': 'A program the operating system can run',
  'bytecode-archive': 'Runs under a runtime such as java',
  'sample-bearing': 'Carries the original sample bytes, recoverable with tooling',
  unknown: 'Not recognised — treated as strictly as a program',
  'opaque-encrypted': 'Encrypted — contents could not be checked at all',
  'unsupported-container': 'Cannot be opened yet — blocked, not cleared',
  'forensic-image': 'A disk or memory image — may contain programs',
};

function verdictBadge(verdict) {
  const badge = el('span', `verdict ${SEVERITY[verdict] || 'is-warn'}`, verdict);
  badge.title = PLAIN[verdict] || verdict;
  return badge;
}

// ---------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------

export async function renderInspect(mount) {
  mount.textContent = '';

  const hero = el('section', 'hero');
  hero.append(el('div', 'eyebrow', 'Inspector'));
  const h1 = el('h1', null, 'What is actually in this archive?');
  h1.tabIndex = -1;
  hero.append(h1);
  hero.append(
    el(
      'p',
      null,
      'Every file below was classified by its bytes, not its name. Nothing was extracted, downloaded, or run — the inspector reads archive metadata and the first few kilobytes of each entry.'
    )
  );
  mount.append(hero);
  h1.focus({ preventScroll: true });

  const status = el('div', 'panel');
  mount.append(status);
  const list = el('div', 'home-grid');
  mount.append(list);

  try {
    const [{ role, claims }, { archives }] = await Promise.all([
      api('/api/status'),
      api('/api/archives'),
    ]);
    renderClaims(status, role, claims);
    if (!archives.length) {
      renderScanPrompt(list, mount);
      return;
    }
    archives.forEach((a) => list.append(archiveCard(a)));
  } catch (err) {
    status.textContent = '';
    status.append(el('div', 'panel__label', 'Backend unavailable'));
    status.append(
      el(
        'p',
        'muted',
        'The inspector needs the local backend. Start it with: python3 backend/api.py'
      )
    );
  }
}

/** State exactly what the integrity check does and does not cover. */
function renderClaims(mount, role, claims) {
  mount.textContent = '';
  mount.append(el('div', 'panel__label', `Integrity monitor · role: ${role}`));

  const yes = el('div', 'claims');
  yes.append(el('div', 'claims__head is-ok', 'Detects'));
  claims.detects.forEach((c) => yes.append(el('div', 'claims__item', c)));
  mount.append(yes);

  const no = el('div', 'claims');
  no.append(el('div', 'claims__head is-bad', 'Does NOT detect'));
  claims.doesNotDetect.forEach((c) => no.append(el('div', 'claims__item', c)));
  mount.append(no);

  mount.append(
    el(
      'p',
      'muted',
      'This is a file-integrity check, not an execution monitor. No userspace tool on macOS can reliably tell you that a program was run.'
    )
  );

  const nav = el('div', 'navbtns');
  const run = el('button', 'btn btn-ghost btn-sm', 'Re-check integrity now');
  run.type = 'button';
  const out = el('div', 'claims');
  run.addEventListener('click', async () => {
    run.disabled = true;
    run.textContent = 'Hashing…';
    try {
      const { results } = await api('/api/verify', { method: 'POST', body: '{}' });
      out.textContent = '';
      const when = new Date().toLocaleTimeString();
      out.append(el('div', 'claims__head is-ok', `Checked at ${when}`));
      results.forEach((r) => {
        out.append(
          el('div', r.ok ? 'claims__item' : 'member__warn',
             `${r.ok ? '✓' : '⚠'} ${r.path.split('/').pop()} — ${r.detail}`)
        );
      });
      if (!results.length) out.append(el('div', 'claims__item', 'Nothing is being tracked yet.'));
    } catch (err) {
      out.textContent = '';
      out.append(el('div', 'member__warn', err.message));
    } finally {
      run.disabled = false;
      run.textContent = 'Re-check integrity now';
    }
  });
  nav.append(run);
  mount.append(nav);
  mount.append(out);
}

function renderScanPrompt(list, mount) {
  list.remove();
  const panel = el('div', 'panel');
  panel.append(el('div', 'panel__label', 'No archives indexed yet'));
  panel.append(
    el('p', 'muted', 'Point the inspector at a folder of .zip files to index them. Files are only read, never extracted.')
  );
  const input = el('input', 'text-input');
  input.type = 'text';
  input.placeholder = '~/path/to/a/folder/of/zip/files';
  input.setAttribute('aria-label', 'Folder to index');
  panel.append(input);

  const nav = el('div', 'navbtns');
  const go = el('button', 'btn btn-primary', 'Index this folder');
  go.type = 'button';
  go.addEventListener('click', async () => {
    go.disabled = true;
    go.textContent = 'Reading…';
    try {
      await api('/api/scan', { method: 'POST', body: JSON.stringify({ dir: input.value }) });
      renderInspect(mount);
    } catch (err) {
      go.disabled = false;
      go.textContent = 'Index this folder';
      const msg = el('p', 'feedback is-bad', err.message);
      panel.append(msg);
    }
  });
  nav.append(go);
  panel.append(nav);
  mount.append(panel);
}

function archiveCard(a) {
  const card = el('button', 'lesson-card');
  card.type = 'button';
  const name = a.path.split('/').pop();
  card.setAttribute('aria-label', `Inspect ${name}`);
  card.append(el('span', 'lesson-card__tag', `${a.members} entries`));
  card.append(el('div', 'lesson-card__title', name));
  card.append(el('p', 'lesson-card__desc mono', `sha256 ${a.sha256.slice(0, 24)}…`));
  const meta = el('div', 'lesson-card__meta');
  meta.append(el('span', null, `${(a.size / 1e6).toFixed(1)} MB`));
  meta.append(el('span', null, a.last_status === 'ok' ? 'verified' : a.last_status));
  card.append(meta);
  card.addEventListener('click', () => {
    location.hash = `#/inspect/${a.id}`;
  });
  return card;
}

// ---------------------------------------------------------------------------
// Member list + preview
// ---------------------------------------------------------------------------

export async function renderArchive(mount, archiveId) {
  mount.textContent = '';

  const page = el('div', 'player');
  mount.append(page);

  const head = el('div', 'stage-head');
  const title = el('h2', 'stage-name', 'Archive contents');
  title.tabIndex = -1;
  head.append(title);
  page.append(head);

  const back = el('button', 'btn btn-ghost', 'Back to inspector');
  back.type = 'button';
  back.addEventListener('click', () => {
    location.hash = '#/inspect';
  });

  let members;
  try {
    const [membersRes, { archives }] = await Promise.all([
      api(`/api/archives/${encodeURIComponent(archiveId)}/members`),
      api('/api/archives'),
    ]);
    members = membersRes.members;
    const match = archives.find((a) => String(a.id) === String(archiveId));
    if (!match) {
      const panel = el('div', 'panel');
      panel.append(el('div', 'panel__label', 'No such archive'));
      panel.append(el('p', 'muted', `There is no indexed archive with id ${archiveId}.`));
      page.append(panel);
      const nav = el('div', 'navbtns');
      nav.append(back);
      page.append(nav);
      return;
    }
    title.textContent = match.path.split('/').pop();
  } catch (err) {
    const panel = el('div', 'panel');
    panel.append(el('div', 'panel__label', 'Could not load'));
    panel.append(el('p', 'muted', err.message));
    page.append(panel);
    const nav = el('div', 'navbtns');
    nav.append(back);
    page.append(nav);
    return;
  }

  const unrecognised = members.filter((m) => m.verdict === 'unknown').length;
  const runnable = members.filter(
    (m) => SEVERITY[m.verdict] === 'is-bad' && m.verdict !== 'unknown'
  ).length;
  // Blocked is the wider set: anything not plainly inert, plus anything inert
  // whose NAME is hostile. Reporting only "runnable" would understate it.
  const blocked = members.filter(
    (m) => m.verdict !== 'inert-data' || m.warnings
  ).length;

  const summary = el('div', 'panel');
  summary.append(el('div', 'panel__label', 'Summary'));
  const line = `${members.length} ${members.length === 1 ? 'entry' : 'entries'}. ` +
    `${runnable} could run on some system, ` +
    `${unrecognised} were not recognised and are treated just as strictly. ` +
    `${blocked} ${blocked === 1 ? 'is' : 'are'} blocked from being written to disk.`;
  summary.append(el('p', null, line));
  summary.append(
    el(
      'p',
      'muted',
      'Blocked means the inspector will not write it out — because it can run, because it could not be read, or because its name is hostile.'
    )
  );
  page.append(summary);
  title.focus({ preventScroll: true });

  const table = el('div', 'member-list');
  members.forEach((m) => table.append(memberRow(m, archiveId)));
  page.append(table);

  const nav = el('div', 'navbtns');
  nav.append(back);

  const gen = el('button', 'btn btn-primary', 'Build a lesson from these logs');
  gen.type = 'button';
  const genOut = el('div', 'panel');
  genOut.hidden = true;
  gen.addEventListener('click', async () => {
    gen.disabled = true;
    gen.textContent = 'Reading logs…';
    genOut.textContent = '';
    genOut.hidden = false;
    try {
      const r = await api('/api/generate', {
        method: 'POST',
        body: JSON.stringify({ archive: Number(archiveId) }),
      });
      genOut.append(el('div', 'panel__label', 'Lesson built'));
      genOut.append(
        el('p', null,
           `${r.stages} stages, ${r.events} observed events, ${r.tagged} with an ATT&CK technique attached.`)
      );
      genOut.append(
        el('p', 'muted',
           'Techniques are attached only where a log field says so outright. Everything else is left untagged on purpose — deciding what the rest means is the exercise.')
      );
      const open = el('button', 'btn btn-primary', 'Open the lesson');
      open.type = 'button';
      open.addEventListener('click', () => {
        location.hash = `#/lesson/${r.id}`;
      });
      const row = el('div', 'navbtns');
      row.append(open);
      genOut.append(row);
    } catch (err) {
      genOut.append(el('div', 'panel__label', 'Could not build a lesson'));
      genOut.append(el('p', 'muted', err.message));
    } finally {
      gen.disabled = false;
      gen.textContent = 'Build a lesson from these logs';
    }
  });
  nav.append(gen);
  page.append(nav);
  page.append(genOut);
}

function memberRow(m, archiveId) {
  const row = el('div', 'member');
  const bar = el('div', 'member__bar');
  bar.append(verdictBadge(m.verdict));

  const nameEl = el('div', 'member__name mono');
  nameEl.textContent = showBidi(m.name);
  bar.append(nameEl);
  bar.append(el('span', 'member__size mono', `${m.size} B`));
  row.append(bar);

  row.append(el('div', 'member__kind', m.kind));
  row.append(el('div', 'member__plain', PLAIN[m.verdict] || ''));

  if (hasBidi(m.name)) {
    row.append(
      el(
        'div',
        'member__warn',
        '⚠ This name contains bidirectional-override characters, shown above as <U+…>. They make a name display in a different order than its real bytes.'
      )
    );
  }

  if (m.warnings) {
    m.warnings.split('\n').filter(Boolean).forEach((w) => {
      row.append(el('div', 'member__warn', `⚠ ${showBidi(w)}`));
    });
  }

  const toggle = el('button', 'btn btn-ghost btn-sm', 'Show first bytes');
  toggle.type = 'button';
  const holder = el('div', 'hexdump');
  holder.hidden = true;
  // A scrollable region is unreachable by keyboard without a tabindex.
  holder.tabIndex = 0;
  holder.setAttribute('role', 'region');
  holder.setAttribute('aria-label', 'First bytes of this entry');
  toggle.setAttribute('aria-expanded', 'false');
  toggle.addEventListener('click', async () => {
    if (!holder.hidden) {
      holder.hidden = true;
      toggle.setAttribute('aria-expanded', 'false');
      toggle.textContent = 'Show first bytes';
      return;
    }
    toggle.disabled = true;
    try {
      const data = await api(
        `/api/archives/${encodeURIComponent(archiveId)}/members/${encodeURIComponent(m.idx)}/preview`
      );
      holder.textContent = '';
      if (data.note) holder.append(el('div', 'hexdump__note', data.note));
      data.rows.forEach((r) => {
        const line = el('div', 'hexdump__row');
        line.append(el('span', 'hexdump__off', r.offset));
        line.append(el('span', 'hexdump__hex', r.hex));
        line.append(el('span', 'hexdump__txt', r.text));
        holder.append(line);
      });
      holder.hidden = false;
      toggle.setAttribute('aria-expanded', 'true');
      toggle.textContent = 'Hide bytes';
    } catch (err) {
      holder.textContent = err.message;
      holder.hidden = false;
    } finally {
      toggle.disabled = false;
    }
  });
  row.append(toggle);
  row.append(holder);
  return row;
}
