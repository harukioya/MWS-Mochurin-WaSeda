// recap.js — 最終調査レポート。
//
// 得点と ATT&CK の一覧だけでは、「何が観測され、どの順で記録され、何がまだ
// 分からないか」を説明できるようにならない。ここは、回答結果（利用者ごとに
// 変わる）と、教材に保存された静的なレポート（誰が解いても同じ）を、画面で
// 結合して見せる。教材へ得点を書き戻さないのは、同じ教材を複数人が解くため。
//
// ZIP 由来の文字列は textContent でのみ描く。原文の不可視文字は evidence.js
// の visible() を通す。

import {
  citedEvidence,
  evidenceCard,
  evidenceMap,
  jumpButtons,
  visible,
} from './evidence.js';
import { glossary, staticGlossary } from './intro.js';
import { profileLine, profileOfLesson } from './profile.js';

const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
};

const STATUS_LABEL = {
  observed: '観測された事実',
  correlated: '複数記録からの関連付け',
  hypothesis: '未確定（追加調査が必要）',
};

const CATEGORY_LABEL = {
  'log-reading': 'ログの意味を読む',
  evidence: '根拠を特定する',
  correlation: '二つの証拠を関連付ける',
  attck: '観測を手法に対応させる',
  limits: '断定できない理由を説明する',
  'static-string': '命令が参照する文字列を読む',
  'static-call': '直接呼び出しの行き先を読む',
  'static-external': '外部関数を見分ける',
};

// このレポート画面の id 空間。演習の段階とは別に持つ。レポートは mount を
// 丸ごと差し替えて描かれるので、段階側のカードはもう頁に無い。同じ id を
// 探していたために、レポートの「根拠ログを見る」は押しても何も起きなかった。
const SCOPE = 'report';

/** 見出し付きの区画。中身が空なら null を返し、空の箱を並べない。 */
function section(title, build) {
  const box = el('section', 'panel');
  box.append(el('div', 'panel__label', title));
  const filled = build(box);
  return filled === false ? null : box;
}

const SVG_NS = 'http://www.w3.org/2000/svg';

/**
 * 正答率のリング。中央に % を出し、開いたときに弧が伸びる。
 *
 * 伸びる動きは CSS の keyframes（`from` だけを書く）で付ける。終点は
 * `stroke-dashoffset` 属性に置いた値で、アニメーションが終わるとそこへ
 * 落ち着く。JS でタイマーを回さないので、動きを減らす設定の利用者には
 * CSS 側で止めるだけで済む。
 *
 * 数字は見出しの「正解 X / Y」と同じ値から出す。読み上げでは円は 1 枚の
 * 画像として「正答率 N%」とだけ伝え、中の図形は読ませない。
 */
function scoreRing(correct, total) {
  const pct = total > 0 ? Math.round((correct / total) * 100) : 0;

  const wrap = el('div', 'ring');
  wrap.setAttribute('role', 'img');
  wrap.setAttribute('aria-label', `正答率 ${pct}%`);

  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 120 120');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');

  const circle = (cls) => {
    const c = document.createElementNS(SVG_NS, 'circle');
    c.setAttribute('class', cls);
    c.setAttribute('cx', '60');
    c.setAttribute('cy', '60');
    c.setAttribute('r', '50');
    // 円周を 100 と見なす。% をそのまま長さとして使える。
    c.setAttribute('pathLength', '100');
    return c;
  };
  svg.append(circle('ring__track'));
  // 0% のときは弧を描かない。端が丸いので、長さ 0 でも点が 1 つ残る。
  if (pct > 0) {
    const bar = circle('ring__bar');
    bar.setAttribute('stroke-dasharray', '100');
    bar.setAttribute('stroke-dashoffset', String(100 - pct));
    svg.append(bar);
  }
  wrap.append(svg);
  wrap.append(el('span', 'ring__label', `${pct}%`));
  return wrap;
}

/**
 * @param {HTMLElement} mount
 * @param {object} lesson
 * @param {{correct:number,total:number,answers?:Array,goToStage?:Function}} stats
 */
export function renderRecap(mount, lesson, stats) {
  const recap = lesson.recap || {};
  const report = lesson.report || {};
  const evidence = evidenceMap(lesson);
  const correct = Number(stats && stats.correct) || 0;
  const total = Number(stats && stats.total) || 0;
  const answers = (stats && stats.answers) || [];
  const goToStage = stats && stats.goToStage;
  // 静的解析の教材には時系列が無い。記録の順序や ATT&CK の代わりに、静的に
  // 確かめられた事実と、実行しないと分からないことを並べる。
  const staticLesson = lesson.kind === 'static';
  const staticFacts = staticLesson && Array.isArray(report.facts) ? report.facts : [];

  const root = document.createElement('section');
  root.className = 'recap';

  // ---- 得点 ----
  root.appendChild(el('p', 'eyebrow', '調査レポート'));
  const scoreRow = el('div', 'recap__score');
  const heading = document.createElement('h1');
  heading.textContent = `正解 ${correct} / ${total}`;
  heading.tabIndex = -1;
  scoreRow.append(heading, scoreRing(correct, total));
  root.appendChild(scoreRow);

  // どのデータセット形式として読んだ教材か。データセット画面・導入画面と
  // 同じ 1 行を出す。レポートだけを見た人にも、分類の前提が分かるように。
  const profile = profileOfLesson(lesson);
  if (profile) {
    root.appendChild(el('p', 'muted', profileLine(profile)));
  }

  if (recap.summary) {
    root.appendChild(el('p', 'muted', visible(recap.summary)));
  }

  // ---- 段階別・カテゴリ別 ----
  if (answers.length) {
    const byStage = new Map();
    const byCategory = new Map();
    answers.forEach((a) => {
      for (const [map, key, label] of [
        [byStage, a.stageId || a.stageName, a.stageName || a.stageId],
        [byCategory, a.category, CATEGORY_LABEL[a.category] || a.category],
      ]) {
        const row = map.get(key) || { label, correct: 0, total: 0 };
        row.total += 1;
        if (a.correct) row.correct += 1;
        map.set(key, row);
      }
    });
    const scores = section('段階別・カテゴリ別の成績', (box) => {
      [['段階別', byStage], ['学習カテゴリ別', byCategory]].forEach(([name, map]) => {
        box.append(el('p', 'muted', name));
        const list = el('div', 'scorelist');
        [...map.values()].forEach((row) => {
          const line = el('div', 'scorelist__row');
          line.append(el('span', 'scorelist__name', visible(row.label)));
          line.append(el('span', 'scorelist__val mono', `${row.correct} / ${row.total}`));
          list.append(line);
        });
        box.append(list);
      });
    });
    root.appendChild(scores);
  }

  // ---- 観測された時系列 ----
  const timeline = Array.isArray(report.timeline) ? report.timeline : [];
  const techniques = Array.isArray(report.techniques) ? report.techniques : [];
  if (staticLesson) {
    root.appendChild(
      section('静的に確認できた事実', (box) => {
        box.append(
          el('p', 'muted',
            'Ghidra が GZF に保存した記録から、直接確かめられたことの一覧です。どれも「そういう命令・記録がある」という事実で、実行時に起きたことではありません。')
        );
        if (!staticFacts.length) {
          box.append(el('p', 'muted', '示せる事実がありませんでした。'));
          return;
        }
        const list = el('ol', 'timeline');
        staticFacts.forEach((row) => {
          const item = el('li', 'timeline__row');
          item.append(el('span', 'timeline__status', CATEGORY_LABEL[row.category] || ''));
          item.append(el('span', 'timeline__title', visible(row.title || '')));
          const jump = jumpButtons(row.evidenceIds, evidence, SCOPE, '根拠の記録を見る');
          if (jump) item.append(jump);
          list.append(item);
        });
        box.append(list);
      })
    );
  }

  if (!staticLesson) root.appendChild(
    section('記録された順序', (box) => {
      box.append(
        el('p', 'muted',
          'ログにこの順で記録された、という一覧です。記録の前後は、一方が他方を引き起こしたことを意味しません。')
      );
      if (!timeline.length) {
        box.append(el('p', 'muted', '時刻を読み取れた記録がありませんでした。'));
        return;
      }
      const list = el('ol', 'timeline');
      timeline.forEach((row) => {
        const item = el('li', 'timeline__row');
        const when = el('span', 'timeline__time mono',
          row.timeKnown ? visible(row.timestamp) : '時刻不明');
        item.append(when);
        // タイムゾーンが読めなかった行は、同じログの中でしか前後を比べ
        // られない。一本の軸に並んでいる見た目に引きずられないよう、行に
        // そう書く。教材側の相関も、この札が同じ行どうししか結ばない。
        if (row.timeKnown && row.timeComparable === false) {
          const mark = el('span', 'timeline__basis', '基準不明');
          mark.setAttribute(
            'title',
            'タイムゾーンが書かれていません。同じログの中でのみ前後を比べられます。'
          );
          when.append(mark);
        }
        item.append(el('span', 'timeline__title', visible(row.title || '')));
        // 状態は色だけでなく文言でも出す。
        item.append(
          el('span', 'timeline__status',
            STATUS_LABEL[row.status] || row.status || '')
        );
        item.append(
          el('span', 'timeline__src mono',
            `${visible(row.member || '')} : ${row.line} 行目`)
        );
        const jump = jumpButtons(row.evidenceIds, evidence, SCOPE);
        if (jump) item.append(jump);
        list.append(item);
      });
      box.append(list);
    })
  );

  // ---- このレポートが参照する記録 ----
  //
  // レポートの中から「根拠ログを見る」で飛べる先は、ここに置いたカードだけ
  // である。だから、レポートのどこかが指している証拠は、ひとつ残らずここに
  // 並べなければならない。以前は回答が指したものだけを並べ、しかも
  // anchor=false で id を付けていなかったので、時系列と ATT&CK のボタンは
  // 押しても何も起きなかった。
  //
  // 集める順は、時系列（記録された順）、ATT&CK、回答。先頭を時系列にして
  // おくと、一覧そのものが読み下せる並びになる。
  const keyIds = [];
  const addId = (i) => {
    if (evidence[i] && !keyIds.includes(i)) keyIds.push(i);
  };
  timeline.forEach((row) => (row.evidenceIds || []).forEach(addId));
  staticFacts.forEach((row) => (row.evidenceIds || []).forEach(addId));
  techniques.forEach((t) => {
    (t.evidenceIds || []).forEach(addId);
    (t.reasons || []).forEach((r) => (r.evidenceIds || []).forEach(addId));
  });
  answers.forEach((a) => (a.evidenceIds || []).forEach(addId));
  if (keyIds.length) {
    root.appendChild(
      section('判断の根拠になった記録', (box) => {
        box.append(
          el('p', 'muted',
            staticLesson
              ? 'このレポートの「根拠の記録を見る」は、すべてこの一覧の記録を指しています。'
              : 'このレポートの「根拠ログを見る」は、すべてこの一覧の記録を指しています。')
        );
        const list = el('div', 'evidence-list');
        keyIds.forEach((i) => list.append(evidenceCard(evidence[i], null, true, SCOPE)));
        box.append(list);
      })
    );
  }

  // ---- ATT&CK ----
  if (!staticLesson) root.appendChild(
    section('MITRE ATT&CK との対応', (box) => {
      if (!techniques.length) {
        box.append(
          el('p', 'muted',
            '根拠を説明できる対応が見つかりませんでした。推測で手法を当てはめていません。')
        );
        // 旧形式の recap.chain があれば、そちらは従来どおり出す。
        return;
      }
      techniques.forEach((t) => {
        const card = el('div', 'technique');
        const head = el('div', 'technique__head');
        head.append(el('span', 'attck-badge', `${visible(t.id)} · ${visible(t.name)}`));
        head.append(
          el('span', 'technique__status',
            `${STATUS_LABEL[t.status] || t.status || ''}／確信度 ${visible(t.confidence || '')}`)
        );
        card.append(head);

        // 同じ手法でも、理由が違えば根拠も違う。vssadmin と bcdedit は
        // どちらも T1490 だが、観測しているものは別である。理由ごとに
        // その理由を支える記録だけを並べ、まとめて 1 つの説明に押し込まない。
        const reasons = Array.isArray(t.reasons) && t.reasons.length
          ? t.reasons
          : [{ reason: t.reason || '', evidenceIds: t.evidenceIds || [] }];
        let linked = false;
        reasons.forEach((r) => {
          card.append(el('p', 'technique__reason', visible(r.reason || '')));
          const jump = jumpButtons(r.evidenceIds, evidence, SCOPE);
          if (jump) {
            card.append(jump);
            linked = true;
          }
        });
        if (!linked) card.append(el('p', 'muted', '根拠の記録を特定できませんでした。'));
        card.append(
          el('p', 'technique__rule mono', `対応規則 ${visible(t.ruleVersion || '')}`)
        );
        box.append(card);
      });
    })
  );

  // ---- 旧形式のキルチェーン ----
  const chain = Array.isArray(recap.chain) ? recap.chain : [];
  if (chain.length) {
    const killchain = el('div', 'killchain');
    chain.forEach((step) => {
      const kc = el('div', 'kc-step');
      kc.append(
        el('div', 'kc-step__name',
          step.stage ? `${visible(step.stage)}: ${visible(step.name || '')}`
                     : visible(step.name || ''))
      );
      if (step.desc) kc.append(el('p', 'kc-step__desc', visible(step.desc)));
      (Array.isArray(step.attck) ? step.attck : []).forEach((t) => {
        kc.append(
          el('span', 'attck-badge',
            t && t.name ? `${visible(t.id)} · ${visible(t.name)}` : visible((t && t.id) || ''))
        );
      });
      killchain.append(kc);
    });
    root.appendChild(killchain);
  }

  // ---- 間違えた問題と復習 ----
  const wrong = answers.filter((a) => !a.correct);
  root.appendChild(
    section('間違えた問題', (box) => {
      if (!answers.length) {
        box.append(el('p', 'muted', '回答の記録がありません。'));
        return;
      }
      if (!wrong.length) {
        box.append(el('p', 'muted', '間違えた問題はありません。'));
        return;
      }
      wrong.forEach((a) => {
        const row = el('div', 'review');
        row.append(
          el('div', 'review__q',
            visible((a.quiz && (a.quiz.q || a.quiz.prompt)) || a.questionId))
        );
        row.append(
          el('p', 'muted',
            `${visible(a.stageName || '')}／${CATEGORY_LABEL[a.category] || a.category}`)
        );
        // 根拠をその場で再表示する。戻らなくても確かめられるようにする。
        const cited = citedEvidence(a.evidenceIds, evidence);
        if (cited) row.append(cited);

        const nav = el('div', 'navbtns navbtns--wrap');
        if (goToStage && a.stageId) {
          const back = el('button', 'btn btn-ghost btn-sm', 'この段階へ戻って解き直す');
          back.type = 'button';
          back.addEventListener('click', () => goToStage(a.stageId));
          nav.append(back);
        }
        const jump = jumpButtons(
          a.evidenceIds, evidence, SCOPE,
          staticLesson ? '根拠の記録を見る' : '根拠ログを見る'
        );
        if (jump) nav.append(...jump.children);
        if (nav.children.length) row.append(nav);
        box.append(row);
      });
    })
  );

  // ---- 未確定事項 ----
  const unknowns = Array.isArray(report.unknowns) ? report.unknowns : [];
  if (unknowns.length) {
    root.appendChild(
      section('断定できなかったこと', (box) => {
        unknowns.forEach((u) => {
          box.append(el('div', 'unknown__topic', visible(u.topic || '')));
          box.append(el('p', 'unknown__detail', visible(u.detail || '')));
        });
      })
    );
  }

  // ---- 追加調査 ----
  const next = Array.isArray(report.nextInvestigations) ? report.nextInvestigations : [];
  if (next.length) {
    root.appendChild(
      section('次に調べるとよいこと', (box) => {
        const ul = el('ul', 'bullets');
        next.forEach((t) => ul.append(el('li', null, visible(t))));
        box.append(ul);
      })
    );
  }

  root.appendChild(staticLesson ? staticGlossary() : glossary());

  // 何も無い教材でも白画面にしない。
  if (!timeline.length && !techniques.length && !answers.length && !chain.length
      && !staticFacts.length) {
    root.appendChild(
      el('p', 'muted',
        'この演習からは、まとめとして示せる記録が得られませんでした。読み取れたログが少ないか、根拠が不足しています。')
    );
  }

  // ---- 導線 ----
  const nav = el('div', 'navbtns');
  const back = el('button', 'btn btn-ghost', '演習の一覧に戻る');
  back.type = 'button';
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
    // 演習を作り直すので、得点も回答履歴もここで捨てられる。
    const target = `#/lesson/${lesson.id}`;
    if (location.hash === target) {
      window.dispatchEvent(new HashChangeEvent('hashchange'));
    } else {
      location.hash = target;
    }
  });
  nav.appendChild(replay);
  root.appendChild(nav);

  mount.replaceChildren(root);
  heading.focus({ preventScroll: true });
}
