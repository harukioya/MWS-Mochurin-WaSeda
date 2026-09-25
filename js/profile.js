// profile.js — データセット形式（プロファイル）の見せ方。
//
// データセット画面・導入画面・最終レポートの三か所で、同じ言い方をする
// ための部品。画面ごとに組み立てると、同じ教材なのに画面によって呼び名や
// 「誰が決めたか」の書き方がずれる。
//
// 年度のような特別な項目は扱わない。版・時期・回の区別は、プロファイルの
// 任意の文字列 `edition` にある。無ければ括弧ごと出さない。
//
// プロファイルの名前は外部の JSON から来るので、描画は textContent だけで
// 行い、不可視の制御文字は visible() で見える形にする。

import { visible } from './evidence.js';

/** プロファイルを特定できなかったときの呼び名。サーバー側と同じ文言。 */
export const GENERIC_LABEL = 'プロファイル未特定（汎用解析）';

/** 表示名。edition があれば括弧で添え、無ければ括弧を付けない。 */
export function profileName(info) {
  const label = visible((info && info.label) || GENERIC_LABEL);
  const raw = info && typeof info.edition === 'string' ? info.edition.trim() : '';
  return raw ? `${label}（${visible(raw)}）` : label;
}

/** 自動判定か、利用者の指定か。 */
export function decidedBy(info) {
  return info && info.forced ? '利用者が指定した形式' : '自動で判定した形式';
}

/** 三つの画面で共通の 1 行。 */
export function profileLine(info) {
  return `データセット形式: ${profileName(info)}／${decidedBy(info)}`;
}

/**
 * 教材に残っている形式の情報。無ければ null。
 *
 * 新しい教材は `lesson.dataset` に全体を、`lesson.introduction.dataset` に
 * 写しを持つ。どちらか片方しか無い教材もあるので、両方を見る。古い教材に
 * 残っている互換用の項目（年度など）は読まない。
 */
export function profileOfLesson(lesson) {
  const ds =
    (lesson && lesson.dataset) ||
    (lesson && lesson.introduction && lesson.introduction.dataset);
  if (!ds || (!ds.label && !ds.profileId)) return null;
  return {
    label: ds.label || '',
    edition: typeof ds.edition === 'string' ? ds.edition : '',
    forced: Boolean(ds.forced),
  };
}
