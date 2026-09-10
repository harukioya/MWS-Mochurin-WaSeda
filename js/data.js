// data.js — JSON loaders for lessons. No execution, synthetic data only.

const INDEX_URL = "data/lessons/index.json";

/**
 * Fetch and parse the lesson index.
 * @returns {Promise<Array<{id:string,title:string,tagline:string,difficulty:string,family:string,file:string}>>}
 */
export async function loadIndex() {
  let res;
  try {
    res = await fetch(INDEX_URL, { cache: "no-cache" });
  } catch (err) {
    throw new Error(`演習の一覧を読み込めませんでした（通信エラー）: ${err.message}`);
  }
  if (!res.ok) {
    throw new Error(`演習の一覧を読み込めませんでした (HTTP ${res.status})。`);
  }
  let data;
  try {
    data = await res.json();
  } catch (err) {
    throw new Error(`演習の一覧が正しい JSON ではありません: ${err.message}`);
  }
  if (!Array.isArray(data)) {
    throw new Error("演習の一覧は配列である必要があります。");
  }
  return data;
}

/**
 * Load a single lesson by id, resolving its file through the index.
 * @param {string} id
 * @returns {Promise<object>} the lesson object
 */
export async function loadLesson(id) {
  if (!id) throw new Error("演習の id が指定されていません。");

  // Lessons generated from real dataset logs live in the backend's manifest,
  // not on disk, so they are fetched rather than read from data/lessons/.
  if (/^gen-[A-Za-z0-9_-]{1,60}$/.test(id)) {
    const res = await fetch(`/api/lessons/${encodeURIComponent(id)}`, {
      cache: "no-cache",
    });
    if (!res.ok) throw new Error(`自動生成された演習 "${id}" は利用できません。`);
    return res.json();
  }

  const index = await loadIndex();
  const entry = index.find((l) => l && l.id === id);
  if (!entry) {
    throw new Error(`id "${id}" の演習は見つかりません。`);
  }
  if (!entry.file) {
    throw new Error(`演習 "${id}" のファイルが一覧に記載されていません。`);
  }

  // Resolve the lesson file relative to the lessons directory.
  const url = `data/lessons/${entry.file}`;

  let res;
  try {
    res = await fetch(url, { cache: "no-cache" });
  } catch (err) {
    throw new Error(`演習 "${id}" を読み込めませんでした（通信エラー）: ${err.message}`);
  }
  if (!res.ok) {
    throw new Error(`演習 "${id}" を読み込めませんでした (HTTP ${res.status})。`);
  }
  let lesson;
  try {
    lesson = await res.json();
  } catch (err) {
    throw new Error(`演習 "${id}" が正しい JSON ではありません: ${err.message}`);
  }
  return lesson;
}
