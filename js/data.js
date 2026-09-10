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
    throw new Error(`Could not load the lesson index (network error): ${err.message}`);
  }
  if (!res.ok) {
    throw new Error(`Could not load the lesson index (HTTP ${res.status}).`);
  }
  let data;
  try {
    data = await res.json();
  } catch (err) {
    throw new Error(`The lesson index is not valid JSON: ${err.message}`);
  }
  if (!Array.isArray(data)) {
    throw new Error("The lesson index must be an array of lessons.");
  }
  return data;
}

/**
 * Load a single lesson by id, resolving its file through the index.
 * @param {string} id
 * @returns {Promise<object>} the lesson object
 */
export async function loadLesson(id) {
  if (!id) throw new Error("No lesson id was given.");

  // Lessons generated from real dataset logs live in the backend's manifest,
  // not on disk, so they are fetched rather than read from data/lessons/.
  if (/^gen-[A-Za-z0-9_-]{1,60}$/.test(id)) {
    const res = await fetch(`/api/lessons/${encodeURIComponent(id)}`, {
      cache: "no-cache",
    });
    if (!res.ok) throw new Error(`Generated lesson "${id}" is not available.`);
    return res.json();
  }

  const index = await loadIndex();
  const entry = index.find((l) => l && l.id === id);
  if (!entry) {
    throw new Error(`No lesson found with id "${id}".`);
  }
  if (!entry.file) {
    throw new Error(`Lesson "${id}" has no file listed in the index.`);
  }

  // Resolve the lesson file relative to the lessons directory.
  const url = `data/lessons/${entry.file}`;

  let res;
  try {
    res = await fetch(url, { cache: "no-cache" });
  } catch (err) {
    throw new Error(`Could not load lesson "${id}" (network error): ${err.message}`);
  }
  if (!res.ok) {
    throw new Error(`Could not load lesson "${id}" (HTTP ${res.status}).`);
  }
  let lesson;
  try {
    lesson = await res.json();
  } catch (err) {
    throw new Error(`Lesson "${id}" is not valid JSON: ${err.message}`);
  }
  return lesson;
}
