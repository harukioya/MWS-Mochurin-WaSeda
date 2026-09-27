// app.js — entry point + hash router.

import { renderHome } from "./home.js";
import { renderLesson } from "./player.js";
import { renderArchive, renderInspect } from "./inspect.js";
import { renderGhidra } from "./ghidra.js";
import { initTheme } from "./theme.js";

const MOUNT_ID = "app";

function getMount() {
  return document.getElementById(MOUNT_ID);
}

/** Parse the current location.hash into a route. */
function parseRoute() {
  const hash = location.hash || "";
  // Strip leading '#', tolerate optional leading '/'.
  const path = hash.replace(/^#/, "");
  const parts = path.split("/").filter(Boolean); // e.g. ['lesson','lesson-01']

  if (parts.length === 0) {
    return { view: "home" };
  }
  if (parts[0] === "lesson" && parts[1]) {
    return { view: "lesson", id: decodeURIComponent(parts[1]) };
  }
  if (parts[0] === "inspect") {
    // Archive ids are integers from our own manifest; anything else is not a
    // route we serve, so fall back rather than passing it to the backend.
    if (parts[1] && /^\d{1,9}$/.test(parts[1])) {
      return { view: "archive", id: parts[1] };
    }
    return { view: "inspect" };
  }
  if (parts[0] === "ghidra") {
    return { view: "ghidra" };
  }
  return { view: "home" };
}

async function render() {
  const app = getMount();
  if (!app) return;

  // Every render draws into its own container, and swapping it in detaches the
  // previous one.
  //
  // The views fetch before they draw, so a route change can land while a
  // request is still in flight. Sharing one mount meant that request's
  // continuation appended its half of the old screen onto the new one --
  // leaving, say, the lesson list with a stray "read a ZIP" panel stapled to
  // it. Handing each render a private container makes a late continuation
  // write into a node that is no longer in the document, where it is harmless
  // and gets collected. Views also check `isConnected` to stop early rather
  // than keep fetching for a screen nobody is looking at.
  const view = document.createElement("div");
  app.replaceChildren(view);

  const route = parseRoute();
  try {
    if (route.view === "lesson") {
      await renderLesson(view, route.id);
    } else if (route.view === "inspect") {
      await renderInspect(view);
    } else if (route.view === "archive") {
      await renderArchive(view, route.id);
    } else if (route.view === "ghidra") {
      await renderGhidra(view);
    } else {
      await renderHome(view);
    }
  } catch (err) {
    // A failure belonging to a screen the person already left must not replace
    // the one they are on now.
    if (view.isConnected) showError(view, err);
    else console.error(err);
  }
}

function showError(mount, err) {
  mount.replaceChildren();

  const panel = document.createElement("section");
  panel.className = "panel center";

  const label = document.createElement("div");
  label.className = "panel__label";
  label.textContent = "問題が発生しました";

  const msg = document.createElement("p");
  msg.className = "muted";
  msg.textContent = err && err.message ? err.message : String(err);

  const nav = document.createElement("div");
  nav.className = "navbtns";
  const back = document.createElement("a");
  back.className = "btn btn-primary";
  back.href = "#/";
  back.textContent = "演習の一覧に戻る";
  nav.appendChild(back);

  panel.append(label, msg, nav);
  mount.appendChild(panel);

  console.error(err);
}

function boot() {
  initTheme();
  render();
  window.addEventListener("hashchange", render);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", boot, { once: true });
} else {
  boot();
}
