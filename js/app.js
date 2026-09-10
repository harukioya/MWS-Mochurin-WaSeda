// app.js — entry point + hash router.

import { renderHome } from "./home.js";
import { renderLesson } from "./player.js";
import { renderArchive, renderInspect } from "./inspect.js";
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
  return { view: "home" };
}

async function render() {
  const mount = getMount();
  if (!mount) return;

  // Clear the previous view.
  mount.replaceChildren();

  const route = parseRoute();
  try {
    if (route.view === "lesson") {
      await renderLesson(mount, route.id);
    } else if (route.view === "inspect") {
      await renderInspect(mount);
    } else if (route.view === "archive") {
      await renderArchive(mount, route.id);
    } else {
      await renderHome(mount);
    }
  } catch (err) {
    showError(mount, err);
  }
}

function showError(mount, err) {
  mount.replaceChildren();

  const panel = document.createElement("section");
  panel.className = "panel center";

  const label = document.createElement("div");
  label.className = "panel__label";
  label.textContent = "Something went wrong";

  const msg = document.createElement("p");
  msg.className = "muted";
  msg.textContent = err && err.message ? err.message : String(err);

  const nav = document.createElement("div");
  nav.className = "navbtns";
  const back = document.createElement("a");
  back.className = "btn btn-primary";
  back.href = "#/";
  back.textContent = "Back to lessons";
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
