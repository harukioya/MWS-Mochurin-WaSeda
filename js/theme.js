// theme.js — theme toggle: cycles system → light → dark, persists choice.

const STORAGE_KEY = "mws-theme";
const CYCLE = ["system", "light", "dark"];

const LABELS = {
  system: "◐ Theme", // ◐ Theme
  light: "☀ Light",  // ☀ Light
  dark: "☾ Dark",     // ☾ Dark
};

function readStored() {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === "light" || v === "dark") return v;
  } catch (e) {
    /* storage unavailable — fall through to system */
  }
  return "system";
}

function persist(mode) {
  try {
    if (mode === "system") localStorage.removeItem(STORAGE_KEY);
    else localStorage.setItem(STORAGE_KEY, mode);
  } catch (e) {
    /* storage unavailable — theme still applies for this session */
  }
}

function apply(mode, btn) {
  const root = document.documentElement;
  if (mode === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", mode);

  if (btn) {
    btn.textContent = LABELS[mode];
    btn.setAttribute(
      "aria-label",
      `Color theme: ${mode}. Click to change.`
    );
  }
}

/**
 * Wire #themeToggle to cycle system → light → dark and persist the choice.
 * Honors the no-flash value already applied in index.html.
 */
export function initTheme() {
  const btn = document.getElementById("themeToggle");
  // Current mode: whatever the no-flash script (and storage) resolved to.
  let mode = readStored();
  apply(mode, btn);

  if (!btn) return;

  btn.addEventListener("click", () => {
    const next = CYCLE[(CYCLE.indexOf(mode) + 1) % CYCLE.length];
    mode = next;
    persist(mode);
    apply(mode, btn);
  });
}
