// theme.js — theme toggle: switches between light and dark, persists the choice.

const STORAGE_KEY = "mws-theme";

const LABELS = {
  light: "☀ 明るい",
  dark: "☾ 暗い",
};

function systemPrefersDark() {
  try {
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  } catch (e) {
    return false; // matchMedia unavailable — design.css defaults to light
  }
}

function readStored() {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === "light" || v === "dark") return v;
  } catch (e) {
    /* storage unavailable — fall back to the system preference */
  }
  return null;
}

function persist(mode) {
  try {
    localStorage.setItem(STORAGE_KEY, mode);
  } catch (e) {
    /* storage unavailable — theme still applies for this session */
  }
}

function apply(mode, btn) {
  document.documentElement.setAttribute("data-theme", mode);
  if (!btn) return;
  btn.textContent = LABELS[mode];
  btn.setAttribute(
    "aria-label",
    `配色: ${mode === "dark" ? "暗い" : "明るい"}。押すと${mode === "dark" ? "明るい" : "暗い"}配色に切り替わります。`
  );
}

/**
 * Wire #themeToggle to switch between light and dark, and persist the choice.
 * Honors the no-flash value already applied in index.html.
 */
export function initTheme() {
  const btn = document.getElementById("themeToggle");
  const stored = readStored();

  // Until the visitor picks a side, leave data-theme unset so design.css's
  // prefers-color-scheme rules stay in charge (and the OS can change under us).
  // We still track what is actually on screen, so the first click flips away
  // from what the visitor is looking at rather than appearing to do nothing.
  let mode = stored || (systemPrefersDark() ? "dark" : "light");

  if (stored) apply(mode, btn);
  else if (btn) {
    btn.textContent = LABELS[mode];
    btn.setAttribute(
      "aria-label",
      `配色: ${mode === "dark" ? "暗い" : "明るい"}。押すと${mode === "dark" ? "明るい" : "暗い"}配色に切り替わります。`
    );
  }

  if (!btn) return;

  // Until the visitor picks a side we are following the OS, so we must keep
  // following it. Without this the label goes stale when the system flips and
  // the first click appears to do nothing, because `mode` still holds the
  // value read at boot.
  if (!stored) {
    try {
      const mq = window.matchMedia("(prefers-color-scheme: dark)");
      mq.addEventListener("change", (e) => {
        if (readStored()) return; // an explicit choice has since been made
        mode = e.matches ? "dark" : "light";
        btn.textContent = LABELS[mode];
        btn.setAttribute(
          "aria-label",
          `配色: ${mode === "dark" ? "暗い" : "明るい"}。押すと${mode === "dark" ? "明るい" : "暗い"}配色に切り替わります。`
        );
      });
    } catch (e) {
      /* matchMedia unavailable - the label just stays as first resolved */
    }
  }

  btn.addEventListener("click", () => {
    mode = mode === "dark" ? "light" : "dark";
    persist(mode);
    apply(mode, btn);
  });
}
