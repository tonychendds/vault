import { SYNC_URL } from "./config.js";
import { PBKDF2_ITERATIONS, deriveKeys, encryptJson, decryptJson } from "./lib/crypto.js";
import { EMPTY_ERROR, mergeEntries, uploadPlan } from "./lib/merge.js";
import { generatePassword } from "./lib/password.js";
import { buildBackup, parseBackup } from "./lib/backup.js";
import { isValidEmail, normalizeEmail } from "./lib/email.js";

const IDLE_MS = 5 * 60 * 1000;
const HIDE_MS = 15 * 1000;
const CLIPBOARD_MS = 30 * 1000;
const SESSION_KEY = "vault.session.v1";
const SIGNED_OUT = "Not signed in. This vault stays on this device until you create an account and sync.";
const LOCAL_ONLY = "Local only. The sync server could not be reached, so changes stay on this device.";
const LOCAL_ONLY_DIRTY = "Local only. Unsynced changes are saved on this device because the server could not be reached.";
const UNSYNCED = "Unsynced. Changes are saved on this device and have not reached the server.";

const MODE_COPY = {
  signin: "Unlock this device and download the encrypted vault.",
  create: "The server stores an authentication hash and ciphertext. It cannot read your vault.",
  device: "Entries stay on this device until you create an account.",
};
const SUBMIT_LABEL = {
  signin: "Unlock",
  create: "Create account",
  device: "Save on this device",
};

const session = loadSession();
const secrets = { encKey: null, authHash: "" };
const state = {
  mode: "signin",
  busy: false,
  items: [],
  editorId: null,
  editorIsNew: false,
  deleteArmed: false,
};

let epoch = 0;
let queue = Promise.resolve();
let idleTimer = 0;
let hideTimer = 0;
let clipboardTimer = 0;
let clipboardValue = "";
let clipboardButton = null;
let deleteTimer = 0;

const emailInput = document.getElementById("email");
const masterInput = document.getElementById("master");
const confirmInput = document.getElementById("confirm");
const submitButton = document.getElementById("submit-button");
const bannerEl = document.getElementById("banner");
const syncLabel = document.getElementById("sync-label");
const lockButton = document.getElementById("lock-button");
const syncButton = document.getElementById("sync-button");
const entryForm = document.getElementById("entry-form");
const editorEmpty = document.getElementById("editor-empty");
const listEl = document.getElementById("entry-list");
const searchInput = document.getElementById("search");
const titleInput = document.getElementById("entry-title");
const usernameInput = document.getElementById("entry-username");
const passwordInput = document.getElementById("entry-password");
const urlInput = document.getElementById("entry-url");
const notesInput = document.getElementById("entry-notes");
const deleteButton = document.getElementById("delete-entry");
const generator = document.getElementById("generator");
const genLength = document.getElementById("gen-length");
const genOutput = document.getElementById("gen-output");

function loadSession() {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    if (!raw) return { email: "", token: null, lastSyncError: false };
    const value = JSON.parse(raw);
    return {
      email: typeof value.email === "string" ? value.email : "",
      token: typeof value.token === "string" && /^[a-f0-9]{64}$/.test(value.token) ? value.token : null,
      lastSyncError: !!value.lastSyncError,
    };
  } catch {
    return { email: "", token: null, lastSyncError: false };
  }
}

function saveSession() {
  localStorage.setItem(
    SESSION_KEY,
    JSON.stringify({
      email: session.email,
      token: session.token,
      lastSyncError: !!session.lastSyncError,
    }),
  );
}

function boxKey(email) {
  return `vault.box.v1.${encodeURIComponent(email)}`;
}

function hasBox(email) {
  return !!email && localStorage.getItem(boxKey(email)) != null;
}

function loadBox(email) {
  const raw = localStorage.getItem(boxKey(email));
  if (!raw) return [];
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed)) throw new Error("This device's vault data could not be read.");
  return parsed.map((item) => {
    if (!item || typeof item.id !== "string" || typeof item.iv !== "string" || typeof item.ciphertext !== "string") {
      throw new Error("This device's vault data could not be read.");
    }
    return {
      id: item.id,
      iv: item.iv,
      ciphertext: item.ciphertext,
      updatedAt: typeof item.updatedAt === "number" ? item.updatedAt : 0,
      deleted: !!item.deleted,
      version: typeof item.version === "number" ? item.version : 0,
      dirty: !!item.dirty,
    };
  });
}

function hasDirty(email) {
  if (!email) return false;
  try {
    return loadBox(email).some((item) => item.dirty);
  } catch {
    return false;
  }
}

function blankPlain() {
  return { title: "", username: "", password: "", url: "", notes: "", unreadable: false };
}

function sanitizePlain(value) {
  const source = value && typeof value === "object" ? value : {};
  const text = (field, max) => (typeof source[field] === "string" ? source[field].slice(0, max) : "");
  return {
    title: text("title", 200),
    username: text("username", 320),
    password: text("password", 1000),
    url: text("url", 2000),
    notes: text("notes", 5000),
  };
}

function stillOpen(ticket) {
  return ticket === epoch && !!secrets.encKey;
}

function persistSnapshot(items) {
  if (!secrets.encKey || !session.email) return;
  const stored = items.map((item) => ({
    id: item.id,
    iv: item.iv,
    ciphertext: item.ciphertext,
    updatedAt: item.updatedAt,
    deleted: !!item.deleted,
    version: item.version || 0,
    dirty: !!item.dirty && !item.unreadable,
  }));
  localStorage.setItem(boxKey(session.email), JSON.stringify(stored));
}

function enqueue(task) {
  const run = queue.then(() => task());
  queue = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}

function setText(id, message) {
  const node = document.getElementById(id);
  node.textContent = message || "";
  node.hidden = !message;
}

function renderChrome() {
  const unlocked = !!secrets.encKey;
  const dirty = unlocked ? state.items.some((item) => item.dirty) : hasDirty(session.email);
  let banner = "";
  let label = "Not signed in";
  if (!session.token) {
    banner = SIGNED_OUT;
    label = "Not signed in";
  } else if (session.lastSyncError) {
    banner = dirty ? LOCAL_ONLY_DIRTY : LOCAL_ONLY;
    label = "Local only";
  } else if (dirty) {
    banner = UNSYNCED;
    label = "Unsynced";
  } else {
    label = unlocked ? "Synced" : "Signed in";
  }
  bannerEl.textContent = banner;
  bannerEl.hidden = !banner;
  syncLabel.textContent = label;
  lockButton.hidden = !unlocked;
  syncButton.hidden = !unlocked || !session.token;
  document.getElementById("enable-sync").hidden = !unlocked || !!session.token;
  document.getElementById("signout-button").hidden = !unlocked || !session.token;
}

function setMode(mode) {
  state.mode = mode;
  for (const button of document.querySelectorAll("[data-mode]")) {
    const active = button.dataset.mode === mode;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", active ? "true" : "false");
  }
  document.getElementById("mode-copy").textContent = MODE_COPY[mode];
  document.getElementById("recovery-warning").hidden = mode === "signin";
  document.getElementById("confirm-label").hidden = mode === "signin";
  confirmInput.disabled = mode === "signin";
  masterInput.autocomplete = mode === "signin" ? "current-password" : "new-password";
  if (!state.busy) submitButton.textContent = SUBMIT_LABEL[mode];
}

function yieldToPaint() {
  return new Promise((resolve) => {
    requestAnimationFrame(() => resolve());
  });
}

function storageWorks() {
  try {
    localStorage.setItem("vault.probe", "1");
    localStorage.removeItem("vault.probe");
    return true;
  } catch {
    return false;
  }
}

function assertSyncUrl() {
  const url = new URL(SYNC_URL);
  if (url.protocol !== "https:") throw new Error("Sync URL must use https.");
}

async function onAuthSubmit(event) {
  event.preventDefault();
  if (state.busy) return;
  const mode = state.mode;
  const email = normalizeEmail(emailInput.value);
  const password = masterInput.value;
  setText("form-error", "");
  if (!isValidEmail(email)) {
    setText("form-error", "Enter a valid email address.");
    return;
  }
  if (password.length < 8 || password.length > 200) {
    setText("form-error", "Master password must be 8 to 200 characters.");
    return;
  }
  if (mode !== "signin" && password !== confirmInput.value) {
    setText("form-error", "Master password confirmation does not match.");
    return;
  }
  state.busy = true;
  submitButton.disabled = true;
  submitButton.textContent = "Deriving keys…";
  await yieldToPaint();
  try {
    const keys = await deriveKeys(email, password);
    if (mode === "device") {
      session.email = email;
      session.token = null;
      session.lastSyncError = false;
      saveSession();
      await openVault(keys);
      return;
    }
    if (mode === "create") await registerOrFail(email, keys.authHash);
    else await loginOrOffline(email, keys.authHash);
    session.email = email;
    saveSession();
    await openVault(keys);
    if (session.token) await requestSync();
  } catch (error) {
    secrets.encKey = null;
    secrets.authHash = "";
    setText("form-error", error instanceof Error ? error.message : "Could not unlock.");
  } finally {
    state.busy = false;
    submitButton.disabled = false;
    setMode(state.mode);
  }
}

async function registerOrFail(email, authHash) {
  const result = await postAuth("/auth/register", email, authHash, 201);
  session.token = result.token;
  session.lastSyncError = false;
}

async function loginOrOffline(email, authHash) {
  try {
    const result = await postAuth("/auth/login", email, authHash, 200);
    session.token = result.token;
    session.lastSyncError = false;
  } catch (error) {
    if (error && error.status === 0 && hasBox(email)) {
      session.token = session.email === email ? session.token : null;
      session.lastSyncError = true;
      return;
    }
    if (error && error.status === 401 && hasBox(email)) {
      throw new Error("Email or master password does not match. A vault is already saved on this device — use On device to open it without the server.");
    }
    throw error;
  }
}

async function postAuth(path, email, authHash, expectedStatus) {
  const result = await api(path, {
    method: "POST",
    body: JSON.stringify({ email, authHash }),
  });
  const token = result.body && typeof result.body.token === "string" ? result.body.token : "";
  const returned = result.body && typeof result.body.email === "string" ? normalizeEmail(result.body.email) : "";
  if (result.status !== expectedStatus || !result.ok || !/^[a-f0-9]{64}$/.test(token) || returned !== email) {
    const fallback = path.endsWith("register") ? "Account was not created." : "Sign-in failed.";
    const error = new Error(result.body && typeof result.body.error === "string" ? result.body.error : fallback);
    error.status = result.status;
    throw error;
  }
  return { token };
}

async function openVault(keys) {
  const ticket = epoch;
  secrets.encKey = keys.encKey;
  secrets.authHash = keys.authHash;
  try {
    await hydrateFromDisk(ticket);
  } catch (error) {
    secrets.encKey = null;
    secrets.authHash = "";
    throw error;
  }
  if (!stillOpen(ticket)) return;
  masterInput.value = "";
  confirmInput.value = "";
  showApp();
}

async function hydrateFromDisk(ticket) {
  const stored = loadBox(session.email);
  const next = [];
  for (const item of stored) {
    if (!stillOpen(ticket)) return;
    if (item.deleted) {
      next.push({ ...blankPlain(), ...item, deleted: true });
      continue;
    }
    try {
      const plain = await decryptJson(secrets.encKey, item.iv, item.ciphertext);
      if (!stillOpen(ticket)) return;
      next.push({ ...item, ...sanitizePlain(plain), deleted: false, unreadable: false });
    } catch {
      if (!stillOpen(ticket)) return;
      next.push({ ...blankPlain(), ...item, title: "Unreadable entry", unreadable: true, dirty: false });
    }
  }
  if (!stillOpen(ticket)) return;
  state.items = next;
  persistSnapshot(next);
}

function showApp() {
  document.getElementById("lock-screen").hidden = true;
  document.getElementById("app-screen").hidden = false;
  document.body.classList.add("unlocked");
  armIdle();
  renderChrome();
  renderList();
  searchInput.focus();
}

function lockVault() {
  window.clearTimeout(idleTimer);
  window.clearTimeout(hideTimer);
  if (!secrets.encKey) return;
  epoch += 1;
  secrets.encKey = null;
  secrets.authHash = "";
  void clearClipboard();
  state.items = [];
  state.editorId = null;
  state.editorIsNew = false;
  clearEntryForm();
  searchInput.value = "";
  genOutput.value = "";
  listEl.replaceChildren();
  document.body.classList.remove("editing", "unlocked");
  document.getElementById("app-screen").hidden = true;
  document.getElementById("lock-screen").hidden = false;
  entryForm.hidden = true;
  editorEmpty.hidden = false;
  masterInput.value = "";
  confirmInput.value = "";
  renderChrome();
  masterInput.focus();
}

function armIdle() {
  window.clearTimeout(idleTimer);
  if (!secrets.encKey) return;
  idleTimer = window.setTimeout(() => lockVault(), IDLE_MS);
}

function scheduleHideLock() {
  window.clearTimeout(hideTimer);
  if (!secrets.encKey) return;
  hideTimer = window.setTimeout(() => lockVault(), HIDE_MS);
}

function noteActivity() {
  if (!secrets.encKey) return;
  armIdle();
}

function setButtonLabel(button, label) {
  const span = button.querySelector(".btn-label");
  if (span) span.textContent = label;
  else button.textContent = label;
}

async function clearClipboard() {
  const expected = clipboardValue;
  clipboardValue = "";
  window.clearTimeout(clipboardTimer);
  if (clipboardButton) {
    setButtonLabel(clipboardButton, clipboardButton.dataset.label || "Copy");
    clipboardButton = null;
  }
  if (!expected) return;
  try {
    let current = expected;
    try {
      current = await navigator.clipboard.readText();
    } catch {
      current = expected;
    }
    if (current === expected) await navigator.clipboard.writeText("");
  } catch {
    /* Safari can reject a clipboard write that is not tied to a fresh tap. */
  }
}

async function copyText(value, button) {
  if (!value) return;
  await navigator.clipboard.writeText(value);
  clipboardValue = value;
  if (clipboardButton && clipboardButton !== button) {
    setButtonLabel(clipboardButton, clipboardButton.dataset.label || "Copy");
  }
  clipboardButton = button;
  setButtonLabel(button, "Copied");
  window.clearTimeout(clipboardTimer);
  clipboardTimer = window.setTimeout(() => {
    void clearClipboard();
  }, CLIPBOARD_MS);
}

function hostOf(value) {
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" && url.protocol !== "http:") return "";
    return url.host;
  } catch {
    return "";
  }
}

function safeUrl(value) {
  try {
    const url = new URL(value);
    if (url.protocol === "https:" || url.protocol === "http:") return url.href;
  } catch {
    /* not a URL */
  }
  return "";
}

function renderList() {
  const query = searchInput.value.trim().toLowerCase();
  const items = state.items
    .filter((item) => !item.deleted)
    .filter((item) => {
      if (!query) return true;
      return [item.title, item.username, item.password, item.url, item.notes].join("\n").toLowerCase().includes(query);
    })
    .sort((left, right) => (left.title || "").localeCompare(right.title || ""));
  listEl.replaceChildren();
  if (!items.length) {
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.textContent = query ? "No matching entries." : "No entries yet.";
    listEl.append(empty);
    return;
  }
  for (const item of items) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "entry";
    if (item.id === state.editorId) button.classList.add("active");
    const title = document.createElement("span");
    title.className = "entry-title";
    title.textContent = item.title || "Untitled";
    const meta = document.createElement("span");
    meta.className = "entry-meta";
    const detail = [item.username, hostOf(item.url)].filter(Boolean).join(" · ");
    meta.textContent = detail || "No username";
    button.append(title, meta);
    if (item.dirty) {
      const dot = document.createElement("span");
      dot.className = "dot";
      dot.title = "Not synced";
      button.append(dot);
    }
    button.addEventListener("click", () => openEditor(item.id));
    listEl.append(button);
  }
}

function setFieldsDisabled(disabled) {
  for (const id of ["entry-title", "entry-username", "entry-password", "entry-url", "entry-notes", "save-entry", "open-generator", "toggle-password"]) {
    document.getElementById(id).disabled = disabled;
  }
}

function fillForm(item) {
  titleInput.value = item.title || "";
  usernameInput.value = item.username || "";
  passwordInput.value = item.password || "";
  passwordInput.type = "password";
  document.getElementById("toggle-password").textContent = "Show";
  urlInput.value = item.url || "";
  notesInput.value = item.notes || "";
  generator.hidden = true;
  refreshUrlButton();
  setText("entry-error", "");
}

function clearEntryForm() {
  fillForm(blankPlain());
  document.getElementById("editor-unreadable").hidden = true;
  setFieldsDisabled(false);
  deleteButton.textContent = "Delete";
  state.deleteArmed = false;
}

function openEditor(id) {
  const item = state.items.find((entry) => entry.id === id);
  if (!item || item.deleted) return;
  state.editorId = id;
  state.editorIsNew = false;
  state.deleteArmed = false;
  window.clearTimeout(deleteTimer);
  deleteButton.textContent = "Delete";
  fillForm(item);
  document.getElementById("editor-heading").textContent = item.unreadable ? "Unreadable entry" : item.title || "Entry";
  document.getElementById("editor-unreadable").hidden = !item.unreadable;
  setFieldsDisabled(!!item.unreadable);
  entryForm.hidden = false;
  editorEmpty.hidden = true;
  document.body.classList.add("editing");
  if (!item.unreadable) titleInput.focus();
  renderList();
}

function newEntry() {
  state.editorId = crypto.randomUUID();
  state.editorIsNew = true;
  state.deleteArmed = false;
  window.clearTimeout(deleteTimer);
  deleteButton.textContent = "Delete";
  fillForm(blankPlain());
  document.getElementById("editor-heading").textContent = "New entry";
  document.getElementById("editor-unreadable").hidden = true;
  setFieldsDisabled(false);
  entryForm.hidden = false;
  editorEmpty.hidden = true;
  document.body.classList.add("editing");
  titleInput.focus();
  renderList();
}

function closeEditor() {
  state.editorId = null;
  state.editorIsNew = false;
  clearEntryForm();
  entryForm.hidden = true;
  editorEmpty.hidden = false;
  document.body.classList.remove("editing");
  renderList();
}

function refreshUrlButton() {
  const button = document.getElementById("open-url");
  const href = safeUrl(urlInput.value.trim());
  button.hidden = !href;
  button.dataset.href = href;
}

async function seal(item) {
  const payload = item.deleted
    ? {}
    : {
        title: item.title,
        username: item.username,
        password: item.password,
        url: item.url,
        notes: item.notes,
      };
  const packed = await encryptJson(secrets.encKey, payload);
  item.iv = packed.iv;
  item.ciphertext = packed.ciphertext;
}

async function saveEntry() {
  try {
    const saved = await enqueue(() => saveEntryInner());
    if (saved && session.token && secrets.encKey) await requestSync();
    return saved;
  } catch (error) {
    setText("entry-error", error instanceof Error ? error.message : "Could not save.");
    return false;
  }
}

async function saveEntryInner() {
  const ticket = epoch;
  const id = state.editorId;
  if (!id || !secrets.encKey) return false;
  const existing = state.items.find((item) => item.id === id);
  if (existing?.unreadable) {
    setText("entry-error", "This entry could not be decrypted.");
    return false;
  }
  const draft = {
    title: titleInput.value.trim(),
    username: usernameInput.value,
    password: passwordInput.value,
    url: urlInput.value.trim(),
    notes: notesInput.value,
  };
  if (!draft.title) {
    setText("entry-error", "Enter a title.");
    return false;
  }
  if (draft.title.length > 200 || draft.username.length > 320 || draft.password.length > 1000 || draft.url.length > 2000 || draft.notes.length > 5000) {
    setText("entry-error", "One of the fields is too long.");
    return false;
  }
  const item = existing || {
    id,
    iv: "",
    ciphertext: "",
    updatedAt: 0,
    deleted: false,
    version: 0,
    dirty: true,
    ...blankPlain(),
  };
  item.title = draft.title;
  item.username = draft.username;
  item.password = draft.password;
  item.url = draft.url;
  item.notes = draft.notes;
  item.updatedAt = Date.now();
  item.deleted = false;
  item.dirty = true;
  item.unreadable = false;
  await seal(item);
  if (!stillOpen(ticket)) return false;
  if (!existing) state.items.push(item);
  state.editorIsNew = false;
  document.getElementById("editor-heading").textContent = item.title;
  persistSnapshot(state.items);
  setText("entry-error", "");
  renderList();
  renderChrome();
  return true;
}

async function deleteEntry() {
  const id = state.editorId;
  if (!id) return;
  const existing = state.items.find((item) => item.id === id);
  if (!existing && state.editorIsNew) {
    closeEditor();
    return;
  }
  if (!state.deleteArmed) {
    state.deleteArmed = true;
    deleteButton.textContent = "Tap again to delete";
    window.clearTimeout(deleteTimer);
    deleteTimer = window.setTimeout(() => {
      state.deleteArmed = false;
      deleteButton.textContent = "Delete";
    }, 4000);
    return;
  }
  state.deleteArmed = false;
  deleteButton.textContent = "Delete";
  try {
    await enqueue(() => deleteEntryInner(id));
    if (session.token && secrets.encKey) await requestSync();
  } catch (error) {
    setText("entry-error", error instanceof Error ? error.message : "Could not delete.");
  }
}

async function deleteEntryInner(id) {
  const ticket = epoch;
  const item = state.items.find((entry) => entry.id === id);
  if (!item || !secrets.encKey) return;
  item.deleted = true;
  item.dirty = true;
  item.updatedAt = Date.now();
  item.title = "";
  item.username = "";
  item.password = "";
  item.url = "";
  item.notes = "";
  item.unreadable = false;
  await seal(item);
  if (!stillOpen(ticket)) return;
  persistSnapshot(state.items);
  closeEditor();
  renderChrome();
}

function generatorOptions() {
  return {
    lower: document.getElementById("gen-lower").checked,
    upper: document.getElementById("gen-upper").checked,
    digit: document.getElementById("gen-digit").checked,
    symbol: document.getElementById("gen-symbol").checked,
  };
}

function fillGenerator() {
  const length = Number(genLength.value);
  document.getElementById("gen-length-out").textContent = String(length);
  try {
    genOutput.value = generatePassword(length, generatorOptions());
    setText("gen-error", "");
  } catch (error) {
    genOutput.value = "";
    setText("gen-error", error instanceof Error ? error.message : "Could not generate a password.");
  }
}

async function exportBackup() {
  if (!secrets.encKey) return;
  if (state.editorId && formIsDirty()) {
    setText("app-message", "Unsaved changes in the open entry were left out of the backup.");
  } else {
    setText("app-message", "");
  }
  const backup = buildBackup(
    session.email,
    state.items.filter((item) => item.iv && item.ciphertext),
    PBKDF2_ITERATIONS,
  );
  const blob = new Blob([JSON.stringify(backup, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "vault-backup.json";
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  setText("app-message", "Backup downloaded. It contains ciphertext only.");
}

function formIsDirty() {
  const item = state.items.find((entry) => entry.id === state.editorId);
  const current = {
    title: titleInput.value.trim(),
    username: usernameInput.value,
    password: passwordInput.value,
    url: urlInput.value.trim(),
    notes: notesInput.value,
  };
  if (!item) return !!(current.title || current.username || current.password || current.url || current.notes);
  return current.title !== item.title || current.username !== item.username || current.password !== item.password || current.url !== item.url || current.notes !== item.notes;
}

async function importBackup(file) {
  let parsed;
  try {
    parsed = parseBackup(JSON.parse(await file.text()));
  } catch (error) {
    setText("app-message", error instanceof Error ? error.message : "Backup file is not valid.");
    return;
  }
  if (normalizeEmail(parsed.email) !== session.email) {
    setText("app-message", "This backup belongs to a different email.");
    return;
  }
  if (parsed.iterations !== PBKDF2_ITERATIONS) {
    setText("app-message", "This backup uses a different key derivation and cannot be opened.");
    return;
  }
  closeEditor();
  try {
    await enqueue(() => integrate(parsed.items, true));
  } catch (error) {
    setText("app-message", error instanceof Error ? error.message : "Backup could not be imported.");
    return;
  }
  renderList();
  renderChrome();
  setText("app-message", "Backup imported. Entries stay encrypted and will sync if you are signed in.");
  if (session.token && secrets.encKey) await requestSync();
}

async function integrate(remoteItems, incomingDirty) {
  const ticket = epoch;
  const localStored = state.items.map((item) => ({
    id: item.id,
    iv: item.iv,
    ciphertext: item.ciphertext,
    updatedAt: item.updatedAt,
    deleted: !!item.deleted,
    version: item.version || 0,
    dirty: !!item.dirty,
    unreadable: !!item.unreadable,
  }));
  const merged = mergeEntries(localStored, remoteItems, { incomingDirty });
  const previous = new Map(state.items.map((item) => [item.id, item]));
  const next = [];
  for (const item of merged) {
    if (!stillOpen(ticket)) return;
    const prior = previous.get(item.id);
    if (item.deleted) {
      next.push({ ...blankPlain(), ...item, deleted: true, password: "" });
      continue;
    }
    const same = prior && prior.iv === item.iv && prior.ciphertext === item.ciphertext && !prior.unreadable;
    if (same) {
      next.push({
        ...prior,
        ...item,
        title: prior.title,
        username: prior.username,
        password: prior.password,
        url: prior.url,
        notes: prior.notes,
        unreadable: false,
      });
      continue;
    }
    try {
      const plain = await decryptJson(secrets.encKey, item.iv, item.ciphertext);
      if (!stillOpen(ticket)) return;
      next.push({ ...item, ...sanitizePlain(plain), deleted: false, unreadable: false });
    } catch {
      if (!stillOpen(ticket)) return;
      next.push({ ...blankPlain(), ...item, title: "Unreadable entry", unreadable: true, dirty: false });
    }
  }
  if (!stillOpen(ticket)) return;
  state.items = next;
  persistSnapshot(next);
}

function requestSync() {
  return enqueue(() => syncNow());
}

async function syncNow() {
  if (!session.token || !secrets.encKey) {
    renderChrome();
    return;
  }
  const ticket = epoch;
  syncButton.disabled = true;
  try {
    let remote;
    try {
      remote = await pull();
    } catch (error) {
      if (!stillOpen(ticket)) return;
      if (error && error.status === 401) {
        session.token = null;
        saveSession();
        renderChrome();
        setText("app-message", "Sign in again.");
        return;
      }
      session.lastSyncError = true;
      saveSession();
      renderChrome();
      return;
    }
    if (!stillOpen(ticket)) return;
    await integrate(remote, false);
    if (!stillOpen(ticket)) return;
    let plan = uploadPlan(state.items, remote);
    if (!plan.allow) {
      session.lastSyncError = false;
      saveSession();
      renderChrome();
      setText("app-message", EMPTY_ERROR);
      return;
    }
    for (let attempt = 0; attempt < 3 && plan.items.length > 0; attempt += 1) {
      const sending = plan.items.map((item) => ({
        id: item.id,
        iv: item.iv,
        ciphertext: item.ciphertext,
        updatedAt: item.updatedAt,
        deleted: !!item.deleted,
        version: item.version || 0,
      }));
      const result = await putAll(sending, plan.confirmEmpty);
      if (!stillOpen(ticket)) return;
      if (result.status === 401) {
        session.token = null;
        saveSession();
        renderChrome();
        setText("app-message", "Sign in again.");
        return;
      }
      if (result.status === 409 && result.body && result.body.error === EMPTY_ERROR) {
        session.lastSyncError = false;
        saveSession();
        renderChrome();
        setText("app-message", EMPTY_ERROR);
        return;
      }
      if (result.status === 409) {
        try {
          remote = await pull();
        } catch (error) {
          if (!stillOpen(ticket)) return;
          if (error && error.status === 401) {
            session.token = null;
            saveSession();
            renderChrome();
            setText("app-message", "Sign in again.");
            return;
          }
          session.lastSyncError = true;
          saveSession();
          renderChrome();
          return;
        }
        if (!stillOpen(ticket)) return;
        await integrate(remote, false);
        if (!stillOpen(ticket)) return;
        plan = uploadPlan(state.items, remote);
        if (!plan.allow) {
          setText("app-message", EMPTY_ERROR);
          renderChrome();
          return;
        }
        continue;
      }
      if (!result.ok || !result.body || result.body.ok !== true || !Array.isArray(result.body.items)) {
        session.lastSyncError = true;
        saveSession();
        renderChrome();
        setText("app-message", (result.body && result.body.error) || "Sync did not finish.");
        return;
      }
      const versions = new Map(result.body.items.map((item) => [item.id, item]));
      const sentById = new Map(sending.map((item) => [item.id, item]));
      for (const item of state.items) {
        const updated = versions.get(item.id);
        const sent = sentById.get(item.id);
        if (!updated || !sent || typeof updated.version !== "number") continue;
        if (item.iv !== sent.iv || item.ciphertext !== sent.ciphertext || item.updatedAt !== sent.updatedAt) continue;
        item.version = updated.version;
        item.dirty = false;
      }
      persistSnapshot(state.items);
      session.lastSyncError = false;
      saveSession();
      renderList();
      renderChrome();
      return;
    }
    if (plan.items.length === 0) {
      session.lastSyncError = false;
      saveSession();
      renderChrome();
      renderList();
      return;
    }
    session.lastSyncError = true;
    saveSession();
    renderChrome();
    setText("app-message", "Sync did not finish.");
  } finally {
    syncButton.disabled = false;
  }
}

async function pull() {
  const result = await api("/sync");
  if (result.status === 401) {
    const error = new Error(result.body && result.body.error ? result.body.error : "Sign in again.");
    error.status = 401;
    throw error;
  }
  if (!result.ok || !result.body || !Array.isArray(result.body.items)) {
    const error = new Error(result.body && result.body.error ? result.body.error : "Could not download the vault.");
    error.status = result.status;
    throw error;
  }
  return result.body.items.map((item) => {
    if (!item || typeof item.id !== "string" || typeof item.iv !== "string" || typeof item.ciphertext !== "string") {
      throw new Error("The server vault is invalid.");
    }
    if (typeof item.updatedAt !== "number" || typeof item.version !== "number") {
      throw new Error("The server vault is invalid.");
    }
    return {
      id: item.id,
      iv: item.iv,
      ciphertext: item.ciphertext,
      updatedAt: item.updatedAt,
      version: item.version,
      deleted: !!item.deleted,
      dirty: false,
    };
  });
}

async function putAll(items, confirmEmpty) {
  const accepted = [];
  for (let index = 0; index < items.length; index += 30) {
    const chunk = items.slice(index, index + 30);
    const result = await api("/sync", {
      method: "PUT",
      body: JSON.stringify({
        confirmEmpty,
        items: chunk.map((item) => ({
          id: item.id,
          iv: item.iv,
          ciphertext: item.ciphertext,
          updatedAt: item.updatedAt,
          deleted: !!item.deleted,
          baseVersion: item.version || 0,
        })),
      }),
    });
    if (!result.ok || result.status === 409) return result;
    if (result.body && Array.isArray(result.body.items)) accepted.push(...result.body.items);
  }
  return { ok: true, status: 200, body: { ok: true, items: accepted } };
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  if (session.token && !headers.Authorization) headers.Authorization = `Bearer ${session.token}`;
  let response;
  try {
    response = await fetch(`${SYNC_URL}${path}`, {
      method: options.method || "GET",
      headers,
      body: options.body,
      cache: "no-store",
      credentials: "omit",
      mode: "cors",
    });
  } catch {
    const error = new Error("The sync server could not be reached.");
    error.status = 0;
    throw error;
  }
  const text = await response.text();
  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = null;
    }
  }
  return { ok: response.ok, status: response.status, body };
}

async function enableSync() {
  if (!secrets.authHash || !session.email) {
    setText("app-message", "Lock the vault and create the account from the sign-in screen.");
    return;
  }
  setText("app-message", "Creating the account…");
  try {
    try {
      await registerOrFail(session.email, secrets.authHash);
    } catch (error) {
      if (!error || error.status !== 409) throw error;
      const result = await postAuth("/auth/login", session.email, secrets.authHash, 200);
      session.token = result.token;
      session.lastSyncError = false;
    }
    saveSession();
    renderChrome();
    setText("app-message", "");
    await requestSync();
    if (session.token && !session.lastSyncError) setText("app-message", "Signed in. The encrypted vault can sync.");
  } catch (error) {
    setText("app-message", error instanceof Error ? error.message : "Account was not created.");
  }
}

async function signOut() {
  const token = session.token;
  session.token = null;
  session.lastSyncError = false;
  saveSession();
  lockVault();
  if (!token) return;
  try {
    await api("/auth/logout", { method: "POST", headers: { Authorization: `Bearer ${token}` } });
  } catch {
    /* The token is already gone on this device. */
  }
}

function registerServiceWorker() {
  if (!("serviceWorker" in navigator)) return;
  const workerUrl = new URL("sw.js", import.meta.url);
  navigator.serviceWorker.register(workerUrl).catch(() => {});
}

function bind() {
  document.getElementById("auth-form").addEventListener("submit", (event) => {
    void onAuthSubmit(event);
  });
  for (const button of document.querySelectorAll("[data-mode]")) {
    button.addEventListener("click", () => {
      setMode(button.dataset.mode);
      setText("form-error", "");
    });
  }
  lockButton.addEventListener("click", () => lockVault());
  syncButton.addEventListener("click", () => {
    void requestSync();
  });
  document.getElementById("new-entry").addEventListener("click", () => newEntry());
  searchInput.addEventListener("input", () => renderList());
  entryForm.addEventListener("submit", (event) => {
    event.preventDefault();
    void saveEntry();
  });
  document.getElementById("close-editor").addEventListener("click", () => closeEditor());
  deleteButton.addEventListener("click", () => {
    void deleteEntry();
  });
  document.getElementById("toggle-password").addEventListener("click", () => {
    const hidden = passwordInput.type === "password";
    passwordInput.type = hidden ? "text" : "password";
    document.getElementById("toggle-password").textContent = hidden ? "Hide" : "Show";
  });
  document.getElementById("copy-password").addEventListener("click", () => {
    void copyText(passwordInput.value, document.getElementById("copy-password"));
  });
  document.getElementById("copy-username").addEventListener("click", () => {
    void copyText(usernameInput.value, document.getElementById("copy-username"));
  });
  document.getElementById("open-generator").addEventListener("click", () => {
    generator.hidden = !generator.hidden;
    if (!generator.hidden) fillGenerator();
  });
  genLength.addEventListener("input", () => fillGenerator());
  for (const id of ["gen-lower", "gen-upper", "gen-digit", "gen-symbol"]) {
    document.getElementById(id).addEventListener("change", () => fillGenerator());
  }
  document.getElementById("gen-refresh").addEventListener("click", () => fillGenerator());
  document.getElementById("gen-use").addEventListener("click", () => {
    if (genOutput.value) passwordInput.value = genOutput.value;
  });
  document.getElementById("gen-copy").addEventListener("click", () => {
    void copyText(genOutput.value, document.getElementById("gen-copy"));
  });
  urlInput.addEventListener("input", () => refreshUrlButton());
  document.getElementById("open-url").addEventListener("click", () => {
    const href = document.getElementById("open-url").dataset.href;
    if (href) window.open(href, "_blank", "noopener");
  });
  document.getElementById("export-button").addEventListener("click", () => {
    void exportBackup();
  });
  document.getElementById("import-button").addEventListener("click", () => {
    document.getElementById("import-file").click();
  });
  document.getElementById("import-file").addEventListener("change", (event) => {
    const file = event.target.files && event.target.files[0];
    event.target.value = "";
    if (file) void importBackup(file);
  });
  document.getElementById("enable-sync").addEventListener("click", () => {
    void enableSync();
  });
  document.getElementById("signout-button").addEventListener("click", () => {
    void signOut();
  });
  document.addEventListener("pointerdown", () => noteActivity(), true);
  document.addEventListener("keydown", (event) => {
    noteActivity();
    if (event.key === "Escape" && secrets.encKey && state.editorId) closeEditor();
  });
  document.addEventListener("touchstart", () => noteActivity(), { passive: true });
  document.addEventListener("scroll", () => noteActivity(), true);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") scheduleHideLock();
    else {
      window.clearTimeout(hideTimer);
      noteActivity();
    }
  });
}

function start() {
  try {
    assertSyncUrl();
  } catch (error) {
    setText("form-error", error instanceof Error ? error.message : "Sync URL is invalid.");
  }
  if (!storageWorks()) {
    setText("form-error", "This browser is blocking local storage, so the vault cannot be saved.");
    submitButton.disabled = true;
  }
  if (session.email) emailInput.value = session.email;
  setMode("signin");
  renderChrome();
  bind();
  registerServiceWorker();
}

start();
