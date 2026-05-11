/* global require, monaco */

let editor = null;
let editorReady = false;
let selectedJobId = null;
let pollTimer = null;
const openTabs = new Map(); // path -> { model }
let openTabOrder = [];
let activePath = null;

const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("file-input");
const uploadStatus = document.getElementById("upload-status");
const jobList = document.getElementById("job-list");
const jobSearchInput = document.getElementById("job-search");
const jobSearchStatus = document.getElementById("job-search-status");
const refreshJobsBtn = document.getElementById("refresh-jobs");
const settingsBtn = document.getElementById("settings-btn");
const settingsModal = document.getElementById("settings-modal");
const settingsCloseBtns = document.querySelectorAll("[data-settings-close]");
const refreshJavaBtn = document.getElementById("refresh-java");
const javaList = document.getElementById("java-list");
const javaSelected = document.getElementById("java-selected");
const javaNote = document.getElementById("java-note");
const jobsModal = document.getElementById("jobs-modal");
const jobsModalBtn = document.getElementById("jobs-modal-btn");
const jobsModalCloseBtns = document.querySelectorAll("[data-jobs-close]");
const jobsPaneRefreshBtn = document.getElementById("jobs-pane-refresh");
const jobsPaneSearchInput = document.getElementById("jobs-pane-search");
const jobsPaneList = document.getElementById("jobs-pane-list");
const jobsLogRefreshBtn = document.getElementById("jobs-log-refresh");
const jobsLogTitle = document.getElementById("jobs-log-title");
const jobsLogText = document.getElementById("jobs-log-text");

const jobTitle = document.getElementById("job-title");
const jobBadge = document.getElementById("job-badge");
const btnLog = document.getElementById("btn-log");
const btnDownload = document.getElementById("btn-download");
const btnDelete = document.getElementById("btn-delete");

const treeRoot = document.getElementById("tree-root");
const treeSearchInput = document.getElementById("tree-search");
const treeSearchStatus = document.getElementById("tree-search-status");
const treeProgress = document.getElementById("tree-progress");
const treeProgressText = document.getElementById("tree-progress-text");
const treeProgressBar = document.getElementById("tree-progress-bar");
const tabsEl = document.getElementById("tabs");
const editorMount = document.getElementById("editor-mount");
const editorStatus = document.getElementById("editor-status");

let _allJobs = [];
let _treeRenderToken = 0;
let _javaLoaded = false;

let _activePaneTab = "editor";
let _analysisCache = null; // { jobId, summary, findings, total, filters }
let _analysisFiltersDirty = false;
let _analysisPollTimer = null;
let _analysisPageSize = 200;
const _analysisDecorationsByPath = new Map(); // path -> string[] decoration ids
let _jobsPaneSelectedId = null;

const modalEl = document.getElementById("modal");
const modalTitleEl = modalEl.querySelector(".modal-title");
const modalBodyEl = modalEl.querySelector(".modal-body");
const modalFootEl = modalEl.querySelector(".modal-foot");
const modalCloseBtn = modalEl.querySelector("[data-modal-close]");

let _modalResolver = null;

function _settleModal(id) {
  if (_modalResolver) {
    const r = _modalResolver;
    _modalResolver = null;
    r(id);
  }
}

function closeModal(id = "cancel") {
  _settleModal(id);
  if (modalEl.open) modalEl.close();
}

function openModal({ title, body, actions, bodyClass } = {}) {
  return new Promise((resolve) => {
    _settleModal("cancel");
    _modalResolver = resolve;

    modalTitleEl.textContent = title || "";
    modalBodyEl.innerHTML = "";
    modalBodyEl.className = "modal-body" + (bodyClass ? " " + bodyClass : "");
    if (typeof body === "string") {
      modalBodyEl.textContent = body;
    } else if (body instanceof Node) {
      modalBodyEl.appendChild(body);
    }

    modalFootEl.innerHTML = "";
    const buttons = actions && actions.length ? actions : [{ id: "ok", label: "OK", primary: true }];
    for (const a of buttons) {
      const btn = document.createElement("button");
      btn.type = "button";
      let cls = "ghost";
      if (a.primary) cls = "primary";
      else if (a.danger) cls = "danger";
      btn.className = cls;
      btn.textContent = a.label;
      btn.addEventListener("click", () => closeModal(a.id));
      modalFootEl.appendChild(btn);
    }

    if (!modalEl.open) modalEl.showModal();
  });
}

modalCloseBtn.addEventListener("click", () => closeModal("cancel"));
modalEl.addEventListener("close", () => _settleModal("cancel"));
modalEl.addEventListener("click", (ev) => {
  // Click on the dialog element itself (the backdrop area, not its children).
  if (ev.target === modalEl) closeModal("cancel");
});

async function showConfirm(title, message, { confirmLabel = "OK", danger = false } = {}) {
  const choice = await openModal({
    title,
    body: message,
    actions: [
      { id: "cancel", label: "Cancel" },
      { id: "confirm", label: confirmLabel, primary: !danger, danger },
    ],
  });
  return choice === "confirm";
}

async function showAlert(title, message) {
  await openModal({
    title,
    body: message,
    actions: [{ id: "ok", label: "OK", primary: true }],
  });
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  const mb = kb / 1024;
  if (mb < 1024) return `${mb.toFixed(2)} MB`;
  return `${(mb / 1024).toFixed(2)} GB`;
}

function parseFilenameFromDisposition(cd) {
  if (!cd) return null;
  const star = cd.match(/filename\*\s*=\s*(?:UTF-8'')?([^;]+)/i);
  if (star && star[1]) {
    try {
      return decodeURIComponent(star[1].trim().replace(/^"|"$/g, ""));
    } catch {
      /* fall through */
    }
  }
  const plain = cd.match(/filename\s*=\s*"?([^";]+)"?/i);
  return plain ? plain[1].trim() : null;
}

async function downloadJobZipWithProgress(jobId, label) {
  if (!jobId) return;

  const status = document.createElement("p");
  status.className = "muted small";
  status.style.margin = "0";
  status.textContent = "Contacting server...";

  const counter = document.createElement("p");
  counter.className = "small";
  counter.style.margin = "0";
  counter.textContent = "";

  const progressWrap = document.createElement("div");
  progressWrap.className = "progress";
  const bar = document.createElement("div");
  bar.className = "progress-bar indeterminate";
  progressWrap.appendChild(bar);

  const container = document.createElement("div");
  container.style.display = "flex";
  container.style.flexDirection = "column";
  container.style.gap = "10px";
  container.appendChild(status);
  container.appendChild(counter);
  container.appendChild(progressWrap);

  const controller = new AbortController();
  let succeeded = false;

  const modalPromise = openModal({
    title: `Packaging ZIP - ${label || jobId.slice(0, 8)}`,
    body: container,
    actions: [{ id: "cancel", label: "Cancel", danger: true }],
  });
  modalPromise.then((id) => {
    if (!succeeded && id !== "done") {
      controller.abort();
    }
  });

  let response;
  try {
    response = await fetch(`/api/jobs/${jobId}/download`, {
      credentials: "same-origin",
      signal: controller.signal,
    });
  } catch (e) {
    if (e.name === "AbortError") return;
    status.textContent = `Failed: ${e.message || e}`;
    return;
  }

  if (!response.ok) {
    status.textContent = `Server returned HTTP ${response.status}`;
    return;
  }
  if (!response.body || !response.body.getReader) {
    status.textContent = "Streaming downloads not supported by this browser.";
    return;
  }

  const totalFilesRaw = parseInt(response.headers.get("X-Job-File-Count") || "0", 10);
  const totalFiles = Number.isFinite(totalFilesRaw) && totalFilesRaw > 0 ? totalFilesRaw : null;
  const filename =
    parseFilenameFromDisposition(response.headers.get("Content-Disposition")) ||
    `${(label || "job").replace(/\.apk$/i, "")}.zip`;

  status.textContent = totalFiles
    ? `Packaging ${totalFiles.toLocaleString()} files...`
    : "Packaging files...";

  const reader = response.body.getReader();
  const parts = [];
  let received = 0;
  let lastPaint = 0;

  while (true) {
    let result;
    try {
      result = await reader.read();
    } catch (e) {
      if (e.name === "AbortError") return;
      status.textContent = `Stream error: ${e.message || e}`;
      return;
    }
    if (result.done) break;
    parts.push(result.value);
    received += result.value.byteLength;
    const now = performance.now();
    if (now - lastPaint > 80) {
      lastPaint = now;
      counter.textContent = totalFiles
        ? `${formatBytes(received)} packaged - ${totalFiles.toLocaleString()} files`
        : `${formatBytes(received)} packaged`;
    }
  }

  counter.textContent = totalFiles
    ? `${formatBytes(received)} packaged - ${totalFiles.toLocaleString()} files`
    : `${formatBytes(received)} packaged`;
  bar.classList.remove("indeterminate");
  bar.style.width = "100%";
  status.textContent = `Saving ${filename}...`;

  const blob = new Blob(parts, { type: "application/zip" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);

  succeeded = true;
  status.textContent = `Saved ${filename}`;
  setTimeout(() => closeModal("done"), 600);
}

async function showLogModal(jobId, label) {
  const pre = document.createElement("pre");
  pre.className = "log-text";
  pre.textContent = "Loading…";
  const heading = label ? `Log — ${label}` : "Job log";
  const p = openModal({
    title: heading,
    body: pre,
    bodyClass: "modal-body-log",
    actions: [{ id: "ok", label: "Close", primary: true }],
  });
  try {
    const data = await fetchJSON(`/api/jobs/${jobId}/log`);
    pre.textContent = data.log && data.log.length ? data.log : "(empty)";
  } catch (e) {
    pre.textContent = String(e.message || e);
  }
  await p;
}

function badgeClass(status) {
  if (status === "done") return "ok";
  if (status === "done_with_errors") return "warn";
  if (status === "running" || status === "queued") return "run";
  return "bad";
}

function isTerminalStatus(status) {
  return status === "done" || status === "done_with_errors" || status === "failed";
}

function hasOutput(status) {
  return status === "done" || status === "done_with_errors";
}

async function fetchJSON(url, opts) {
  const res = await fetch(url, {
    credentials: "same-origin",
    headers: opts?.headers || {},
    ...opts,
  });
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  if (!res.ok) {
    const msg = data?.error || text || `HTTP ${res.status}`;
    throw new Error(msg);
  }
  return data;
}

function formatTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

async function loadJobs() {
  const data = await fetchJSON("/api/jobs");
  _allJobs = data.jobs || [];
  renderJobs(filteredJobs());
  renderJobsPane();
}

function filteredJobs() {
  const q = (jobSearchInput?.value || "").trim().toLowerCase();
  if (!q) {
    if (jobSearchStatus) jobSearchStatus.textContent = "";
    return _allJobs;
  }
  const out = _allJobs.filter((j) => {
    const name = (j.original_filename || "").toLowerCase();
    const id = (j.id || "").toLowerCase();
    const status = (j.status || "").toLowerCase();
    return name.includes(q) || id.includes(q) || status.includes(q);
  });
  if (jobSearchStatus) {
    jobSearchStatus.textContent = `${out.length} of ${_allJobs.length} matches`;
  }
  return out;
}

async function loadJavaRuntimes(refresh) {
  if (!javaList || !javaSelected || !javaNote) return;
  javaNote.textContent = refresh ? "Scanning installed Java runtimes…" : "";
  try {
    const q = refresh ? "?refresh=1" : "";
    const data = await fetchJSON(`/api/java-runtimes${q}`);
    javaList.innerHTML = "";

    const eff = data.effective_selected || data.recommended_for_jadx || "";
    javaSelected.innerHTML = eff
      ? `<strong>Using for decompile:</strong><br/><span class="muted">${eff}</span>`
      : `<span class="muted">No suitable Java ${data.minimum_major ?? 11}+ runtime detected.</span>`;

    javaNote.textContent = data.note || "";
    if (data.used_disk_cache && !refresh) {
      javaNote.textContent += (javaNote.textContent ? " " : "") + "(Cached scan)";
    }

    const rows = data.runtimes || [];
    _javaLoaded = true;
    if (!rows.length) {
      const empty = document.createElement("div");
      empty.className = "muted small";
      empty.textContent = "No Java installations detected.";
      javaList.appendChild(empty);
      return;
    }

    for (const r of rows) {
      const div = document.createElement("div");
      div.className = "java-row";
      const rec =
        r.path === data.recommended_for_jadx ? ' <span class="muted">(recommended)</span>' : "";
      div.innerHTML = `<div><strong>Java ${r.major}</strong>${rec}</div><div class="muted">${r.path}</div>`;
      javaList.appendChild(div);
    }
  } catch (e) {
    javaNote.textContent = String(e.message || e);
  }
}

async function openSettings() {
  if (!settingsModal) return;
  if (!settingsModal.open) settingsModal.showModal();
  if (!_javaLoaded) {
    await loadJavaRuntimes(false);
  }
  void loadAnalysisTools();
}

function openJobsModal() {
  if (!jobsModal) return;
  if (!jobsModal.open) jobsModal.showModal();
  renderJobsPane();
  loadJobs().catch(() => {});
}

function closeJobsModal() {
  if (jobsModal?.open) jobsModal.close();
}

const analysisToolsList = document.getElementById("analysis-tools-list");
const refreshToolsBtn = document.getElementById("refresh-tools");

const TOOL_LABELS = {
  gitleaks: "Gitleaks",
  trufflehog: "TruffleHog",
  radare2: "radare2 / r2",
};

const TOOL_DESCRIPTIONS = {
  gitleaks: "Pattern-driven secret scanner that runs over the decompiled tree.",
  trufflehog: "Detector-based secret scanner; high signal on common API keys.",
  radare2: "Binary RE toolkit; pulls imports/exports/entries from each .so.",
};

async function loadAnalysisTools() {
  if (!analysisToolsList) return;
  analysisToolsList.innerHTML = "<div class=\"muted small\">Loading…</div>";
  let data;
  try {
    data = await fetchJSON("/api/analysis/tools");
  } catch (e) {
    analysisToolsList.innerHTML = `<div class="muted small">${e.message || e}</div>`;
    return;
  }
  analysisToolsList.innerHTML = "";
  const tools = data.tools || {};
  for (const key of Object.keys(tools)) {
    const t = tools[key];
    const row = document.createElement("div");
    row.className = "analysis-tool-row";

    const top = document.createElement("div");
    top.className = "analysis-tool-top";

    const titleWrap = document.createElement("div");
    titleWrap.className = "analysis-tool-title";
    const name = document.createElement("strong");
    name.textContent = TOOL_LABELS[key] || key;
    titleWrap.appendChild(name);
    const state = document.createElement("span");
    state.className = "analysis-tool-state";
    state.textContent = t.installed
      ? "Installed"
      : t.auto_install
        ? "Not installed"
        : "Not on PATH";
    state.classList.add(t.installed ? "ok" : "warn");
    titleWrap.appendChild(state);
    top.appendChild(titleWrap);

    const toggle = document.createElement("label");
    toggle.className = "analysis-tool-toggle";
    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.checked = !!t.enabled;
    checkbox.addEventListener("change", async () => {
      try {
        await fetchJSON(`/api/analysis/tools/${key}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action: checkbox.checked ? "enable" : "disable" }),
        });
      } catch (e) {
        checkbox.checked = !checkbox.checked;
        await showAlert("Toggle failed", String(e.message || e));
      }
    });
    toggle.appendChild(checkbox);
    const lab = document.createElement("span");
    lab.textContent = "Enabled";
    toggle.appendChild(lab);
    top.appendChild(toggle);
    row.appendChild(top);

    const desc = document.createElement("p");
    desc.className = "muted small";
    desc.textContent = TOOL_DESCRIPTIONS[key] || "";
    row.appendChild(desc);

    if (t.binary_path) {
      const bp = document.createElement("p");
      bp.className = "muted small analysis-tool-path";
      bp.textContent = t.binary_path;
      row.appendChild(bp);
    }

    if (t.auto_install && !t.installed) {
      const install = document.createElement("button");
      install.type = "button";
      install.className = "ghost small";
      install.textContent = "Install";
      install.addEventListener("click", async () => {
        install.disabled = true;
        install.textContent = "Installing…";
        try {
          await fetchJSON(`/api/analysis/tools/${key}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ action: "install" }),
          });
          await loadAnalysisTools();
        } catch (e) {
          await showAlert("Install failed", String(e.message || e));
          install.disabled = false;
          install.textContent = "Install";
        }
      });
      row.appendChild(install);
    }

    analysisToolsList.appendChild(row);
  }
}

if (refreshToolsBtn) {
  refreshToolsBtn.addEventListener("click", () => void loadAnalysisTools());
}

// ---------------------------------------------------------------------------
// Plugin system
// ---------------------------------------------------------------------------

const pluginListEl = document.getElementById("plugin-list");
const pluginsSettingsListEl = document.getElementById("plugins-settings-list");
const refreshPluginsBtn = document.getElementById("refresh-plugins-settings");
const pluginsAddForm = document.getElementById("plugins-add-form");
const pluginsAddStatus = document.getElementById("plg-add-status");

let _pluginsCache = [];
let _pluginsLoadErrors = [];

function pluginAcceptsRule(ruleId) {
  if (!ruleId) return [];
  return _pluginsCache.filter((p) => (p.accepts || []).includes(ruleId));
}

async function loadPlugins() {
  let data;
  try {
    data = await fetchJSON("/api/plugins");
  } catch {
    if (pluginListEl) pluginListEl.textContent = "Failed to load plugins.";
    return;
  }
  _pluginsCache = Array.isArray(data?.plugins) ? data.plugins : [];
  _pluginsLoadErrors = Array.isArray(data?.errors) ? data.errors : [];
  renderPluginSidebar();
  renderPluginsSettings();
  if (typeof refreshAnalysisListInPlace === "function") {
    refreshAnalysisListInPlace();
  }
}

function renderPluginSidebar() {
  if (!pluginListEl) return;
  pluginListEl.innerHTML = "";
  if (!_pluginsCache.length) {
    pluginListEl.classList.add("muted", "small");
    pluginListEl.textContent = "No plugins installed.";
    return;
  }
  pluginListEl.classList.remove("muted", "small");
  for (const plg of _pluginsCache) {
    const row = document.createElement("a");
    row.className = "plugin-sidebar-row";
    row.href = plg.url || `/plugins/${plg.id}`;
    row.title = plg.description || plg.name;
    const name = document.createElement("span");
    name.className = "plugin-sidebar-name";
    name.textContent = plg.name;
    const src = document.createElement("span");
    src.className = `plugin-sidebar-source ${plg.source || "builtin"}`;
    src.textContent = plg.source || "builtin";
    row.appendChild(name);
    row.appendChild(src);
    pluginListEl.appendChild(row);
  }
}

function renderPluginsSettings() {
  if (!pluginsSettingsListEl) return;
  pluginsSettingsListEl.innerHTML = "";
  if (!_pluginsCache.length && !_pluginsLoadErrors.length) {
    const empty = document.createElement("div");
    empty.className = "muted small";
    empty.textContent = "No plugins installed yet.";
    pluginsSettingsListEl.appendChild(empty);
    return;
  }
  for (const plg of _pluginsCache) {
    const row = document.createElement("div");
    row.className = "plugin-settings-row";
    row.innerHTML = `
      <div class="plugin-settings-head">
        <span class="plugin-settings-name">${escapeHtml(plg.name)}</span>
        <span class="plugin-settings-source ${plg.source}">${plg.source}</span>
        <span class="muted small">v${escapeHtml(plg.version || "0.0.0")}</span>
      </div>
      <div class="muted small">${escapeHtml(plg.description || "")}</div>
      <div class="muted small">URL: <code>${escapeHtml(plg.url)}</code> &middot; mode: ${escapeHtml(plg.mode)}</div>
    `;
    const actions = document.createElement("div");
    actions.className = "plugin-settings-actions";
    const open = document.createElement("a");
    open.className = "ghost small";
    open.href = plg.url;
    open.textContent = "Open";
    actions.appendChild(open);
    if (plg.source === "external") {
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "danger small";
      remove.textContent = "Remove";
      remove.addEventListener("click", async () => {
        if (!confirm(`Remove external plugin "${plg.id}"? Server restart required.`)) return;
        try {
          await fetchJSON(`/api/plugins/external/${encodeURIComponent(plg.id)}`, { method: "DELETE" });
          await loadPlugins();
        } catch (e) {
          alert("Remove failed: " + (e?.message || e));
        }
      });
      actions.appendChild(remove);
    }
    row.appendChild(actions);
    pluginsSettingsListEl.appendChild(row);
  }
  if (_pluginsLoadErrors.length) {
    const errBox = document.createElement("div");
    errBox.className = "plugin-settings-errors";
    errBox.innerHTML = "<strong>Load errors:</strong>";
    const ul = document.createElement("ul");
    for (const err of _pluginsLoadErrors) {
      const li = document.createElement("li");
      li.textContent = `${err.source}: ${err.error}`;
      ul.appendChild(li);
    }
    errBox.appendChild(ul);
    pluginsSettingsListEl.appendChild(errBox);
  }
}

if (refreshPluginsBtn) {
  refreshPluginsBtn.addEventListener("click", () => loadPlugins().catch(() => {}));
}

if (pluginsAddForm) {
  pluginsAddForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const body = {
      id: document.getElementById("plg-id").value.trim(),
      name: document.getElementById("plg-name").value.trim(),
      external_path: document.getElementById("plg-path").value.trim() || null,
      module: document.getElementById("plg-module").value.trim() || null,
      blueprint_attr: document.getElementById("plg-bp").value.trim() || "bp",
      mode: document.getElementById("plg-mode").value || "iframe",
      accepts: document.getElementById("plg-accepts").value
        .split(",").map(s => s.trim()).filter(Boolean),
    };
    if (!body.id) {
      pluginsAddStatus.textContent = "ID is required.";
      return;
    }
    if (!body.external_path && !body.module) {
      pluginsAddStatus.textContent = "Provide external_path or module.";
      return;
    }
    pluginsAddStatus.textContent = "Saving...";
    try {
      await fetchJSON("/api/plugins/external", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      pluginsAddStatus.textContent = "Saved. Restart the server to load the new plugin.";
      pluginsAddForm.reset();
      document.getElementById("plg-bp").value = "bp";
      await loadPlugins();
    } catch (e) {
      pluginsAddStatus.textContent = "Failed: " + (e?.message || e);
    }
  });
}

function escapeHtml(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

function closeSettings() {
  if (settingsModal?.open) settingsModal.close();
}

function renderJobs(jobs) {
  jobList.innerHTML = "";
  for (const j of jobs) {
    const div = document.createElement("div");
    div.className = "job-item" + (j.id === selectedJobId ? " active" : "");
    div.dataset.jobId = j.id;

    const top = document.createElement("div");
    top.className = "job-item-top";

    const name = document.createElement("div");
    name.className = "job-name";
    name.textContent = j.original_filename || j.id;

    if ((j.analysis_high_count || 0) > 0) {
      const dot = document.createElement("span");
      dot.className = "job-finding-dot";
      dot.title = `${j.analysis_high_count} high-severity finding${j.analysis_high_count === 1 ? "" : "s"}`;
      name.prepend(dot);
    }

    const badge = document.createElement("span");
    badge.className = `badge ${badgeClass(j.status)}`;
    badge.textContent = j.status || "unknown";

    top.appendChild(name);
    top.appendChild(badge);

    const meta = document.createElement("div");
    meta.className = "job-meta muted small";

    const left = document.createElement("span");
    left.textContent = formatTime(j.created_at);

    const right = document.createElement("span");
    right.textContent = j.id.slice(0, 8);

    meta.appendChild(left);
    meta.appendChild(right);

    div.appendChild(top);
    div.appendChild(meta);

    const actions = document.createElement("div");
    actions.className = "job-actions";

    const logBtn = document.createElement("button");
    logBtn.type = "button";
    logBtn.className = "ghost small";
    logBtn.textContent = "Log";
    logBtn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      showLogModal(j.id, j.original_filename || j.id.slice(0, 8)).catch(() => {});
    });

    const dlBtn = document.createElement("button");
    dlBtn.type = "button";
    dlBtn.className = "ghost small";
    dlBtn.textContent = "ZIP";
    dlBtn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      downloadJobZipWithProgress(j.id, j.original_filename || j.id.slice(0, 8)).catch(() => {});
    });

    const delBtn = document.createElement("button");
    delBtn.type = "button";
    delBtn.className = "ghost small danger";
    delBtn.textContent = "Delete";
    delBtn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      deleteJobById(j.id, j.original_filename || j.id.slice(0, 8)).catch(() => {});
    });

    actions.appendChild(logBtn);
    actions.appendChild(dlBtn);
    actions.appendChild(delBtn);
    div.appendChild(actions);

    div.addEventListener("click", () => selectJob(j.id));
    jobList.appendChild(div);
  }
}

function filteredJobsForPane() {
  const q = (jobsPaneSearchInput?.value || "").trim().toLowerCase();
  if (!q) return _allJobs;
  return _allJobs.filter((j) => {
    const fields = [
      j.original_filename,
      j.id,
      j.status,
      j.analysis_status,
      j.error_message,
    ];
    return fields.some((v) => String(v || "").toLowerCase().includes(q));
  });
}

function renderJobsPane() {
  if (!jobsPaneList) return;
  const jobs = filteredJobsForPane();
  jobsPaneList.innerHTML = "";
  if (!jobs.length) {
    jobsPaneList.textContent = _allJobs.length ? "No jobs match the filter." : "No jobs yet.";
    return;
  }

  for (const j of jobs) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "jobs-pane-row" + (j.id === _jobsPaneSelectedId ? " active" : "");
    row.dataset.jobId = j.id;

    const title = document.createElement("div");
    title.className = "jobs-pane-row-title";
    const name = document.createElement("strong");
    name.textContent = j.original_filename || j.id;
    title.appendChild(name);

    const status = document.createElement("span");
    status.className = `badge ${badgeClass(j.status)}`;
    status.textContent = j.status || "unknown";
    title.appendChild(status);
    row.appendChild(title);

    const meta = document.createElement("div");
    meta.className = "jobs-pane-row-meta muted small";
    const analysis = j.analysis_status ? `analysis: ${j.analysis_status}` : "analysis: none";
    const highs = (j.analysis_high_count || 0) > 0 ? ` · high: ${j.analysis_high_count}` : "";
    meta.textContent = `${formatTime(j.created_at)} · ${j.id.slice(0, 8)} · ${analysis}${highs}`;
    row.appendChild(meta);

    if (j.error_message) {
      const err = document.createElement("div");
      err.className = "jobs-pane-error small";
      err.textContent = j.error_message;
      row.appendChild(err);
    }

    row.addEventListener("click", () => {
      _jobsPaneSelectedId = j.id;
      renderJobsPane();
      loadJobLogInPane(j.id, j.original_filename || j.id.slice(0, 8)).catch(() => {});
    });
    jobsPaneList.appendChild(row);
  }
}

async function loadJobLogInPane(jobId, label) {
  if (!jobsLogText || !jobsLogTitle || !jobsLogRefreshBtn) return;
  jobsLogRefreshBtn.disabled = true;
  jobsLogTitle.textContent = `Loading log - ${label || jobId.slice(0, 8)}`;
  jobsLogText.textContent = "Loading...";
  try {
    const data = await fetchJSON(`/api/jobs/${jobId}/log`);
    jobsLogTitle.textContent = `Job log - ${label || jobId.slice(0, 8)}`;
    jobsLogText.textContent = data.log && data.log.length ? data.log : "(empty)";
  } catch (e) {
    jobsLogTitle.textContent = "Log failed";
    jobsLogText.textContent = String(e.message || e);
  } finally {
    jobsLogRefreshBtn.disabled = false;
  }
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

function startPolling(jobId) {
  stopPolling();
  pollTimer = setInterval(async () => {
    try {
      const meta = await fetchJSON(`/api/jobs/${jobId}`);
      updateJobHeader(meta);
      if (isTerminalStatus(meta.status)) {
        stopPolling();
        await loadJobs();
        if (hasOutput(meta.status)) {
          await loadTree(jobId, meta);
          setAnalysisTabEnabled(true, meta.analysis_high_count || 0);
          void refreshAnalysisStatus(jobId);
        } else {
          treeRoot.textContent = "Decompile failed. Open Log for details.";
        }
      }
    } catch {
      stopPolling();
    }
  }, 1200);
}

function updateJobHeader(meta) {
  jobTitle.textContent = meta.original_filename || meta.id;
  jobBadge.textContent = meta.status || "";
  jobBadge.className = `badge ${badgeClass(meta.status)}`;
}

function setToolbarEnabled(enabled) {
  btnLog.disabled = !enabled;
  btnDelete.disabled = !enabled;
  btnDownload.disabled = !enabled;
}

async function selectJob(jobId) {
  selectedJobId = jobId;
  clearOpenTabs();
  hideTreeProgress();
  resetAnalysisUI();
  if (treeSearchInput) {
    treeSearchInput.value = "";
    treeSearchInput.disabled = true;
  }
  if (treeSearchStatus) treeSearchStatus.textContent = "";
  treeRoot.innerHTML = "";
  treeRoot.textContent = "Loading...";

  await loadJobs();

  try {
    const meta = await fetchJSON(`/api/jobs/${jobId}`);
    updateJobHeader(meta);
    setToolbarEnabled(true);

    if (meta.status === "running" || meta.status === "queued") {
      startPolling(jobId);
    } else {
      stopPolling();
    }

    if (hasOutput(meta.status)) {
      await loadTree(jobId, meta);
      setAnalysisTabEnabled(true, meta.analysis_high_count || 0);
      void refreshAnalysisStatus(jobId);
    } else {
      treeRoot.textContent =
        meta.status === "failed"
          ? "Decompile failed. Open Log for details."
          : "Decompile in progress...";
    }
  } catch (e) {
    treeRoot.textContent = String(e.message || e);
    setToolbarEnabled(false);
  }
}

function guessLanguage(path) {
  const lower = path.toLowerCase();
  const ext = lower.includes(".") ? lower.split(".").pop() : "";
  const map = {
    java: "java",
    kt: "kotlin",
    kts: "kotlin",
    xml: "xml",
    smali: "plaintext",
    json: "json",
    md: "markdown",
    gradle: "groovy",
    properties: "ini",
    yml: "yaml",
    yaml: "yaml",
    py: "python",
    txt: "plaintext",
    mf: "plaintext",
    sf: "plaintext",
    rsa: "plaintext",
    dex: "plaintext",
    so: "plaintext",
  };
  return map[ext] || "plaintext";
}

const FILE_ICON_BASE = "https://cdn.jsdelivr.net/npm/material-icon-theme@5/icons";

function fileIconName(path) {
  const lower = (path || "").toLowerCase();
  const baseName = lower.split("/").pop() || lower;
  const ext = baseName.includes(".") ? baseName.split(".").pop() : "";
  const byExt = {
    java: "java",
    class: "java",
    jar: "java",
    kt: "kotlin",
    kts: "kotlin",
    xml: "xml",
    html: "xml",
    json: "json",
    yml: "yaml",
    yaml: "yaml",
    md: "markdown",
    markdown: "markdown",
    gradle: "gradle",
    properties: "settings",
    cfg: "settings",
    ini: "settings",
    toml: "settings",
    smali: "assembly",
    dex: "assembly",
    so: "file",
    apk: "android",
    aar: "android",
    txt: "document",
    log: "log",
    pem: "key",
    key: "key",
    crt: "certificate",
    cer: "certificate",
    rsa: "key",
    sf: "certificate",
    mf: "settings",
    ttf: "font",
    otf: "font",
    woff: "font",
    woff2: "font",
    mp3: "audio",
    wav: "audio",
    ogg: "audio",
    flac: "audio",
    mp4: "video",
    webm: "video",
    mov: "video",
    png: "image",
    jpg: "image",
    jpeg: "image",
    gif: "image",
    webp: "image",
    bmp: "image",
    ico: "image",
    svg: "svg",
    pdf: "pdf",
    db: "database",
    sql: "database",
    sqlite: "database",
  };
  return byExt[ext] || "file";
}

function fileIconUrl(path) {
  return `${FILE_ICON_BASE}/${fileIconName(path)}.svg`;
}

function countTreeNodes(node) {
  if (!node) return 0;
  let count = 1;
  if (node.type === "dir" && node.children) {
    for (const ch of node.children) count += countTreeNodes(ch);
  }
  return count;
}

function buildFileRow(node, jobId, depth) {
  const row = document.createElement("div");
  row.className = "tree-row file";
  row.dataset.path = node.path || "";
  row.style.setProperty("--depth", String(depth));

  const toggle = document.createElement("span");
  toggle.className = "tree-toggle";
  row.appendChild(toggle);

  const icon = document.createElement("span");
  icon.className = "tree-icon file-icon";
  icon.style.backgroundImage = `url("${fileIconUrl(node.path || node.name)}")`;
  row.appendChild(icon);

  const label = document.createElement("span");
  label.className = "tree-label";
  label.textContent = node.name || node.path;
  label.title = node.path || node.name || "";
  row.appendChild(label);

  if (node.path) {
    const dl = document.createElement("a");
    dl.className = "tree-download";
    dl.href = `/api/jobs/${jobId}/raw?path=${encodeURIComponent(node.path)}`;
    dl.title = `Download ${node.name || node.path}`;
    dl.setAttribute("aria-label", `Download ${node.name || node.path}`);
    dl.textContent = "\u2B07"; // ⬇
    dl.addEventListener("click", (ev) => ev.stopPropagation());
    row.appendChild(dl);
  }

  row.addEventListener("click", async (ev) => {
    ev.stopPropagation();
    await openFile(node.path);
  });
  return row;
}

function buildDirNode(node, depth) {
  // Root (depth 0) and the first inner level start expanded so the user
  // sees something immediately; anything deeper starts collapsed.
  const startCollapsed = depth >= 2;

  const wrap = document.createElement("div");
  wrap.className = "tree-node" + (startCollapsed ? " collapsed" : "");

  const header = document.createElement("div");
  header.className = "tree-row dir";
  header.style.setProperty("--depth", String(depth));

  const toggle = document.createElement("span");
  toggle.className = "tree-toggle";
  toggle.textContent = startCollapsed ? "+" : "-";
  header.appendChild(toggle);

  const icon = document.createElement("span");
  icon.className = "tree-icon dir-icon";
  header.appendChild(icon);

  const label = document.createElement("span");
  label.className = "tree-label";
  label.textContent = node.name || "/";
  header.appendChild(label);

  header.addEventListener("click", (ev) => {
    ev.stopPropagation();
    const nowCollapsed = wrap.classList.toggle("collapsed");
    toggle.textContent = nowCollapsed ? "+" : "-";
  });

  wrap.appendChild(header);

  const childrenContainer = document.createElement("div");
  childrenContainer.className = "tree-children";
  wrap.appendChild(childrenContainer);

  return { wrap, childrenContainer };
}

function showTreeProgress(text, fraction) {
  if (!treeProgress) return;
  treeProgress.classList.remove("hidden");
  if (treeProgressText) treeProgressText.textContent = text;
  if (treeProgressBar) {
    if (fraction == null) {
      treeProgressBar.classList.add("indeterminate");
      treeProgressBar.style.width = "";
    } else {
      treeProgressBar.classList.remove("indeterminate");
      const pct = Math.max(0, Math.min(1, fraction)) * 100;
      treeProgressBar.style.width = `${pct.toFixed(1)}%`;
    }
  }
}

function hideTreeProgress() {
  if (treeProgress) treeProgress.classList.add("hidden");
}

function nextFrame() {
  return new Promise((r) => requestAnimationFrame(() => r()));
}

async function renderTreeChunked(rootNode, container, jobId, token) {
  // Iterative DFS so we keep alphabetic / priority order from the server.
  // Each entry: { node, parent (DOM), depth }
  const rootKids = rootNode?.type === "dir" ? rootNode.children || [] : [];
  const stack = rootKids.length
    ? rootKids.slice().reverse().map((node) => ({ node, parent: container, depth: 0 }))
    : [{ node: rootNode, parent: container, depth: 0 }];
  const total = countTreeNodes(rootNode);
  let processed = 0;
  const BATCH = 400;

  while (stack.length) {
    if (token !== _treeRenderToken) return;
    let batch = 0;
    while (stack.length && batch < BATCH) {
      const { node, parent, depth } = stack.pop();
      if (node.type === "file") {
        parent.appendChild(buildFileRow(node, jobId, depth));
      } else {
        const { wrap, childrenContainer } = buildDirNode(node, depth);
        parent.appendChild(wrap);
        const kids = node.children || [];
        for (let i = kids.length - 1; i >= 0; i--) {
          stack.push({ node: kids[i], parent: childrenContainer, depth: depth + 1 });
        }
      }
      processed++;
      batch++;
    }
    showTreeProgress(
      `Rendering tree... ${processed.toLocaleString()} / ${total.toLocaleString()} nodes`,
      processed / Math.max(1, total),
    );
    await nextFrame();
  }
}

async function loadTree(jobId, meta) {
  const token = ++_treeRenderToken;
  treeRoot.innerHTML = "";
  if (treeSearchInput) {
    treeSearchInput.value = "";
    treeSearchInput.disabled = true;
  }
  if (treeSearchStatus) treeSearchStatus.textContent = "";

  showTreeProgress("Fetching file tree from server...", null);

  let data;
  try {
    data = await fetchJSON(`/api/jobs/${jobId}/tree`);
  } catch (e) {
    if (token !== _treeRenderToken) return;
    hideTreeProgress();
    treeRoot.textContent = String(e.message || e);
    return;
  }
  if (token !== _treeRenderToken) return;

  if (meta && meta.status === "done_with_errors" && meta.error_message) {
    const banner = document.createElement("div");
    banner.className = "warn small";
    banner.style.padding = "6px 8px";
    banner.style.border = "1px solid rgba(204, 167, 0, 0.35)";
    banner.style.borderRadius = "6px";
    banner.style.marginBottom = "8px";
    banner.textContent = `Finished with warnings: ${meta.error_message}`;
    treeRoot.appendChild(banner);
  }
  if (data.truncated) {
    const warn = document.createElement("div");
    warn.className = "muted small";
    warn.style.padding = "6px";
    warn.textContent = `Warning: file tree was truncated at ${data.max_nodes ?? "the node"} limit.`;
    treeRoot.appendChild(warn);
  }

  const holder = document.createElement("div");
  treeRoot.appendChild(holder);

  showTreeProgress("Rendering tree...", 0);
  await renderTreeChunked(data.tree, holder, jobId, token);
  if (token !== _treeRenderToken) return;

  hideTreeProgress();
  if (treeSearchInput) treeSearchInput.disabled = false;
  if (treeSearchStatus) {
    treeSearchStatus.textContent = `${(data.node_count ?? "?").toLocaleString?.() ?? data.node_count} entries`;
  }
}

function applyTreeSearch(query) {
  const q = (query || "").trim().toLowerCase();
  const allNodes = treeRoot.querySelectorAll(".tree-node, .tree-row.file");

  if (!q) {
    allNodes.forEach((el) => {
      el.removeAttribute("data-search-hidden");
      el.style.display = "";
    });
    if (treeSearchStatus) {
      const fileCount = treeRoot.querySelectorAll(".tree-row.file").length;
      treeSearchStatus.textContent = `${fileCount.toLocaleString()} entries`;
    }
    return;
  }

  allNodes.forEach((el) => {
    el.setAttribute("data-search-hidden", "1");
    el.style.display = "none";
  });

  const files = treeRoot.querySelectorAll(".tree-row.file");
  let visible = 0;
  files.forEach((row) => {
    const path = (row.dataset.path || "").toLowerCase();
    const label = (row.querySelector(".tree-label")?.textContent || "").toLowerCase();
    if (path.includes(q) || label.includes(q)) {
      visible++;
      row.removeAttribute("data-search-hidden");
      row.style.display = "";
      let p = row.parentElement;
      while (p && p !== treeRoot) {
        if (p.classList.contains("tree-node")) {
          p.removeAttribute("data-search-hidden");
          p.style.display = "";
          p.classList.remove("collapsed");
          const t = p.querySelector(":scope > .tree-row.dir > .tree-toggle");
          if (t) t.textContent = "-";
        }
        p = p.parentElement;
      }
    }
  });

  if (treeSearchStatus) {
    treeSearchStatus.textContent = `${visible.toLocaleString()} match${visible === 1 ? "" : "es"}`;
  }
}

async function openFile(relPath) {
  if (!selectedJobId) return;
  if (!editorReady || !editor || !window.monaco) {
    editorStatus.textContent = "Editor is still loading. Try again in a moment.";
    return;
  }

  activePath = relPath;

  const existing = openTabs.get(relPath);
  if (existing) {
    editor.setModel(existing.model);
    renderTabs();
    editorStatus.textContent = "";
    return;
  }

  editorStatus.textContent = "Loading file…";
  let payload;
  try {
    payload = await fetchJSON(`/api/jobs/${selectedJobId}/file?path=${encodeURIComponent(relPath)}`);
  } catch (e) {
    editorStatus.textContent = String(e.message || e);
    return;
  }

  const lang = guessLanguage(payload.path || relPath);
  let value = payload.text;
  if (value == null) {
    value = payload.binary_note || "Binary file.";
    editorStatus.textContent = payload.binary_note || "Cannot display this file as text.";
  } else {
    editorStatus.textContent = payload.binary_note || "";
  }

  const uri = window.monaco.Uri.parse(`inmemory:/${relPath.replace(/\\/g, "/")}`);
  const model = window.monaco.editor.createModel(value, lang, uri);
  openTabs.set(relPath, { model });
  openTabOrder.push(relPath);
  editor.setModel(model);
  renderTabs();
}

function closeTab(path) {
  const entry = openTabs.get(path);
  if (!entry) return;
  try {
    entry.model.dispose();
  } catch {
    /* ignore */
  }
  openTabs.delete(path);
  openTabOrder = openTabOrder.filter((p) => p !== path);

  if (activePath === path) {
    activePath = openTabOrder[openTabOrder.length - 1] || null;
    if (activePath) {
      const next = openTabs.get(activePath);
      if (next && editor) editor.setModel(next.model);
    } else if (editor) {
      editor.setModel(null);
      editorStatus.textContent = "";
    }
  }
  renderTabs();
}

function clearOpenTabs() {
  for (const { model } of openTabs.values()) {
    try {
      model.dispose();
    } catch {
      /* ignore */
    }
  }
  openTabs.clear();
  openTabOrder = [];
  activePath = null;
  tabsEl.innerHTML = "";
  editorStatus.textContent = "";
  if (editorReady && editor) editor.setModel(null);
}

function renderTabs() {
  tabsEl.innerHTML = "";
  for (const path of openTabOrder) {
    const tab = openTabs.get(path);
    if (!tab) continue;

    const wrap = document.createElement("span");
    wrap.className = "tab" + (path === activePath ? " active" : "");
    wrap.title = path;

    const label = document.createElement("span");
    label.className = "tab-label";
    label.textContent = path.split("/").pop() || path;
    label.addEventListener("click", () => {
      activePath = path;
      const latest = openTabs.get(path);
      if (latest && editor) editor.setModel(latest.model);
      renderTabs();
    });

    const close = document.createElement("button");
    close.type = "button";
    close.className = "tab-close";
    close.setAttribute("aria-label", `Close ${label.textContent}`);
    close.textContent = "x";
    close.addEventListener("click", (ev) => {
      ev.stopPropagation();
      closeTab(path);
    });

    wrap.appendChild(label);
    wrap.appendChild(close);

    // Middle-click anywhere on the tab closes it too.
    wrap.addEventListener("mousedown", (ev) => {
      if (ev.button === 1) {
        ev.preventDefault();
        closeTab(path);
      }
    });

    tabsEl.appendChild(wrap);
  }
}

async function uploadFile(file) {
  uploadStatus.textContent = "";
  const fd = new FormData();
  fd.append("file", file);
  uploadStatus.textContent = "Uploading…";
  try {
    const res = await fetch("/api/upload", { method: "POST", body: fd, credentials: "same-origin" });
    const text = await res.text();
    const data = text ? JSON.parse(text) : null;
    if (!res.ok) throw new Error(data?.error || text || `HTTP ${res.status}`);
    uploadStatus.textContent = "Queued.";
    await loadJobs();
    await selectJob(data.job_id);
  } catch (e) {
    uploadStatus.textContent = String(e.message || e);
  }
}

async function deleteJobById(jobId, label) {
  const ok = await showConfirm(
    "Delete job",
    `Delete ${label || jobId.slice(0, 8)} and all decompiled files? This cannot be undone.`,
    { confirmLabel: "Delete", danger: true },
  );
  if (!ok) return;

  try {
    await fetchJSON(`/api/jobs/${jobId}`, { method: "DELETE" });
  } catch (e) {
    await showAlert("Delete failed", String(e.message || e));
    return;
  }

  if (selectedJobId === jobId) {
    selectedJobId = null;
    stopPolling();
    clearOpenTabs();
    hideTreeProgress();
    if (treeSearchInput) {
      treeSearchInput.value = "";
      treeSearchInput.disabled = true;
    }
    if (treeSearchStatus) treeSearchStatus.textContent = "";
    jobTitle.textContent = "Select a job";
    jobBadge.textContent = "";
    jobBadge.className = "badge muted";
    treeRoot.innerHTML = "";
    treeRoot.textContent = "Select a job to load the file tree.";
    setToolbarEnabled(false);
  }
  await loadJobs();
}

async function deleteSelectedJob() {
  if (!selectedJobId) return;
  await deleteJobById(selectedJobId, jobTitle.textContent);
}

async function showLog() {
  if (!selectedJobId) return;
  await showLogModal(selectedJobId, jobTitle.textContent);
}

function setupDropzone() {
  dropzone.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", () => {
    const f = fileInput.files && fileInput.files[0];
    if (f) uploadFile(f);
    fileInput.value = "";
  });

  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
  });
  dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    const f = e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) uploadFile(f);
  });
}

function setupMonaco() {
  const base = "https://cdn.jsdelivr.net/npm/monaco-editor@0.50.0/min/vs";

  self.MonacoEnvironment = {
    getWorkerUrl(_workerId, label) {
      if (label === "json") return `${base}/language/json/json.worker.js`;
      if (label === "css" || label === "scss" || label === "less") return `${base}/language/css/css.worker.js`;
      if (label === "html" || label === "handlebars" || label === "razor") return `${base}/language/html/html.worker.js`;
      if (label === "typescript" || label === "javascript") return `${base}/language/typescript/ts.worker.js`;
      return `${base}/editor/editor.worker.js`;
    },
  };

  require.config({ paths: { vs: `${base}` } });
  require(["vs/editor/editor.main"], () => {
    editor = monaco.editor.create(editorMount, {
      automaticLayout: true,
      readOnly: true,
      minimap: { enabled: true },
      fontSize: 13,
      scrollBeyondLastLine: false,
      wordWrap: "on",
      theme: "vs-dark",
    });
    editorReady = true;
    editorStatus.textContent = "";
  });
}

// ---------------------------------------------------------------------------
// Analysis tab
// ---------------------------------------------------------------------------

const paneTabButtons = document.querySelectorAll(".pane-tab");
const paneSections = document.querySelectorAll(".pane-section");
const analysisTabBtn = document.querySelector('.pane-tab[data-pane-tab="analysis"]');
const analysisTabBadge = document.getElementById("analysis-tab-badge");
const analysisSummaryEl = document.getElementById("analysis-summary");
const analysisListEl = document.getElementById("analysis-list");
const analysisEmptyEl = document.getElementById("analysis-empty");
const analysisRerunBtn = document.getElementById("analysis-rerun");
const analysisStatusText = document.getElementById("analysis-status-text");
const analysisProgressWrap = document.getElementById("analysis-progress");
const analysisProgressBar = document.getElementById("analysis-progress-bar");
const analysisProgressText = document.getElementById("analysis-progress-text");
const analysisProgressPhase = document.getElementById("analysis-progress-phase");
const analysisLogWrap = document.getElementById("analysis-log-wrap");
const analysisLogEl = document.getElementById("analysis-log");
const analysisLogMeta = document.getElementById("analysis-log-meta");
let _analysisLogFrozen = false;
let _analysisLogLastBytes = 0;
const analysisSeverityFilter = document.getElementById("analysis-severity");
const analysisCategoryFilter = document.getElementById("analysis-category");
const analysisSearchInput = document.getElementById("analysis-search");
const analysisLoadMoreWrap = document.getElementById("analysis-load-more-wrap");
const analysisLoadMoreBtn = document.getElementById("analysis-load-more");

function switchPaneTab(name) {
  _activePaneTab = name;
  paneTabButtons.forEach((btn) => {
    const active = btn.dataset.paneTab === name;
    btn.classList.toggle("active", active);
    btn.setAttribute("aria-selected", active ? "true" : "false");
  });
  paneSections.forEach((sec) => {
    sec.classList.toggle("hidden", sec.dataset.paneSection !== name);
  });
  if (name === "analysis") {
    void refreshAnalysisIfNeeded();
  } else if (name === "editor" && editor) {
    requestAnimationFrame(() => {
      try {
        editor.layout();
      } catch {
        /* ignore */
      }
    });
  }
}

paneTabButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    if (btn.disabled) return;
    switchPaneTab(btn.dataset.paneTab);
  });
});

function setAnalysisTabEnabled(enabled, highCount = 0) {
  if (!analysisTabBtn) return;
  analysisTabBtn.disabled = !enabled;
  if (!enabled) {
    if (analysisTabBadge) {
      analysisTabBadge.textContent = "0";
      analysisTabBadge.classList.add("hidden");
    }
    if (_activePaneTab === "analysis") {
      switchPaneTab("editor");
    }
    return;
  }
  if (analysisTabBadge) {
    if (highCount > 0) {
      analysisTabBadge.textContent = highCount > 999 ? "999+" : String(highCount);
      analysisTabBadge.classList.remove("hidden");
      analysisTabBadge.classList.add("danger");
    } else {
      analysisTabBadge.classList.add("hidden");
      analysisTabBadge.classList.remove("danger");
    }
  }
}

function setAnalysisRerunEnabled(enabled) {
  if (analysisRerunBtn) analysisRerunBtn.disabled = !enabled;
}

function renderAnalysisSummary(summary) {
  if (!analysisSummaryEl) return;
  analysisSummaryEl.innerHTML = "";
  if (!summary || !summary.findings_count && summary.findings_count !== 0) {
    return;
  }
  const sev = summary.by_severity || {};
  const cards = [
    { label: "Findings", value: summary.findings_count ?? 0, tone: "neutral" },
    { label: "High", value: sev.high ?? 0, tone: "high" },
    { label: "Medium", value: sev.medium ?? 0, tone: "medium" },
    { label: "Low", value: sev.low ?? 0, tone: "low" },
    { label: "Files", value: summary.files_scanned ?? 0, tone: "neutral" },
    { label: "Duration", value: `${(summary.duration_sec ?? 0).toFixed(1)}s`, tone: "neutral" },
  ];
  for (const card of cards) {
    const c = document.createElement("div");
    c.className = `analysis-card analysis-card-${card.tone}`;
    const v = document.createElement("div");
    v.className = "analysis-card-value";
    v.textContent = card.value;
    const l = document.createElement("div");
    l.className = "analysis-card-label";
    l.textContent = card.label;
    c.appendChild(v);
    c.appendChild(l);
    analysisSummaryEl.appendChild(c);
  }
}

function findingFileLabel(path) {
  if (!path) return "(unknown)";
  const parts = path.split("/");
  if (parts.length <= 3) return path;
  return ".../" + parts.slice(-3).join("/");
}

function severityRank(s) {
  return { high: 3, medium: 2, low: 1, info: 0 }[s] ?? -1;
}

function buildFindingRow(item) {
  const row = document.createElement("div");
  row.className = `finding finding-${item.severity || "info"}`;
  row.dataset.findingId = item.id || "";

  const head = document.createElement("div");
  head.className = "finding-head";

  const sev = document.createElement("span");
  sev.className = `finding-sev sev-${item.severity || "info"}`;
  sev.textContent = (item.severity || "info").toUpperCase();
  head.appendChild(sev);

  const title = document.createElement("span");
  title.className = "finding-title";
  title.textContent = item.title || item.rule_id || "Finding";
  head.appendChild(title);

  const rule = document.createElement("span");
  rule.className = "finding-rule muted small";
  rule.textContent = item.rule_id || "";
  head.appendChild(rule);

  const match = document.createElement("div");
  match.className = "finding-match";
  match.textContent = item.match || "";

  const loc = document.createElement("div");
  loc.className = "finding-loc muted small";
  const fileLabel = document.createElement("a");
  fileLabel.href = "#";
  fileLabel.className = "finding-link";
  fileLabel.title = item.file || "";
  fileLabel.textContent = findingFileLabel(item.file || "");
  fileLabel.addEventListener("click", (ev) => {
    ev.preventDefault();
    void jumpToFinding(item);
  });
  loc.appendChild(fileLabel);
  if (item.line && item.line > 0) {
    const line = document.createElement("span");
    line.textContent = `  line ${item.line}`;
    loc.appendChild(line);
  }
  if (item.tool && item.tool !== "regex") {
    const tool = document.createElement("span");
    tool.className = "finding-tool";
    tool.textContent = item.tool;
    loc.appendChild(tool);
  }

  if (item.snippet) {
    const snip = document.createElement("pre");
    snip.className = "finding-snippet";
    snip.textContent = item.snippet;
    row.appendChild(head);
    row.appendChild(match);
    row.appendChild(loc);
    row.appendChild(snip);
  } else {
    row.appendChild(head);
    row.appendChild(match);
    row.appendChild(loc);
  }

  row.addEventListener("click", () => {
    void jumpToFinding(item);
  });

  return row;
}

function renderAnalysisList(state) {
  if (!analysisListEl) return;
  analysisListEl.innerHTML = "";
  const items = state.findings || [];
  if (!items.length) {
    if (analysisEmptyEl) {
      analysisEmptyEl.classList.remove("hidden");
      analysisEmptyEl.textContent = state.summary && state.summary.findings_count
        ? "No findings match the current filters."
        : "No findings yet.";
    }
    if (analysisLoadMoreWrap) analysisLoadMoreWrap.classList.add("hidden");
    return;
  }
  if (analysisEmptyEl) analysisEmptyEl.classList.add("hidden");

  const frag = document.createDocumentFragment();
  for (const item of items) {
    frag.appendChild(buildFindingRow(item));
  }
  analysisListEl.appendChild(frag);

  if (analysisLoadMoreWrap) {
    if (items.length < (state.total || 0)) {
      analysisLoadMoreWrap.classList.remove("hidden");
    } else {
      analysisLoadMoreWrap.classList.add("hidden");
    }
  }
}

function currentAnalysisFilters() {
  return {
    severity: analysisSeverityFilter?.value || "",
    category: analysisCategoryFilter?.value || "",
    q: (analysisSearchInput?.value || "").trim(),
  };
}

async function fetchAnalysisPage(jobId, offset, limit) {
  const params = new URLSearchParams();
  const filters = currentAnalysisFilters();
  if (filters.severity) params.set("severity", filters.severity);
  if (filters.category) params.set("category", filters.category);
  if (filters.q) params.set("q", filters.q);
  params.set("limit", String(limit));
  params.set("offset", String(offset));
  return fetchJSON(`/api/jobs/${jobId}/analysis?${params.toString()}`);
}

async function loadAnalysisForJob(jobId, { force = false } = {}) {
  if (!jobId) return;
  if (!force && _analysisCache && _analysisCache.jobId === jobId && !_analysisFiltersDirty) {
    return;
  }
  if (analysisEmptyEl) {
    analysisEmptyEl.classList.remove("hidden");
    analysisEmptyEl.textContent = "Loading analysis…";
  }
  if (analysisListEl) analysisListEl.innerHTML = "";

  let summary = null;
  try {
    summary = await fetchJSON(`/api/jobs/${jobId}/analysis/summary`);
  } catch {
    summary = null;
  }

  let page = { total: 0, findings: [] };
  try {
    page = await fetchAnalysisPage(jobId, 0, _analysisPageSize);
  } catch (e) {
    if (analysisEmptyEl) {
      analysisEmptyEl.classList.remove("hidden");
      analysisEmptyEl.textContent = String(e.message || e);
    }
    return;
  }

  _analysisCache = {
    jobId,
    summary: summary || {},
    findings: page.findings || [],
    total: page.total || 0,
    offset: page.findings ? page.findings.length : 0,
  };
  _analysisFiltersDirty = false;
  renderAnalysisSummary(summary || {});
  renderAnalysisList(_analysisCache);
  setAnalysisExportEnabled(!!(summary && (summary.findings_count ?? 0) > 0));
}

async function loadMoreAnalysis() {
  if (!_analysisCache) return;
  try {
    const page = await fetchAnalysisPage(
      _analysisCache.jobId,
      _analysisCache.offset,
      _analysisPageSize,
    );
    _analysisCache.findings.push(...(page.findings || []));
    _analysisCache.offset += page.findings ? page.findings.length : 0;
    _analysisCache.total = page.total || _analysisCache.total;
    renderAnalysisList(_analysisCache);
  } catch (e) {
    await showAlert("Load more failed", String(e.message || e));
  }
}

async function refreshAnalysisIfNeeded() {
  if (!selectedJobId) return;
  if (!_analysisCache || _analysisCache.jobId !== selectedJobId || _analysisFiltersDirty) {
    await loadAnalysisForJob(selectedJobId);
  }
}

function setAnalysisProgress(progress) {
  if (!analysisProgressWrap || !analysisProgressBar || !analysisProgressText) return;
  if (!progress) {
    analysisProgressWrap.classList.add("hidden");
    return;
  }
  const done = progress.files_done || 0;
  const total = progress.files_total || 0;
  const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;
  analysisProgressBar.style.width = `${pct || 5}%`;
  analysisProgressBar.classList.toggle("indeterminate", total === 0);
  const phaseLabel = progress.phase_label
    || ({ discover: "Discovering files", global: "Manifest / global scanners", scan: "Scanning files" }[progress.phase] || "Working…");
  if (analysisProgressPhase) {
    analysisProgressPhase.textContent = `Phase: ${phaseLabel}`;
  }
  let line = total
    ? `${done.toLocaleString()} / ${total.toLocaleString()} files (${pct}%)`
    : "Preparing…";
  if (progress.findings_so_far) {
    line += ` · ${progress.findings_so_far} findings so far`;
  }
  if (progress.files_per_sec) {
    line += ` · ${progress.files_per_sec} files/s`;
  }
  analysisProgressText.textContent = line;
  analysisProgressWrap.classList.remove("hidden");
}

function showAnalysisLogWrap() {
  if (!analysisLogWrap) return;
  analysisLogWrap.classList.remove("hidden");
  if (!analysisLogWrap.open) analysisLogWrap.open = true;
}

function hideAnalysisLogWrap() {
  if (!analysisLogWrap) return;
  analysisLogWrap.classList.add("hidden");
}

function resetAnalysisLog() {
  _analysisLogFrozen = false;
  _analysisLogLastBytes = 0;
  if (analysisLogEl) analysisLogEl.textContent = "";
  if (analysisLogMeta) analysisLogMeta.textContent = "";
  hideAnalysisLogWrap();
}

function renderAnalysisLog(text, { live = false } = {}) {
  if (!analysisLogEl) return;
  const wasAtBottom =
    analysisLogEl.scrollHeight - analysisLogEl.scrollTop - analysisLogEl.clientHeight < 40;
  analysisLogEl.textContent = text || "";
  if (analysisLogMeta) {
    if (live) {
      analysisLogMeta.textContent = "streaming…";
      analysisLogMeta.classList.add("ok");
    } else {
      analysisLogMeta.textContent = "finished";
      analysisLogMeta.classList.remove("ok");
    }
  }
  if (wasAtBottom && !_analysisLogFrozen) {
    analysisLogEl.scrollTop = analysisLogEl.scrollHeight;
  }
}

async function fetchAnalysisLog(jobId) {
  if (!jobId) return null;
  try {
    return await fetchJSON(`/api/jobs/${jobId}/analysis/log?tail_bytes=131072`);
  } catch {
    return null;
  }
}

async function refreshAnalysisLog(jobId, { live }) {
  const data = await fetchAnalysisLog(jobId);
  if (!data) return;
  if (!data.log) {
    if (live) {
      showAnalysisLogWrap();
      renderAnalysisLog("Starting…", { live: true });
    }
    return;
  }
  if (data.bytes === _analysisLogLastBytes && !live) return;
  _analysisLogLastBytes = data.bytes;
  showAnalysisLogWrap();
  renderAnalysisLog(data.log, { live });
}

if (analysisLogEl) {
  // While the user is actively scrolling the log, don't yank them back.
  analysisLogEl.addEventListener("wheel", () => {
    const atBottom =
      analysisLogEl.scrollHeight - analysisLogEl.scrollTop - analysisLogEl.clientHeight < 40;
    _analysisLogFrozen = !atBottom;
  });
}

function stopAnalysisPolling() {
  if (_analysisPollTimer) {
    clearInterval(_analysisPollTimer);
    _analysisPollTimer = null;
  }
}

function startAnalysisPolling(jobId) {
  stopAnalysisPolling();
  _analysisPollTimer = setInterval(async () => {
    try {
      const s = await fetchJSON(`/api/jobs/${jobId}/analysis/status`);
      if (analysisStatusText) {
        analysisStatusText.textContent = s.status ? `Status: ${s.status}` : "";
      }
      setAnalysisProgress(s.progress || null);
      void refreshAnalysisLog(jobId, { live: !!s.running });
      if (!s.running && (s.status === "done" || s.status === "done_with_errors" || s.status === "failed")) {
        stopAnalysisPolling();
        setAnalysisProgress(null);
        setAnalysisRerunEnabled(true);
        if (s.status !== "failed") {
          await loadAnalysisForJob(jobId, { force: true });
          if (analysisTabBadge) {
            setAnalysisTabEnabled(true, s.high_count || 0);
          }
        }
        // Final log snapshot so the user can read the summary.
        void refreshAnalysisLog(jobId, { live: false });
        await loadJobs();
      }
    } catch {
      stopAnalysisPolling();
      setAnalysisRerunEnabled(true);
    }
  }, 700);
}

async function triggerAnalysisRerun() {
  if (!selectedJobId) return;
  setAnalysisRerunEnabled(false);
  resetAnalysisLog();
  showAnalysisLogWrap();
  renderAnalysisLog("[analysis] queued…", { live: true });
  setAnalysisProgress({
    phase: "discover",
    phase_label: "Queued",
    files_done: 0,
    files_total: 0,
    findings_so_far: 0,
  });
  try {
    await fetchJSON(`/api/jobs/${selectedJobId}/analysis`, { method: "POST" });
    if (analysisStatusText) analysisStatusText.textContent = "Status: starting…";
    startAnalysisPolling(selectedJobId);
  } catch (e) {
    setAnalysisRerunEnabled(true);
    resetAnalysisLog();
    setAnalysisProgress(null);
    await showAlert("Re-run failed", String(e.message || e));
  }
}

async function refreshAnalysisStatus(jobId) {
  try {
    const s = await fetchJSON(`/api/jobs/${jobId}/analysis/status`);
    if (analysisStatusText) {
      analysisStatusText.textContent = s.status ? `Status: ${s.status}` : "";
    }
    setAnalysisTabEnabled(true, s.high_count || 0);
    setAnalysisRerunEnabled(!s.running);
    setAnalysisProgress(s.progress || null);
    void refreshAnalysisLog(jobId, { live: !!s.running });
    if (s.running) startAnalysisPolling(jobId);
  } catch {
    /* ignore */
  }
}

function clearEditorAnalysisDecorations() {
  if (!editor || !_analysisDecorationsByPath.size) return;
  for (const [path, ids] of _analysisDecorationsByPath.entries()) {
    const entry = openTabs.get(path);
    if (entry && entry.model && ids.length) {
      try {
        entry.model.deltaDecorations(ids, []);
      } catch {
        /* ignore */
      }
    }
  }
  _analysisDecorationsByPath.clear();
}

function applyEditorAnalysisDecoration(path, line, column, matchLen) {
  if (!editor || !window.monaco) return;
  const entry = openTabs.get(path);
  if (!entry) return;
  const startCol = Math.max(1, column || 1);
  const endCol = Math.max(startCol + 1, startCol + (matchLen || 1));
  const newIds = entry.model.deltaDecorations(
    _analysisDecorationsByPath.get(path) || [],
    [
      {
        range: new window.monaco.Range(line, 1, line, 1),
        options: {
          isWholeLine: true,
          className: "finding-line-highlight",
          glyphMarginClassName: "finding-glyph",
          stickiness: 1,
        },
      },
      {
        range: new window.monaco.Range(line, startCol, line, endCol),
        options: {
          inlineClassName: "finding-inline-highlight",
          stickiness: 1,
        },
      },
    ],
  );
  _analysisDecorationsByPath.set(path, newIds);
}

async function jumpToFinding(item) {
  if (!selectedJobId || !item || !item.file) return;
  await openFile(item.file);
  switchPaneTab("editor");
  if (!editor || !window.monaco) return;
  const line = Math.max(1, item.line || 1);
  const column = Math.max(1, item.column || 1);
  try {
    editor.layout();
    editor.revealLineInCenter(line);
    editor.setPosition({ lineNumber: line, column });
    editor.focus();
  } catch {
    /* ignore */
  }
  applyEditorAnalysisDecoration(item.file, line, column, (item.full_match || item.match || "").length);
}

function resetAnalysisUI() {
  stopAnalysisPolling();
  _analysisCache = null;
  _analysisFiltersDirty = false;
  if (analysisSummaryEl) analysisSummaryEl.innerHTML = "";
  if (analysisListEl) analysisListEl.innerHTML = "";
  if (analysisEmptyEl) {
    analysisEmptyEl.classList.remove("hidden");
    analysisEmptyEl.textContent = "Select a finished job to view analysis.";
  }
  if (analysisStatusText) analysisStatusText.textContent = "";
  setAnalysisProgress(null);
  setAnalysisRerunEnabled(false);
  setAnalysisTabEnabled(false);
  setAnalysisExportEnabled(false);
  if (analysisLoadMoreWrap) analysisLoadMoreWrap.classList.add("hidden");
  resetAnalysisLog();
  clearEditorAnalysisDecorations();
}

[analysisSeverityFilter, analysisCategoryFilter].forEach((el) => {
  if (!el) return;
  el.addEventListener("change", () => {
    _analysisFiltersDirty = true;
    if (selectedJobId) void loadAnalysisForJob(selectedJobId, { force: true });
  });
});

if (analysisSearchInput) {
  let analysisSearchTimer = null;
  analysisSearchInput.addEventListener("input", () => {
    if (analysisSearchTimer) clearTimeout(analysisSearchTimer);
    analysisSearchTimer = setTimeout(() => {
      _analysisFiltersDirty = true;
      if (selectedJobId) void loadAnalysisForJob(selectedJobId, { force: true });
    }, 200);
  });
}

if (analysisRerunBtn) {
  analysisRerunBtn.addEventListener("click", () => {
    void triggerAnalysisRerun();
  });
}

if (analysisLoadMoreBtn) {
  analysisLoadMoreBtn.addEventListener("click", () => void loadMoreAnalysis());
}

const analysisExportButtons = document.querySelectorAll("[data-export]");
function setAnalysisExportEnabled(enabled) {
  analysisExportButtons.forEach((btn) => (btn.disabled = !enabled));
}
analysisExportButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    if (!selectedJobId) return;
    const fmt = btn.dataset.export;
    const url = `/api/jobs/${selectedJobId}/analysis/export?format=${encodeURIComponent(fmt)}`;
    const a = document.createElement("a");
    a.href = url;
    a.rel = "noopener";
    document.body.appendChild(a);
    a.click();
    a.remove();
  });
});

refreshJobsBtn.addEventListener("click", () => loadJobs());
if (jobsPaneRefreshBtn) {
  jobsPaneRefreshBtn.addEventListener("click", () => loadJobs().catch(() => {}));
}
if (jobsPaneSearchInput) {
  jobsPaneSearchInput.addEventListener("input", () => renderJobsPane());
}
if (jobsLogRefreshBtn) {
  jobsLogRefreshBtn.addEventListener("click", () => {
    if (!_jobsPaneSelectedId) return;
    const job = _allJobs.find((j) => j.id === _jobsPaneSelectedId);
    loadJobLogInPane(_jobsPaneSelectedId, job?.original_filename || _jobsPaneSelectedId.slice(0, 8)).catch(
      () => {},
    );
  });
}
if (refreshJavaBtn) {
  refreshJavaBtn.addEventListener("click", () => loadJavaRuntimes(true));
}
if (settingsBtn) {
  settingsBtn.addEventListener("click", () => openSettings().catch(() => {}));
}
settingsCloseBtns.forEach((btn) => btn.addEventListener("click", () => closeSettings()));
if (settingsModal) {
  settingsModal.addEventListener("click", (ev) => {
    if (ev.target === settingsModal) closeSettings();
  });
}
if (jobsModalBtn) {
  jobsModalBtn.addEventListener("click", () => openJobsModal());
}
jobsModalCloseBtns.forEach((btn) => btn.addEventListener("click", () => closeJobsModal()));
if (jobsModal) {
  jobsModal.addEventListener("click", (ev) => {
    if (ev.target === jobsModal) closeJobsModal();
  });
}
btnDelete.addEventListener("click", () => deleteSelectedJob());
btnLog.addEventListener("click", () => showLog());
btnDownload.addEventListener("click", () => {
  if (!selectedJobId) return;
  downloadJobZipWithProgress(selectedJobId, jobTitle.textContent).catch(() => {});
});

if (jobSearchInput) {
  jobSearchInput.addEventListener("input", () => renderJobs(filteredJobs()));
}
if (treeSearchInput) {
  let treeSearchTimer = null;
  treeSearchInput.addEventListener("input", () => {
    if (treeSearchTimer) clearTimeout(treeSearchTimer);
    treeSearchTimer = setTimeout(() => applyTreeSearch(treeSearchInput.value), 120);
  });
}

setupDropzone();
setupMonaco();
loadJobs().catch(() => {});
loadPlugins().catch(() => {});
