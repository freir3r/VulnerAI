/* ====== AUTH ====== */
const AUTH_KEY = 'vulnerai.auth';
function isLoggedIn() {
  try { return !!JSON.parse(localStorage.getItem(AUTH_KEY)); }
  catch { return false; }
}
function requireAuth() {
  if (!isLoggedIn()) {
    window.location.href = 'login.html';
    return false;
  }
  return true;
}

/* ====== STATE ====== */
const state = {
  targets: []
};

/* ====== HELPERS ====== */
const qs = (s, el = document) => el.querySelector(s);
const qsa = (s, el = document) => [...el.querySelectorAll(s)];
const uid = () => Math.random().toString(36).slice(2, 9);

/* ====== PERSISTENCE ====== */
const LS_KEY = "vulnerai.targets";

function loadTargets() {
  try { state.targets = JSON.parse(localStorage.getItem(LS_KEY) || "[]"); }
  catch (_) { state.targets = []; }
}
function saveTargets() {
  localStorage.setItem(LS_KEY, JSON.stringify(state.targets));
}

/* ====== VALIDATION ====== */
const reIPv4 = /^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/;
const reCIDR = /^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}\/([0-9]|[12][0-9]|3[0-2])$/;
const reHost = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$/;

function isValidHostOrIPorCIDR(s) {
  if (!s) return false;
  const v = s.trim();
  return reIPv4.test(v) || reCIDR.test(v) || reHost.test(v);
}

/* ====== TARGETS RENDER ====== */
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, m => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m]));
}

function renderTargets() {
  const wrap = document.getElementById("targets-list");
  const empty = document.getElementById("targets-empty");
  const count = document.getElementById("targets-count");
  if (!wrap || !empty || !count) return;

  const term = (document.getElementById("tgt-search")?.value || "").toLowerCase().trim();
  let list = state.targets.filter(t =>
    !term || t.name.toLowerCase().includes(term) || t.value.toLowerCase().includes(term)
  );

  const sort = document.getElementById("tgt-sort")?.value || "recent";
  list.sort((a, b) => {
    if (sort === "name") return a.name.localeCompare(b.name);
    if (sort === "scans") return (b.scans || 0) - (a.scans || 0);
    if (sort === "cves") return (b.cves || 0) - (a.cves || 0);
    return (b.addedAt || 0) - (a.addedAt || 0);
  });

  count.textContent = `${state.targets.length} saved`;
  empty.style.display = state.targets.length ? "none" : "block";

  wrap.innerHTML = "";
  list.forEach(t => {
    const art = document.createElement("article");
    art.className = "target-card";
    art.dataset.kind = t.kind;

    art.innerHTML = `
      <label class="sel"><input type="checkbox" data-id="${t.id}" /></label>
      <div class="tgt-main">
        <div class="tgt-line">
          <span class="tgt-name">${escapeHtml(t.name)}</span>
          <span class="badge kind">${t.kind === "network" ? "Network" : "Host"}</span>
          ${t.risk ? `<span class="chip ${t.risk === 'Low' ? 'chip-green' : ''}">${escapeHtml(t.risk)} risk</span>` : ""}
        </div>
        <div class="tgt-sub muted">${escapeHtml(t.value)} • Added: ${new Date(t.addedAt).toISOString().slice(0, 10)}</div>
      </div>

      <div class="tgt-stats">
        <div class="stat"><span class="num">${t.scans ?? 0}</span><span class="lbl">Scans</span></div>
        <div class="stat"><span class="num">${t.cves ?? 0}</span><span class="lbl">Unique CVEs</span></div>
        <div class="stat"><span class="num">${t.lastScan ?? "-"}</span><span class="lbl">Last scan</span></div>
      </div>

      <div class="tgt-actions">
        <button class="btn-secondary small" data-action="view-scans" data-id="${t.id}">View scans</button>
        <button class="btn-primary small"   data-action="start-scan" data-id="${t.id}">Start scan</button>
        <button class="btn-secondary danger small" data-action="delete" data-id="${t.id}">Delete</button>
      </div>
    `;
    wrap.appendChild(art);
  });

  const bulk = document.querySelector(".bulk");
  if (bulk) {
    const any = list.length > 0;
    bulk.setAttribute("aria-hidden", any ? "false" : "true");
    document.getElementById("tgt-selected").textContent = "0 selected";
    const allChk = document.getElementById("tgt-checkall");
    if (allChk) allChk.checked = false;
  }
}

function selectedTargetIds() {
  return qsa('#targets-list input[type="checkbox"]:checked').map(c => c.dataset.id);
}

function updateBulkCount() {
  const n = selectedTargetIds().length;
  document.getElementById("tgt-selected").textContent = `${n} selected`;
}

/* ====== INIT ====== */
function init() {
  if (!requireAuth()) return;

  // DARK MODE
  const themeQuick = localStorage.getItem("vulnerai.theme");
  const isDark = themeQuick ? (themeQuick === "dark") : false;
  document.body.classList.toggle("dark", isDark);

  loadTargets();
  renderTargets();

  /* SIDEBAR */
  const sidebar = document.getElementById("sidebar");
  const burger = document.getElementById("btn-burger");
  const SAVED = localStorage.getItem("vulnerai.sidebarCollapsed") === "1";
  if (SAVED) sidebar?.classList.add("collapsed");
  burger?.addEventListener("click", (e) => {
    e.stopPropagation();
    sidebar?.classList.toggle("collapsed");
    const collapsed = sidebar?.classList.contains("collapsed");
    localStorage.setItem("vulnerai.sidebarCollapsed", collapsed ? "1" : "0");
  });

  /* USER MENU */
  const userBtn = document.getElementById("btn-user");
  const userMenu = document.getElementById("menu-user");
  function closeUserMenu() { userBtn?.setAttribute("aria-expanded", "false"); userMenu?.setAttribute("aria-hidden", "true"); }
  function openUserMenu() { userBtn?.setAttribute("aria-expanded", "true"); userMenu?.setAttribute("aria-hidden", "false"); }
  userBtn?.addEventListener("click", (e) => {
    e.stopPropagation();
    const isOpen = userMenu?.getAttribute("aria-hidden") === "false";
    if (isOpen) closeUserMenu(); else openUserMenu();
  });
  document.addEventListener("click", (e) => {
    const clickedInside = userMenu?.contains(e.target) || userBtn?.contains(e.target);
    if (!clickedInside) closeUserMenu();
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeUserMenu(); });
  userMenu?.addEventListener("click", (e) => {
    const item = e.target.closest(".menu-item");
    if (!item) return;
    const action = item.dataset.action;
    closeUserMenu();
    if (action === "settings") { window.location.href = "settings.html"; }
    if (action === "logout") {
      localStorage.removeItem(AUTH_KEY);
      window.location.href = "login.html";
    }
  });

  /* PREMIUM MODAL */
  const premiumBtn = document.getElementById("btn-premium");
  const premiumModal = document.getElementById("modal-premium");
  const closePremium = () => premiumModal?.setAttribute("aria-hidden", "true");
  const openPremium = () => premiumModal?.setAttribute("aria-hidden", "false");
  premiumBtn?.addEventListener("click", (e) => { e.stopPropagation(); openPremium(); });
  premiumModal?.addEventListener("click", (e) => {
    if (e.target.hasAttribute("data-close") || e.target.classList.contains("close") || e.target.classList.contains("backdrop")) {
      closePremium();
    }
  });
  document.addEventListener("keydown", (e) => { if (e.key === 'Escape') closePremium(); });

  /* IP LIST MODAL + FORM */
  const iplistModal = document.getElementById("iplist-modal");
  const btnOpenAdd = document.getElementById("iplist-open-add");
  const iplistForm = document.getElementById("iplist-form");

  btnOpenAdd?.addEventListener("click", () => iplistModal?.setAttribute("aria-hidden", "false"));
  iplistModal?.addEventListener("click", (e) => {
    if (e.target.hasAttribute("data-close") || e.target.classList.contains("iplist-close") || e.target.classList.contains("iplist-backdrop")) {
      iplistModal.setAttribute("aria-hidden", "true");
    }
  });

  iplistForm?.addEventListener("submit", (e) => {
    e.preventDefault();
    const name = document.getElementById("iplist-name").value.trim();
    const kind = document.getElementById("iplist-kind").value;
    const value = document.getElementById("iplist-value").value.trim();

    if (!name) { alert("Please enter a Name/Title."); return; }
    if (!isValidHostOrIPorCIDR(value)) { alert("Please enter a valid Host/IP, domain, or CIDR."); return; }

    state.targets.push({
      id: uid(),
      kind, name, value,
      addedAt: Date.now(),
      scans: 0, cves: 0, lastScan: "-",
      tags: [], risk: "Low"
    });
    saveTargets();
    renderTargets();
    iplistForm.reset();
    iplistModal.setAttribute("aria-hidden", "true");
  });

  /* Search & Sort */
  document.getElementById("tgt-search")?.addEventListener("input", renderTargets);
  document.getElementById("tgt-sort")?.addEventListener("change", renderTargets);

  /* Bulk controls */
  document.getElementById("tgt-checkall")?.addEventListener("change", (e) => {
    qsa('#targets-list input[type="checkbox"]').forEach(c => c.checked = e.target.checked);
    updateBulkCount();
  });
  
  document.getElementById("targets-list")?.addEventListener("change", (e) => {
    if (e.target.type === "checkbox") updateBulkCount();
  });
  
  document.getElementById("tgt-bulk-delete")?.addEventListener("click", () => {
    const ids = selectedTargetIds();
    if (!ids.length) return;
    if (confirm(`Delete ${ids.length} selected target(s)?`)) {
      state.targets = state.targets.filter(t => !ids.includes(t.id));
      saveTargets(); 
      renderTargets();
    }
  });
  
  document.getElementById("tgt-bulk-scan")?.addEventListener("click", () => {
    const ids = selectedTargetIds();
    if (!ids.length) return;
    if (ids.length === 1) {
      const t = state.targets.find(x => x.id === ids[0]);
      if (t) {
        window.location.href = `scans.html?target=${encodeURIComponent(t.value)}&id=${t.id}`;
      }
    } else {
      window.location.href = 'scans.html';
    }
  });
  
  document.getElementById("tgt-bulk-tags")?.addEventListener("click", () => alert("Tagging not implemented in this demo."));

  /* IP List actions (delegation) */
  document.getElementById("view-iplist")?.addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-action]");
    if (!btn) return;
    const id = btn.dataset.id;
    
    if (btn.dataset.action === "delete") {
      state.targets = state.targets.filter(t => t.id !== id);
      saveTargets(); 
      renderTargets();
      return;
    }
    
    if (btn.dataset.action === "start-scan") {
      const t = state.targets.find(x => x.id === id);
      if (t) {
        window.location.href = `scans.html?target=${encodeURIComponent(t.value)}&id=${t.id}`;
      }
      return;
    }
    
    if (btn.dataset.action === "view-scans") {
      window.location.href = 'scans.html';
      return;
    }
  });

  /* UPGRADE BUTTON */
  const upgradeBtn = document.getElementById('btn-upgrade');
  upgradeBtn?.addEventListener('click', (e) => {
    e.preventDefault();
    localStorage.setItem('vulnerai.intent', 'upgrade');
    document.getElementById('modal-premium')?.setAttribute('aria-hidden', 'true');
    window.location.href = 'pricing.html';
  });
}

/* ====== BOOT ====== */
document.addEventListener("DOMContentLoaded", init);