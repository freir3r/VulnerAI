/* iplist.js — robust version
   - Safe event listener attachments (checks element existence)
   - Console diagnostics
   - CSV import with header support and detailed feedback
   - Bulk tag modal, bulk actions, tag-click filtering
   - Prevention of duplicates
   - Defensive try/catch so one error doesn't stop everything
*/

(function(){
  'use strict';

  /* ====== AUTH ====== */
  const AUTH_KEY = 'vulnerai.auth';
  function isLoggedIn() {
    try { return !!JSON.parse(localStorage.getItem(AUTH_KEY)); }
    catch { return false; }
  }
  function requireAuth() {
    if (!isLoggedIn()) {
      console.warn('requireAuth: not logged in — redirecting to login.html');
      try { window.location.replace('login.html'); } catch(e) {}
      return false;
    }
    return true;
  }

  /* ====== STATE ====== */
  const state = { targets: [] };

  /* ====== HELPERS ====== */
  const qs = (s, el = document) => el.querySelector(s);
  const qsa = (s, el = document) => Array.from(el.querySelectorAll(s));
  const uid = () => Math.random().toString(36).slice(2, 9);

  /* ====== PERSISTENCE ====== */
  const LS_KEY = "vulnerai.targets";
  const TAGS_KEY = "vulnerai.tags";

  function loadTargets() {
    try { state.targets = JSON.parse(localStorage.getItem(LS_KEY) || "[]"); } catch (_) { state.targets = []; }
  }
  function saveTargets() { try { localStorage.setItem(LS_KEY, JSON.stringify(state.targets)); } catch(e){ console.error('saveTargets', e); } }

  let allTags = [];
  function loadTags() { try { allTags = JSON.parse(localStorage.getItem(TAGS_KEY) || "[]"); } catch { allTags = []; } }
  function saveTags() { try { localStorage.setItem(TAGS_KEY, JSON.stringify(allTags)); } catch(e){ console.error('saveTags', e); } }
  function addTagIfNew(tag) { if (!tag) return; tag = tag.trim(); if (tag && !allTags.includes(tag)) { allTags.push(tag); saveTags(); } }

  /* ====== VALIDATION ====== */
  const reIPv4 = /^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/;
  const reCIDR = /^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}\/([0-9]|[12][0-9]|3[0-2])$/;
  const reHost = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$/;

  function isValidHostOrIPorCIDR(s) {
    if (!s) return false;
    const v = s.trim();
    return reIPv4.test(v) || reCIDR.test(v) || reHost.test(v);
  }

  function escapeHtml(s) {
    return String(s || '').replace(/[&<>\"']/g, m => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m]));
  }

  /* ====== UI RENDER ====== */
  function getRiskColor(cves) {
    if (cves >= 10) return "chip-red";
    if (cves >= 5) return "chip-orange";
    if (cves >= 1) return "chip-yellow";
    return "chip-green";
  }

  function renderTagsFilter() {
    const container = document.getElementById("tags-filter");
    if (!container) return;
    const options = ['<option value="">All tags</option>'].concat(
      allTags.map(tag => `<option value="${escapeHtml(tag)}">${escapeHtml(tag)}</option>`)
    ).join('');
    container.innerHTML = options;
  }

  function renderTargets() {
    try {
      const wrap = document.getElementById("targets-list");
      const empty = document.getElementById("targets-empty");
      const count = document.getElementById("targets-count");
      if (!wrap || !empty || !count) {
        console.warn('renderTargets: missing container(s)');
        return;
      }

      const term = (document.getElementById("tgt-search")?.value || "").toLowerCase().trim();
      const tagFilter = document.getElementById("tags-filter")?.value || "";
      const sort = document.getElementById("tgt-sort")?.value || "recent";

      let list = state.targets.filter(t =>
        (!term || (t.name || '').toLowerCase().includes(term) || (t.value || '').toLowerCase().includes(term)) &&
        (!tagFilter || (t.tags || []).includes(tagFilter))
      );

      list.sort((a, b) => {
        if (sort === "name") return (a.name || '').localeCompare(b.name || '');
        if (sort === "scans") return (b.scans || 0) - (a.scans || 0);
        if (sort === "cves") return (b.cves || 0) - (a.cves || 0);
        return (b.addedAt || 0) - (a.addedAt || 0);
      });

      count.textContent = `${state.targets.length} saved`;
      empty.style.display = state.targets.length ? "none" : "block";

      wrap.innerHTML = "";
      list.forEach(t => {
        const riskClass = getRiskColor(t.cves || 0);
        const lastScan = t.lastScan && t.lastScan !== "-" ? (new Date(t.lastScan)).toISOString().slice(0,10) : "-";

        let vulnChips = "";
        if (t.vulnSummary) {
          const vs = t.vulnSummary;
          if (vs.critical) vulnChips += `<span class="chip chip-critical" title="Critical">C:${vs.critical}</span>`;
          if (vs.high)     vulnChips += `<span class="chip chip-high" title="High">H:${vs.high}</span>`;
          if (vs.medium)   vulnChips += `<span class="chip chip-medium" title="Medium">M:${vs.medium}</span>`;
        }

        const art = document.createElement("article");
        art.className = "target-card";
        art.dataset.kind = t.kind || 'host';

        art.innerHTML = `
          <label class="sel"><input type="checkbox" data-id="${t.id}" /></label>
          <div class="tgt-main">
            <div class="tgt-line">
              <span class="tgt-name">${escapeHtml(t.name)}</span>
              <span class="badge kind">${t.kind === "network" ? "Network" : "Host"}</span>
              <span class="chip ${riskClass}">${t.cves ?? 0} CVE${(t.cves ?? 0) !== 1 ? 's' : ''}</span>
              ${(t.tags || []).map(tag => `<button class="chip chip-tag" data-tag="${escapeHtml(tag)}" title="Filter by ${escapeHtml(tag)}">${escapeHtml(tag)}</button>`).join(' ')}
              ${vulnChips}
            </div>
            <div class="tgt-sub muted">${escapeHtml(t.value)} • Added: ${(new Date(t.addedAt)).toISOString().slice(0,10)}</div>
          </div>

          <div class="tgt-stats">
            <div class="stat"><span class="num">${t.scans ?? 0}</span><span class="lbl">Scans</span></div>
            <div class="stat"><span class="num">${t.cves ?? 0}</span><span class="lbl">Unique CVEs</span></div>
            <div class="stat"><span class="num">${lastScan}</span><span class="lbl">Last scan</span></div>
          </div>

          <div class="tgt-actions">
            <button class="btn-secondary small" data-action="edit" data-id="${t.id}">Edit</button>
            <button class="btn-secondary small" data-action="tags" data-id="${t.id}">Tags</button>
            <button class="btn-secondary small" data-action="view-scans" data-id="${t.id}">View scans</button>
            <button class="btn-primary small"   data-action="start-scan" data-id="${t.id}">Start scan</button>
            <button class="btn-secondary danger small" data-action="delete" data-id="${t.id}">Delete</button>
          </div>
        `;
        wrap.appendChild(art);
      });

      const bulk = document.querySelector(".bulk");
      if (bulk) {
        const any = (list.length > 0);
        bulk.setAttribute("aria-hidden", any ? "false" : "true");
        document.getElementById("tgt-selected") && (document.getElementById("tgt-selected").textContent = "0 selected");
        const allChk = document.getElementById("tgt-checkall");
        if (allChk) allChk.checked = false;
      }
    } catch (err) {
      console.error('renderTargets error', err);
    }
  }

  function selectedTargetIds() {
    return qsa('#targets-list input[type="checkbox"]:checked').map(c => c.dataset.id);
  }

  function updateBulkCount() {
    try {
      const n = selectedTargetIds().length;
      const el = document.getElementById("tgt-selected");
      if (el) el.textContent = `${n} selected`;
    } catch(e){ console.error(e); }
  }

  /* ====== CSV IMPORT (robust) ====== */
  function handleCSVImport(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const text = e.target.result;
        const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
        if (!lines.length) { alert("CSV vazio."); return; }

        const headerCols = lines[0].split(',').map(s=>s.trim().toLowerCase());
        const hasHeader = headerCols.includes('name') && headerCols.includes('value');
        const start = hasHeader ? 1 : 0;

        const imported = [], skipped = [];
        const existingValues = new Set(state.targets.map(t => (t.value || '').toLowerCase()));

        for (let i = start; i < lines.length; i++) {
          const cols = lines[i].split(',').map(c => c.trim());
          const name = cols[0] || `Imported #${i+1}`;
          const value = cols[1] || '';
          const tagsRaw = cols[2] || '';

          if (!value) { skipped.push({line: i+1, reason: 'empty value'}); continue; }
          if (!isValidHostOrIPorCIDR(value)) { skipped.push({line: i+1, reason: 'invalid host/ip/cidr'}); continue; }
          if (existingValues.has(value.toLowerCase())) { skipped.push({line: i+1, reason: 'duplicate'}); continue; }

          const kind = value.includes('/') ? 'network' : 'host';
          const tags = tagsRaw ? tagsRaw.split(/[;,]+/).map(t => t.trim()).filter(Boolean) : [];

          const target = {
            id: uid(),
            kind, name, value,
            addedAt: Date.now(),
            scans: 0, cves: 0, lastScan: "-",
            tags,
            risk: "Low"
          };
          imported.push(target);
          tags.forEach(addTagIfNew);
          existingValues.add(value.toLowerCase());
        }

        if (imported.length === 0) {
          const msg = skipped.length ? `Nenhum target válido. Detalhes: ${skipped.map(s=>`(linha ${s.line}: ${s.reason})`).join(', ')}` : 'Nenhum target válido encontrado no CSV.';
          alert(msg);
          return;
        }

        state.targets = state.targets.concat(imported);
        saveTargets();
        saveTags();
        renderTagsFilter();
        renderTargets();
        alert(`${imported.length} target(s) importados com sucesso! ${skipped.length ? skipped.length + ' linhas ignoradas.' : ''}`);
      } catch (err) {
        console.error('handleCSVImport', err);
        alert("Erro ao processar o CSV. Verifique o formato.");
      }
    };
    reader.readAsText(file);
  }

  /* ====== EDIT TARGET (modal-safe) ====== */
  function openEditModal(target) {
    try {
      const modal = document.getElementById("iplist-modal");
      const form = document.getElementById("iplist-form");
      const title = document.getElementById("iplist-modal-title");
      const nameInput = document.getElementById("iplist-name");
      const kindInput = document.getElementById("iplist-kind");
      const valueInput = document.getElementById("iplist-value");
      if (!modal || !form || !nameInput || !kindInput || !valueInput) {
        alert('Edit modal elements missing.');
        return;
      }

      title.textContent = "Edit Target";
      nameInput.value = target.name || '';
      kindInput.value = target.kind || 'host';
      valueInput.value = target.value || '';

      const originalOnSubmit = form.onsubmit;
      form.onsubmit = (e) => {
        e.preventDefault();
        const newName = nameInput.value.trim();
        const newValue = valueInput.value.trim();
        if (!newName) { alert("Please enter a Name/Title."); return; }
        if (!isValidHostOrIPorCIDR(newValue)) { alert("Please enter a valid Host/IP, domain, or CIDR."); return; }

        if (state.targets.some(t => t.value.toLowerCase() === newValue.toLowerCase() && t.id !== target.id)) {
          alert('Another target with this value already exists.');
          return;
        }

        const idx = state.targets.findIndex(t => t.id === target.id);
        if (idx !== -1) {
          state.targets[idx] = {
            ...state.targets[idx],
            name: newName,
            value: newValue,
            kind: kindInput.value
          };
          saveTargets();
          renderTargets();
        }
        modal.setAttribute("aria-hidden", "true");
        form.onsubmit = originalOnSubmit;
      };

      modal.setAttribute("aria-hidden", "false");
    } catch (err) { console.error('openEditModal', err); }
  }

  /* ====== BULK TAG MODAL (create if missing) ====== */
  function ensureTagModal() {
    if (document.getElementById('bulk-tag-modal')) return;
    const div = document.createElement('div');
    div.id = 'bulk-tag-modal';
    div.className = 'modal';
    div.setAttribute('aria-hidden','true');
    div.style.zIndex = 1200;
    div.innerHTML = `
      <div class="backdrop" data-close></div>
      <div class="dialog">
        <button class="close" data-close aria-label="Close">×</button>
        <h2>Tag selected targets</h2>
        <p class="muted">Add an existing tag or create a new one (comma or semicolon separated).</p>
        <div style="margin:10px 0;">
          <input id="bulk-tag-input" class="input" placeholder="e.g., web, production" />
          <div class="muted small" style="margin-top:6px;">Existing tags: <span id="bulk-tag-suggestions" class="muted"></span></div>
        </div>
        <div style="display:flex;gap:8px;justify-content:flex-end;">
          <button class="btn-secondary" data-close>Cancel</button>
          <button class="btn-primary" id="bulk-tag-apply">Apply</button>
        </div>
      </div>
    `;
    document.body.appendChild(div);

    div.addEventListener('click', (e) => {
      if (e.target.hasAttribute('data-close') || e.target.classList.contains('close') || e.target.classList.contains('backdrop')) {
        div.setAttribute('aria-hidden','true');
      }
    });

    div.querySelector('#bulk-tag-apply')?.addEventListener('click', ()=> {
      const raw = (document.getElementById('bulk-tag-input')?.value || '').trim();
      const tags = raw.split(/[;,]+/).map(t => t.trim()).filter(Boolean);
      if (!tags.length) { alert('Enter at least one tag.'); return; }
      const ids = selectedTargetIds();
      if (!ids.length) { alert('No targets selected.'); div.setAttribute('aria-hidden','true'); return; }

      ids.forEach(id => {
        const t = state.targets.find(x => x.id === id);
        if (!t) return;
        const merged = Array.from(new Set([...(t.tags || []), ...tags]));
        t.tags = merged;
        tags.forEach(addTagIfNew);
      });
      saveTargets(); saveTags();
      renderTagsFilter();
      renderTargets();
      div.setAttribute('aria-hidden','true');
    });
  }

  /* ====== INIT (robust attachments) ====== */
  function attachIf(el, event, cb) { try { if (!el) return false; el.addEventListener(event, cb); return true; } catch(e){ console.error('attachIf', e); return false; } }

  function init() {
    try {
      console.log('iplist:init start');

      if (!requireAuth()) { console.warn('Auth failed — init aborted'); return; }

      window._lastJsError = null;
      window.addEventListener('error', (ev)=> { window._lastJsError = ev; }, true);
      window.addEventListener('unhandledrejection', (ev)=> { window._lastJsError = ev; }, true);

      loadTargets();
      loadTags();

      renderTagsFilter();
      renderTargets();

      ensureTagModal();
      const suggestions = document.getElementById('bulk-tag-suggestions');
      if (suggestions) suggestions.textContent = allTags.join(', ');

      const sidebar = document.getElementById("sidebar");
      const burger = document.getElementById("btn-burger");
      const SAVED = localStorage.getItem("vulnerai.sidebarCollapsed") === "1";
      if (SAVED && sidebar) sidebar.classList.add("collapsed");
      attachIf(burger, 'click', (e) => {
        e.stopPropagation();
        if (!sidebar) return;
        sidebar.classList.toggle("collapsed");
        const collapsed = sidebar.classList.contains("collapsed");
        localStorage.setItem("vulnerai.sidebarCollapsed", collapsed ? "1" : "0");
      });

      const userBtn = document.getElementById("btn-user");
      const userMenu = document.getElementById("menu-user");
      if (userBtn && userMenu) {
        const closeUserMenu = ()=> { userBtn.setAttribute("aria-expanded","false"); userMenu.setAttribute("aria-hidden","true"); };
        const openUserMenu  = ()=> { userBtn.setAttribute("aria-expanded","true");  userMenu.setAttribute("aria-hidden","false"); };
        attachIf(userBtn, 'click', (e)=> {
          e.stopPropagation();
          const isOpen = userMenu.getAttribute("aria-hidden") === "false";
          if (isOpen) closeUserMenu(); else openUserMenu();
        });
        document.addEventListener("click", (e)=> {
          const clickedInside = userMenu.contains(e.target) || userBtn.contains(e.target);
          if (!clickedInside) closeUserMenu();
        });
        attachIf(userMenu, 'click', (e)=> {
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
      }

      attachIf(document.getElementById('btn-premium'), 'click', (e)=> {
        e.stopPropagation();
        const pm = document.getElementById('modal-premium');
        if (pm) pm.setAttribute('aria-hidden','false');
      });
      attachIf(document.getElementById('modal-premium'), 'click', (e)=> {
        if (e.target.hasAttribute('data-close') || e.target.classList.contains('close') || e.target.classList.contains('backdrop')) {
          e.currentTarget.setAttribute('aria-hidden','true');
        }
      });

      const iplistModal = document.getElementById("iplist-modal");
      const btnOpenAdd = document.getElementById("iplist-open-add");
      const iplistForm = document.getElementById("iplist-form");
      if (btnOpenAdd && iplistModal && iplistForm) {
        attachIf(btnOpenAdd, 'click', ()=> {
          document.getElementById("iplist-modal-title") && (document.getElementById("iplist-modal-title").textContent = "Add Target");
          iplistForm.reset();
          iplistModal.setAttribute("aria-hidden","false");
        });
        attachIf(iplistModal, 'click', (e)=> {
          if (e.target.hasAttribute("data-close") || e.target.classList.contains("iplist-close") || e.target.classList.contains("iplist-backdrop")) {
            iplistModal.setAttribute("aria-hidden","true");
          }
        });
      }

      if (iplistForm) {
        attachIf(iplistForm, 'submit', (e)=> {
          e.preventDefault();
          try {
            const name = (document.getElementById("iplist-name")?.value || '').trim();
            const kind = document.getElementById("iplist-kind")?.value || 'host';
            const value = (document.getElementById("iplist-value")?.value || '').trim();

            if (!name) { alert("Please enter a Name/Title."); return; }
            if (!isValidHostOrIPorCIDR(value)) { alert("Please enter a valid Host/IP, domain, or CIDR."); return; }
            if (state.targets.some(t => (t.value || '').toLowerCase() === value.toLowerCase())) { alert('Target with this value already exists.'); return; }

            state.targets.push({
              id: uid(), kind, name, value,
              addedAt: Date.now(), scans: 0, cves: 0, lastScan: "-", tags: [], risk: "Low"
            });
            saveTargets();
            renderTargets();
            iplistForm.reset();
            iplistModal && iplistModal.setAttribute("aria-hidden","true");
          } catch(err) { console.error('iplistForm submit', err); }
        });
      }

      attachIf(document.getElementById("tgt-search"), 'input', renderTargets);
      attachIf(document.getElementById("tgt-sort"), 'change', renderTargets);
      attachIf(document.getElementById("tags-filter"), 'change', renderTargets);

      attachIf(document.getElementById("tgt-checkall"), 'change', (e)=> {
        qsa('#targets-list input[type="checkbox"]').forEach(c => c.checked = e.target.checked);
        updateBulkCount();
      });
      attachIf(document.getElementById("targets-list"), 'change', (e)=> {
        if (e.target && e.target.type === "checkbox") updateBulkCount();
      });

      attachIf(document.getElementById("tgt-bulk-delete"), 'click', ()=> {
        const ids = selectedTargetIds();
        if (!ids.length) return;
        if (confirm(`Delete ${ids.length} selected target(s)?`)) {
          state.targets = state.targets.filter(t => !ids.includes(t.id));
          saveTargets(); renderTargets();
        }
      });

      attachIf(document.getElementById("tgt-bulk-scan"), 'click', ()=> {
        const ids = selectedTargetIds();
        if (!ids.length) return;
        if (ids.length === 1) {
          const t = state.targets.find(x => x.id === ids[0]);
          if (t) window.location.href = `scans.html?target=${encodeURIComponent(t.value)}&id=${t.id}`;
        } else {
          window.location.href = 'scans.html';
        }
      });

      attachIf(document.getElementById("tgt-bulk-tags"), 'click', ()=> {
        const ids = selectedTargetIds();
        if (!ids.length) { alert('No targets selected.'); return; }
        document.getElementById('bulk-tag-input') && (document.getElementById('bulk-tag-input').value = '');
        document.getElementById('bulk-tag-modal') && document.getElementById('bulk-tag-modal').setAttribute('aria-hidden','false');
      });

      let csvInput = document.getElementById("csv-upload-input");
      if (!csvInput) {
        csvInput = document.createElement("input");
        csvInput.type = "file";
        csvInput.accept = ".csv,text/csv";
        csvInput.style.display = "none";
        csvInput.id = "csv-upload-input";
        document.body.appendChild(csvInput);
      }
      attachIf(document.getElementById("iplist-import-csv"), 'click', ()=> csvInput.click());
      attachIf(csvInput, 'change', (e) => {
        const file = e.target.files && e.target.files[0];
        if (file) handleCSVImport(file);
        e.target.value = "";
      });

      attachIf(document.getElementById("view-iplist"), 'click', (e)=> {
        try {
          const btn = e.target.closest("button[data-action]");
          if (!btn) {
            const chip = e.target.closest('.chip-tag');
            if (chip && chip.dataset.tag) {
              const tag = chip.dataset.tag;
              const tagSel = document.getElementById('tags-filter');
              if (tagSel) { tagSel.value = tag; renderTargets(); }
            }
            return;
          }
          const id = btn.dataset.id;
          const target = state.targets.find(x => x.id === id);
          if (!target) return;

          const act = btn.dataset.action;
          if (act === "delete") {
            if (confirm("Delete this target?")) {
              state.targets = state.targets.filter(t => t.id !== id);
              saveTargets(); renderTargets();
            }
            return;
          }
          if (act === "edit") { openEditModal(target); return; }
          if (act === "tags") {
            const current = prompt("Enter tags (comma-separated):", (target.tags || []).join(", ")) || "";
            const tags = current.split(/[;,]+/).map(t => t.trim()).filter(Boolean);
            tags.forEach(addTagIfNew);
            target.tags = tags;
            saveTargets(); saveTags(); renderTagsFilter(); renderTargets();
            return;
          }
          if (act === "start-scan") { window.location.href = `scans.html?target=${encodeURIComponent(target.value)}&id=${target.id}`; return; }
          if (act === "view-scans")  { window.location.href = `scans.html?target=${encodeURIComponent(target.value)}&id=${target.id}`; return; }
        } catch(err) { console.error('view-iplist click handler', err); }
      });

      attachIf(document.getElementById('targets-list'), 'click', (e)=> {
        const chip = e.target.closest('.chip-tag');
        if (chip && chip.dataset.tag) {
          const tag = chip.dataset.tag;
          const tagSel = document.getElementById('tags-filter');
          if (tagSel) { tagSel.value = tag; renderTargets(); }
        }
      });

      attachIf(document.getElementById('btn-upgrade'), 'click', (e)=> {
        e && e.preventDefault();
        localStorage.setItem('vulnerai.intent', 'upgrade');
        document.getElementById('modal-premium')?.setAttribute('aria-hidden','true');
        window.location.href = 'pricing.html';
      });

      console.log('iplist:init done — listeners attached (if elements exist).');
      const expectedIds = ['btn-burger','btn-premium','btn-user','iplist-open-add','iplist-import-csv','tgt-search','tgt-sort','tags-filter','tgt-checkall','tgt-bulk-scan','tgt-bulk-tags','tgt-bulk-delete','targets-list','iplist-modal','iplist-form'];
      const missing = expectedIds.filter(id => !document.getElementById(id));
      if (missing.length) console.warn('iplist:init — missing elements (these IDs were not found):', missing);
      console.log('localStorage[vulnerai.auth]:', localStorage.getItem('vulnerai.auth'));
      if (window._lastJsError) console.warn('Recent JS error captured:', window._lastJsError);
    } catch (e) {
      console.error('iplist.init fatal', e);
    }
  }

  document.addEventListener('DOMContentLoaded', init);
})();

/* ===================================================== */
/* AUTO-START SCAN ON scans.html?target=IP&id=XYZ       */
/* ===================================================== */
if (window.location.pathname.includes('scans.html') || window.location.pathname.endsWith('/scans')) {
  document.addEventListener('DOMContentLoaded', () => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const target = urlParams.get('target');
      const targetId = urlParams.get('id');

      if (target && targetId) {
        console.log('[Auto-Scan] Parâmetros detectados:', { target, targetId });

        const startScan = () => {
          // Tenta múltiplos seletores comuns para o botão de iniciar scan
          const selectors = [
            '#start-scan-btn',
            'button[data-action="start-scan"]',
            '.btn-start-scan',
            'button:contains("Start Scan")',
            '#btn-start-scan'
          ];

          for (const sel of selectors) {
            const btn = document.querySelector(sel);
            if (btn && !btn.disabled && btn.offsetParent !== null) {
              console.log('[Auto-Scan] Botão encontrado:', sel);
              setTimeout(() => btn.click(), 300); // pequeno delay para UI
              return true;
            }
          }
          return false;
        };

        // Tenta imediatamente
        if (startScan()) return;

        // Se não encontrou, espera até 8s
        let attempts = 0;
        const interval = setInterval(() => {
          attempts++;
          if (startScan() || attempts > 80) {
            clearInterval(interval);
          }
        }, 100);

      }
    } catch (e) {
      console.error('[Auto-Scan] Erro:', e);
    }
  });
}