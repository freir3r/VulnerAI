/* iplist.js — Firebase Integrated Version
   - Uses LocalStorage for quick UI Auth Check (Your requirement)
   - Uses Firebase SDK Auth for Database Security
   - Persists data to Firestore "Targets" collection
*/

import { initializeApp } from "https://www.gstatic.com/firebasejs/9.22.2/firebase-app.js";
import { 
    getFirestore, collection, addDoc, getDocs, 
    query, where, deleteDoc, doc, updateDoc, writeBatch 
} from "https://www.gstatic.com/firebasejs/9.22.2/firebase-firestore.js";
import { getAuth, onAuthStateChanged } from "https://www.gstatic.com/firebasejs/9.22.2/firebase-auth.js";

// --- FIREBASE CONFIG ---
const firebaseConfig = {
    apiKey: "AIzaSyBuaJdeJSHhn8zvOt3COp1fy987Zx4Da9k",
    authDomain: "vulnerai.firebaseapp.com",
    projectId: "vulnerai",
    storageBucket: "vulnerai.firebasestorage.app",
    messagingSenderId: "576892753213",
    appId: "1:576892753213:web:b418a23c16b808c1d4a154",
    measurementId: "G-K38GLCC5XL"
};

const app = initializeApp(firebaseConfig);
const db = getFirestore(app);
const auth = getAuth(app);

(function(){
  'use strict';

  /* ====== AUTH (Mantido como pediste + Helper para DB) ====== */
  const AUTH_KEY = 'vulnerai.auth';

  // 1. A tua verificação original via LocalStorage (Rápida para UI)
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

  // 2. Helper para garantir que temos o UID seguro para falar com a Base de Dados
  async function ensureFirebaseUser() {
      if (auth.currentUser) return auth.currentUser;
      return new Promise((resolve, reject) => {
          const unsubscribe = onAuthStateChanged(auth, (user) => {
              unsubscribe();
              if (user) resolve(user);
              else {
                  // Se falhar aqui, o token local pode ser inválido
                  window.location.replace('login.html');
                  reject('No Firebase User');
              }
          });
      });
  }

  /* ====== STATE ====== */
  const state = { targets: [] };
  let allTags = new Set(); // Usamos Set para evitar duplicados

  /* ====== HELPERS ====== */
  const qs = (s, el = document) => el.querySelector(s);
  const qsa = (s, el = document) => Array.from(el.querySelectorAll(s));
  const uid = () => Math.random().toString(36).slice(2, 9); // Fallback para UI

  /* ====== FIRESTORE ACTIONS (Substitui LocalStorage) ====== */

  // 1. LOAD TARGETS
  async function loadTargets() {
    if (!requireAuth()) return; // A tua verificação
    
    try {
        const user = await ensureFirebaseUser(); // Espera pelo Auth do Firebase
        
        const q = query(collection(db, "Targets"), where("user_id", "==", user.uid));
        const querySnapshot = await getDocs(q);
        
        state.targets = [];
        allTags.clear();

        querySnapshot.forEach((docSnap) => {
            const data = docSnap.data();
            // Converter Snake_case (BD) para CamelCase (UI)
            const target = {
                id: docSnap.id, 
                name: data.name,
                value: data.value,
                kind: data.kind || (data.value.includes('/') ? 'network' : 'host'),
                addedAt: data.added_at || Date.now(),
                tags: data.tags || [],
                scans: data.scans || 0,
                cves: data.cves || 0,
                lastScan: data.last_scan || "-"
            };
            state.targets.push(target);
            
            if (target.tags && Array.isArray(target.tags)) {
                target.tags.forEach(t => allTags.add(t));
            }
        });

        renderTargets();
        renderTagsFilter();
    } catch (e) {
        console.error("Erro ao carregar targets:", e);
    }
  }

  // 2. ADD TARGET (Guardar na Firebase)
  async function addTargetToFirestore(targetData) {
      if (!requireAuth()) return;
      const user = await ensureFirebaseUser();

      try {
          await addDoc(collection(db, "Targets"), {
              name: targetData.name,
              value: targetData.value,
              kind: targetData.kind,
              user_id: user.uid, // Associa ao User
              added_at: Date.now(),
              tags: targetData.tags || [],
              scans: 0, 
              cves: 0, 
              last_scan: "-"
          });
          await loadTargets(); // Atualiza a lista
          return true;
      } catch (e) {
          console.error("Erro ao salvar:", e);
          alert("Erro ao conectar com a base de dados.");
          return false;
      }
  }

  // 3. UPDATE TARGET
  async function updateTargetInFirestore(id, updatedData) {
      if (!requireAuth()) return;
      await ensureFirebaseUser();

      try {
          const targetRef = doc(db, "Targets", id);
          await updateDoc(targetRef, updatedData);
          await loadTargets();
      } catch (e) { console.error("Erro ao atualizar:", e); }
  }

  // 4. DELETE TARGET
  async function deleteTargetFromFirestore(id) {
      if (!requireAuth()) return;
      await ensureFirebaseUser();

      if (!confirm("Delete this target?")) return;
      try {
          await deleteDoc(doc(db, "Targets", id));
          state.targets = state.targets.filter(t => t.id !== id);
          renderTargets();
      } catch (e) { console.error("Erro ao apagar:", e); }
  }

  // 5. BATCH DELETE
  async function batchDeleteFirestore(ids) {
      if (!requireAuth()) return;
      await ensureFirebaseUser();
      if (!ids.length) return;
      if (!confirm(`Delete ${ids.length} selected target(s)?`)) return;

      const batch = writeBatch(db);
      ids.forEach(id => {
          const ref = doc(db, "Targets", id);
          batch.delete(ref);
      });

      try {
          await batch.commit();
          await loadTargets();
          const allChk = document.getElementById("tgt-checkall");
          if (allChk) allChk.checked = false;
      } catch (e) { console.error("Batch delete error:", e); }
  }

  // 6. TAGS UPDATE
  async function updateTagsFirestore(ids, newTags) {
      if (!requireAuth()) return;
      await ensureFirebaseUser();

      const batch = writeBatch(db);
      ids.forEach(id => {
          const t = state.targets.find(x => x.id === id);
          if (!t) return;
          const mergedTags = Array.from(new Set([...(t.tags || []), ...newTags]));
          const ref = doc(db, "Targets", id);
          batch.update(ref, { tags: mergedTags });
      });

      try {
          await batch.commit();
          await loadTargets();
      } catch (e) { console.error("Tags update error:", e); }
  }

  /* ====== VALIDATION ====== */
  const reIPv4 = /^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/;
  const reCIDR = /^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}\/([0-9]|[12][0-9]|3[0-2])$/;
  const reHost = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$/;

  function isValidHostOrIPorCIDR(s) {
    if (!s) return false;
    const v = s.trim();
    if (v === 'localhost') return true;
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
    const sortedTags = Array.from(allTags).sort();
    const options = ['<option value="">All tags</option>'].concat(
      sortedTags.map(tag => `<option value="${escapeHtml(tag)}">${escapeHtml(tag)}</option>`)
    ).join('');
    container.innerHTML = options;
  }

  function renderTargets() {
    try {
      const wrap = document.getElementById("targets-list");
      const empty = document.getElementById("targets-empty");
      const count = document.getElementById("targets-count");
      if (!wrap) return;

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

      if(count) count.textContent = `${list.length} saved`;
      if(empty) empty.style.display = state.targets.length ? "none" : "block";

      wrap.innerHTML = "";
      list.forEach(t => {
        const riskClass = getRiskColor(t.cves || 0);
        const dateObj = new Date(t.addedAt);
        const addedStr = !isNaN(dateObj) ? dateObj.toISOString().slice(0,10) : '-';
        const lastScanStr = t.lastScan && t.lastScan !== '-' ? new Date(t.lastScan).toISOString().slice(0,10) : '-';

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
            <div class="tgt-sub muted">${escapeHtml(t.value)} • Added: ${addedStr}</div>
          </div>

          <div class="tgt-stats">
            <div class="stat"><span class="num">${t.scans ?? 0}</span><span class="lbl">Scans</span></div>
            <div class="stat"><span class="num">${t.cves ?? 0}</span><span class="lbl">Unique CVEs</span></div>
            <div class="stat"><span class="num">${lastScanStr}</span><span class="lbl">Last scan</span></div>
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

  /* ====== CSV IMPORT (Firestore) ====== */
  function handleCSVImport(file) {
    if (!requireAuth()) return;

    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const user = await ensureFirebaseUser();
        const text = e.target.result;
        const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
        if (!lines.length) { alert("CSV vazio."); return; }

        const headerCols = lines[0].split(',').map(s=>s.trim().toLowerCase());
        const start = (headerCols.includes('name') && headerCols.includes('value')) ? 1 : 0;

        const batch = writeBatch(db);
        let count = 0;
        const skipped = [];
        const existingValues = new Set(state.targets.map(t => (t.value || '').toLowerCase()));

        for (let i = start; i < lines.length; i++) {
          const cols = lines[i].split(',').map(c => c.trim());
          const name = cols[0] || `Imported #${i+1}`;
          const value = cols[1] || '';
          const tagsRaw = cols[2] || '';

          if (!value) { skipped.push({line: i+1, reason: 'empty'}); continue; }
          if (!isValidHostOrIPorCIDR(value)) { skipped.push({line: i+1, reason: 'invalid IP'}); continue; }
          if (existingValues.has(value.toLowerCase())) { skipped.push({line: i+1, reason: 'duplicate'}); continue; }

          const kind = value.includes('/') ? 'network' : 'host';
          const tags = tagsRaw ? tagsRaw.split(/[;,]+/).map(t => t.trim()).filter(Boolean) : [];

          const newRef = doc(collection(db, "Targets"));
          batch.set(newRef, {
              name, value, kind,
              user_id: user.uid,
              added_at: Date.now(),
              tags, scans: 0, cves: 0, last_scan: "-"
          });
          
          existingValues.add(value.toLowerCase());
          count++;
        }

        if (count === 0) {
          alert(`Nenhum target importado. ${skipped.length} ignorados.`);
          return;
        }

        await batch.commit();
        await loadTargets();
        alert(`${count} targets importados com sucesso!`);
      } catch (err) {
        console.error('handleCSVImport', err);
        alert("Erro ao processar CSV.");
      }
    };
    reader.readAsText(file);
  }

  /* ====== MODALS & EVENT LISTENERS ====== */
  function openEditModal(target) {
    try {
      const modal = document.getElementById("iplist-modal");
      const form = document.getElementById("iplist-form");
      const title = document.getElementById("iplist-modal-title");
      const nameInput = document.getElementById("iplist-name");
      const kindInput = document.getElementById("iplist-kind");
      const valueInput = document.getElementById("iplist-value");
      
      if (!modal || !form) return;

      title.textContent = "Edit Target";
      nameInput.value = target.name || '';
      kindInput.value = target.kind || 'host';
      valueInput.value = target.value || '';
      
      form.dataset.mode = "edit";
      form.dataset.targetId = target.id;

      modal.setAttribute("aria-hidden", "false");
    } catch (err) { console.error('openEditModal', err); }
  }

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
        <p class="muted">Add tags (comma separated).</p>
        <div style="margin:10px 0;">
          <input id="bulk-tag-input" class="input" placeholder="e.g., web, production" />
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
      const ids = selectedTargetIds();
      if (!tags.length || !ids.length) return;

      updateTagsFirestore(ids, tags).then(() => {
          div.setAttribute('aria-hidden','true');
      });
    });
  }

  function attachIf(el, event, cb) { try { if (!el) return false; el.addEventListener(event, cb); return true; } catch(e){ console.error('attachIf', e); return false; } }

  function init() {
    try {
      console.log('iplist:init start (Firebase mode)');

      // 1. Verificar Auth Local
      if (!requireAuth()) return;

      // 2. Iniciar carregamento (vai esperar pelo Firebase Auth)
      loadTargets();

      ensureTagModal();

      // UI Listeners
      const sidebar = document.getElementById("sidebar");
      const burger = document.getElementById("btn-burger");
      const SAVED = localStorage.getItem("vulnerai.sidebarCollapsed") === "1";
      if (SAVED && sidebar) sidebar.classList.add("collapsed");
      attachIf(burger, 'click', (e) => {
        e.stopPropagation();
        if (!sidebar) return;
        sidebar.classList.toggle("collapsed");
        localStorage.setItem("vulnerai.sidebarCollapsed", sidebar.classList.contains("collapsed") ? "1" : "0");
      });

      const userBtn = document.getElementById("btn-user");
      const userMenu = document.getElementById("menu-user");
      if (userBtn && userMenu) {
        attachIf(userBtn, 'click', (e)=> {
          e.stopPropagation();
          const isOpen = userMenu.getAttribute("aria-hidden") === "false";
          userBtn.setAttribute("aria-expanded", !isOpen);
          userMenu.setAttribute("aria-hidden", isOpen ? "true" : "false");
        });
        document.addEventListener("click", ()=> userMenu.setAttribute("aria-hidden", "true"));
      }

      attachIf(document.getElementById('btn-premium'), 'click', (e)=> {
        e.stopPropagation();
        document.getElementById('modal-premium')?.setAttribute('aria-hidden','false');
      });
      attachIf(document.getElementById('modal-premium'), 'click', (e)=> {
        if (e.target.hasAttribute('data-close') || e.target.classList.contains('backdrop')) {
          e.currentTarget.setAttribute('aria-hidden','true');
        }
      });

      // --- ADD TARGET MODAL ---
      const iplistModal = document.getElementById("iplist-modal");
      const btnOpenAdd = document.getElementById("iplist-open-add");
      const iplistForm = document.getElementById("iplist-form");

      if (btnOpenAdd && iplistModal && iplistForm) {
        attachIf(btnOpenAdd, 'click', ()=> {
          document.getElementById("iplist-modal-title").textContent = "Add Target";
          iplistForm.reset();
          iplistForm.dataset.mode = "create";
          delete iplistForm.dataset.targetId;
          iplistModal.setAttribute("aria-hidden","false");
        });
        attachIf(iplistModal, 'click', (e)=> {
          if (e.target.hasAttribute("data-close") || e.target.classList.contains("iplist-backdrop")) {
            iplistModal.setAttribute("aria-hidden","true");
          }
        });
      }

      // --- FORM SUBMIT (Create/Update) ---
      if (iplistForm) {
        attachIf(iplistForm, 'submit', async (e)=> {
          e.preventDefault();
          if (!requireAuth()) return; 

          try {
            const name = (document.getElementById("iplist-name")?.value || '').trim();
            const kind = document.getElementById("iplist-kind")?.value || 'host';
            const value = (document.getElementById("iplist-value")?.value || '').trim();

            if (!name) { alert("Please enter a Name."); return; }
            if (!isValidHostOrIPorCIDR(value)) { alert("Invalid Host/IP."); return; }
            
            // Check duplicado local
            if (iplistForm.dataset.mode !== "edit") {
                if (state.targets.some(t => (t.value || '').toLowerCase() === value.toLowerCase())) { 
                    alert('Target already exists.'); return; 
                }
            }

            if (iplistForm.dataset.mode === "edit") {
                const id = iplistForm.dataset.targetId;
                await updateTargetInFirestore(id, { name, kind, value });
            } else {
                await addTargetToFirestore({ name, kind, value });
            }

            iplistForm.reset();
            iplistModal && iplistModal.setAttribute("aria-hidden","true");
          } catch(err) { console.error('form submit', err); }
        });
      }

      // Filtros
      attachIf(document.getElementById("tgt-search"), 'input', renderTargets);
      attachIf(document.getElementById("tgt-sort"), 'change', renderTargets);
      attachIf(document.getElementById("tags-filter"), 'change', renderTargets);

      // Bulk Actions
      attachIf(document.getElementById("tgt-checkall"), 'change', (e)=> {
        qsa('#targets-list input[type="checkbox"]').forEach(c => c.checked = e.target.checked);
        updateBulkCount();
      });
      attachIf(document.getElementById("targets-list"), 'change', (e)=> {
        if (e.target && e.target.type === "checkbox") updateBulkCount();
      });
      attachIf(document.getElementById("tgt-bulk-delete"), 'click', ()=> {
        batchDeleteFirestore(selectedTargetIds());
      });
      attachIf(document.getElementById("tgt-bulk-tags"), 'click', ()=> {
        const ids = selectedTargetIds();
        if (!ids.length) { alert('No targets selected.'); return; }
        document.getElementById('bulk-tag-input') && (document.getElementById('bulk-tag-input').value = '');
        document.getElementById('bulk-tag-modal') && document.getElementById('bulk-tag-modal').setAttribute('aria-hidden','false');
      });
      attachIf(document.getElementById("tgt-bulk-scan"), 'click', ()=> {
        const ids = selectedTargetIds();
        if (!ids.length) return;
        if (ids.length === 1) {
          const t = state.targets.find(x => x.id === ids[0]);
          if (t) window.location.href = `scans.html?target=${encodeURIComponent(t.value)}&id=${t.id}`;
        } else {
          alert("Multi-scan not implemented in UI yet.");
        }
      });

      // CSV Import
      let csvInput = document.getElementById("csv-upload-input");
      if (!csvInput) {
        csvInput = document.createElement("input");
        csvInput.type = "file";
        csvInput.accept = ".csv";
        csvInput.style.display = "none";
        csvInput.id = "csv-upload-input";
        document.body.appendChild(csvInput);
      }
      attachIf(document.getElementById("iplist-import-csv"), 'click', ()=> csvInput.click());
      attachIf(csvInput, 'change', (e) => {
        if (e.target.files[0]) handleCSVImport(e.target.files[0]);
        e.target.value = "";
      });

      // Lista Actions (Edit/Delete/Scan)
      attachIf(document.getElementById("view-iplist"), 'click', (e)=> {
        const btn = e.target.closest("button[data-action]");
        const chip = e.target.closest('.chip-tag');
        
        if (chip && chip.dataset.tag) {
             const tag = chip.dataset.tag;
             const tagSel = document.getElementById('tags-filter');
             if (tagSel) { tagSel.value = tag; renderTargets(); }
             return;
        }

        if (!btn) return;
        const id = btn.dataset.id;
        const target = state.targets.find(x => x.id === id);
        if (!target) return;

        const act = btn.dataset.action;
        if (act === "delete") deleteTargetFromFirestore(id);
        if (act === "edit") openEditModal(target);
        if (act === "tags") {
            const current = prompt("Enter tags (comma-separated):", (target.tags || []).join(", ")) || "";
            const tags = current.split(/[;,]+/).map(t => t.trim()).filter(Boolean);
            if (tags.length) updateTagsFirestore([id], tags);
        }
        if (act === "start-scan" || act === "view-scans") { 
            window.location.href = `scans.html?target=${encodeURIComponent(target.value)}&id=${target.id}`; 
        }
      });

      // Logout
      attachIf(document.getElementById('menu-user'), 'click', (e) => {
          const item = e.target.closest(".menu-item");
          if (item && item.dataset.action === "logout") {
             auth.signOut().then(() => {
                 localStorage.removeItem('vulnerai.auth');
                 window.location.href = "login.html";
             });
          }
      });

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
          const selectors = ['#start-scan-btn', 'button[data-action="start-scan"]', '#btn-start-scan'];
          for (const sel of selectors) {
            const btn = document.querySelector(sel);
            if (btn && !btn.disabled) {
              setTimeout(() => btn.click(), 300); 
              return true;
            }
          }
          return false;
        };
        if (startScan()) return;
        let attempts = 0;
        const interval = setInterval(() => {
          attempts++;
          if (startScan() || attempts > 80) clearInterval(interval);
        }, 100);
      }
    } catch (e) { console.error('[Auto-Scan] Erro:', e); }
  });
}