/* iplist.js — Firebase Integrated Version with Real-Time Stats */

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

(function () {
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
      try { window.location.replace('login.html'); } catch (e) { }
      return false;
    }
    return true;
  }

  /* ====== STATE ====== */
  const state = {
    targets: [],
    currentUser: null,
    isFirebaseReady: false
  };

  let allTags = new Set();

  /* ====== HELPERS ====== */
  const qs = (s, el = document) => el.querySelector(s);
  const qsa = (s, el = document) => Array.from(el.querySelectorAll(s));
  const uid = () => Math.random().toString(36).slice(2, 9);

  // Helper para formatar data (Dia, Hora:Minutos)
  function formatDateNice(timestamp) {
    if (!timestamp || timestamp === "-") return "-";

    // Se for timestamp do Firestore (objeto com seconds)
    let date;
    if (timestamp.seconds) {
      date = new Date(timestamp.seconds * 1000);
    } else {
      date = new Date(timestamp);
    }

    if (isNaN(date.getTime())) return "-";

    // Formato: 13/12/2025 18:30
    return new Intl.DateTimeFormat('pt-PT', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    }).format(date);
  }

  /* ====== FIRESTORE ACTIONS ====== */

  async function ensureFirebaseUser() {
    if (state.currentUser) return state.currentUser;
    return new Promise((resolve) => {
      const unsubscribe = onAuthStateChanged(auth, (user) => {
        unsubscribe();
        if (user) {
          state.currentUser = user;
          state.isFirebaseReady = true;
          resolve(user);
        } else {
          console.warn("Firebase Auth falhou.");
          window.location.replace('login.html');
          resolve(null);
        }
      });
    });
  }

  // 1. CARREGAR (COM ESTATÍSTICAS DA COLEÇÃO SCAN)
  async function loadTargets() {
    if (!requireAuth()) return;

    const user = await ensureFirebaseUser();
    if (!user) return;

    try {
      console.log("A carregar Targets e Scans...");

      // 1. Buscar Targets do User
      const qTargets = query(collection(db, "Targets"), where("user_id", "==", user.uid));
      const targetsSnap = await getDocs(qTargets);

      // 2. Buscar Scans do User (para calcular estatísticas)
      const qScans = query(collection(db, "Scan"), where("user_id", "==", user.uid));
      const scansSnap = await getDocs(qScans);

      // Converter scans para array simples
      const allScans = [];
      scansSnap.forEach(doc => allScans.push(doc.data()));

      state.targets = [];
      allTags.clear();

      targetsSnap.forEach((docSnap) => {
        const tData = docSnap.data();

        // --- LÓGICA DE ESTATÍSTICA ---
        // Encontrar scans que correspondem a este target (pelo campo 'value' == 'target')
        const relevantScans = allScans.filter(scan => scan.target === tData.value);

        // 1. Quantidade de Scans
        const totalScans = relevantScans.length;

        // 2. Encontrar o último scan (para data e CVEs atuais)
        let lastScanDate = "-";
        let currentCVEs = 0;

        if (totalScans > 0) {
          // Ordenar por data (mais recente primeiro)
          relevantScans.sort((a, b) => {
            const dateA = a.submitted_at?.seconds ? a.submitted_at.seconds : (a.submitted_at || 0);
            const dateB = b.submitted_at?.seconds ? b.submitted_at.seconds : (b.submitted_at || 0);
            return dateB - dateA;
          });

          const latest = relevantScans[0];

          // Definir data do último scan
          if (latest.submitted_at) {
            lastScanDate = latest.submitted_at;
          }

          // Definir CVEs do último scan (assumindo que está em summary.vulnerabilities_total)
          if (latest.summary && typeof latest.summary.vulnerabilities_total !== 'undefined') {
            currentCVEs = latest.summary.vulnerabilities_total;
          }
        }

        // Construir objeto final
        const target = {
          id: docSnap.id,
          name: tData.name,
          value: tData.value,
          kind: tData.kind || (tData.value.includes('/') ? 'network' : 'host'),
          addedAt: tData.added_at || Date.now(),
          user_id: tData.user_id,
          tags: tData.tags || [],

          // Dados calculados dinamicamente
          scans: totalScans,
          cves: currentCVEs,
          lastScan: lastScanDate
        };

        state.targets.push(target);

        if (target.tags && Array.isArray(target.tags)) {
          target.tags.forEach(t => allTags.add(t));
        }
      });

      renderTargets();
      renderTagsFilter();
    } catch (error) {
      console.error("Erro ao carregar dados:", error);
    }
  }

  // 2. ADICIONAR (CREATE)
  async function addTargetToFirestore(targetData) {
    if (!requireAuth()) return false;
    const user = await ensureFirebaseUser();
    if (!user) return false;

    try {
      await addDoc(collection(db, "Targets"), {
        name: targetData.name,
        value: targetData.value,
        kind: targetData.kind,
        user_id: user.uid,
        added_at: Date.now(),
        tags: targetData.tags || []
        // Nota: não precisamos salvar scans/cves aqui, pois são calculados dinamicamente
      });
      await loadTargets();
      return true;
    } catch (e) {
      console.error("Erro ao salvar:", e);
      alert("Erro ao conectar com a base de dados.");
      return false;
    }
  }

  // 3. EDITAR (UPDATE)
  async function updateTargetInFirestore(id, updatedData) {
    if (!requireAuth()) return;
    await ensureFirebaseUser();

    try {
      const targetRef = doc(db, "Targets", id);
      await updateDoc(targetRef, updatedData);
      await loadTargets();
    } catch (e) { console.error("Erro ao atualizar:", e); }
  }

  // 4. APAGAR (DELETE)
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

      if (count) count.textContent = `${list.length} saved`;
      if (empty) empty.style.display = state.targets.length ? "none" : "block";

      wrap.innerHTML = "";
      list.forEach(t => {
        const riskClass = getRiskColor(t.cves || 0);

        // Data de adição
        const dateObj = new Date(t.addedAt);
        const addedStr = !isNaN(dateObj) ? dateObj.toISOString().slice(0, 10) : '-';

        // Data do último scan (formatada com dia e hora)
        const lastScanStr = formatDateNice(t.lastScan);

        let vulnChips = "";
        // Se quiseres mostrar badges de risco (opcional, requer lógica adicional no objeto t)
        if (t.cves > 0) {
          vulnChips = `<span class="chip ${riskClass}" title="Total Vulnerabilities">${t.cves} CVEs</span>`;
        } else {
          vulnChips = `<span class="chip chip-green">0 CVEs</span>`;
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
              ${vulnChips}
              ${(t.tags || []).map(tag => `<button class="chip chip-tag" data-tag="${escapeHtml(tag)}" title="Filter by ${escapeHtml(tag)}">${escapeHtml(tag)}</button>`).join(' ')}
            </div>
            <div class="tgt-sub muted">${escapeHtml(t.value)} • Added: ${addedStr}</div>
          </div>

          <div class="tgt-stats">
            <div class="stat"><span class="num">${t.scans}</span><span class="lbl">Total Scans</span></div>
            <div class="stat"><span class="num" style="font-size:0.9em">${lastScanStr}</span><span class="lbl">Last scan</span></div>
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
    } catch (e) { console.error(e); }
  }

  /* ====== CSV IMPORT ====== */
  function handleCSVImport(file) {
    if (!requireAuth()) return;

    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const user = await ensureFirebaseUser();
        const text = e.target.result;
        const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
        if (!lines.length) { alert("CSV vazio."); return; }

        const headerCols = lines[0].split(',').map(s => s.trim().toLowerCase());
        const start = (headerCols.includes('name') && headerCols.includes('value')) ? 1 : 0;

        const batch = writeBatch(db);
        let count = 0;
        const skipped = [];
        const existingValues = new Set(state.targets.map(t => (t.value || '').toLowerCase()));

        for (let i = start; i < lines.length; i++) {
          const cols = lines[i].split(',').map(c => c.trim());
          const name = cols[0] || `Imported #${i + 1}`;
          const value = cols[1] || '';
          const tagsRaw = cols[2] || '';

          if (!value) { skipped.push({ line: i + 1, reason: 'empty' }); continue; }
          if (!isValidHostOrIPorCIDR(value)) { skipped.push({ line: i + 1, reason: 'invalid IP' }); continue; }
          if (existingValues.has(value.toLowerCase())) { skipped.push({ line: i + 1, reason: 'duplicate' }); continue; }

          const kind = value.includes('/') ? 'network' : 'host';
          const tags = tagsRaw ? tagsRaw.split(/[;,]+/).map(t => t.trim()).filter(Boolean) : [];

          const newRef = doc(collection(db, "Targets"));
          batch.set(newRef, {
            name, value, kind,
            user_id: user.uid,
            added_at: Date.now(),
            tags
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
    div.setAttribute('aria-hidden', 'true');
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
        div.setAttribute('aria-hidden', 'true');
      }
    });

    div.querySelector('#bulk-tag-apply')?.addEventListener('click', () => {
      const raw = (document.getElementById('bulk-tag-input')?.value || '').trim();
      const tags = raw.split(/[;,]+/).map(t => t.trim()).filter(Boolean);
      const ids = selectedTargetIds();
      if (!tags.length || !ids.length) return;

      updateTagsFirestore(ids, tags).then(() => {
        div.setAttribute('aria-hidden', 'true');
      });
    });
  }

  function attachIf(el, event, cb) { try { if (!el) return false; el.addEventListener(event, cb); return true; } catch (e) { console.error('attachIf', e); return false; } }

  /* ====== AUTO-OPEN MODALS FROM URL ====== */
function checkUrlForActions() {
    const urlParams = new URLSearchParams(window.location.search);
    const action = urlParams.get('action');

    if (action === 'add') {
        console.log('[Auto-Action] Opening Add Target modal');
        // Simular clique no botão "Add Target" da página para abrir o modal
        const btnAdd = document.getElementById("iplist-open-add");
        if (btnAdd) setTimeout(() => btnAdd.click(), 300);
    }

    if (action === 'import') {
        console.log('[Auto-Action] Opening Import modal');
        // Simular clique no botão "Import CSV"
        const btnImport = document.getElementById("iplist-import-csv");
        if (btnImport) setTimeout(() => btnImport.click(), 300);
    }
}

  function init() {
    try {
      console.log('iplist:init start (Firebase mode + Stats)');

      // 1. Verificar Auth Local
      if (!requireAuth()) return;

      // 2. Iniciar carregamento
      loadTargets();
      checkUrlForActions();
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
        attachIf(userBtn, 'click', (e) => {
          e.stopPropagation();
          const isOpen = userMenu.getAttribute("aria-hidden") === "false";
          userBtn.setAttribute("aria-expanded", !isOpen);
          userMenu.setAttribute("aria-hidden", isOpen ? "true" : "false");
        });
        document.addEventListener("click", () => userMenu.setAttribute("aria-hidden", "true"));
      }

      attachIf(document.getElementById('btn-premium'), 'click', (e) => {
        e.stopPropagation();
        document.getElementById('modal-premium')?.setAttribute('aria-hidden', 'false');
      });
      attachIf(document.getElementById('modal-premium'), 'click', (e) => {
        if (e.target.hasAttribute('data-close') || e.target.classList.contains('backdrop')) {
          e.currentTarget.setAttribute('aria-hidden', 'true');
        }
      });

      // --- ADD TARGET MODAL ---
      const iplistModal = document.getElementById("iplist-modal");
      const btnOpenAdd = document.getElementById("iplist-open-add");
      const iplistForm = document.getElementById("iplist-form");

      if (btnOpenAdd && iplistModal && iplistForm) {
        attachIf(btnOpenAdd, 'click', () => {
          document.getElementById("iplist-modal-title").textContent = "Add Target";
          iplistForm.reset();
          iplistForm.dataset.mode = "create";
          delete iplistForm.dataset.targetId;
          iplistModal.setAttribute("aria-hidden", "false");
        });
        attachIf(iplistModal, 'click', (e) => {
          if (e.target.hasAttribute("data-close") || e.target.classList.contains("iplist-backdrop")) {
            iplistModal.setAttribute("aria-hidden", "true");
          }
        });
      }

      // --- FORM SUBMIT (Create/Update) ---
      if (iplistForm) {
        attachIf(iplistForm, 'submit', async (e) => {
          e.preventDefault();
          if (!requireAuth()) return;

          try {
            const name = (document.getElementById("iplist-name")?.value || '').trim();
            const kind = document.getElementById("iplist-kind")?.value || 'host';
            const value = (document.getElementById("iplist-value")?.value || '').trim();

            if (!name) { alert("Please enter a Name."); return; }
            if (!isValidHostOrIPorCIDR(value)) { alert("Invalid Host/IP."); return; }

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
            iplistModal && iplistModal.setAttribute("aria-hidden", "true");
          } catch (err) { console.error('form submit', err); }
        });
      }

      // Filtros
      attachIf(document.getElementById("tgt-search"), 'input', renderTargets);
      attachIf(document.getElementById("tgt-sort"), 'change', renderTargets);
      attachIf(document.getElementById("tags-filter"), 'change', renderTargets);

      // Checkboxes & Bulk
      attachIf(document.getElementById("tgt-checkall"), 'change', (e) => {
        qsa('#targets-list input[type="checkbox"]').forEach(c => c.checked = e.target.checked);
        updateBulkCount();
      });
      attachIf(document.getElementById("targets-list"), 'change', (e) => {
        if (e.target && e.target.type === "checkbox") updateBulkCount();
      });
      attachIf(document.getElementById("tgt-bulk-delete"), 'click', () => {
        batchDeleteFirestore(selectedTargetIds());
      });
      attachIf(document.getElementById("tgt-bulk-tags"), 'click', () => {
        const ids = selectedTargetIds();
        if (!ids.length) { alert('No targets selected.'); return; }
        document.getElementById('bulk-tag-input') && (document.getElementById('bulk-tag-input').value = '');
        document.getElementById('bulk-tag-modal') && document.getElementById('bulk-tag-modal').setAttribute('aria-hidden', 'false');
      });
      attachIf(document.getElementById("tgt-bulk-scan"), 'click', () => {
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
      attachIf(document.getElementById("iplist-import-csv"), 'click', () => csvInput.click());
      attachIf(csvInput, 'change', (e) => {
        if (e.target.files[0]) handleCSVImport(e.target.files[0]);
        e.target.value = "";
      });

      // Lista Actions
      attachIf(document.getElementById("view-iplist"), 'click', (e) => {
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
        if (act === "view-scans") {
          window.location.href = `scans.html?target=${encodeURIComponent(target.value)}`;
        }

        // Ação: Começar novo scan (Leva target, id e flag action=start)
        if (act === "start-scan") {
          window.location.href = `scans.html?target=${encodeURIComponent(target.value)}&id=${target.id}&action=start`;
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
/* AUTO-START SCAN                                       */
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