/* iplist.js — Firebase Integrated Version
   - Mantém o teu UI (Popup, Filtros, CSV, Tags)
   - Substitui LocalStorage por Firestore
   - Garante isolamento por User ID
*/

import { initializeApp } from "https://www.gstatic.com/firebasejs/9.22.2/firebase-app.js";
import { 
    getFirestore, collection, addDoc, getDocs, 
    query, where, deleteDoc, doc, updateDoc, writeBatch 
} from "https://www.gstatic.com/firebasejs/9.22.2/firebase-firestore.js";
import { getAuth, onAuthStateChanged } from "https://www.gstatic.com/firebasejs/9.22.2/firebase-auth.js";

// --- TUA CONFIGURAÇÃO FIREBASE ---
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

  /* ====== STATE ====== */
  const state = { 
      targets: [],
      currentUser: null
  };

  // Tags agora são calculadas dinamicamente baseadas nos dados da BD
  let allTags = new Set();

  /* ====== HELPERS ====== */
  const qs = (s, el = document) => el.querySelector(s);
  const qsa = (s, el = document) => Array.from(el.querySelectorAll(s));
  // UID agora é gerado pelo Firestore, mas mantemos a função para casos de fallback
  const uid = () => Math.random().toString(36).slice(2, 9); 

  /* ====== FIRESTORE ACTIONS (Substitui LocalStorage) ====== */
  
  // 1. CARREGAR (READ) - Filtra pelo ID do utilizador logado
  async function loadTargets() {
    if (!state.currentUser) return;

    try {
        const q = query(collection(db, "Targets"), where("user_id", "==", state.currentUser.uid));
        const querySnapshot = await getDocs(q);
        
        state.targets = [];
        allTags.clear();

        querySnapshot.forEach((docSnap) => {
            const data = docSnap.data();
            // Mapeamos os campos da BD (snake_case) para o teu UI (camelCase)
            const target = {
                id: docSnap.id, // ID real do documento Firestore
                name: data.name,
                value: data.value,
                kind: data.kind || (data.value.includes('/') ? 'network' : 'host'),
                addedAt: data.added_at || Date.now(),
                user_id: data.user_id,
                tags: data.tags || [],
                scans: data.scans || 0,
                cves: data.cves || 0,
                lastScan: data.last_scan || "-"
            };
            state.targets.push(target);
            
            // Atualizar lista de tags disponíveis
            if (target.tags && Array.isArray(target.tags)) {
                target.tags.forEach(t => allTags.add(t));
            }
        });

        renderTargets();
        renderTagsFilter();
    } catch (error) {
        console.error("Erro ao carregar targets da Firebase:", error);
    }
  }

  // 2. SALVAR/CRIAR (CREATE)
  async function addTargetToFirestore(targetData) {
      if (!state.currentUser) return false;
      try {
          // Guardamos com os campos que a tua BD espera (ver imagem que mandaste)
          await addDoc(collection(db, "Targets"), {
              name: targetData.name,
              value: targetData.value,
              kind: targetData.kind,
              user_id: state.currentUser.uid,
              added_at: Date.now(),
              tags: targetData.tags || [],
              scans: 0, 
              cves: 0, 
              last_scan: "-"
          });
          await loadTargets(); // Recarregar lista
          return true;
      } catch (e) {
          console.error("Erro ao salvar no Firestore:", e);
          alert("Erro ao conectar com a base de dados.");
          return false;
      }
  }

  // 3. EDITAR (UPDATE)
  async function updateTargetInFirestore(id, updatedData) {
      try {
          const targetRef = doc(db, "Targets", id);
          await updateDoc(targetRef, updatedData);
          await loadTargets();
      } catch (e) {
          console.error("Erro ao atualizar:", e);
      }
  }

  // 4. APAGAR (DELETE)
  async function deleteTargetFromFirestore(id) {
      if (!confirm("Delete this target?")) return;
      try {
          await deleteDoc(doc(db, "Targets", id));
          // Atualiza UI localmente instantaneamente
          state.targets = state.targets.filter(t => t.id !== id);
          renderTargets();
      } catch (e) {
          console.error("Erro ao apagar:", e);
      }
  }

  // 5. APAGAR MÚLTIPLOS (BATCH DELETE)
  async function batchDeleteFirestore(ids) {
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
          // Reset checkall
          const allChk = document.getElementById("tgt-checkall");
          if (allChk) allChk.checked = false;
      } catch (e) {
          console.error("Erro no batch delete:", e);
      }
  }

  // 6. TAGS UPDATE
  async function updateTagsFirestore(ids, newTags) {
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
      } catch (e) {
          console.error("Erro ao atualizar tags:", e);
      }
  }

  /* ====== VALIDATION ====== */
  const reIPv4 = /^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/;
  const reCIDR = /^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}\/([0-9]|[12][0-9]|3[0-2])$/;
  const reHost = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$/;

  function isValidHostOrIPorCIDR(s) {
    if (!s) return false;
    const v = s.trim();
    // Adicionei localhost para testes
    if (v === 'localhost') return true;
    return reIPv4.test(v) || reCIDR.test(v) || reHost.test(v);
  }

  function escapeHtml(s) {
    return String(s || '').replace(/[&<>\"']/g, m => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m]));
  }

  /* ====== UI RENDER (IGUAL AO TEU) ====== */
  function getRiskColor(cves) {
    if (cves >= 10) return "chip-red";
    if (cves >= 5) return "chip-orange";
    if (cves >= 1) return "chip-yellow";
    return "chip-green";
  }

  function renderTagsFilter() {
    const container = document.getElementById("tags-filter");
    if (!container) return;
    // Converter Set para Array e ordenar
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
        // Formatação de data segura
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

  /* ====== CSV IMPORT (Modificado para Firestore Batch) ====== */
  function handleCSVImport(file) {
    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const text = e.target.result;
        const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
        if (!lines.length) { alert("CSV vazio."); return; }

        const headerCols = lines[0].split(',').map(s=>s.trim().toLowerCase());
        const hasHeader = headerCols.includes('name') && headerCols.includes('value');
        const start = hasHeader ? 1 : 0;

        // Validar e preparar batch
        const batch = writeBatch(db);
        let count = 0;
        const skipped = [];

        // Check duplicados localmente primeiro para evitar chamadas
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

          // Criar referência para novo doc
          const newRef = doc(collection(db, "Targets"));
          batch.set(newRef, {
              name, value, kind,
              user_id: state.currentUser.uid,
              added_at: Date.now(),
              tags, scans: 0, cves: 0, last_scan: "-"
          });
          
          existingValues.add(value.toLowerCase());
          count++;
        }

        if (count === 0) {
          const msg = skipped.length ? `Nenhum target importado. Erros: ${skipped.map(s=>`(L${s.line}: ${s.reason})`).join(', ')}` : 'Nenhum dado válido.';
          alert(msg);
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

  /* ====== EDIT TARGET (Modificado para usar ID) ====== */
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
      
      // Guardar ID e modo no dataset do form
      form.dataset.mode = "edit";
      form.dataset.targetId = target.id;

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

      // Chamar função de update do Firestore
      updateTagsFirestore(ids, tags).then(() => {
          div.setAttribute('aria-hidden','true');
      });
    });
  }

  /* ====== INIT & LISTENERS ====== */
  function attachIf(el, event, cb) { try { if (!el) return false; el.addEventListener(event, cb); return true; } catch(e){ console.error('attachIf', e); return false; } }

  function init() {
    try {
      console.log('iplist:init start (Firebase mode)');

      // 1. AUTH LISTENER - Substitui verificação síncrona
      onAuthStateChanged(auth, (user) => {
          if (user) {
              state.currentUser = user;
              console.log("Logged in as:", user.email);
              loadTargets();
          } else {
              console.warn("No user, redirecting...");
              window.location.replace('login.html');
          }
      });

      ensureTagModal();
      const suggestions = document.getElementById('bulk-tag-suggestions');
      if (suggestions) suggestions.textContent = Array.from(allTags).join(', ');

      // Sidebar logic
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

      // User Menu logic
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
      }

      // Premium Modal
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

      // --- TARGET POPUP & FORM LOGIC ---
      const iplistModal = document.getElementById("iplist-modal");
      const btnOpenAdd = document.getElementById("iplist-open-add");
      const iplistForm = document.getElementById("iplist-form");

      // Botão "+ Add Target"
      if (btnOpenAdd && iplistModal && iplistForm) {
        attachIf(btnOpenAdd, 'click', ()=> {
          document.getElementById("iplist-modal-title") && (document.getElementById("iplist-modal-title").textContent = "Add Target");
          iplistForm.reset();
          // Reset mode
          iplistForm.dataset.mode = "create";
          delete iplistForm.dataset.targetId;
          iplistModal.setAttribute("aria-hidden","false");
        });
        
        attachIf(iplistModal, 'click', (e)=> {
          if (e.target.hasAttribute("data-close") || e.target.classList.contains("iplist-close") || e.target.classList.contains("iplist-backdrop")) {
            iplistModal.setAttribute("aria-hidden","true");
          }
        });
      }

      // SUBMIT DO FORMULÁRIO (ADD OU EDIT)
      if (iplistForm) {
        attachIf(iplistForm, 'submit', async (e)=> {
          e.preventDefault();
          try {
            const name = (document.getElementById("iplist-name")?.value || '').trim();
            const kind = document.getElementById("iplist-kind")?.value || 'host';
            const value = (document.getElementById("iplist-value")?.value || '').trim();

            if (!name) { alert("Please enter a Name/Title."); return; }
            if (!isValidHostOrIPorCIDR(value)) { alert("Please enter a valid Host/IP."); return; }
            
            // Se for CREATE, verifica duplicados localmente
            if (iplistForm.dataset.mode !== "edit") {
                if (state.targets.some(t => (t.value || '').toLowerCase() === value.toLowerCase())) { 
                    alert('Target with this value already exists.'); return; 
                }
            }

            // Ação Firestore
            if (iplistForm.dataset.mode === "edit") {
                const id = iplistForm.dataset.targetId;
                await updateTargetInFirestore(id, { name, kind, value });
            } else {
                await addTargetToFirestore({ name, kind, value });
            }

            iplistForm.reset();
            iplistModal && iplistModal.setAttribute("aria-hidden","true");
          } catch(err) { console.error('iplistForm submit', err); }
        });
      }

      // Filtros
      attachIf(document.getElementById("tgt-search"), 'input', renderTargets);
      attachIf(document.getElementById("tgt-sort"), 'change', renderTargets);
      attachIf(document.getElementById("tags-filter"), 'change', renderTargets);

      // Checkboxes & Bulk
      attachIf(document.getElementById("tgt-checkall"), 'change', (e)=> {
        qsa('#targets-list input[type="checkbox"]').forEach(c => c.checked = e.target.checked);
        updateBulkCount();
      });
      attachIf(document.getElementById("targets-list"), 'change', (e)=> {
        if (e.target && e.target.type === "checkbox") updateBulkCount();
      });

      // Bulk Delete
      attachIf(document.getElementById("tgt-bulk-delete"), 'click', ()=> {
        const ids = selectedTargetIds();
        batchDeleteFirestore(ids);
      });

      // Bulk Scan
      attachIf(document.getElementById("tgt-bulk-scan"), 'click', ()=> {
        const ids = selectedTargetIds();
        if (!ids.length) return;
        if (ids.length === 1) {
          const t = state.targets.find(x => x.id === ids[0]);
          if (t) window.location.href = `scans.html?target=${encodeURIComponent(t.value)}&id=${t.id}`;
        } else {
          // Exemplo: passar IDs via URL ou localStorage para página de scan
          alert("Multi-scan not implemented in UI yet.");
        }
      });

      // Bulk Tags
      attachIf(document.getElementById("tgt-bulk-tags"), 'click', ()=> {
        const ids = selectedTargetIds();
        if (!ids.length) { alert('No targets selected.'); return; }
        document.getElementById('bulk-tag-input') && (document.getElementById('bulk-tag-input').value = '');
        document.getElementById('bulk-tag-modal') && document.getElementById('bulk-tag-modal').setAttribute('aria-hidden','false');
      });

      // CSV Upload
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

      // Cliques na lista (Edit, Delete, Start Scan)
      attachIf(document.getElementById("view-iplist"), 'click', (e)=> {
        const btn = e.target.closest("button[data-action]");
        
        // Tratar clique em TAG (chip)
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
        if (act === "delete") {
            deleteTargetFromFirestore(id);
            return;
        }
        if (act === "edit") { 
            openEditModal(target); 
            return; 
        }
        if (act === "tags") {
            const current = prompt("Enter tags (comma-separated):", (target.tags || []).join(", ")) || "";
            const tags = current.split(/[;,]+/).map(t => t.trim()).filter(Boolean);
            if (tags.length) updateTagsFirestore([id], tags);
            return;
        }
        if (act === "start-scan" || act === "view-scans") { 
            window.location.href = `scans.html?target=${encodeURIComponent(target.value)}&id=${target.id}`; 
            return; 
        }
      });

      attachIf(document.getElementById('targets-list'), 'click', (e)=> {
          // Fallback para clicks dentro da lista se view-iplist não apanhar
          const chip = e.target.closest('.chip-tag');
          if (chip && chip.dataset.tag) {
            const tag = chip.dataset.tag;
            const tagSel = document.getElementById('tags-filter');
            if (tagSel) { tagSel.value = tag; renderTargets(); }
          }
      });

      // Logout / Upgrade
      // (Mantido a lógica original de logout dentro do listener do menu, mas agora o auth listener vai redirecionar)
      attachIf(document.getElementById('menu-user'), 'click', (e) => {
          const item = e.target.closest(".menu-item");
          if (item && item.dataset.action === "logout") {
             auth.signOut().then(() => localStorage.removeItem('vulnerai.auth'));
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