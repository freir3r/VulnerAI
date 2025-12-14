/* index.js — Firebase Integrated (Complete with UI Polish) */

import { initializeApp } from "https://www.gstatic.com/firebasejs/9.22.2/firebase-app.js";
import { 
    getFirestore, collection, getDocs, query, where, orderBy, limit 
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

/* ====== AUTH (guard) ====== */
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

/* ====== HELPERS ====== */
const qs = (s, el = document) => el.querySelector(s);
const qsa = (s, el = document) => [...el.querySelectorAll(s)];
const escapeHtml = (str = '') => String(str)
  .replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;')
  .replaceAll('"','&quot;').replaceAll("'",'&#039;');

/* ====== Storage keys and events ---- */
const STORAGE_TARGETS_KEY = 'vulnerai.targets';
const STORAGE_SCANS_KEY = 'vulnerai.scans';
const STORAGE_SCHEDULES_KEY = 'vulnerai.schedules';
const STORAGE_ACTIVITY_KEY = 'vulnerai.activity';

const events = {
  handlers: {},
  on(k, fn){ (this.handlers[k] ||= []).push(fn); },
  emit(k,d){ (this.handlers[k] || []).forEach(f => f(d)); }
};

/* ---- utils ---- */
const uid = (p='id') => `${p}_${Math.random().toString(36).slice(2,9)}`;
const nowTs = () => Date.now();
const isCIDR = s => typeof s === 'string' && s.includes('/');
const msToHuman = ms => {
  if(ms == null || isNaN(ms)) return '-';
  const s = Math.round(ms/1000);
  if(s < 60) return `${s}s`;
  if(s < 3600) return `${Math.round(s/60)}m`;
  return `${Math.round(s/3600)}h`;
};
const timeAgo = ts => {
  if(!ts) return '-';
  const diff = Math.floor((Date.now()-ts)/1000);
  if(diff < 60) return `Just now`;
  if(diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if(diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return `${Math.floor(diff/86400)}d ago`;
};

// Helper for mixed dates (Firebase Timestamp or ISO String)
function parseDate(val) {
    if (!val) return 0;
    if (val.seconds) return val.seconds * 1000; 
    return new Date(val).getTime(); 
}

/* ---- storage helpers (Keeping these for non-scan related features like scheduling/activity if needed locally) ---- */
function loadTargets(){ try { return JSON.parse(localStorage.getItem(STORAGE_TARGETS_KEY) || '[]'); } catch { return []; } }
function saveTargets(list){ localStorage.setItem(STORAGE_TARGETS_KEY, JSON.stringify(list || [])); events.emit('targets:updated', list); }
// Scans are now loaded from Firebase, but keeping save/load as fallback or for demo data
function loadScansLocal(){ try { return JSON.parse(localStorage.getItem(STORAGE_SCANS_KEY) || '[]'); } catch { return []; } }
function saveScansLocal(list){ localStorage.setItem(STORAGE_SCANS_KEY, JSON.stringify(list || [])); events.emit('scans:updated', list); }
function loadSchedules(){ try { return JSON.parse(localStorage.getItem(STORAGE_SCHEDULES_KEY) || '[]'); } catch { return []; } }
function saveSchedules(list){ localStorage.setItem(STORAGE_SCHEDULES_KEY, JSON.stringify(list || [])); events.emit('schedules:updated', list); }
function loadActivity(){ try { return JSON.parse(localStorage.getItem(STORAGE_ACTIVITY_KEY) || '[]'); } catch { return []; } }
function saveActivity(list){ localStorage.setItem(STORAGE_ACTIVITY_KEY, JSON.stringify(list || [])); events.emit('activity:updated', list); }

/* ====== STATE & DATA LOADING ====== */
const state = {
    currentUser: null,
    scans: [],
    stats: {
        networks: 0, // Quick scans
        hosts: 0,    // Deep scans
        total: 0,    // Total ScanResults
        lastScanDate: 0,
        lastScanStatus: '-'
    }
};

/* ====== FIREBASE DATA LOADING ====== */
async function ensureFirebaseUser() {
    if (state.currentUser) return state.currentUser;
    return new Promise((resolve) => {
        const unsubscribe = onAuthStateChanged(auth, (user) => {
            unsubscribe();
            if (user) {
                state.currentUser = user;
                resolve(user);
            } else {
                window.location.replace('login.html');
                resolve(null);
            }
        });
    });
}

async function loadDashboardData() {
    const user = await ensureFirebaseUser();
    if (!user) return;

    try {
        console.log("Loading dashboard stats from Firebase...");

        const qScans = query(collection(db, "Scan"), where("user_id", "==", user.uid));
        const scansSnap = await getDocs(qScans);
        
        state.scans = [];
        state.stats = { networks: 0, hosts: 0, total: 0, lastScanDate: 0, lastScanStatus: '-' };

        scansSnap.forEach(doc => {
            const data = doc.data();
            const scan = { id: doc.id, ...data };
            
            scan._startedAt = parseDate(data.started_at);
            scan._finishedAt = parseDate(data.finished_at);
            
            state.scans.push(scan);

            // --- KPI LOGIC ---
            // Networks = Quick Scans
            if (data.scan_type === 'quick_scan') {
                state.stats.networks++;
            }
            // Hosts = Deep Scans
            if (data.scan_type === 'deep_scan') {
                state.stats.hosts++;
            }
            // Total = scans
            state.stats.total = state.stats.networks + state.stats.hosts;
        });

        // Find Last Scan (based on finished_at)
        const finishedScans = state.scans.filter(s => s._finishedAt > 0);
        finishedScans.sort((a, b) => b._finishedAt - a._finishedAt);

        if (finishedScans.length > 0) {
            const last = finishedScans[0];
            state.stats.lastScanDate = last._finishedAt;
            state.stats.lastScanStatus = last.status === 'complete' ? 'Completed' : 'Failed';
        }

        // Sort overall list by start date for table
        state.scans.sort((a, b) => b._startedAt - a._startedAt);

        renderAll();

    } catch (error) {
        console.error("Error loading dashboard data:", error);
    }
}

/* ---------------------------
   Dashboard injection
   --------------------------- */
function injectDashboard(){
  const view = document.getElementById('view-home');
  if(!view) return;
  view.innerHTML = `
    <div class="dashboard-grid">
      <div class="kpi-row">
        <div class="card kpi">
          <div class="kpi-label">Networks (Quick Scans)</div>
          <div class="kpi-value" id="kpi-networks">—</div>
        </div>
        <div class="card kpi">
          <div class="kpi-label">Hosts (Deep Scans)</div>
          <div class="kpi-value" id="kpi-hosts">—</div>
        </div>
        <div class="card kpi">
          <div class="kpi-label">Total Results</div>
          <div class="kpi-value" id="kpi-scans">—</div>
        </div>
        <div class="card kpi">
          <div class="kpi-label">Last scan</div>
          <div class="kpi-value" id="kpi-last-status">—</div>
          <div class="kpi-small muted" id="kpi-last-ts"></div>
        </div>
      </div>

      <div class="main-row">
        <div class="card panel">
          <div class="panel-header">
            <h3>Latest 5 Scans</h3>
            <div class="panel-actions">
              <button class="btn btn-ghost" id="btn-add-target">+ Add Target</button>

              <div style="position:relative;display:inline-block">
                <button class="btn btn-primary" id="btn-start-scan">Start Scan ▾</button>
                <div id="newscan-dropdown" style="position:absolute;right:0;top:110%;display:none;background:#fff;border:1px solid #eee;padding:8px;border-radius:8px;box-shadow:0 8px 28px rgba(0,0,0,.06);z-index:50">
                  <button data-scan="quick" style="display:block;margin-bottom:6px;padding:8px 12px;border-radius:6px;border:0;background:#fff;cursor:pointer;width:100%;text-align:left">Quick Scan</button>
                  <button data-scan="deep" style="display:block;margin-bottom:6px;padding:8px 12px;border-radius:6px;border:0;background:#fff;cursor:pointer;width:100%;text-align:left">Deep Scan</button>
                </div>
              </div>

            </div>
          </div>
          <div class="panel-body" id="recent-scans-area">
            <div class="empty-note" id="no-scans-note">No scans yet.</div>
            <table class="table" id="recent-scans-table" style="display:none">
              <thead>
                <tr><th>Target</th><th>Type</th><th>Status</th><th>Findings</th><th>Date</th><th></th></tr>
              </thead>
              <tbody id="recent-scans-body"></tbody>
            </table>
          </div>
        </div>

        <div class="card side-panel">
          <h4>At a glance</h4>
          <div style="display:flex;flex-direction:column;gap:10px">
            <div style="display:flex;justify-content:space-between"><div class="muted">Scans today</div><div id="stat-scans-today">—</div></div>

            <div id="stat-vuln-counts" style="min-height:42px"></div>

            <div>
              <h5 style="margin:8px 0 6px 0">Quick Actions</h5>
              <div style="display:flex;flex-direction:column;gap:8px">
                <button class="btn btn-primary" id="qa-add-target">+ Add Target</button>
                <button class="btn btn-ghost" id="qa-import">Import IPs</button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="main-row" style="margin-top:18px">
        <div class="card" style="width:100%">
          <h4>Activity (recent)</h4>
          <div id="activity-feed" style="min-height:60px;color:#444;font-size:13px"></div>
        </div>
      </div>
    </div>

    <div id="dashboard-modal-root" aria-hidden="true"></div>
  `;
}

/* ---------- Activity (simple) ---------- */
function pushActivity(txt){
  const list = loadActivity();
  list.unshift({ id: uid('a'), text: txt, ts: nowTs() });
  while(list.length > 80) list.pop();
  saveActivity(list);
  renderActivity();
}
function renderActivity(){
  const feed = document.getElementById('activity-feed');
  if(!feed) return;
  const list = loadActivity();
  if(list.length === 0){ feed.innerHTML = '<div class="muted">No activity yet.</div>'; return; }
  feed.innerHTML = list.slice(0,12).map(it => `<div style="padding:6px 0;border-bottom:1px dashed #f0f0f0"><strong style="font-weight:600">${escapeHtml(it.text)}</strong><div class="muted" style="font-size:12px;margin-top:4px">${timeAgo(it.ts)} ago</div></div>`).join('');
}

/* ---------- RENDER KPI & SCANS (UPDATED FOR FIREBASE) ---------- */
function renderKPIs(){
  const elNet = document.getElementById('kpi-networks');
  const elHost = document.getElementById('kpi-hosts');
  const elScans = document.getElementById('kpi-scans');
  const statusEl = document.getElementById('kpi-last-status');
  const tsEl = document.getElementById('kpi-last-ts');
  const elScansCountToday = document.getElementById('stat-scans-today');

  // Fill values from state (Firebase data)
  if(elNet) elNet.textContent = state.stats.networks;
  if(elHost) elHost.textContent = state.stats.hosts;
  if(elScans) elScans.textContent = state.stats.total;

  // Last scan
  if(statusEl) statusEl.textContent = state.stats.lastScanStatus;
  if(tsEl && state.stats.lastScanDate > 0) tsEl.textContent = timeAgo(state.stats.lastScanDate);

  // Scans today
  const startOfDay = new Date(); startOfDay.setHours(0,0,0,0);
  const scansToday = state.scans.filter(s => s._startedAt >= startOfDay.getTime()).length;
  if(elScansCountToday) elScansCountToday.textContent = scansToday;

  // Vulnerabilities summary (Total CVEs)
  let totalVulns = 0;
  state.scans.forEach(s => {
      if (s.summary) {
          totalVulns += (s.summary.cves_total || s.summary.vulnerabilities_total || 0);
      }
  });

  const vulnEl = document.getElementById('stat-vuln-counts');
  if(vulnEl){
    vulnEl.innerHTML = `
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <div style="text-align:center;padding:6px 8px;border-radius:8px;background:#f8f9fa;box-shadow:0 1px 0 rgba(0,0,0,.05)">
          <div style="font-size:11px;color:#666;text-transform:uppercase;letter-spacing:0.5px">Total CVEs</div>
          <div style="font-weight:700;font-size:16px;color:#d32f2f">${totalVulns}</div>
        </div>
      </div>
    `;
  }
}

function renderRecentScans(){
  const body = document.getElementById('recent-scans-body');
  const table = document.getElementById('recent-scans-table');
  const noNote = document.getElementById('no-scans-note');
  if(!body) return;

  // 1. FILTRAR: Apenas scans terminados (ignora 'ongoing')
  // Aceita 'complete', 'completed', 'failed', 'timeout', etc.
  const finishedScans = state.scans.filter(s => s.status !== 'ongoing');

  // 2. ORDENAR: Pela data de fim (mais recente primeiro)
  finishedScans.sort((a, b) => (b._finishedAt || 0) - (a._finishedAt || 0));

  // 3. RECORTAR: Apenas os top 5
  const recent = finishedScans.slice(0, 5);
  
  body.innerHTML = '';
  
  if(recent.length === 0){
    if(table) table.style.display = 'none';
    if(noNote) noNote.style.display = 'block';
    // Se não houver scans terminados, ajusta a mensagem
    noNote.textContent = "No finished scans yet."; 
    return;
  }
  
  if(table) table.style.display = 'table';
  if(noNote) noNote.style.display = 'none';

  recent.forEach(s => {
    const tr = document.createElement('tr');

    // Target
    const tTarget = document.createElement('td'); 
    tTarget.innerHTML = `<strong>${escapeHtml(s.target || '—')}</strong>`;
    
    // Type
    const tType = document.createElement('td'); 
    tType.textContent = s.scan_type === 'quick_scan' ? 'Quick' : 'Deep';

    // Status
    const tStatus = document.createElement('td');
    const dot = document.createElement('span');
    dot.className = 'status-dot';
    dot.style.display = 'inline-block'; dot.style.width='10px'; dot.style.height='10px'; dot.style.borderRadius='50%'; dot.style.marginRight='8px';
    
    let statusText = s.status;
    if(s.status === 'complete' || s.status === 'completed') { 
        dot.style.background = '#22c55e'; 
        statusText = 'Completed'; 
    } else { 
        // Failed, Timeout, etc.
        dot.style.background = '#ef4444'; 
        statusText = 'Failed'; 
    }
    
    tStatus.appendChild(dot);
    tStatus.appendChild(document.createTextNode(statusText));

    // Findings (CVEs / Hosts)
    const tFind = document.createElement('td'); 
    const count = s.summary?.cves_total || s.summary?.total_hosts || 0;
    tFind.textContent = count; 

    // Date (Tempo desde que acabou)
    const tDate = document.createElement('td'); 
    // Como filtramos apenas os acabados, usamos sempre _finishedAt
    tDate.textContent = timeAgo(s._finishedAt);

    // Actions
    const tAction = document.createElement('td');
    const btnV = document.createElement('button');
    btnV.className = 'btn btn-secondary small'; btnV.textContent = 'View';
    btnV.addEventListener('click', ()=> window.location.href = `scans.html?target=${encodeURIComponent(s.target)}`);
    tAction.appendChild(btnV);

    tr.append(tTarget, tType, tStatus, tFind, tDate, tAction);
    body.appendChild(tr);
  });
}

function renderAll(){
  renderKPIs();
  renderRecentScans();
  renderActivity(); // Keep activity feed
}

/* ---- Modals (Add/Import/Schedule) ---- */
// Keeping these helper functions to maintain modal functionality
function openModal(html){
  const root = document.getElementById('dashboard-modal-root');
  if(!root) return;
  root.innerHTML = `<div class="modal-backdrop" id="dash-modal-backdrop"><div class="modal-dialog">${html}</div></div>`;
  root.style.display = 'block';
  root.setAttribute('aria-hidden','false');
  document.getElementById('dash-modal-backdrop')?.addEventListener('click', (e) => {
    if(e.target && e.target.id === 'dash-modal-backdrop') closeModal();
  });
}
function closeModal(){
  const root = document.getElementById('dashboard-modal-root');
  if(!root) return;
  root.style.display = 'none';
  root.innerHTML = '';
  root.setAttribute('aria-hidden','true');
}

function showAddTargetModal(){
  openModal(`
    <div class="modal-header"><h3>Add Target</h3></div>
    <div class="modal-body">
      <label>IP or CIDR</label>
      <input id="m-target-value" type="text" placeholder="e.g. 192.168.1.5 or 10.0.0.0/24" />
      <label>Name (optional)</label>
      <input id="m-target-name" type="text" placeholder="Target name" />
    </div>
    <div class="modal-footer">
      <button class="btn btn-ghost" id="m-cancel">Cancel</button>
      <button class="btn btn-primary" id="m-save">Add</button>
    </div>
  `);
  document.getElementById('m-cancel')?.addEventListener('click', closeModal);
  document.getElementById('m-save')?.addEventListener('click', ()=>{
    // For simplicity, redirect to iplist.html or implement Firebase add here
    window.location.href = 'iplist.html';
  });
}

function showImportIPsModal(){
    // Simplified: redirect to iplist page
    window.location.href = 'iplist.html';
}

function showScheduleModal(){
    // Placeholder for schedule logic
    alert("Scheduling feature coming soon!");
}

/* ---- Wire UI (complete) ---------- */
function wireDashboardUI(){
  // primary quick actions
  const btnAdd = document.getElementById('btn-add-target');
  const btnImport = document.getElementById('btn-import-ips');
  const btnStart = document.getElementById('btn-start-scan');

if(btnAdd) btnAdd.addEventListener('click', (e)=> { 
    e.preventDefault(); 
    // Redireciona com instrução para abrir modal
    window.location.href = 'iplist.html?action=add'; 
});
  if(btnImport) btnImport.addEventListener('click', (e)=> { e.preventDefault(); showImportIPsModal(); });

  // dropdown for start scan
  if(btnStart){
    btnStart.addEventListener('click', (e) => {
      const dd = document.getElementById('newscan-dropdown');
      if(dd) dd.style.display = (dd.style.display === 'block' ? 'none' : 'block');
    });
  }
  const dd = document.getElementById('newscan-dropdown');
  if(dd){
    dd.querySelectorAll('button[data-scan]').forEach(b => {
      b.addEventListener('click', (ev) => {
        // Redirect to scans.html with action=new to open modal
        window.location.href = 'scans.html?action=new';
      });
    });
  }

  // side quick actions
  document.getElementById('qa-add-target')?.addEventListener('click', (e)=> { e.preventDefault(); window.location.href = 'iplist.html'; });
  document.getElementById('qa-import')?.addEventListener('click', (e)=> { e.preventDefault(); window.location.href = 'iplist.html'; });
  document.getElementById('qa-schedule')?.addEventListener('click', (e)=> { e.preventDefault(); showScheduleModal(); });

  // close dropdown when clicking elsewhere
  document.addEventListener('click', (ev) => {
    const dd = document.getElementById('newscan-dropdown');
    const btn = document.getElementById('btn-start-scan');
    if(!dd) return;
    if(ev.target !== dd && !dd.contains(ev.target) && ev.target !== btn){
      dd.style.display = 'none';
    }
  });
}

/* ========================
   INIT
   ======================== */
function init() {
  if (!requireAuth()) return;

  const themeQuick = localStorage.getItem("vulnerai.theme");
  const isDark = themeQuick ? (themeQuick === "dark") : false;
  document.body.classList.toggle("dark", isDark);

  // 1. Inject HTML
  injectDashboard();
  wireDashboardUI();

  // 2. Load Data (Firebase)
  loadDashboardData();

  /* SIDEBAR */
  const sidebar = qs("#sidebar");
  const burger = qs("#btn-burger");
  const SAVED = localStorage.getItem("vulnerai.sidebarCollapsed") === "1";
  if (SAVED) sidebar?.classList.add("collapsed");
  burger?.addEventListener("click", (e) => {
    e.stopPropagation();
    sidebar?.classList.toggle("collapsed");
    localStorage.setItem("vulnerai.sidebarCollapsed", sidebar?.classList.contains("collapsed") ? "1" : "0");
  });

  /* USER MENU */
  const userBtn = qs("#btn-user");
  const userMenu = qs("#menu-user");
  userBtn?.addEventListener("click", (e) => {
    e.stopPropagation();
    const isOpen = userMenu?.getAttribute("aria-hidden") === "false";
    userBtn.setAttribute("aria-expanded", !isOpen);
    userMenu.setAttribute("aria-hidden", isOpen ? "true" : "false");
  });
  document.addEventListener("click", () => userMenu?.setAttribute("aria-hidden", "true"));
  
  userMenu?.addEventListener("click", (e) => {
    const item = e.target.closest(".menu-item");
    if (!item) return;
    if (item.dataset.action === "logout") {
        auth.signOut().then(() => {
            localStorage.removeItem(AUTH_KEY);
            window.location.href = "login.html";
        });
    }
  });

  /* Upgrade → Pricing */
  const upgradeBtn = document.getElementById('btn-upgrade');
  upgradeBtn?.addEventListener('click', (e) => {
    e.preventDefault();
    localStorage.setItem('vulnerai.intent', 'upgrade');
    window.location.href = 'pricing.html';
  });
}

/* BOOT */
document.addEventListener("DOMContentLoaded", init);

/* ---------- UI polish helpers: icons, ripple, modal anim ---------- */
(function uiPolish(){
  function svg(name){
    const svgs = {
      play: `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M5 3v18l15-9L5 3z"/></svg>`,
      plus: `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14M5 12h14"/></svg>`,
      import: `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M12 3v12"/><path d="M8 11l4 4 4-4"/><path d="M21 21H3"/></svg>`,
      refresh: `<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M21 12a9 9 0 10-3.2 6.6"/><path d="M21 3v6h-6"/></svg>`
    };
    return svgs[name] || '';
  }

  function addIconsOnce(){
    const map = [
      ['#btn-start-scan','play'],
      ['#btn-add-target','plus'],
      ['#btn-import-ips','import'],
      ['#qa-add-target','plus'],
      ['#qa-import','import']
    ];
    map.forEach(([sel,name])=>{
      const el = document.querySelector(sel);
      if(el && !el.dataset.iconInjected){
        el.insertAdjacentHTML('afterbegin', `<span class="ico" style="display:inline-flex;align-items:center;justify-content:center;margin-right:6px">${svg(name)}</span>`);
        el.dataset.iconInjected = '1';
      }
    });
  }

  function wireModalAnimation(){
    const root = document.getElementById('dashboard-modal-root');
    if(!root) return;
    const observer = new MutationObserver(()=> {
      const backdrop = root.querySelector('.modal-backdrop');
      if(backdrop && !backdrop.classList.contains('show')){
        setTimeout(()=> backdrop.classList.add('show'), 10);
        backdrop.querySelector('.modal-dialog')?.addEventListener('click', (ev)=> ev.stopPropagation());
      }
    });
    observer.observe(root, { childList: true, subtree: true });
  }

  document.addEventListener('DOMContentLoaded', () => {
    setTimeout(()=> {
      addIconsOnce();
      wireModalAnimation();
    }, 240);
    document.addEventListener('click', ()=> setTimeout(addIconsOnce,200));
  });
})();