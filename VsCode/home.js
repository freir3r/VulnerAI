/* ====== home.js (complete) ====== */

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
  if(ms == null) return '-';
  const s = Math.round(ms/1000);
  if(s < 60) return `${s}s`;
  if(s < 3600) return `${Math.round(s/60)}m`;
  return `${Math.round(s/3600)}h`;
};
const timeAgo = ts => {
  if(!ts) return '-';
  const diff = Math.floor((Date.now()-ts)/1000);
  if(diff < 60) return `${diff}s`;
  if(diff < 3600) return `${Math.floor(diff/60)}m`;
  if(diff < 86400) return `${Math.floor(diff/3600)}h`;
  return `${Math.floor(diff/86400)}d`;
};

/* ---- storage helpers ---- */
function loadTargets(){ try { return JSON.parse(localStorage.getItem(STORAGE_TARGETS_KEY) || '[]'); } catch { return []; } }
function saveTargets(list){ localStorage.setItem(STORAGE_TARGETS_KEY, JSON.stringify(list || [])); events.emit('targets:updated', list); }
function loadScans(){ try { return JSON.parse(localStorage.getItem(STORAGE_SCANS_KEY) || '[]'); } catch { return []; } }
function saveScans(list){ localStorage.setItem(STORAGE_SCANS_KEY, JSON.stringify(list || [])); events.emit('scans:updated', list); }
function loadSchedules(){ try { return JSON.parse(localStorage.getItem(STORAGE_SCHEDULES_KEY) || '[]'); } catch { return []; } }
function saveSchedules(list){ localStorage.setItem(STORAGE_SCHEDULES_KEY, JSON.stringify(list || [])); events.emit('schedules:updated', list); }
function loadActivity(){ try { return JSON.parse(localStorage.getItem(STORAGE_ACTIVITY_KEY) || '[]'); } catch { return []; } }
function saveActivity(list){ localStorage.setItem(STORAGE_ACTIVITY_KEY, JSON.stringify(list || [])); events.emit('activity:updated', list); }

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
          <div class="kpi-label">Networks (CIDR)</div>
          <div class="kpi-value" id="kpi-networks">—</div>
        </div>
        <div class="card kpi">
          <div class="kpi-label">Hosts (IPs)</div>
          <div class="kpi-value" id="kpi-hosts">—</div>
        </div>
        <div class="card kpi">
          <div class="kpi-label">Total scans</div>
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
              <button class="btn btn-ghost" id="btn-import-ips">Import IPs</button>

              <!-- Start Scan dropdown (quick options) -->
              <div style="position:relative;display:inline-block">
                <button class="btn btn-primary" id="btn-start-scan">Start Scan ▾</button>
                <div id="newscan-dropdown" style="position:absolute;right:0;top:110%;display:none;background:#fff;border:1px solid #eee;padding:8px;border-radius:8px;box-shadow:0 8px 28px rgba(0,0,0,.06);z-index:50">
                  <button data-scan="quick" style="display:block;margin-bottom:6px;padding:8px 12px;border-radius:6px;border:0;background:#fff;cursor:pointer">Quick Scan</button>
                  <button data-scan="deep" style="display:block;margin-bottom:6px;padding:8px 12px;border-radius:6px;border:0;background:#fff;cursor:pointer">Full Scan</button>
                  <button data-scan="custom" style="display:block;padding:8px 12px;border-radius:6px;border:0;background:#fff;cursor:pointer">Custom</button>
                </div>
              </div>

            </div>
          </div>
          <div class="panel-body" id="recent-scans-area">
            <div class="empty-note" id="no-scans-note">No scans yet.</div>
            <table class="table" id="recent-scans-table" style="display:none">
              <thead>
                <tr><th>Target</th><th>Type</th><th>Status</th><th>Findings</th><th>Duration</th><th></th></tr>
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
                <button class="btn btn-ghost" id="qa-schedule">Schedule Scan</button>
              </div>
            </div>

            <div>
              <h5 style="margin:8px 0 6px 0">Top vulnerabilities</h5>
              <div id="top-vulns-list" style="display:flex;flex-wrap:wrap"></div>
            </div>

            <div>
              <h5 style="margin:8px 0 6px 0">Targets status</h5>
              <div id="targets-breakdown-stats">—</div>
            </div>
          </div>
        </div>
      </div>

      <!-- activity feed placeholder -->
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

/* ---------- Helpers: vuln aggregation & targets breakdown ---------- */
function aggregateVulns(scans){
  // returns { counts: { total, critical, high, medium, low }, top: [title strings] }
  const out = { counts: { total:0, critical:0, high:0, medium:0, low:0 }, map: {}, top: [] };
  const sevOrder = ['critical','high','medium','low'];
  loadScans().forEach(s => {
    if(!s.findings || !Array.isArray(s.findings)) return;
    s.findings.forEach(f => {
      const sev = (f.severity || '').toLowerCase();
      out.counts.total += 1;
      if(sev.includes('crit')) out.counts.critical += 1;
      else if(sev.includes('high')) out.counts.high += 1;
      else if(sev.includes('med')) out.counts.medium += 1;
      else out.counts.low += 1;

      const key = f.title || f.id || (f.description ? f.description.slice(0,40) : 'unknown');
      out.map[key] = (out.map[key] || 0) + 1;
    });
  });
  // top vulnerabilities by occurrences
  out.top = Object.entries(out.map).sort((a,b)=> b[1]-a[1]).slice(0,6).map(e => `${e[0]} (${e[1]})`);
  return out;
}

function computeTargetsBreakdown(targets, scans){
  const total = targets.length || 0;
  // naive online/offline detection: a target appears in a completed scan recently => online
  const now = Date.now();
  const onlineSet = new Set();
  const criticalSet = new Set();
  (scans || loadScans()).forEach(s => {
    if(!s.targetValue) return;
    if(s.status === 'completed' && ((s.finishedAt || 0)+ (24*3600*1000) > now)) onlineSet.add(s.targetValue);
    if(s.findings && s.findings.some(f => (f.severity || '').toLowerCase().includes('crit'))) criticalSet.add(s.targetValue);
  });
  return { total, online: onlineSet.size, offline: Math.max(0, total - onlineSet.size), hasCritical: criticalSet.size };
}

/* ---------- Activity (simple) ---------- */
function pushActivity(txt){
  const list = loadActivity();
  list.unshift({ id: uid('a'), text: txt, ts: nowTs() });
  // keep small history
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

/* ---------- REPLACE renderKPIs() ---------- */
function renderKPIs(){
  const rawTargets = loadTargets();
  const targets = rawTargets.map(t => {
    if(!t) return null;
    if(typeof t === 'string') return { value: t };
    const value = t.value || t.ip || t.address || t.cidr || '';
    const kind = t.kind || (typeof value === 'string' && value.includes('/') ? 'cidr' : 'ip');
    return { ...t, value, kind };
  }).filter(Boolean);

  const networks = targets.filter(t => (t.kind === 'cidr') || (typeof t.value === 'string' && t.value.includes('/'))).length;
  const hosts = targets.filter(t => (t.kind === 'ip') || (typeof t.value === 'string' && t.value && !t.value.includes('/'))).length;

  const scans = loadScans();

  // Scans today & last 24h
  const startOfDay = new Date(); startOfDay.setHours(0,0,0,0);
  const scansToday = scans.filter(s => (s.startedAt || 0) >= startOfDay.getTime()).length;
  const since24 = Date.now() - 24*60*60*1000;
  const scans24count = scans.filter(s => (s.startedAt || 0) >= since24).length;

  const elNet = document.getElementById('kpi-networks');
  const elHost = document.getElementById('kpi-hosts');
  const elScans = document.getElementById('kpi-scans');
  const elScans24 = document.getElementById('kpi-scans-24h'); // optional
  const elScansCountToday = document.getElementById('stat-scans-today');

  if(elNet) elNet.textContent = networks;
  if(elHost) elHost.textContent = hosts;
  if(elScans) elScans.textContent = scans.length;
  if(elScans24) elScans24.textContent = scans24count;
  if(elScansCountToday) elScansCountToday.textContent = scansToday;

  // Last scan
  const last = scans.slice().sort((a,b)=> (b.startedAt||0)-(a.startedAt||0))[0];
  const statusEl = document.getElementById('kpi-last-status');
  const tsEl = document.getElementById('kpi-last-ts');
  if(!last){
    if(statusEl) statusEl.textContent = '—';
    if(tsEl) tsEl.textContent = '';
  } else {
    if(statusEl) statusEl.textContent = (last.status === 'completed' ? 'Completed' : (last.status ? (last.status[0].toUpperCase()+last.status.slice(1)) : '-'));
    if(tsEl) tsEl.textContent = (last.startedAt ? timeAgo(last.startedAt) + ' ago' : '');
  }

  // Vulnerabilities summary (aggregated)
  const agg = aggregateVulns(scans);
  const vulnEl = document.getElementById('stat-vuln-counts');
  if(vulnEl){
    vulnEl.innerHTML = `
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <div style="text-align:center;padding:6px 8px;border-radius:8px;background:#fff;box-shadow:0 1px 0 rgba(0,0,0,.03)">
          <div style="font-size:12px;color:#666">Total</div>
          <div style="font-weight:700;font-size:16px">${agg.counts.total||0}</div>
        </div>
        <div style="text-align:center;padding:6px 8px;border-radius:8px;background:#fff;">
          <div style="font-size:12px;color:#666">Critical</div>
          <div style="font-weight:700">${agg.counts.critical||0}</div>
        </div>
        <div style="text-align:center;padding:6px 8px;border-radius:8px;background:#fff;">
          <div style="font-size:12px;color:#666">High</div>
          <div style="font-weight:700">${agg.counts.high||0}</div>
        </div>
        <div style="text-align:center;padding:6px 8px;border-radius:8px;background:#fff;">
          <div style="font-size:12px;color:#666">Medium</div>
          <div style="font-weight:700">${agg.counts.medium||0}</div>
        </div>
        <div style="text-align:center;padding:6px 8px;border-radius:8px;background:#fff;">
          <div style="font-size:12px;color:#666">Low</div>
          <div style="font-weight:700">${agg.counts.low||0}</div>
        </div>
      </div>
    `;
  }

  // Top vulnerabilities (as clickable pills)
  const topEl = document.getElementById('top-vulns-list');
  if(topEl){
    if(agg.top && agg.top.length){
      topEl.innerHTML = agg.top.map(t => `<button class="vuln-pill" style="margin:6px 6px 0 0;padding:6px 8px;border-radius:18px;border:1px solid #eee;background:#fff;cursor:pointer;font-size:13px">${escapeHtml(t)}</button>`).join('');
      topEl.querySelectorAll('.vuln-pill').forEach((b, idx) => {
        b.addEventListener('click', ()=> {
          const txt = agg.top[idx];
          // current behaviour: remember filter then open scans page
          localStorage.setItem('vulnerai.filterVuln', txt);
          pushActivity('Filter -> ' + txt);
          alert('Filtering history by: ' + txt + '\nOpen Scans page to see filtered results.');
        });
      });
    } else {
      topEl.textContent = '—';
    }
  }

  // Targets breakdown
  const td = computeTargetsBreakdown(targets, scans);
  const tgtEl = document.getElementById('targets-breakdown-stats');
  if(tgtEl) tgtEl.textContent = `Total ${td.total} — Online ${td.online} — Offline ${td.offline} — Critical ${td.hasCritical}`;
}

/* ---- render helpers ---- */
function render24h(){
  const scans = loadScans();
  const since = Date.now() - 24*60*60*1000;
  const scans24 = scans.filter(s => (s.startedAt || 0) >= since);
  const vulns24 = scans24.reduce((acc,s) => acc + (s.findings ? s.findings.length : 0), 0);
  const e24s = document.getElementById('stat-24-scans');
  const e24v = document.getElementById('stat-24-vulns');
  if(e24s) e24s.textContent = scans24.length;
  if(e24v) e24v.textContent = vulns24;
}

function renderRecentScans(){
  const body = document.getElementById('recent-scans-body');
  const table = document.getElementById('recent-scans-table');
  const noNote = document.getElementById('no-scans-note');
  if(!body) return;

  const scans = loadScans().slice().sort((a,b)=> (b.startedAt||0)-(a.startedAt||0)).slice(0,5);
  body.innerHTML = '';
  if(scans.length === 0){
    if(table) table.style.display = 'none';
    if(noNote) noNote.style.display = 'block';
    return;
  }
  if(table) table.style.display = '';
  if(noNote) noNote.style.display = 'none';

  scans.forEach(s => {
    const tr = document.createElement('tr');

    const tTarget = document.createElement('td'); tTarget.textContent = s.targetValue || s.target || s.targetId || '—';
    const tType = document.createElement('td'); tType.textContent = s.type || '-';

    const tStatus = document.createElement('td');
    const dot = document.createElement('span');
    dot.className = 'status-dot ' + (s.status === 'ongoing' ? 'ongoing' : s.status === 'completed' ? 'completed' : 'error');
    dot.style.display = 'inline-block';
    dot.style.width='10px';
    dot.style.height='10px';
    dot.style.borderRadius='50%';
    dot.style.marginRight='8px';
    if(s.status === 'ongoing') dot.style.background = '#60a5fa';
    else if(s.status === 'completed') dot.style.background = '#16a34a';
    else dot.style.background = '#ef4444';
    tStatus.appendChild(dot);
    tStatus.appendChild(document.createTextNode(s.status ? (s.status[0].toUpperCase() + s.status.slice(1)) : '-'));

    const criticalCount = (s.findings || []).filter(f => (f.severity||'').toLowerCase().includes('crit')).length;
    const highCount = (s.findings || []).filter(f => (f.severity||'').toLowerCase().includes('high')).length;

    const tFind = document.createElement('td'); tFind.innerHTML = `${(s.findings ? s.findings.length : 0)} <span class="muted" style="font-size:12px;margin-left:6px">(${criticalCount}C / ${highCount}H)</span>`;
    const tDur = document.createElement('td'); tDur.textContent = s.durationMs ? msToHuman(s.durationMs) : (s.status === 'ongoing' ? 'ongoing' : '-');

    const tAction = document.createElement('td');
    const btnR = document.createElement('button');
    btnR.className = 'btn btn-ghost';
    btnR.textContent = 'Re-run';
    btnR.addEventListener('click', ()=> reRunScan(s.id));
    const btnV = document.createElement('button');
    btnV.className = 'btn btn-secondary';
    btnV.style.marginLeft = '6px';
    btnV.textContent = 'View';
    btnV.addEventListener('click', ()=> {
      // store view params and redirect
      localStorage.setItem('vulnerai.openScanId', s.id);
      pushActivity('View scan: ' + (s.targetValue || s.id));
      window.location.href = 'scans.html';
    });
    tAction.appendChild(btnR);
    tAction.appendChild(btnV);

    tr.appendChild(tTarget);
    tr.appendChild(tType);
    tr.appendChild(tStatus);
    tr.appendChild(tFind);
    tr.appendChild(tDur);
    tr.appendChild(tAction);

    body.appendChild(tr);
  });
}

/* ---- Modals ---- */
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

/* ---- Add Target modal ---- */
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
    const val = document.getElementById('m-target-value').value.trim();
    const name = document.getElementById('m-target-name').value.trim();
    if(!val){ alert('Provide an IP or CIDR'); return; }
    const t = { id: uid('t'), value: val, kind: isCIDR(val) ? 'cidr' : 'ip', name: name || val, addedAt: nowTs() };
    const list = loadTargets(); list.push(t); saveTargets(list);
    closeModal();
    renderAll();
    pushActivity('Added target: ' + val);
  });
}

/* ---- Import IPs modal (reused) ---- */
function showImportIPsModal(){
  openModal(`
    <div class="modal-header"><h3>Import IPs / CIDRs</h3></div>
    <div class="modal-body">
      <div class="muted">Paste one IP/CIDR per line. e.g. 192.168.1.5 or 10.0.0.0/24</div>
      <textarea id="m-import-list" placeholder="192.168.1.5\n10.0.0.0/24" style="width:100%;min-height:140px;margin-top:10px"></textarea>
    </div>
    <div class="modal-footer">
      <button class="btn btn-ghost" id="m-import-cancel">Cancel</button>
      <button class="btn btn-primary" id="m-import-save">Import</button>
    </div>
  `);
  document.getElementById('m-import-cancel')?.addEventListener('click', closeModal);
  document.getElementById('m-import-save')?.addEventListener('click', ()=>{
    const raw = document.getElementById('m-import-list').value.trim();
    if(!raw){ alert('Paste the list'); return; }
    const lines = raw.split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
    const existing = loadTargets();
    const added = [];
    lines.forEach(l => {
      const t = { id: uid('t'), value: l, kind: isCIDR(l) ? 'cidr' : 'ip', name: l, addedAt: nowTs() };
      existing.push(t); added.push(t);
    });
    saveTargets(existing);
    closeModal();
    renderAll();
    pushActivity(`Imported ${added.length} targets`);
    alert(`Imported ${added.length} targets`);
  });
}

/* ---- Schedule Scan modal (new) ---- */
function showScheduleModal(){
  openModal(`
    <div class="modal-header"><h3>Schedule Scan</h3></div>
    <div class="modal-body">
      <label>Target (IP or saved target)</label>
      <input id="m-sched-target" placeholder="e.g. 8.8.8.8 or saved target name" />
      <label>Schedule At</label>
      <input id="m-sched-datetime" type="datetime-local" />
      <label>Type</label>
      <select id="m-sched-type">
        <option value="quick">Quick</option>
        <option value="deep">Deep</option>
      </select>
    </div>
    <div class="modal-footer">
      <button class="btn btn-ghost" id="m-sched-cancel">Cancel</button>
      <button class="btn btn-primary" id="m-sched-save">Schedule</button>
    </div>
  `);
  document.getElementById('m-sched-cancel')?.addEventListener('click', closeModal);
  document.getElementById('m-sched-save')?.addEventListener('click', ()=>{
    const target = document.getElementById('m-sched-target').value.trim();
    const dt = document.getElementById('m-sched-datetime').value;
    const type = document.getElementById('m-sched-type').value;
    if(!target || !dt){ alert('Provide target and schedule time'); return; }
    const sched = { id: uid('sch'), target, type, runAt: new Date(dt).getTime(), createdAt: nowTs() };
    const all = loadSchedules(); all.push(sched); saveSchedules(all);
    closeModal();
    pushActivity('Scheduled scan: ' + target + ' @ ' + dt);
    alert('Scan scheduled');
  });
}

/* ---- Re-run scan (simulated) ---- */
function reRunScan(scanId){
  const scans = loadScans();
  const orig = scans.find(s => s.id === scanId);
  if(!orig){ alert('Scan not found'); return; }
  const newScan = {
    id: uid('s'),
    targetId: orig.targetId,
    targetValue: orig.targetValue || orig.target || orig.targetValue,
    type: orig.type || 'quick',
    status: 'ongoing',
    startedAt: nowTs(),
    findings: []
  };
  scans.push(newScan);
  saveScans(scans);
  renderAll();
  pushActivity('Re-run scan: ' + (newScan.targetValue || newScan.id));
  setTimeout(()=> simulateComplete(newScan.id), 1200 + Math.random()*1800);
}

function simulateComplete(scanId){
  const scans = loadScans();
  const s = scans.find(x => x.id === scanId);
  if(!s) return;
  const rand = Math.random();
  const findings = [];
  if(rand > 0.6) findings.push({ severity: 'high', title: 'CVE-XXXX-1', description: 'Example high' });
  if(rand > 0.3) findings.push({ severity: 'medium', title: 'CVE-YYYY-2', description: 'Example medium' });
  s.findings = findings;
  s.status = 'completed';
  s.finishedAt = nowTs();
  s.durationMs = s.finishedAt - s.startedAt;
  saveScans(scans);
  renderAll();
  pushActivity('Scan completed: ' + (s.targetValue || s.id));
}

/* ---- Wire UI (complete) ---------- */
function wireDashboardUI(){
  // primary quick actions
  const btnAdd = document.getElementById('btn-add-target');
  const btnImport = document.getElementById('btn-import-ips');
  const btnStart = document.getElementById('btn-start-scan');

  if(btnAdd) btnAdd.addEventListener('click', (e)=> { e.preventDefault(); showAddTargetModal(); pushActivity('Quick Action: Open Add Target'); });
  if(btnImport) btnImport.addEventListener('click', (e)=> { e.preventDefault(); showImportIPsModal(); pushActivity('Quick Action: Open Import IPs'); });

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
        const mode = b.dataset.scan;
        localStorage.setItem('vulnerai.newScanMode', mode);
        pushActivity(`Quick Action: New Scan → ${mode}`);
        window.location.href = 'scans.html';
      });
    });
  }

  // side quick actions (smaller)
  document.getElementById('qa-add-target')?.addEventListener('click', (e)=> { e.preventDefault(); showAddTargetModal(); pushActivity('Quick Action (side): Add Target'); });
  document.getElementById('qa-import')?.addEventListener('click', (e)=> { e.preventDefault(); showImportIPsModal(); pushActivity('Quick Action (side): Import IPs'); });
  document.getElementById('qa-schedule')?.addEventListener('click', (e)=> { e.preventDefault(); showScheduleModal(); pushActivity('Quick Action (side): Schedule Scan'); });

  // CTA on empty block
  document.getElementById('cta-new-scan')?.addEventListener('click', (e) => {
    e.preventDefault();
    localStorage.setItem('vulnerai.openNewScan', '1');
    pushActivity('CTA: Open new scan page');
    window.location.href = 'scans.html';
  });

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

/* ---- render all ---- */
function renderAll(){
  renderKPIs();
  render24h();
  renderRecentScans();
  renderActivity();
}

/* ---- cross-tab sync ---- */
window.addEventListener('storage', (ev) => {
  if(ev.key === STORAGE_TARGETS_KEY || ev.key === STORAGE_SCANS_KEY || ev.key === STORAGE_SCHEDULES_KEY || ev.key === STORAGE_ACTIVITY_KEY) {
    renderAll();
  }
});
events.on('targets:updated', ()=> renderAll());
events.on('scans:updated', ()=> renderAll());
events.on('schedules:updated', ()=> renderAll());
events.on('activity:updated', ()=> renderActivity());

/* ---- demo data if empty (keeps dashboard populated for dev) ---- */
(function initDemoIfEmpty(){
  if(!localStorage.getItem(STORAGE_TARGETS_KEY) && !localStorage.getItem(STORAGE_SCANS_KEY)){
    const t = [
      { id: uid('t'), value: '8.8.8.8', kind: 'ip', name: 'Google DNS', addedAt: nowTs()-3600000 },
      { id: uid('t'), value: '10.0.0.0/24', kind: 'cidr', name: 'Office net', addedAt: nowTs()-3600000 }
    ];
    const s = [
      { id: uid('s'), targetId: t[0].id, targetValue: t[0].value, type: 'quick', status: 'completed', startedAt: nowTs()-7200000, finishedAt: nowTs()-7190000, durationMs:10000, findings: [{severity:'medium',title:'CVE-EX-1',description:'Example'}] },
      { id: uid('s'), targetId: t[1].id, targetValue: t[1].value, type: 'full', status: 'completed', startedAt: nowTs()-3600000, finishedAt: nowTs()-3595000, durationMs:5000, findings: [] }
    ];
    saveTargets(t);
    saveScans(s);
    saveActivity([{id:uid('a'),text:'Demo data populated',ts:nowTs()}]);
  }
})();

/* ========================
   INIT
   ======================== */
function init() {
  if (!requireAuth()) return;

  // DARK MODE
  const themeQuick = localStorage.getItem("vulnerai.theme");
  const isDark = themeQuick ? (themeQuick === "dark") : false;
  document.body.classList.toggle("dark", isDark);

  /* SIDEBAR */
  const sidebar = qs("#sidebar");
  const burger = qs("#btn-burger");
  const SAVED = localStorage.getItem("vulnerai.sidebarCollapsed") === "1";
  if (SAVED) sidebar?.classList.add("collapsed");
  burger?.addEventListener("click", (e) => {
    e.stopPropagation();
    sidebar?.classList.toggle("collapsed");
    const collapsed = sidebar?.classList.contains("collapsed");
    localStorage.setItem("vulnerai.sidebarCollapsed", collapsed ? "1" : "0");
  });

  /* USER MENU */
  const userBtn = qs("#btn-user");
  const userMenu = qs("#menu-user");
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
      (async () => {
        try {
          const appMod = await import('https://www.gstatic.com/firebasejs/9.22.2/firebase-app.js');
          const authMod = await import('https://www.gstatic.com/firebasejs/9.22.2/firebase-auth.js');
          const { initializeApp, getApps } = appMod;
          const { getAuth, signOut } = authMod;
          const firebaseConfig = {
            apiKey: "AIzaSyBuaJdeJSHhn8zvOt3COp1fy987Zx4Da9k",
            authDomain: "vulnerai.firebaseapp.com",
            projectId: "vulnerai",
            storageBucket: "vulnerai.firebasestorage.app",
            messagingSenderId: "576892753213",
            appId: "1:576892753213:web:b418a23c16b808c1d4a154",
            measurementId: "G-K38GLCC5XL"
          };
          if (!getApps().length) initializeApp(firebaseConfig);
          await signOut(getAuth());
        } catch (e) { console.debug('Firebase signOut skipped or failed', e); }

        try {
          for (let i = localStorage.length - 1; i >= 0; i--) {
            const key = localStorage.key(i);
            if (!key) continue;
            if (key.startsWith('vulnerai') || key === AUTH_KEY) localStorage.removeItem(key);
          }
        } catch (e) { localStorage.removeItem(AUTH_KEY); }
        window.location.href = "login.html";
      })();
    }
  });

  /* PREMIUM MODAL */
  const premiumBtn = qs("#btn-premium");
  const premiumModal = qs("#modal-premium");
  const closePremium = () => premiumModal?.setAttribute("aria-hidden", "true");
  const openPremium = () => premiumModal?.setAttribute("aria-hidden", "false");
  premiumBtn?.addEventListener("click", (e) => { e.stopPropagation(); openPremium(); });
  premiumModal?.addEventListener("click", (e) => {
    if (e.target.hasAttribute("data-close") || e.target.classList.contains("close") || e.target.classList.contains("backdrop")) {
      closePremium();
    }
  });
  document.addEventListener("keydown", (e) => { if (e.key === 'Escape') closePremium(); });

  /* Upgrade → Pricing */
  const upgradeBtn = document.getElementById('btn-upgrade');
  upgradeBtn?.addEventListener('click', (e) => {
    e.preventDefault();
    localStorage.setItem('vulnerai.intent', 'upgrade');
    document.getElementById('modal-premium')?.setAttribute('aria-hidden', 'true');
    window.location.href = 'pricing.html';
  });

  /* ---- Inject dashboard and wire UI ---- */
  injectDashboard();
  wireDashboardUI();
  renderAll();
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
    document.querySelectorAll('button').forEach(b=>{
      if(b.textContent && b.textContent.trim().toLowerCase().includes('re-run') && !b.dataset.refreshIcon){
        b.insertAdjacentHTML('afterbegin', `<span class="ico" style="display:inline-flex;margin-right:6px">${svg('refresh')}</span>`);
        b.classList.add('reexec-btn');
        b.dataset.refreshIcon = '1';
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
    window.addEventListener('storage', ()=> setTimeout(addIconsOnce,200));
  });
})();

/* ---- FRONTEND SCHEDULER: runs while the app is open ---- */

function processDueSchedulesOnce(){
  const schedules = loadSchedules();
  if(!schedules || schedules.length === 0) return;
  const now = Date.now();
  let changed = false;
  schedules.forEach(s => {
    if(!s) return;
    if(s.executed) return;
    if((s.runAt || 0) <= now){
      s.executed = true;
      s.executedAt = now;

      const targets = loadTargets();
      let target = targets.find(t => t.value === s.target || t.name === s.target);
      if(!target){
        target = { id: uid('t'), value: s.target, kind: (isCIDR(s.target) ? 'cidr' : 'ip'), name: s.target, addedAt: now };
        targets.push(target);
        saveTargets(targets);
      }

      const scans = loadScans();
      const newScan = {
        id: uid('s'),
        targetId: target.id,
        targetValue: target.value,
        type: s.type || 'quick',
        status: 'ongoing',
        startedAt: now,
        findings: [],
        scheduledFrom: s.id
      };
      scans.push(newScan);
      saveScans(scans);

      setTimeout(()=> simulateComplete(newScan.id), 1000 + Math.random()*2000);

      changed = true;
      pushActivity('Scheduled scan executed: ' + target.value);
    }
  });

  if(changed) saveSchedules(schedules);
}

document.addEventListener('DOMContentLoaded', () => {
  setTimeout(processDueSchedulesOnce, 250);
  const SCHED_INTERVAL_MS = 30 * 1000;
  setInterval(processDueSchedulesOnce, SCHED_INTERVAL_MS);
});