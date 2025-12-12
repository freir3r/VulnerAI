/* ====== Dashboard.js ====== */

/* ====== API CLIENT ====== */
class NmapScanAPI {
  constructor(baseURL = 'http://localhost:3000') {
    this.baseURL = baseURL;
  }

  async _makeRequest(endpoint, options = {}) {
    try {
      // try refresh first (if applicable)
      await refreshTokenIfNeeded();
      const auth = JSON.parse(localStorage.getItem(AUTH_KEY) || '{}');
      const token = auth.token;
      const config = {
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          ...options.headers,
        },
        ...options
      };

      if (options.body) {
        config.body = JSON.stringify(options.body);
      }

      const response = await fetch(`${this.baseURL}${endpoint}`, config);

      if (!response.ok) {
        let details = '';
        try {
          const txt = await response.text();
          try { details = JSON.stringify(JSON.parse(txt)); } catch { details = txt; }
        } catch (e) { details = 'Could not read response body'; }
        const err = new Error(`HTTP error! status: ${response.status} - ${details}`);
        err.status = response.status;
        err.body = details;
        throw err;
      }

      return await response.json();
    } catch (error) {
      console.error('API Request failed:', error);
      throw error;
    }
  }

  // Obter presets disponíveis
  async getPresets() {
    return await this._makeRequest('/presets');
  }

  // Iniciar um scan
  async startScan(target, preset, userId, scanName = '') {
    return await this._makeRequest('/scan', {
      method: 'POST',
      body: {
        target,
        preset,
        userId,
        scanName
      }
    });
  }

  // Obter status de um scan
  async getScanStatus(scanId) {
    return await this._makeRequest(`/scan/${scanId}`);
  }

  // Obter todos os scans de um usuário
  async getUserScans(userId) {
    return await this._makeRequest(`/scans/${userId}`);
  }

  // Health check
  async healthCheck() {
    return await this._makeRequest('/health');
  }
}

// Instância global da API
const nmapAPI = new NmapScanAPI('http://localhost:3000');

/* ====== AUTH (guard) ====== */
const AUTH_KEY = 'vulnerai.auth';
function isLoggedIn() {
  try { return !!JSON.parse(localStorage.getItem(AUTH_KEY)); }
  catch { return false; }
}

// Refresh Firebase ID token if older than 50 minutes
async function refreshTokenIfNeeded() {
  try {
    const authObj = JSON.parse(localStorage.getItem(AUTH_KEY) || '{}');
    if (!authObj || !authObj.token || !authObj.ts) return authObj.token;
    const ageMs = Date.now() - (authObj.ts || 0);
    if (ageMs < 50 * 60 * 1000) return authObj.token; // still fresh enough

    const appMod = await import('https://www.gstatic.com/firebasejs/9.22.2/firebase-app.js');
    const authMod = await import('https://www.gstatic.com/firebasejs/9.22.2/firebase-auth.js');
    const { initializeApp, getApps } = appMod;
    const { getAuth, getIdToken } = authMod;
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
    const auth = getAuth();
    if (!auth || !auth.currentUser) return authObj.token;
    const newToken = await getIdToken(auth.currentUser, true);
    authObj.token = newToken; authObj.ts = Date.now();
    localStorage.setItem(AUTH_KEY, JSON.stringify(authObj));
    return newToken;
  } catch (e) {
    console.warn('refreshTokenIfNeeded failed', e);
    try { const authObj = JSON.parse(localStorage.getItem(AUTH_KEY) || '{}'); return authObj.token; } catch { return null; }
  }
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
  targets: [],     // {id, kind, name, value, addedAt, scans, cves, lastScan, tags:[], risk}
  scans: [],
  lastResult: null
};

/* ====== HELPERS ====== */
const qs = (s, el = document) => el.querySelector(s);
const qsa = (s, el = document) => [...el.querySelectorAll(s)];
const uid = () => Math.random().toString(36).slice(2, 9);

/* ====== PERSISTENCE (targets/scans) ====== */
const LS_KEY = "vulnerai.targets";
const LS_SCANS = "vulnerai.scans";

function loadTargets() {
  try { state.targets = JSON.parse(localStorage.getItem(LS_KEY) || "[]"); }
  catch (_) { state.targets = []; }
}
function saveTargets() {
  localStorage.setItem(LS_KEY, JSON.stringify(state.targets));
}
function loadScans() { try { return JSON.parse(localStorage.getItem(LS_SCANS) || "[]"); } catch { return []; } }
function saveScans(arr) { localStorage.setItem(LS_SCANS, JSON.stringify(arr)); }

/* ====== VALIDATION ====== */
const reIPv4 = /^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/;
const reCIDR = /^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}\/([0-9]|[12][0-9]|3[0-2])$/;
const reHost = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$/;

function isValidHostOrIPorCIDR(s) {
  if (!s) return false;
  const v = s.trim();
  return reIPv4.test(v) || reCIDR.test(v) || reHost.test(v);
}

/* ====== SCAN POLLING ====== */
const activePolling = new Map();

function startScanPolling(scanId) {
  if (activePolling.has(scanId)) return;

  const pollInterval = setInterval(async () => {
    try {
      const status = await nmapAPI.getScanStatus(scanId);
      updateScanStatus(scanId, status);

      // Se o scan estiver completo ou falhou, para o polling
      if (status.scan.status === 'complete' || status.scan.status === 'failed') {
        stopScanPolling(scanId);

        // Atualiza a página de resultados se estiver visível
        if (qs('#view-scans')?.classList.contains('active')) {
          renderScanResultsPage();
        }
      }
    } catch (error) {
      console.error(`Polling error for scan ${scanId}:`, error);
      stopScanPolling(scanId);
    }
  }, 3000); // Poll a cada 3 segundos

  activePolling.set(scanId, pollInterval);
}

function stopScanPolling(scanId) {
  if (activePolling.has(scanId)) {
    clearInterval(activePolling.get(scanId));
    activePolling.delete(scanId);
  }
}

function updateScanStatus(scanId, apiStatus) {
  const scans = loadScans();
  const scanIndex = scans.findIndex(s => s.id === scanId);

  if (scanIndex !== -1) {
    const scan = scans[scanIndex];

    // Atualiza status básico
    scan.status = apiStatus.scan.status;
    scan.apiStatus = apiStatus;

    // Se o scan estiver completo, processa os resultados
    if (apiStatus.scan.status === 'complete' && apiStatus.ScanResults) {
      processCompletedScan(scan, apiStatus);
    }

    // Se falhou, guarda o erro
    if (apiStatus.scan.status === 'failed') {
      scan.error = apiStatus.scan.error;
    }

    saveScans(scans);

    // Se estamos na view de scans, atualiza a UI
    if (qs('#view-scans')?.classList.contains('active')) {
      renderScanResultsPage();
    }
  }
}

function processCompletedScan(scan, apiStatus) {
  // Processa hosts e portas
  if (apiStatus.ScanResults && apiStatus.ScanResults.length > 0) {
    const hosts = apiStatus.ScanResults;
    scan.openPorts = [];
    scan.cveList = [];

    hosts.forEach(host => {
      if (host.ports && Array.isArray(host.ports)) {
        host.ports.forEach(port => {
          if (port.state === 'open') {
            scan.openPorts.push(port.port);
          }
        });
      }
    });

    // Processa vulnerabilidades
    if (apiStatus.foundVulns && Array.isArray(apiStatus.foundVulns)) {
      scan.cveList = apiStatus.foundVulns.map(vuln => ({
        id: vuln.CVE || `VULN-${uid()}`,
        title: vuln.title || `Vulnerability in ${vuln.service || 'unknown'}`,
        cvss: parseFloat(vuln.risk_level) || 0.0,
        severity: cvssToSeverity(parseFloat(vuln.risk_level) || 0.0),
        port: vuln.port,
        service: vuln.service
      }));
    }

    scan.cves = scan.cveList.length;
  }
}

/* ====== VIEW SWITCHING ====== */
function setActiveView(view) {
  qsa('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.view === view));
  qsa('.view').forEach(v => v.classList.remove('active'));
  qs(`#view-${view}`)?.classList.add('active');

  const title =
    view === 'newscan' ? 'New Scan' :
      view === 'scans' ? 'Scans' :
        view === 'iplist' ? 'IP List' : 'Dashboard';
  qs('#page-title').textContent = title;

  if (view === 'scans') {
    renderScanResultsPage();
  }
}

/* ====== IP LIST RENDER ====== */
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, m => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m]));
}

function renderTargets() {
  const wrap = qs("#targets-list");
  const empty = qs("#targets-empty");
  const count = qs("#targets-count");
  if (!wrap || !empty || !count) return;

  const term = (qs("#tgt-search")?.value || "").toLowerCase().trim();
  let list = state.targets.filter(t =>
    !term || t.name.toLowerCase().includes(term) || t.value.toLowerCase().includes(term)
  );

  const sort = qs("#tgt-sort")?.value || "recent";
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

  const bulk = qs("#view-iplist .bulk");
  if (bulk) {
    const any = list.length > 0;
    bulk.setAttribute("aria-hidden", any ? "false" : "true");
    qs("#tgt-selected")?.replaceChildren(document.createTextNode("0 selected"));
    const allChk = qs("#tgt-checkall");
    if (allChk) allChk.checked = false;
  }

  populateSavedTargetsDropdown();
}

function selectedTargetIds() {
  return qsa('#targets-list input[type="checkbox"]:checked').map(c => c.dataset.id);
}
function updateBulkCount() {
  const n = selectedTargetIds().length;
  qs("#tgt-selected")?.replaceChildren(document.createTextNode(`${n} selected`));
}

/* ====== NEW SCAN DROPDOWN ====== */
function populateSavedTargetsDropdown() {
  const sel = qs("#ns-choose");
  if (!sel) return;
  const current = sel.value;
  sel.innerHTML = `<option value="">Choose from saved targets…</option>`;
  state.targets.forEach(t => {
    const opt = document.createElement("option");
    opt.value = t.id;
    opt.textContent = `${t.name} — ${t.value}`;
    sel.appendChild(opt);
  });
  if (current && state.targets.some(t => t.id === current)) {
    sel.value = current;
  }
}

/* ====== DEMO DATA: Ports & CVEs ====== */
function simulateOpenPorts(proto) {
  const commonTCP = [22, 80, 443, 8080, 3306, 5432, 6379];
  const commonUDP = [53, 123, 161];
  const pool = proto === "UDP" ? commonUDP : commonTCP;
  const n = Math.floor(Math.random() * 4); // 0..3
  const shuffled = [...pool].sort(() => Math.random() - 0.5);
  return shuffled.slice(0, n);
}
function simulateCVEs(openPorts) {
  const sampleScores = [0.0, 0.1, 0.7, 1.0, 2.8, 3.6, 5.4, 6.8, 7.2, 8.1, 9.8];
  const n = Math.max(0, (openPorts?.length || 0) + Math.floor(Math.random() * 3) - 1);
  const picks = [];
  const used = new Set();
  while (picks.length < n) {
    const idx = Math.floor(Math.random() * sampleScores.length);
    if (used.has(idx)) continue;
    used.add(idx);
    const score = sampleScores[idx];
    const year = 2015 + Math.floor(Math.random() * 10);
    const num = String(1000 + Math.floor(Math.random() * 9000));
    picks.push({
      id: `CVE-${year}-${num}`,
      title: `Demo vulnerability on port ${openPorts[Math.floor(Math.random() * (openPorts.length || 1))] ?? '—'}`,
      cvss: score,
      severity: cvssToSeverity(score)
    });
  }
  return picks;
}
function cvssToSeverity(score) {
  if (score <= 1.0) return "TRIVIAL";
  if (score < 4.0) return "LOW";
  if (score < 7.0) return "MEDIUM";
  if (score < 9.0) return "HIGH";
  return "CRITICAL";
}

/* ====== CREATE A SCAN (com API real) ====== */
async function addScan({ targetValue, targetId = null, type = "quick", proto = "TCP" }) {
  try {
    // Mapear tipos locais para presets da API
    const presetMap = {
      'quick': 'network_scan',
      'deep': 'deep_scan',
      'cve': 'cve_analysis'
    };

    const preset = presetMap[type] || 'network_scan';

    // Obter userId do localStorage
    const auth = JSON.parse(localStorage.getItem(AUTH_KEY) || '{}');
    const userId = auth.uid || auth.email || 'unknown-user'; // ← USA 'uid' OU 'email'
    const userName = auth.email ? auth.email.split('@')[0] : 'Unknown User';

    const scanName = `Scan ${type} - ${targetValue}`;

    console.log('Starting scan with API:', { targetValue, preset, userId });

    // Chamar a API real
    const result = await nmapAPI.startScan(targetValue, preset, userId, scanName);

    const scan = {
      id: result.scanId,
      targetId,
      targetValue,
      type,
      preset,
      proto,
      startedAt: Date.now(),
      status: "ongoing", // Agora é real - vai mudar conforme o progresso
      apiStatus: result.status,
      openPorts: [],
      cveList: [],
      cves: 0
    };

    // Guardar no histórico local
    const scans = loadScans();
    scans.unshift(scan);
    saveScans(scans);

    // Atualizar estatísticas do target
    if (targetId && state.targets?.length) {
      const t = state.targets.find(x => x.id === targetId);
      if (t) {
        t.scans = (t.scans || 0) + 1;
        t.lastScan = "now";
        saveTargets();
        renderTargets();
      }
    }

    // Iniciar polling para atualizar status
    startScanPolling(result.scanId);

    return scan;

  } catch (error) {
    console.error('Failed to start scan:', error);

    // Fallback para demo se a API falhar
    console.log('Using demo mode due to API error');
    const scans = loadScans();
    const id = uid();
    const openPorts = simulateOpenPorts(proto);
    const cveList = simulateCVEs(openPorts);
    const scan = {
      id, targetId, targetValue, type, proto,
      startedAt: Date.now(),
      status: "Completed",
      openPorts,
      cveList,
      cves: cveList.length,
      apiError: true
    };
    scans.unshift(scan);
    saveScans(scans);

    if (targetId && state.targets?.length) {
      const t = state.targets.find(x => x.id === targetId);
      if (t) {
        t.scans = (t.scans || 0) + 1;
        t.cves = Math.max(t.cves || 0, scan.cves);
        t.lastScan = "now";
        saveTargets();
        renderTargets();
      }
    }
    return scan;
  }
}

/* ====== SCANS PAGE RENDER ====== */
function getLastScanForUI() {
  try {
    const scans = loadScans();
    return scans[0] || null;
  } catch {
    return null;
  }
}

function drawGauge(percent) {
  const path = document.getElementById("g-bar");
  if (!path) return;
  const totalLen = 157;
  const val = Math.max(0, Math.min(1, percent)) * totalLen;
  path.setAttribute("stroke-dasharray", `${val} ${totalLen - val}`);
  path.setAttribute("stroke-dashoffset", "0");
}

function statusClass(s) {
  return s === "open" ? "status-open" : s === "filtered" ? "status-filtered" : "status-closed";
}

function renderScanResultsPage() {
  const last = getLastScanForUI();

  // Modelo fallback para quando não há scans
  const fallback = {
    targetValue: "scanme.nmap.org",
    type: "quick",
    activeHosts: 1,
    openPorts: 3,
    totalPorts: 50,
    cves: 3,
    hosts: [{
      id: "host1", name: "Host 1",
      ports: [
        { port: 22, service: "SSH", status: "open" },
        { port: 80, service: "HTTP", status: "filtered" },
        { port: 443, service: "HTTPS", status: "closed" },
      ]
    }],
    cveList: [
      { id: "CVE-2020-1001", title: "Example issue A", cvss: 0.1, severity: "TRIVIAL" },
      { id: "CVE-2021-2222", title: "Example issue B", cvss: 5.4, severity: "MEDIUM" },
      { id: "CVE-2019-3333", title: "Example issue C", cvss: 8.1, severity: "HIGH" },
    ]
  };

  let model;

  if (last) {
    // Se o scan ainda está em andamento, mostra status atual
    if (last.status === "ongoing" && last.apiStatus) {
      model = createModelFromApiStatus(last);
    } else {
      // Scan completo ou demo
      const open = last.openPorts?.length ?? 0;
      model = {
        targetValue: last.targetValue,
        type: last.type === "deep" ? "deep" : "quick",
        activeHosts: 1,
        openPorts: open,
        totalPorts: 50,
        cves: (last.cveList?.length ?? 0),
        hosts: [{
          id: "host1", name: "Host 1",
          ports: (open ? last.openPorts.map(p => {
            if (p === 22) return { port: 22, service: "SSH", status: "open" };
            if (p === 80) return { port: 80, service: "HTTP", status: "filtered" };
            if (p === 443) return { port: 443, service: "HTTPS", status: "closed" };
            return { port: p, service: "", status: "open" };
          }) : [
            { port: 22, service: "SSH", status: "open" },
            { port: 80, service: "HTTP", status: "filtered" },
            { port: 443, service: "HTTPS", status: "closed" },
          ])
        }],
        cveList: last.cveList ?? [],
        status: last.status,
        apiError: last.apiError
      };
    }
  } else {
    model = fallback;
  }

  // Atualizar UI
  updateScanResultsUI(model);
}

function createModelFromApiStatus(scan) {
  const apiStatus = scan.apiStatus;

  if (!apiStatus || !apiStatus.scan) {
    return {
      targetValue: scan.targetValue,
      type: scan.type,
      activeHosts: 0,
      openPorts: 0,
      totalPorts: 0,
      cves: 0,
      hosts: [],
      cveList: [],
      status: scan.status
    };
  }

  // Se o scan ainda está em andamento
  if (apiStatus.scan.status === 'ongoing') {
    return {
      targetValue: scan.targetValue,
      type: scan.type,
      activeHosts: '...',
      openPorts: 0,
      totalPorts: '...',
      cves: 0,
      hosts: [],
      cveList: [],
      status: 'ongoing',
      message: 'Scan in progress...'
    };
  }

  // Se o scan está completo
  if (apiStatus.scan.status === 'complete' && apiStatus.ScanResults) {
    const hosts = apiStatus.ScanResults;
    const openPorts = hosts.flatMap(host =>
      (host.ports || []).filter(p => p.state === 'open').map(p => p.port)
    );

    const cveList = (apiStatus.foundVulns || []).map(vuln => ({
      id: vuln.CVE || `VULN-${uid()}`,
      title: vuln.title || `Vulnerability in ${vuln.service || 'unknown'}`,
      cvss: parseFloat(vuln.risk_level) || 0.0,
      severity: cvssToSeverity(parseFloat(vuln.risk_level) || 0.0)
    }));

    return {
      targetValue: scan.targetValue,
      type: scan.type,
      activeHosts: hosts.length,
      openPorts: openPorts.length,
      totalPorts: hosts.reduce((sum, host) => sum + (host.ports?.length || 0), 0),
      cves: cveList.length,
      hosts: hosts.map((host, index) => ({
        id: `host${index + 1}`,
        name: host.hostname || `Host ${index + 1}`,
        ports: (host.ports || []).map(port => ({
          port: port.port,
          service: port.service?.name || '',
          status: port.state
        }))
      })),
      cveList: cveList,
      status: 'complete'
    };
  }

  // Fallback
  return {
    targetValue: scan.targetValue,
    type: scan.type,
    activeHosts: 0,
    openPorts: 0,
    totalPorts: 0,
    cves: 0,
    hosts: [],
    cveList: [],
    status: scan.status
  };
}

function updateScanResultsUI(model) {
  // Atualizar resumo
  qs("#sr-target").textContent = model.targetValue;
  qs("#sr-type").textContent = (model.type === "deep" ? "Deep Scan" : "Quick Scan");
  qs("#sr-active-hosts").textContent = model.activeHosts;
  qs("#sr-cves").textContent = model.cves;

  // Mostrar mensagem de progresso se estiver em andamento
  if (model.status === 'ongoing') {
    qs("#sr-ports-text").textContent = "Scanning...";
    drawGauge(0.1); // Pequena animação para mostrar atividade
  } else {
    qs("#sr-ports-text").textContent = `${model.openPorts}/${model.totalPorts}`;
    drawGauge(model.totalPorts ? model.openPorts / model.totalPorts : 0);
  }

  // hosts + tabela de portas
  const sel = qs("#sr-host");
  if (sel) {
    sel.innerHTML = "";
    model.hosts.forEach((h, i) => {
      const opt = document.createElement("option");
      opt.value = h.id;
      opt.textContent = h.name || `Host ${i + 1}`;
      sel.appendChild(opt);
    });
    sel.onchange = () => fillPortsTable(model.hosts.find(h => h.id === sel.value) || model.hosts[0]);
  }
  fillPortsTable(model.hosts[0]);

  // CVEs
  renderCVETable(model.cveList);

  // manter label do botão coerente
  updateClearButtonLabel();
}

function fillPortsTable(host) {
  const tb = qs("#sr-table tbody");
  if (!tb) return;

  if (!host || !host.ports || host.ports.length === 0) {
    tb.innerHTML = '<tr><td colspan="3" class="muted">No ports data available</td></tr>';
    return;
  }

  tb.innerHTML = host.ports.map(r => {
    const cls = statusClass(r.status);
    const txt = r.status ? r.status.charAt(0).toUpperCase() + r.status.slice(1) : 'Unknown';
    return `<tr>
        <td>${r.port}</td>
        <td>${r.service || ""}</td>
        <td><span class="${cls}">${txt}</span></td>
      </tr>`;
  }).join("");
}

/* ====== CVE TABLE RENDER ====== */
function renderCVETable(cves) {
  const tb = qs("#sr-cves-table tbody");
  if (!tb) return;

  if (!cves || cves.length === 0) {
    tb.innerHTML = '<tr><td colspan="4" class="muted">No vulnerabilities found</td></tr>';
    return;
  }

  const rows = cves.map(v => {
    const sev = (v.severity || cvssToSeverity(v.cvss || 0)).toUpperCase();
    const sevCls = `sev-${sev}`;
    const score = (v.cvss ?? 0).toFixed(1);
    return `<tr data-cvss="${v.cvss}">
        <td>${escapeHtml(v.id)}</td>
        <td>${escapeHtml(v.title)}</td>
        <td>${score}</td>
        <td><span class="${sevCls}">${sev}</span></td>
      </tr>`;
  }).join("");
  tb.innerHTML = rows;
  const counter = qs("#sr-cves");
  if (counter) counter.textContent = cves.length;
}

/* ====== CLEAR BUTTON: threshold & label ====== */
function updateClearButtonLabel() {
  const btn = qs("#btn-clear-trivial");
  if (!btn) return;
  const THRESH = parseFloat(localStorage.getItem("vulnerai.clearThreshold") || "4.0");
  if (THRESH <= 1.0) {
    btn.textContent = "Clear Trivial CVEs (CVSS ≤ 1.0)";
    btn.title = "Remove CVEs with CVSS ≤ 1.0";
  } else {
    btn.textContent = `Clear Low & Trivial (CVSS < ${THRESH})`;
    btn.title = `Remove CVEs with CVSS < ${THRESH}`;
  }
}

function cycleClearThreshold() {
  const current = parseFloat(localStorage.getItem("vulnerai.clearThreshold") || "4.0");
  const next = current <= 1.0 ? 4.0 : 1.0;
  localStorage.setItem("vulnerai.clearThreshold", String(next));
  updateClearButtonLabel();
}

/* ====== CLEAR ACTION ====== */
function handleClearTrivial() {
  const scans = loadScans();
  if (!scans.length) { alert("No scans to clean."); return; }

  const THRESH = parseFloat(localStorage.getItem("vulnerai.clearThreshold") || "4.0");

  const last = scans[0];
  if (!Array.isArray(last.cveList)) last.cveList = [];

  const before = last.cveList.length;
  last.cveList = last.cveList.filter(v => (v.cvss ?? 0) >= THRESH);
  last.cves = last.cveList.length;

  saveScans(scans);

  // re-render geral
  renderScanResultsPage();

  const removed = before - last.cveList.length;
  alert(removed > 0
    ? `Removed ${removed} CVE(s) with CVSS < ${THRESH}.`
    : `No CVEs with CVSS < ${THRESH} found.`);
}

/* ====== INIT ====== */
function init() {
  if (!requireAuth()) return; // guard

  // ---- PREFERÊNCIAS ----
  const prefs = (() => { try { return JSON.parse(localStorage.getItem("vulnerai.prefs") || "{}"); } catch { return {} } })();

  // DARK MODE
  const themeQuick = localStorage.getItem("vulnerai.theme");
  const isDark = themeQuick ? (themeQuick === "dark") : !!prefs.themeDarkHeader;
  document.body.classList.toggle("dark", isDark);
  window.addEventListener("storage", (e) => {
    if (e.key === "vulnerai.prefs" || e.key === "vulnerai.theme") {
      try {
        const quick = localStorage.getItem("vulnerai.theme");
        const p = JSON.parse(localStorage.getItem("vulnerai.prefs") || "{}");
        document.body.classList.toggle("dark", quick ? (quick === "dark") : !!p.themeDarkHeader);
      } catch (_) { }
    }
  });

  // Threshold default (LOW+TRIVIAL)
  if (localStorage.getItem("vulnerai.clearThreshold") == null) {
    localStorage.setItem("vulnerai.clearThreshold", "4.0");
  }

  loadTargets();
  renderTargets();
  populateSavedTargetsDropdown();

  /* NAV & VIEWS */
  qsa(".nav-item").forEach(btn => {
    btn.addEventListener("click", () => setActiveView(btn.dataset.view));
  });
  qs("#btn-new-scan")?.addEventListener("click", () => setActiveView("newscan"));
  qs("#cta-new-scan")?.addEventListener("click", () => setActiveView("newscan"));

  /* SIDEBAR */
  const sidebar = qs("#sidebar");
  const burger = qs("#btn-burger");
  if (localStorage.getItem("vulnerai.sidebarCollapsed") == null) {
    localStorage.setItem("vulnerai.sidebarCollapsed", prefs.sidebarCollapsedDefault ? "1" : "0");
  }
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
        // Attempt to sign out from Firebase if available, ignore errors
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
        } catch (e) {
          console.debug('Firebase signOut skipped or failed', e);
        }

        // Clear app data from localStorage
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

  /* IP LIST MODAL + FORM */
  const iplistModal = qs("#iplist-modal");
  const btnOpenAdd = qs("#iplist-open-add");
  const iplistForm = qs("#iplist-form");

  btnOpenAdd?.addEventListener("click", () => iplistModal?.setAttribute("aria-hidden", "false"));
  iplistModal?.addEventListener("click", (e) => {
    if (e.target.hasAttribute("data-close") || e.target.classList.contains("iplist-close") || e.target.classList.contains("iplist-backdrop")) {
      iplistModal.setAttribute("aria-hidden", "true");
    }
  });

  iplistForm?.addEventListener("submit", (e) => {
    e.preventDefault();
    const name = qs("#iplist-name").value.trim();
    const kind = qs("#iplist-kind").value;
    const value = qs("#iplist-value").value.trim();

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
  qs("#tgt-search")?.addEventListener("input", renderTargets);
  qs("#tgt-sort")?.addEventListener("change", renderTargets);

  /* Bulk controls */
  qs("#tgt-checkall")?.addEventListener("change", (e) => {
    qsa('#targets-list input[type="checkbox"]').forEach(c => c.checked = e.target.checked);
    updateBulkCount();
  });
  qs("#targets-list")?.addEventListener("change", (e) => {
    if (e.target.type === "checkbox") updateBulkCount();
  });
  qs("#tgt-bulk-delete")?.addEventListener("click", () => {
    const ids = selectedTargetIds();
    if (!ids.length) return;
    if (confirm(`Delete ${ids.length} selected target(s)?`)) {
      state.targets = state.targets.filter(t => !ids.includes(t.id));
      saveTargets(); renderTargets();
    }
  });
  qs("#tgt-bulk-scan")?.addEventListener("click", () => {
    const ids = selectedTargetIds();
    if (!ids.length) return;
    setActiveView("newscan");
    if (ids.length === 1) {
      const t = state.targets.find(x => x.id === ids[0]);
      if (t) {
        const inp = qs("#ns-target"); if (inp) inp.value = t.value;
        const sel = qs("#ns-choose"); if (sel) sel.value = t.id;
      }
    }
  });
  qs("#tgt-bulk-tags")?.addEventListener("click", () => alert("Tagging not implemented in this demo."));

  /* IP List actions (delegation) */
  qs("#view-iplist")?.addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-action]");
    if (!btn) return;
    const id = btn.dataset.id;
    if (btn.dataset.action === "delete") {
      state.targets = state.targets.filter(t => t.id !== id);
      saveTargets(); renderTargets();
      return;
    }
    if (btn.dataset.action === "start-scan") {
      const t = state.targets.find(x => x.id === id);
      if (t) {
        setActiveView("newscan");
        const inp = qs("#ns-target"); if (inp) inp.value = t.value;
        const sel = qs("#ns-choose"); if (sel) sel.value = t.id;
      }
      return;
    }
    if (btn.dataset.action === "view-scans") {
      setActiveView("scans");
      return;
    }
  });

  /* NEW SCAN enable/start */
  const tos = qs("#ns-tos");
  const targetInp = qs("#ns-target");
  const startBtn = qs("#ns-start");
  const chooseSel = qs("#ns-choose");

  function updateStartEnabled() {
    const hasTarget = (targetInp?.value.trim() || chooseSel?.value);
    const ok = !!(tos?.checked && hasTarget);
    if (startBtn) startBtn.disabled = !ok;
  }
  tos?.addEventListener("change", updateStartEnabled);
  targetInp?.addEventListener("input", updateStartEnabled);
  chooseSel?.addEventListener("change", () => {
    const id = chooseSel.value;
    const t = state.targets.find(x => x.id === id);
    if (targetInp) targetInp.value = t ? t.value : "";
    updateStartEnabled();
  });

  // defaults de scan vindos das prefs
  (function applyScanDefaults() {
    const type = prefs.scanType || "quick";
    const proto = prefs.scanProto || "TCP";
    const rType = document.querySelector(`input[name="ns-type"][value="${type}"]`);
    const rProto = document.querySelector(`input[name="ns-proto"][value="${proto}"]`);
    if (rType) rType.checked = true;
    if (rProto) rProto.checked = true;
    if (prefs.autoAcceptTos && tos) { tos.checked = true; }
    updateStartEnabled();
  })();

  updateStartEnabled();

  qs("#newscan-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!tos?.checked) return alert("Please accept the Terms first.");

    const type = (qs('input[name="ns-type"]:checked')?.value) || "quick";
    const proto = (qs('input[name="ns-proto"]:checked')?.value) || "TCP";

    let finalValue = (targetInp?.value || "").trim();
    const chosenId = chooseSel?.value || null;

    if (!finalValue && chosenId) {
      const t = state.targets.find(x => x.id === chosenId);
      finalValue = t?.value || "";
    }
    if (!finalValue) return alert("Please choose or type a target.");

    // Desabilitar botão durante o scan
    if (startBtn) startBtn.disabled = true;
    startBtn.textContent = "Starting Scan...";

    try {
      await addScan({ targetValue: finalValue, targetId: chooseSel?.value || null, type, proto });
      setActiveView("scans");
    } catch (error) {
      alert("Scan started with fallback mode (API unavailable)");
      setActiveView("scans");
    } finally {
      // Reativar botão
      if (startBtn) {
        startBtn.disabled = false;
        startBtn.textContent = "Start Scan";
      }
    }
  });

  /* Scans controls */
  const btnRefresh = qs("#scan-refresh");
  if (btnRefresh) {
    btnRefresh.addEventListener("click", (e) => {
      e.preventDefault();
      renderScanResultsPage();
    });
  }
  qs("#sr-host")?.addEventListener("change", () => renderScanResultsPage());

  // inicializar label do clear
  updateClearButtonLabel();

  /* ===== Upgrade → Pricing ===== */
  const upgradeBtn = document.getElementById('btn-upgrade');
  upgradeBtn?.addEventListener('click', (e) => {
    e.preventDefault();
    localStorage.setItem('vulnerai.intent', 'upgrade'); // opcional
    document.getElementById('modal-premium')?.setAttribute('aria-hidden', 'true');
    window.location.href = 'pricing.html';
  });

  // Testar conexão com a API no startup
  testAPIConnection();
}

/* ====== TEST API CONNECTION ====== */
async function testAPIConnection() {
  try {
    const health = await nmapAPI.healthCheck();
    console.log('API Connection OK:', health);
  } catch (error) {
    console.warn('API not available, using demo mode:', error.message);
  }
}

/* ====== EVENT DELEGATION ====== */
document.addEventListener("click", (e) => {
  const btn = e.target.closest("#btn-clear-trivial");
  if (btn) {
    e.preventDefault();
    handleClearTrivial();
  }
});
// duplo-clique no botão para alternar threshold 1.0 ↔ 4.0
document.addEventListener("dblclick", (e) => {
  const btn = e.target.closest("#btn-clear-trivial");
  if (btn) {
    e.preventDefault();
    cycleClearThreshold();
  }
});

/* ====== BOOT ====== */
document.addEventListener("DOMContentLoaded", init);