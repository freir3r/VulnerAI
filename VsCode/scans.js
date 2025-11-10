/* ====== API CLIENT ====== */
class NmapScanAPI {
  constructor(baseURL = 'http://localhost:3000') {
    this.baseURL = baseURL;
  }

  async _makeRequest(endpoint, options = {}) {
    try {
      const config = {
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
        },
        ...options
      };

      if (options.body) {
        config.body = JSON.stringify(options.body);
      }

      const response = await fetch(`${this.baseURL}${endpoint}`, config);

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('API Request failed:', error);
      throw error;
    }
  }

  async getPresets() {
    return await this._makeRequest('/presets');
  }

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

  async startDeepSingleScan(targetId, userId, scanName = '') {
    return await this._makeRequest('/scan/deep-single', {
      method: 'POST',
      body: {
        targetId,
        userId,
        scanName
      }
    });
  }

  async startDeepMultipleScan(targetIds, userId, scanName = '') {
    return await this._makeRequest('/scan/deep-multiple', {
      method: 'POST',
      body: {
        targetIds,
        userId,
        scanName
      }
    });
  }

  async getScanStatus(scanId) {
    return await this._makeRequest(`/scan/${scanId}`);
  }

  async getUserScans(userId) {
    return await this._makeRequest(`/scans/${userId}`);
  }

  async healthCheck() {
    return await this._makeRequest('/health');
  }
}

const nmapAPI = new NmapScanAPI('http://localhost:3000');

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

// Function to get current user ID or email
function getCurrentUserId() {
  try {
    const auth = JSON.parse(localStorage.getItem(AUTH_KEY) || '{}');
    return auth.uid || auth.email || 'unknown-user';
  } catch {
    return 'unknown-user';
  }
}

/* ====== STATE ====== */
const state = {
  targets: [],
  scans: [],
  lastResult: null,
  selectedTargets: [] // for deep multiple scans
};

/* ====== PAGINATION MODULE ====== */
const pagination = {
  currentPage: 1,
  itemsPerPage: 10,
  filters: {
    search: '',
    status: '',
    type: ''
  },
  
  applyFilters(scans) {
    const { search, status, type } = this.filters;
    return scans.filter(scan => {
      const matchesSearch = (scan.targetValue.toLowerCase().includes(search.toLowerCase()) ||
                           (scan.scan_name || '').toLowerCase().includes(search.toLowerCase()));
      const matchesStatus = !status || scan.status === status;
      const matchesType = !type || scan.type === type;
      return matchesSearch && matchesStatus && matchesType;
    });
  },
  
  getPaginatedItems(scans) {
    const filtered = this.applyFilters(scans);
    const start = (this.currentPage - 1) * this.itemsPerPage;
    return {
      items: filtered.slice(start, start + this.itemsPerPage),
      total: filtered.length,
      totalPages: Math.ceil(filtered.length / this.itemsPerPage)
    };
  },
  
  renderPagination(totalItems, containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    
    const totalPages = Math.ceil(totalItems / this.itemsPerPage);
    container.innerHTML = '';
    
    // Previous button
    if (this.currentPage > 1) {
      const prevBtn = document.createElement('button');
      prevBtn.className = 'btn-secondary';
      prevBtn.innerHTML = '&laquo;';
      prevBtn.addEventListener('click', () => {
        this.currentPage--;
        window.renderScansHistory();
      });
      container.appendChild(prevBtn);
    }
    
    // Page numbers
    for (let i = 1; i <= totalPages; i++) {
      const btn = document.createElement('button');
      btn.className = 'btn-secondary';
      btn.textContent = i;
      btn.disabled = i === this.currentPage;
      btn.addEventListener('click', () => {
        this.currentPage = i;
        window.renderScansHistory();
      });
      container.appendChild(btn);
    }
    
    // Next button
    if (this.currentPage < totalPages) {
      const nextBtn = document.createElement('button');
      nextBtn.className = 'btn-secondary';
      nextBtn.innerHTML = '&raquo;';
      nextBtn.addEventListener('click', () => {
        this.currentPage++;
        window.renderScansHistory();
      });
      container.appendChild(nextBtn);
    }
  }
};

/* ====== HELPERS ====== */
const qs = (s, el = document) => el.querySelector(s);
const qsa = (s, el = document) => [...el.querySelectorAll(s)];
const uid = () => Math.random().toString(36).slice(2, 9);

/* ====== PERSISTENCE ====== */
const LS_KEY = "vulnerai.targets";
const LS_SCANS = "vulnerai.scans";

function loadTargets() {
  try { state.targets = JSON.parse(localStorage.getItem(LS_KEY) || "[]"); }
  catch (_) { state.targets = []; }
}
function saveTargets() {
  localStorage.setItem(LS_KEY, JSON.stringify(state.targets));
}

// load scans from Firebase
async function loadScans() {
  try {
    const userId = getCurrentUserId();
    console.log('Current User ID:', userId);
    console.log('Auth Data:', localStorage.getItem(AUTH_KEY));

    const response = await nmapAPI.getUserScans(userId);
    console.log('API Response:', response);

    if (response && response.scans) {
      // Convert API response to local model
      const convertedScans = response.scans.map(scan => ({
        id: scan.id,
        targetValue: scan.target,
        targetId: scan.target_ids ? scan.target_ids[0] : null,
        targetIds: scan.target_ids || [],
        type: scan.scan_type === 'quick_scan' ? 'quick' : 'deep',
        preset: scan.preset_used || scan.scan_type,
        proto: 'TCP', // Default, can be adjusted if API provides this info
        startedAt: scan.submitted_at ? new Date(scan.submitted_at._seconds * 1000).getTime() : Date.now(),
        status: scan.status === 'complete' ? 'Completed' :
          scan.status === 'ongoing' ? 'ongoing' : 'failed',
        apiStatus: scan,

        // QUICK SCAN SPECIFIC DATA
        activeHosts: scan.summary?.active_hosts || scan.summary?.total_hosts || 0,
        totalHosts: scan.summary?.total_hosts || 0,
        openPorts: [], // Will be populated from ScanResults
        totalPorts: scan.summary?.open_ports_total || 0,
        deviceTypes: scan.summary?.device_types || [],
        scanDuration: scan.summary?.scan_duration || '',

        cveList: [],
        cves: scan.summary?.vulnerabilities_total || 0,
        user_id: scan.user_id,

        // additional fields
        summary: scan.summary,
        is_network_scan: scan.is_network_scan,
        scan_name: scan.scan_name,
        finished_at: scan.finished_at,
        scan_mode: scan.target_ids ? (scan.target_ids.length > 1 ? 'deep-multiple' : 'deep-single') : 'normal'
      }));

      return convertedScans;
    }
    return [];
  } catch (error) {
    console.error('Firebase error, falling back to localStorage');
    console.error('Error loading scans from Firebase:', error);
    // Fallback to localStorage in case of error
    try {
      return JSON.parse(localStorage.getItem(LS_SCANS) || "[]");
    } catch {
      return [];
    }
  }
}

// save scans to localStorage
function saveScans(arr) {
  try {
    localStorage.setItem(LS_SCANS, JSON.stringify(arr));
  } catch {
    console.warn('Failed to save scans to localStorage');
  }
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

/* ====== SCAN POLLING ====== */
const activePolling = new Map();

function startScanPolling(scanId) {
  if (activePolling.has(scanId)) return;

  const pollInterval = setInterval(async () => {
    try {
      const status = await nmapAPI.getScanStatus(scanId);
      console.log("SCAN STATUS RESPONSE:", status);
      updateScanStatus(scanId, status);

      // Check if scan completed or failed
      if (status.scan.status === 'complete' || status.scan.status === 'failed') {
        stopScanPolling(scanId);

        // Hide loading screen
        document.getElementById('scan-loading').style.display = 'none';

        // Show results section
        document.getElementById('scan-results-content').style.display = 'block';

        // PASS THE API STATUS TO RENDER FUNCTION
        renderScanResultsPageWithData(status);
      }

    } catch (error) {
      console.error(`Polling error for scan ${scanId}:`, error);
      stopScanPolling(scanId);
    }
  }, 3000);

  activePolling.set(scanId, pollInterval);
}


function stopScanPolling(scanId) {
  if (activePolling.has(scanId)) {
    clearInterval(activePolling.get(scanId));
    activePolling.delete(scanId);
  }
}

// NEW FUNCTION: Render scan results with fresh API data
function renderScanResultsPageWithData(apiStatus) {
  console.log('Rendering with fresh API data:', apiStatus);

  // Create model directly from API response
  const model = createModelFromApiResponse(apiStatus);

  // Update the UI immediately with fresh data
  updateScanResultsUI(model);
}

// NEW FUNCTION: Create model directly from API response
function createModelFromApiResponse(apiStatus) {
  console.log('Creating model from API response:', apiStatus);

  if (!apiStatus || !apiStatus.scan) {
    return getFallbackModel();
  }

  if (apiStatus.scan.status === 'ongoing') {
    return {
      targetValue: apiStatus.scan.target || 'Unknown Target',
      type: apiStatus.scan.scan_type === 'quick_scan' ? 'quick' : 'deep',
      activeHosts: '...',
      totalHosts: '...',
      openPorts: 0,
      totalPorts: '...',
      deviceTypes: [],
      scanDuration: '',
      cves: 0,
      hosts: [],
      cveList: [],
      status: 'ongoing',
      message: 'Scan in progress...'
    };
  }

  if (apiStatus.scan.status === 'complete' && apiStatus.ScanResults) {
    const hosts = apiStatus.ScanResults;
    console.log('Processing fresh ScanResults:', hosts);

    // For quick scans, extract host information with proper field mapping
    const hostDetails = hosts.map((host, index) => {
      return {
        id: host.id || `host${index + 1}`,
        ip: host.host, // This is the correct field from your API
        hostname: host.hostname || 'N/A',
        mac_address: host.mac_address || 'N/A',
        vendor: host.vendor || 'Unknown',
        device_type: host.device_type || 'Unknown',
        host_status: host.host_status || 'unknown',
        ports: host.ports || [],
        open_ports_count: host.open_ports_count || 0
      };
    });

    const openPorts = hosts.flatMap(host =>
      (host.ports || []).filter(p => p.state === 'open').map(p => p.port)
    );

    const cveList = (apiStatus.foundVulns || []).map(vuln => ({
      id: vuln.CVE || `VULN-${uid()}`,
      title: vuln.title || `Vulnerability in ${vuln.service || 'unknown'}`,
      cvss: parseFloat(vuln.risk_level) || 0.0,
      severity: cvssToSeverity(parseFloat(vuln.risk_level) || 0.0)
    }));

    const result = {
      targetValue: apiStatus.scan.target,
      type: apiStatus.scan.scan_type === 'quick_scan' ? 'quick' : 'deep',
      activeHosts: apiStatus.scan.summary?.active_hosts || hosts.length,
      totalHosts: apiStatus.scan.summary?.total_hosts || hosts.length,
      openPorts: openPorts.length,
      totalPorts: apiStatus.scan.summary?.open_ports_total || openPorts.length,
      deviceTypes: apiStatus.scan.summary?.device_types || [...new Set(hosts.map(h => h.device_type))],
      scanDuration: apiStatus.scan.summary?.scan_duration || '',
      cves: cveList.length,
      hosts: hostDetails,
      cveList: cveList,
      status: 'complete',
      isQuickScan: apiStatus.scan.scan_type === 'quick_scan',
      scanSummary: apiStatus.scan.summary,
      rawResults: apiStatus.ScanResults
    };

    console.log('Fresh model result:', result);
    return result;
  }

  return getFallbackModel();
}

// Helper function for fallback data
function getFallbackModel() {
  return {
    targetValue: "scanme.nmap.org",
    type: "quick",
    activeHosts: 1,
    openPorts: 3,
    totalPorts: 50,
    cves: 4,
    hosts: [{
      id: "host1", name: "Host 1",
      ports: [
        { port: 5432, service: "PostgreSQL", status: "open" },
        { port: 8080, service: "HTTP Proxy", status: "open" },
        { port: 6379, service: "Redis", status: "open" },
      ]
    }],
    cveList: [
      { id: "CVE-2019-8874", title: "Demo vulnerability on port 5432", cvss: 0.7, severity: "TRIVIAL" },
      { id: "CVE-2016-4992", title: "Demo vulnerability on port 5432", cvss: 8.1, severity: "HIGH" },
      { id: "CVE-2021-8031", title: "Demo vulnerability on port 6379", cvss: 0.0, severity: "TRIVIAL" },
      { id: "CVE-2021-5054", title: "Demo vulnerability on port 5432", cvss: 9.8, severity: "CRITICAL" },
    ]
  };
}

function updateScanStatus(scanId, apiStatus) {
  console.log('Updating scan status for:', scanId, apiStatus);

  // update local state 
  const scanIndex = state.scans.findIndex(s => s.id === scanId);

  if (scanIndex !== -1) {
    const scan = state.scans[scanIndex];
    scan.status = apiStatus.scan.status === 'complete' ? 'Completed' :
      apiStatus.scan.status === 'ongoing' ? 'ongoing' : 'failed';
    scan.apiStatus = apiStatus;

    console.log('Updated scan with API status:', scan);

    if (apiStatus.scan.status === 'complete' && apiStatus.ScanResults) {
      processCompletedScan(scan, apiStatus);

      // Switch from loading to results view
      document.getElementById('scan-loading').style.display = 'none';
      document.getElementById('scan-results-content').style.display = 'block';

      // RENDER WITH FRESH API DATA
      renderScanResultsPageWithData(apiStatus);
    }

    if (apiStatus.scan.status === 'failed') {
      scan.error = apiStatus.scan.error;
      // Show error state
      document.getElementById('scan-loading').innerHTML = `
        <div style="text-align: center; color: #c02020;">
          <h3>Scan Failed</h3>
          <p>${scan.error || 'Unknown error occurred during scan'}</p>
          <button class="btn-primary" onclick="showScansHistoryView()">Back to History</button>
        </div>
      `;
    }

    // Persist updated scans
    saveScans(state.scans);

  } else {
    console.warn('Scan not found in state:', scanId);
    // If scan completed but not found in state, render directly with API data
    if (apiStatus.scan.status === 'complete') {
      renderScanResultsPageWithData(apiStatus);
    }
  }
}
function processCompletedScan(scan, apiStatus) {
  console.log('Processing completed scan:', scan.id, 'with API data:', apiStatus);

  if (apiStatus.ScanResults && apiStatus.ScanResults.length > 0) {
    const hosts = apiStatus.ScanResults;

    // Update scan with real data from API
    scan.openPorts = [];
    scan.cveList = [];
    scan.activeHosts = apiStatus.scan.summary?.active_hosts || hosts.length;
    scan.totalHosts = apiStatus.scan.summary?.total_hosts || hosts.length;
    scan.deviceTypes = apiStatus.scan.summary?.device_types || [];
    scan.scanDuration = apiStatus.scan.summary?.scan_duration || '';

    // Extract open ports from all hosts
    hosts.forEach(host => {
      if (host.ports && Array.isArray(host.ports)) {
        host.ports.forEach(port => {
          if (port.state === 'open') {
            scan.openPorts.push(port.port);
          }
        });
      }
    });

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

    console.log('Scan after processing:', scan);
  }
}

/* ====== VIEW MANAGEMENT ====== */
function showNewScanModal() {
  document.getElementById('modal-newscan').setAttribute('aria-hidden', 'false');
  updateScanModeUI();
}

function hideNewScanModal() {
  document.getElementById('modal-newscan').setAttribute('aria-hidden', 'true');
}

// update UI based on selected scan mode
function updateScanModeUI() {
  const scanMode = document.querySelector('input[name="ns-scan-mode"]:checked')?.value || 'normal';
  const targetSection = document.getElementById('ns-target-section');
  const targetSelectionSection = document.getElementById('ns-target-selection-section');
  const scanTypeSection = document.getElementById('ns-scan-type-section');

  // Hide all sections initially
  if (targetSection) targetSection.style.display = 'none';
  if (targetSelectionSection) targetSelectionSection.style.display = 'none';
  if (scanTypeSection) scanTypeSection.style.display = 'none';

  switch (scanMode) {
    case 'normal':
      if (targetSection) targetSection.style.display = 'block';
      if (scanTypeSection) scanTypeSection.style.display = 'block';
      populateSavedTargetsDropdown();
      break;
    case 'deep-single':
      if (targetSelectionSection) targetSelectionSection.style.display = 'block';
      populateTargetSelection();
      break;
    case 'deep-multiple':
      if (targetSelectionSection) targetSelectionSection.style.display = 'block';
      populateTargetSelection(true);
      break;
  }

  updateStartEnabled();
}

// populate target selection list
function populateTargetSelection(multiple = false) {
  const container = document.getElementById('ns-target-selection-container');
  if (!container) return;

  const targets = state.targets || [];

  if (targets.length === 0) {
    container.innerHTML = '<div class="muted" style="padding: 20px; text-align: center;">No targets available. Please add targets first.</div>';
    return;
  }

  container.innerHTML = targets.map(target => `
    <div class="target-selection-item">
      <label class="checkbox-label">
        <input type="${multiple ? 'checkbox' : 'radio'}" name="${multiple ? 'ns-selected-targets' : 'ns-selected-target'}" value="${target.id}" 
               onchange="updateStartEnabled()">
        <span class="checkmark"></span>
        <div class="target-info">
          <strong>${target.name || 'Unnamed Target'}</strong>
          <span>${target.value}</span>
          ${target.device_type ? `<small>${target.device_type}</small>` : ''}
        </div>
      </label>
    </div>
  `).join('');
}

function showActiveScanView(scanData = null) {
  const historyView = document.getElementById('view-scans-history');
  const activeView = document.getElementById('view-active-scan');
  const loading = document.getElementById('scan-loading');
  const results = document.getElementById('scan-results-content');

  // Hide history view and show active scan section
  historyView.classList.remove('active');
  historyView.style.display = 'none';
  activeView.style.display = 'block';
  document.getElementById('page-title').textContent = 'Active Scan';

  // If scanData exists -> show loading screen
  if (scanData) {
    loading.style.display = 'block';
    results.style.display = 'none';
    document.getElementById('loading-target').textContent =
      scanData.targetValue || scanData.scan_name || 'Multiple Targets';
    animateProgress();
  }
}


async function showScansHistoryView() {
  document.getElementById('view-active-scan').style.display = 'none';
  document.getElementById('view-scans-history').classList.add('active');
  document.getElementById('page-title').textContent = 'Scans';
  await renderScansHistory();
}

function animateProgress() {
  const progressFill = document.querySelector('.progress-fill');
  const progressText = document.querySelector('.progress-text');
  const steps = [
    { width: '10%', text: 'Initializing scan...' },
    { width: '25%', text: 'Discovering hosts...' },
    { width: '45%', text: 'Scanning ports...' },
    { width: '70%', text: 'Analyzing services...' },
    { width: '85%', text: 'Checking vulnerabilities...' },
    { width: '95%', text: 'Finalizing results...' }
  ];

  let currentStep = 0;
  const interval = setInterval(() => {
    if (currentStep < steps.length) {
      progressFill.style.width = steps[currentStep].width;
      progressText.textContent = steps[currentStep].text;
      currentStep++;
    } else {
      clearInterval(interval);
    }
  }, 2000);
}

/* ====== SCANS HISTORY RENDER ====== */
async function renderScansHistory() {
  const scansList = document.getElementById('scans-list');
  const scansEmpty = document.getElementById('scans-empty');
  const scansCount = document.getElementById('scans-count');

  // Load scans from API
  state.scans = await loadScans();

  // Use pagination module
  const { items: paginatedScans, total, totalPages } = pagination.getPaginatedItems(state.scans);

  scansCount.textContent = `${total} scan${total !== 1 ? 's' : ''}`;

  if (total === 0) {
    scansList.style.display = 'none';
    scansEmpty.style.display = 'block';
    // Hide pagination if no results
    document.getElementById('history-pagination').style.display = 'none';
    return;
  }

  scansList.style.display = 'grid';
  scansEmpty.style.display = 'none';
  
  // Show pagination
  document.getElementById('history-pagination').style.display = 'flex';

  scansList.innerHTML = paginatedScans.map(scan => {
    const startDate = new Date(scan.startedAt);
    const statusClass = scan.status === 'ongoing' ? 'ongoing' :
      scan.status === 'Completed' ? 'completed' : 'failed';

    // Determine scan type display
    let scanTypeDisplay = scan.type === 'deep' ? 'Deep Scan' : 'Quick Scan';
    if (scan.scan_mode === 'deep-single') scanTypeDisplay = 'Deep Single';
    if (scan.scan_mode === 'deep-multiple') scanTypeDisplay = `Deep Multiple (${scan.targetIds?.length || 0})`;

    return `
    <div class="scan-item" data-scan-id="${scan.id}">
      <div class="scan-info">
        <h4> ${scan.scan_name}</h4>
        <div class="scan-meta">
          <span>${scanTypeDisplay} • ${scan.proto}</span>
          <span>Started: ${startDate.toLocaleString()}</span>
          <span>CVEs: ${scan.cves || 0} • Ports: ${scan.openPorts?.length || 0}</span>
          ${scan.scan_name ? `<span>Target: ${escapeHtml(scan.targetValue || scan.scan_name || 'Unknown Target')}</span>` : ''}
        </div>
      </div>
      <div class="scan-status status-${statusClass}">
        ${scan.status === 'ongoing' ? 'In Progress' : scan.status === 'Completed' ? 'Completed' : 'Failed'}
      </div>
      <div class="scan-actions">
        <button class="btn-secondary small" data-action="view-scan" data-scan-id="${scan.id}">View</button>
        ${scan.status === 'Completed' ? `<button class="btn-primary small" data-action="rescan" data-scan-id="${scan.id}">Rescan</button>` : ''}
        <button class="btn-secondary small" data-action="export-csv" data-scan-id="${scan.id}">Export CSV</button>
      </div>
    </div>
  `}).join('');

  // Render pagination controls
  pagination.renderPagination(total, 'history-pagination');
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, m => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m]));
}

/* ====== POPULATE TARGETS DROPDOWN ====== */
function populateSavedTargetsDropdown() {
  const sel = document.getElementById("ns-choose");
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

/* ====== DEMO DATA ====== */
function simulateOpenPorts(proto) {
  const commonTCP = [22, 80, 443, 8080, 3306, 5432, 6379];
  const commonUDP = [53, 123, 161];
  const pool = proto === "UDP" ? commonUDP : commonTCP;
  const n = Math.floor(Math.random() * 4);
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

/* ====== CREATE SCAN ====== */
async function addScan({ targetValue, targetId = null, targetIds = [], type = "quick", proto = "TCP", scanMode = "normal", scanName = "" }) {
  try {
    const userId = getCurrentUserId();
    let result;

    if (scanMode === 'deep-single') {
      if (!targetId) throw new Error('Target ID required for deep single scan');
      result = await nmapAPI.startDeepSingleScan(targetId, userId, scanName);
    } else if (scanMode === 'deep-multiple') {
      if (!targetIds.length) throw new Error('At least one target required for deep multiple scan');
      if (targetIds.length > 10) throw new Error('Maximum 10 targets allowed for deep multiple scan');
      result = await nmapAPI.startDeepMultipleScan(targetIds, userId, scanName);
    } else {
      // normal scan
      const presetMap = {
        'quick': 'quick_scan',
        'deep': 'deep_scan'
      };
      const preset = presetMap[type] || 'quick_scan';
      result = await nmapAPI.startScan(targetValue, preset, userId, scanName);
    }

    const scan = {
      id: result.scanId,
      targetId: scanMode === 'deep-single' ? targetId : null,
      targetIds: scanMode === 'deep-multiple' ? targetIds : [],
      targetValue: targetValue ||
        (scanMode === 'deep-multiple' ? result.targets?.map(t => t.host).join(', ') : null) ||
        result.target ||
        'Multiple Targets',
      type: scanMode.includes('deep') ? 'deep' : type,
      preset: scanMode.includes('deep') ? 'deep_scan' : (type === 'deep' ? 'deep_scan' : 'quick_scan'),
      proto,
      startedAt: Date.now(),
      status: "ongoing",
      apiStatus: result,
      openPorts: [],
      cveList: [],
      cves: 0,
      user_id: userId,
      scan_name: scanName || result.scan_name || `${scanMode} Scan`,
      scan_mode: scanMode
    };

    // Add to local state and persist
    state.scans.unshift(scan);
    saveScans(state.scans);

    // Hide modal and show active scan view
    hideNewScanModal();
    showActiveScanView(scan);

    startScanPolling(result.scanId);
    return scan;

  } catch (error) {
    console.error('Failed to start scan:', error);

    // Fallback to demo mode
    const userId = getCurrentUserId();
    const openPorts = simulateOpenPorts(proto);
    const cveList = simulateCVEs(openPorts);

    const scan = {
      id: uid(),
      targetId: scanMode === 'deep-single' ? targetId : null,
      targetIds: scanMode === 'deep-multiple' ? targetIds : [],
      targetValue: targetValue || 'Demo Target',
      type: scanMode.includes('deep') ? 'deep' : type,
      proto,
      startedAt: Date.now(),
      status: "Completed",
      openPorts,
      cveList,
      cves: cveList.length,
      apiError: true,
      user_id: userId,
      scan_name: scanName || `Demo ${scanMode} Scan`,
      scan_mode: scanMode
    };

    state.scans.unshift(scan);
    saveScans(state.scans);

    // Hide modal and show active scan view
    hideNewScanModal();
    showActiveScanView(scan);

    return scan;
  }
}

/* ====== SCANS PAGE RENDER ====== */
function getLastScanForUI() {
  try {
    return state.scans[0] || null;
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

async function renderScanResultsPage() {
  // Update local state before rendering
  state.scans = await loadScans();
  const last = getLastScanForUI();

  const fallback = {
    targetValue: "scanme.nmap.org",
    type: "quick",
    activeHosts: 1,
    openPorts: 3,
    totalPorts: 50,
    cves: 4,
    hosts: [{
      id: "host1", name: "Host 1",
      ports: [
        { port: 5432, service: "PostgreSQL", status: "open" },
        { port: 8080, service: "HTTP Proxy", status: "open" },
        { port: 6379, service: "Redis", status: "open" },
      ]
    }],
    cveList: [
      { id: "CVE-2019-8874", title: "Demo vulnerability on port 5432", cvss: 0.7, severity: "TRIVIAL" },
      { id: "CVE-2016-4992", title: "Demo vulnerability on port 5432", cvss: 8.1, severity: "HIGH" },
      { id: "CVE-2021-8031", title: "Demo vulnerability on port 6379", cvss: 0.0, severity: "TRIVIAL" },
      { id: "CVE-2021-5054", title: "Demo vulnerability on port 5432", cvss: 9.8, severity: "CRITICAL" },
    ]
  };

  let model;

  if (last) {
    if (last.status === "ongoing" && last.apiStatus) {
      model = createModelFromApiStatus(last);
    } else {
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
            if (p === 5432) return { port: 5432, service: "PostgreSQL", status: "open" };
            if (p === 8080) return { port: 8080, service: "HTTP Proxy", status: "open" };
            if (p === 6379) return { port: 6379, service: "Redis", status: "open" };
            return { port: p, service: "", status: "open" };
          }) : [
            { port: 5432, service: "PostgreSQL", status: "open" },
            { port: 8080, service: "HTTP Proxy", status: "open" },
            { port: 6379, service: "Redis", status: "open" },
          ])
        }],
        cveList: last.cveList ?? fallback.cveList,
        status: last.status,
        apiError: last.apiError
      };
    }
  } else {
    model = fallback;
  }

  updateScanResultsUI(model);
}

function createModelFromApiStatus(scan) {
  const apiStatus = scan.apiStatus;
  console.log('API Status for model creation:', apiStatus); // Debug log

  if (!apiStatus || !apiStatus.scan) {
    return {
      targetValue: scan.targetValue,
      type: scan.type,
      activeHosts: scan.activeHosts || 0,
      totalHosts: scan.totalHosts || 0,
      openPorts: scan.openPorts || 0,
      totalPorts: scan.totalPorts || 0,
      deviceTypes: scan.deviceTypes || [],
      scanDuration: scan.scanDuration || '',
      cves: scan.cves || 0,
      hosts: [],
      cveList: [],
      status: scan.status
    };
  }

  if (apiStatus.scan.status === 'ongoing') {
    return {
      targetValue: scan.targetValue,
      type: scan.type,
      activeHosts: '...',
      totalHosts: '...',
      openPorts: 0,
      totalPorts: '...',
      deviceTypes: [],
      scanDuration: '',
      cves: 0,
      hosts: [],
      cveList: [],
      status: 'ongoing',
      message: 'Scan in progress...'
    };
  }

  if (apiStatus.scan.status === 'complete' && apiStatus.ScanResults) {
    const hosts = apiStatus.ScanResults;
    console.log('Processing ScanResults:', hosts); // Debug log

    // For quick scans, extract host information with proper field mapping
    const hostDetails = hosts.map((host, index) => {
      console.log('Processing host:', host); // Debug each host
      return {
        id: host.id || `host${index + 1}`,
        ip: host.host, // This is the correct field from your API
        hostname: host.hostname || 'N/A',
        mac_address: host.mac_address || 'N/A',
        vendor: host.vendor || 'Unknown',
        device_type: host.device_type || 'Unknown',
        host_status: host.host_status || 'unknown',
        ports: host.ports || [],
        open_ports_count: host.open_ports_count || 0
      };
    });

    const openPorts = hosts.flatMap(host =>
      (host.ports || []).filter(p => p.state === 'open').map(p => p.port)
    );

    const cveList = (apiStatus.foundVulns || []).map(vuln => ({
      id: vuln.CVE || `VULN-${uid()}`,
      title: vuln.title || `Vulnerability in ${vuln.service || 'unknown'}`,
      cvss: parseFloat(vuln.risk_level) || 0.0,
      severity: cvssToSeverity(parseFloat(vuln.risk_level) || 0.0)
    }));

    const result = {
      targetValue: scan.targetValue,
      type: scan.type,
      activeHosts: apiStatus.scan.summary?.active_hosts || hosts.length,
      totalHosts: apiStatus.scan.summary?.total_hosts || hosts.length,
      openPorts: openPorts.length,
      totalPorts: apiStatus.scan.summary?.open_ports_total || openPorts.length,
      deviceTypes: apiStatus.scan.summary?.device_types || [...new Set(hosts.map(h => h.device_type))],
      scanDuration: apiStatus.scan.summary?.scan_duration || '',
      cves: cveList.length,
      hosts: hostDetails,
      cveList: cveList,
      status: 'complete',
      isQuickScan: scan.type === 'quick',
      scanSummary: apiStatus.scan.summary,
      rawResults: apiStatus.ScanResults
    };

    console.log('Final model result:', result); // Debug final model
    return result;
  }

  return {
    targetValue: scan.targetValue,
    type: scan.type,
    activeHosts: 0,
    totalHosts: 0,
    openPorts: 0,
    totalPorts: 0,
    deviceTypes: [],
    scanDuration: '',
    cves: 0,
    hosts: [],
    cveList: [],
    status: scan.status
  };
}

function updateScanResultsUI(model) {
  // Update header
  document.getElementById("sr-target").textContent = model.targetValue;
  document.getElementById("sr-type").textContent = (model.type === "deep" ? "Deep Scan" : "Quick Scan");

  // Update summary - show different info for quick vs deep scans
  if (model.type === "quick") {
    document.getElementById("sr-active-hosts").textContent = model.activeHosts;
    document.getElementById("sr-cves").textContent = model.totalHosts; // Show total hosts for quick scans
    document.getElementById("sr-ports-text").textContent = `${model.openPorts} ports open`;

    // Add quick scan specific info
    const quickScanInfo = document.getElementById("quick-scan-info") || createQuickScanInfoSection();
    quickScanInfo.innerHTML = `
      <div class="quick-scan-stats">
        <div class="stat">
          <span class="stat-value">${model.totalHosts}</span>
          <span class="stat-label">Total Hosts</span>
        </div>
        <div class="stat">
          <span class="stat-value">${model.activeHosts}</span>
          <span class="stat-label">Active Hosts</span>
        </div>
        <div class="stat">
          <span class="stat-value">${model.openPorts}</span>
          <span class="stat-label">Open Ports</span>
        </div>
        <div class="stat">
          <span class="stat-value">${model.scanDuration}</span>
          <span class="stat-label">Duration</span>
        </div>
      </div>
    `;
  } else {
    // Deep scan info (your existing code)
    document.getElementById("sr-active-hosts").textContent = model.activeHosts;
    document.getElementById("sr-cves").textContent = model.cves;
    document.getElementById("sr-ports-text").textContent = `${model.openPorts}/${model.totalPorts}`;
  }

  // Update gauge
  if (model.status === 'ongoing') {
    document.getElementById("sr-ports-text").textContent = "Scanning...";
    drawGauge(0.1);
  } else if (model.type === "quick") {
    // For quick scans, show host discovery progress
    const discoveryRate = model.totalHosts > 0 ? model.activeHosts / model.totalHosts : 0;
    drawGauge(discoveryRate);
  } else {
    document.getElementById("sr-ports-text").textContent = `${model.openPorts}/${model.totalPorts}`;
    drawGauge(model.totalPorts ? model.openPorts / model.totalPorts : 0);
  }

  // Update tables based on scan type
  if (model.type === "quick") {
    fillQuickScanHostsTable(model.hosts);
  } else {
    fillPortsTable(model.hosts[0]);
  }

  // Update vulnerabilities table (only for deep scans)
  if (model.type === "deep") {
    renderCVETable(model.cveList);
  } else {
    const vulnContainer = document.getElementById("vuln-table-container");
    if (vulnContainer) {
      vulnContainer.innerHTML = '<div class="muted" style="padding: 20px; text-align: center;">Vulnerability scanning not available for quick scans</div>';
    }
  }

  // Update clear button
  updateClearButtonLabel();
}

// NEW FUNCTION: Create quick scan info section
function createQuickScanInfoSection() {
  const section = document.createElement('div');
  section.id = 'quick-scan-info';
  section.className = 'quick-scan-info';

  const existingSection = document.querySelector('.scan-results-header');
  if (existingSection) {
    existingSection.appendChild(section);
  }

  return section;
}

// NEW FUNCTION: Fill quick scan hosts table
// FIXED FUNCTION: Fill quick scan hosts table
function fillQuickScanHostsTable(hosts) {
  const container = document.getElementById("ports-table-container");
  if (!container) return;

  console.log('Filling quick scan hosts table with:', hosts); // Debug log

  if (!hosts || hosts.length === 0) {
    container.innerHTML = '<div class="muted" style="padding: 20px; text-align: center;">No hosts discovered</div>';
    return;
  }

  container.innerHTML = `
    <div class="quick-scan-results">
      <h3>Discovered Hosts (${hosts.length})</h3>
      <table class="hosts-table">
        <thead>
          <tr>
            <th>IP Address</th>
            <th>Hostname</th>
            <th>MAC Address</th>
            <th>Vendor</th>
            <th>Device Type</th>
            <!--<th>Status</th>-->
            <!--<th>Open Ports</th>-->
          </tr>
        </thead>
        <tbody>
          ${hosts.map(host => {
    console.log('Rendering host row:', host); // Debug each host row

    // Use the actual field names from your API response
    const ip = host.ip || host.host || 'N/A';
    const hostname = host.hostname || 'N/A';
    const mac = host.mac_address || 'N/A';
    const vendor = host.vendor || 'Unknown';
    const deviceType = host.device_type || 'Unknown';
    const status = host.host_status || 'unknown';
    const openPorts = host.open_ports_count || 0;

    const statusClass = `status-${status}`;
    const statusText = status ? status.charAt(0).toUpperCase() + status.slice(1) : 'Unknown';

    return `
            <tr>
              <td><strong>${ip}</strong></td>
              <td>${hostname}</td>
              <td><code>${mac}</code></td>
              <td>${vendor}</td>
              <td><span class="device-type">${deviceType}</span></td>
              <!--<td><span class="${statusClass}">${statusText}</span></td>-->
              <!--<td>${openPorts}</td>-->
            </tr>
          `}).join('')}
        </tbody>
      </table>
    </div>
  `;

  console.log('Quick scan table rendered successfully'); // Debug log
}

function fillPortsTable(host) {
  const container = document.getElementById("ports-table-container");
  if (!container) return;

  if (!host || !host.ports || host.ports.length === 0) {
    container.innerHTML = '<div class="muted" style="padding: 20px; text-align: center;">No ports data available</div>';
    return;
  }

  container.innerHTML = `
    <table class="ports-table">
      <thead>
        <tr>
          <th>Port</th>
          <th>Service</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        ${host.ports.map(port => {
    const statusClass = `status-${port.status}`;
    const statusText = port.status ? port.status.charAt(0).toUpperCase() + port.status.slice(1) : 'Unknown';
    return `
            <tr>
              <td>${port.port}</td>
              <td>${port.service || ""}</td>
              <td><span class="${statusClass}">${statusText}</span></td>
            </tr>
          `;
  }).join('')}
      </tbody>
    </table>
  `;
}

function renderCVETable(cves) {
  const container = document.getElementById("vuln-table-container");
  if (!container) return;

  if (!cves || cves.length === 0) {
    container.innerHTML = '<div class="muted" style="padding: 20px; text-align: center;">No vulnerabilities found</div>';
    return;
  }

  container.innerHTML = `
    <table class="vuln-table">
      <thead>
        <tr>
          <th>CVE</th>
          <th>Title</th>
          <th>CVSS</th>
          <th>Severity</th>
        </tr>
      </thead>
      <tbody>
        ${cves.map(vuln => {
    const sev = (vuln.severity || cvssToSeverity(vuln.cvss || 0)).toUpperCase();
    const sevCls = `sev-${sev}`;
    const score = (vuln.cvss ?? 0).toFixed(1);
    return `
            <tr>
              <td><strong>${vuln.id}</strong></td>
              <td>${vuln.title}</td>
              <td>${score}</td>
              <td><span class="${sevCls}">${sev}</span></td>
            </tr>
          `;
  }).join('')}
      </tbody>
    </table>
  `;
}

function updateClearButtonLabel() {
  const btn = document.getElementById("btn-clear-trivial");
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

function handleClearTrivial() {
  if (!state.scans.length) { alert("No scans to clean."); return; }

  const THRESH = parseFloat(localStorage.getItem("vulnerai.clearThreshold") || "4.0");

  const last = state.scans[0];
  if (!Array.isArray(last.cveList)) last.cveList = [];

  const before = last.cveList.length;
  last.cveList = last.cveList.filter(v => (v.cvss ?? 0) >= THRESH);
  last.cves = last.cveList.length;

  saveScans(state.scans);
  renderScanResultsPage();

  const removed = before - last.cveList.length;
  alert(removed > 0
    ? `Removed ${removed} CVE(s) with CVSS < ${THRESH}.`
    : `No CVEs with CVSS < ${THRESH} found.`);
}

// NOVA FUNÇÃO: Atualizar estado do botão start
function updateStartEnabled() {
  const tos = document.getElementById("ns-tos");
  const startBtn = document.getElementById("ns-start");
  const scanMode = document.querySelector('input[name="ns-scan-mode"]:checked')?.value || 'normal';

  let hasValidInput = false;

  switch (scanMode) {
    case 'normal':
      const targetInp = document.getElementById("ns-target");
      const chooseSel = document.getElementById("ns-choose");
      hasValidInput = !!(targetInp?.value.trim() || chooseSel?.value);
      break;
    case 'deep-single':
      const selectedSingle = document.querySelector('input[name="ns-selected-target"]:checked');
      hasValidInput = !!selectedSingle;
      break;
    case 'deep-multiple':
      const selectedMultiple = document.querySelectorAll('input[name="ns-selected-targets"]:checked');
      hasValidInput = selectedMultiple.length > 0 && selectedMultiple.length <= 10;
      break;
  }

  const ok = !!(tos?.checked && hasValidInput);
  if (startBtn) startBtn.disabled = !ok;
}

// NEW FUNCTION: Export scan to CSV
function exportScanToCSV(scanId) {
  const scan = state.scans.find(s => s.id === scanId);
  if (!scan) return;

  let csvContent = 'data:text/csv;charset=utf-8,';
  csvContent += 'CVE ID,Title,CVSS Score,Severity\n';
  scan.cveList.forEach(cve => {
    csvContent += `${cve.id},${cve.title},${cve.cvss},${cve.severity}\n`;
  });

  const encodedUri = encodeURI(csvContent);
  const link = document.createElement('a');
  link.setAttribute('href', encodedUri);
  link.setAttribute('download', `scan_${scanId}_vulnerabilities.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

/* ====== INIT ====== */
async function init() {
  if (!requireAuth()) return;

  // DARK MODE
  const themeQuick = localStorage.getItem("vulnerai.theme");
  const isDark = themeQuick ? (themeQuick === "dark") : false;
  document.body.classList.toggle("dark", isDark);

  loadTargets();
  populateSavedTargetsDropdown();

  // Carregar scans da Firebase no início
  state.scans = await loadScans();

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

  /* NEW SCAN MODAL */
  const newScanModal = document.getElementById('modal-newscan');
  document.getElementById('btn-new-scan')?.addEventListener('click', showNewScanModal);
  document.getElementById('empty-new-scan')?.addEventListener('click', showNewScanModal);

  newScanModal?.addEventListener('click', (e) => {
    if (e.target.hasAttribute('data-close') || e.target.classList.contains('close') || e.target.classList.contains('backdrop')) {
      hideNewScanModal();
    }
  });

  // NOVO: Event listeners para modos de scan
  const scanModeRadios = document.querySelectorAll('input[name="ns-scan-mode"]');
  scanModeRadios.forEach(radio => {
    radio.addEventListener('change', updateScanModeUI);
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

  /* NEW SCAN FORM */
  const tos = document.getElementById("ns-tos");
  const targetInp = document.getElementById("ns-target");
  const startBtn = document.getElementById("ns-start");
  const chooseSel = document.getElementById("ns-choose");
  const scanNameInp = document.getElementById("ns-scan-name");

  tos?.addEventListener("change", updateStartEnabled);
  targetInp?.addEventListener("input", updateStartEnabled);
  chooseSel?.addEventListener("change", () => {
    const id = chooseSel.value;
    const t = state.targets.find(x => x.id === id);
    if (targetInp) targetInp.value = t ? t.value : '';
    updateStartEnabled();
  });

  updateStartEnabled();

  document.getElementById("newscan-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!tos?.checked) return alert('Please accept the Terms first.');

    const scanMode = document.querySelector('input[name="ns-scan-mode"]:checked')?.value || 'normal';
    const type = (document.querySelector('input[name="ns-type"]:checked')?.value) || 'quick';
    const proto = (document.querySelector('input[name="ns-proto"]:checked')?.value) || 'TCP';
    const scanName = scanNameInp?.value.trim() || '';

    let targetValue = '';
    let targetId = null;
    let targetIds = [];

    // Obter dados baseado no modo de scan
    switch (scanMode) {
      case 'normal':
        targetValue = (targetInp?.value || '').trim();
        const chosenId = chooseSel?.value || null;
        if (!targetValue && chosenId) {
          const t = state.targets.find(x => x.id === chosenId);
          targetValue = t?.value || '';
        }
        targetId = chosenId;
        break;

      case 'deep-single':
        const selectedSingle = document.querySelector('input[name="ns-selected-target"]:checked');
        if (!selectedSingle) return alert('Please select a target');
        targetId = selectedSingle.value;
        const targetSingle = state.targets.find(t => t.id === targetId);
        targetValue = targetSingle?.value || '';
        break;

      case 'deep-multiple':
        const selectedMultiple = document.querySelectorAll('input[name="ns-selected-targets"]:checked');
        if (selectedMultiple.length === 0) return alert('Please select at least one target');
        if (selectedMultiple.length > 10) return alert('Please select maximum 10 targets');

        targetIds = Array.from(selectedMultiple).map(input => input.value);
        const targetsMultiple = state.targets.filter(t => targetIds.includes(t.id));
        targetValue = targetsMultiple.map(t => t.value).join(', ');
        break;
    }

    if (!targetValue && !targetId && targetIds.length === 0) {
      return alert('Please choose or type a target.');
    }

    if (startBtn) startBtn.disabled = true;
    startBtn.textContent = 'Starting Scan...';

    try {
      await addScan({
        targetValue,
        targetId,
        targetIds,
        type,
        proto,
        scanMode,
        scanName
      });
    } catch (error) {
      alert('Scan started with fallback mode (API unavailable)');
    } finally {
      if (startBtn) {
        startBtn.disabled = false;
        startBtn.textContent = 'Start Scan';
      }
    }
  });

  /* SHOW HISTORY BUTTONS */
  document.getElementById('btn-show-history')?.addEventListener('click', showScansHistoryView);
  document.getElementById('btn-show-history-results')?.addEventListener('click', showScansHistoryView);

/* SCANS HISTORY ACTIONS */
document.getElementById('scans-list')?.addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-action]');
  if (!btn) return;

  const scanId = btn.dataset.scanId;

  if (btn.dataset.action === 'view-scan') {
    await viewHistoricalScan(scanId);
  }

  if (btn.dataset.action === 'rescan') {
    // 🆕 SUBSTITUIR POR:
    await setupRescan(scanId);
  }

  if (btn.dataset.action === 'export-csv') {
    exportScanToCSV(scanId);
  }
});

// 🆕 NOVA FUNÇÃO: Carregar e mostrar scan histórico completo
async function viewHistoricalScan(scanId) {
  try {
    console.log('📋 Loading historical scan:', scanId);
    
    // 1. Mostrar loading screen
    showActiveScanView();
    document.getElementById('scan-loading').style.display = 'block';
    document.getElementById('scan-results-content').style.display = 'none';
    document.getElementById('loading-target').textContent = 'Loading historical scan results...';

    // 2. Buscar dados COMPLETOS do scan da Firebase
    const scanDetails = await nmapAPI.getScanStatus(scanId);
    console.log('📊 Historical scan details:', scanDetails);

    // 3. Processar e mostrar resultados
    if (scanDetails && scanDetails.scan) {
      // Criar model completo com os dados da Firebase
      const model = createModelFromApiResponse(scanDetails);
      
      // Esconder loading e mostrar resultados
      document.getElementById('scan-loading').style.display = 'none';
      document.getElementById('scan-results-content').style.display = 'block';
      
      // Renderizar com dados reais
      updateScanResultsUI(model);
      
      // Atualizar estado local
      updateLocalScanState(scanId, scanDetails);
    } else {
      throw new Error('No scan data found');
    }

  } catch (error) {
    console.error('❌ Error loading historical scan:', error);
    
    // Fallback: usar dados locais se disponíveis
    const localScan = state.scans.find(s => s.id === scanId);
    if (localScan) {
      document.getElementById('scan-loading').style.display = 'none';
      document.getElementById('scan-results-content').style.display = 'block';
      renderScanResultsPage(); // Usa dados locais
    } else {
      alert('Error loading scan results. Please try again.');
      showScansHistoryView();
    }
  }
}

// 🆕 FUNÇÃO AUXILIAR: Atualizar estado local com dados frescos
function updateLocalScanState(scanId, apiData) {
  const scanIndex = state.scans.findIndex(s => s.id === scanId);
  if (scanIndex !== -1) {
    state.scans[scanIndex].apiStatus = apiData;
    state.scans[scanIndex].status = 'Completed';
    
    // Mover para topo temporariamente para display
    const [selectedScan] = state.scans.splice(scanIndex, 1);
    state.scans.unshift(selectedScan);
    saveScans(state.scans);
  }
}

// 🆕 NOVA FUNÇÃO: Configurar rescan com dados pré-preenchidos
async function setupRescan(scanId) {
  try {
    // 1. Buscar dados do scan original
    state.scans = await loadScans();
    const originalScan = state.scans.find(s => s.id === scanId);
    
    if (!originalScan) {
      alert('Scan not found');
      return;
    }

    console.log('🔄 Setting up rescan for:', originalScan);

    // 2. Mostrar o modal de novo scan
    showNewScanModal();

    // 3. Pré-preencher os campos baseado no scan original
    setTimeout(() => {
      prefillRescanForm(originalScan);
    }, 100); // Pequeno delay para garantir que o modal está renderizado

  } catch (error) {
    console.error('Error setting up rescan:', error);
    alert('Error setting up rescan');
  }
}

// 🆕 FUNÇÃO: Pré-preencher o formulário com dados do scan original
function prefillRescanForm(originalScan) {
  console.log('📝 Prefilling form with:', originalScan);

  // 1. Scan Name - adicionar "Rescan" ao nome original
  const scanNameInput = document.getElementById('ns-scan-name');
  if (scanNameInput) {
    const originalName = originalScan.scan_name || originalScan.targetValue || 'Scan';
    scanNameInput.value = `Rescan of ${originalName}`;
  }

  // 2. Determinar modo de scan baseado no original
  let scanMode = 'normal';
  if (originalScan.scan_mode === 'deep-single') {
    scanMode = 'deep-single';
  } else if (originalScan.scan_mode === 'deep-multiple') {
    scanMode = 'deep-multiple';
  }

  // 3. Selecionar o modo de scan correto
  const scanModeRadio = document.querySelector(`input[name="ns-scan-mode"][value="${scanMode}"]`);
  if (scanModeRadio) {
    scanModeRadio.checked = true;
    updateScanModeUI(); // Atualizar UI baseado no modo
  }

  // 4. Pré-preencher baseado no modo de scan
  setTimeout(() => {
    switch (scanMode) {
      case 'normal':
        prefillNormalRescan(originalScan);
        break;
      case 'deep-single':
        prefillDeepSingleRescan(originalScan);
        break;
      case 'deep-multiple':
        prefillDeepMultipleRescan(originalScan);
        break;
    }
    
    updateStartEnabled(); // Atualizar estado do botão Start
  }, 200);
}

// 🆕 FUNÇÃO: Pré-preencher para scan normal
function prefillNormalRescan(originalScan) {
  const targetInput = document.getElementById('ns-target');
  const chooseSelect = document.getElementById('ns-choose');
  
  if (targetInput && originalScan.targetValue) {
    targetInput.value = originalScan.targetValue;
  }
  
  // Tentar selecionar no dropdown de targets salvos
  if (chooseSelect && originalScan.targetId) {
    chooseSelect.value = originalScan.targetId;
  }

  // Selecionar tipo de scan (quick/deep)
  const scanType = originalScan.type === 'deep' ? 'deep' : 'quick';
  const scanTypeRadio = document.querySelector(`input[name="ns-type"][value="${scanType}"]`);
  if (scanTypeRadio) {
    scanTypeRadio.checked = true;
  }

  // Selecionar protocolo
  const protoRadio = document.querySelector(`input[name="ns-proto"][value="${originalScan.proto || 'TCP'}"]`);
  if (protoRadio) {
    protoRadio.checked = true;
  }
}

// 🆕 FUNÇÃO: Pré-preencher para deep single
function prefillDeepSingleRescan(originalScan) {
  if (originalScan.targetId) {
    // Selecionar o target no radio button
    setTimeout(() => {
      const targetRadio = document.querySelector(`input[name="ns-selected-target"][value="${originalScan.targetId}"]`);
      if (targetRadio) {
        targetRadio.checked = true;
      }
    }, 300); // Dar tempo para a UI atualizar
  }
}

// 🆕 FUNÇÃO: Pré-preencher para deep multiple
function prefillDeepMultipleRescan(originalScan) {
  if (originalScan.targetIds && originalScan.targetIds.length > 0) {
    // Selecionar os targets nos checkboxes
    setTimeout(() => {
      originalScan.targetIds.forEach(targetId => {
        const targetCheckbox = document.querySelector(`input[name="ns-selected-targets"][value="${targetId}"]`);
        if (targetCheckbox) {
          targetCheckbox.checked = true;
        }
      });
    }, 300); // Dar tempo para a UI atualizar
  }
}


  /* SCANS CONTROLS */
  const btnRefresh = document.getElementById("scan-refresh");
  if (btnRefresh) {
    btnRefresh.addEventListener("click", async (e) => {
      e.preventDefault();
      // Recarregar scans da Firebase antes de renderizar
      state.scans = await loadScans();
      renderScanResultsPage();
    });
  }

  document.getElementById("btn-clear-trivial")?.addEventListener("click", handleClearTrivial);

  document.addEventListener("dblclick", (e) => {
    const btn = e.target.closest("#btn-clear-trivial");
    if (btn) {
      e.preventDefault();
      cycleClearThreshold();
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

  /* HISTORY FILTERS */
  const searchInput = document.getElementById('history-filter-search');
  searchInput?.addEventListener('input', (e) => {
    pagination.filters.search = e.target.value;
    pagination.currentPage = 1; // Reset to first page when filtering
    renderScansHistory();
  });

  const statusSelect = document.getElementById('history-filter-status');
  statusSelect?.addEventListener('change', (e) => {
    pagination.filters.status = e.target.value;
    pagination.currentPage = 1;
    renderScansHistory();
  });

  const typeSelect = document.getElementById('history-filter-type');
  typeSelect?.addEventListener('change', (e) => {
    pagination.filters.type = e.target.value;
    pagination.currentPage = 1;
    renderScansHistory();
  });

  // Show history by default
  showScansHistoryView();
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

/* ====== BOOT ====== */
document.addEventListener("DOMContentLoaded", init);