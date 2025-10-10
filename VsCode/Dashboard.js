/* ====== STATE ====== */
const state = {
  scans: [],
  ips: [],
  lastResult: null, // guarda o último resultado p/ mostrar em Scans
};

/* ====== HELPERS ====== */
const qs  = (s, el=document)=> el.querySelector(s);
const qsa = (s, el=document)=> [...el.querySelectorAll(s)];
const uid = ()=> Math.random().toString(36).slice(2,9);
const now = ()=> new Date().toLocaleString();

/* ====== VIEWS ====== */
function setActiveView(view){
  qsa('.nav-item').forEach(b=> b.classList.toggle('active', b.dataset.view===view));
  qsa('.view').forEach(v => v.classList.remove('active'));
  qs(`#view-${view}`)?.classList.add('active');

  const title =
    view==='newscan' ? 'New Scan' :
    view==='scans'   ? 'Scans'    :
    view==='iplist'  ? 'IP List'  : 'Dashboard';
  qs('#page-title').textContent = title;

  if(view === 'scans') {
    renderScanResults(state.lastResult); // mostra resultado (ou demo)
  }
}

/* ====== PREMIUM MODAL (usa o teu HTML existente) ====== */
qs('#btn-premium')?.addEventListener('click', ()=>{
  qs('#modal-premium')?.setAttribute('aria-hidden','false');
});
document.addEventListener('click',(e)=>{
  if(e.target.closest('#modal-premium .backdrop,[data-close].btn-secondary,#modal-premium .close')){
    qs('#modal-premium')?.setAttribute('aria-hidden','true');
  }
});
document.addEventListener('keydown',(e)=>{
  if(e.key==='Escape') qs('#modal-premium')?.setAttribute('aria-hidden','true');
});

/* ====== SIDEBAR NAV ====== */
qsa('.nav-item').forEach(btn=> btn.addEventListener('click', ()=> setActiveView(btn.dataset.view)));
qs('#btn-burger')?.addEventListener('click', ()=>{
  const sidebar = qs('#sidebar');
  const isNarrow = window.matchMedia('(max-width: 640px)').matches;
  isNarrow ? sidebar.classList.toggle('hidden') : sidebar.classList.toggle('collapsed');
});

/* ====== HOME / NEW SCAN ====== */
qs('#btn-new-scan')?.addEventListener('click', ()=> setActiveView('newscan'));
qs('#cta-new-scan')?.addEventListener('click', ()=> setActiveView('newscan'));

// habilita botões no New Scan conforme input + checkbox
const nsTarget = qs('#ns-target');
const nsTos    = qs('#ns-tos');
const nsStart  = qs('#ns-start');
const nsStartI = qs('#ns-start-icon');

function updateNSButtons(){
  if(!nsTarget || !nsTos) return;
  const ok = nsTarget.value.trim() && nsTos.checked;
  if(nsStart)  nsStart.disabled  = !ok;
  if(nsStartI) nsStartI.disabled = !ok;
}
nsTarget?.addEventListener('input', updateNSButtons);
nsTos?.addEventListener('change', updateNSButtons);
updateNSButtons();

// submit do New Scan → grava "resultado" demo e vai para Scans
function startDemoScan(e){
  e?.preventDefault();
  if(nsStart && nsStart.disabled) return;

  // Resultado DEMO (igual ao mock)
  state.lastResult = {
    target: (nsTarget?.value || 'scanme.nmap.org').trim() || 'scanme.nmap.org',
    scanType: 'Quick Scan',
    activeHosts: 5,
    openPorts: { open: 50, total: 50 },
    cves: 15,
    ports: [
      { port: 22,  service: 'SSH',   status: 'Open'     },
      { port: 80,  service: 'HTTP',  status: 'Filtered' },
      { port: 443, service: 'HTTPS', status: 'Closed'   },
    ],
  };

  // (opcional) também adiciona à lista de scans recentes
  state.scans.push({ id: uid(), target: state.lastResult.target, profile: 'quick', status:'Completed', createdAt: now() });

  setActiveView('scans');
}
qs('#newscan-form')?.addEventListener('submit', startDemoScan);
nsStartI?.addEventListener('click', startDemoScan);

/* ====== IP LIST ====== */
qs('#ip-add')?.addEventListener('click', ()=>{
  const v = qs('#ip-input').value.trim();
  if(!v) return;
  if(!state.ips.includes(v)) state.ips.push(v);
  qs('#ip-input').value = '';
  renderIPs();
});
qs('#ip-list')?.addEventListener('click',(e)=>{
  const ipToScan   = e.target.getAttribute('data-scan-ip');
  const ipToRemove = e.target.getAttribute('data-remove-ip');
  if(ipToScan){
    setActiveView('newscan');
    if(nsTarget){ nsTarget.value = ipToScan; updateNSButtons(); }
  }
  if(ipToRemove){
    state.ips = state.ips.filter(ip => ip!==ipToRemove);
    renderIPs();
  }
});
function renderIPs(){
  const list = qs('#ip-list');
  if(!list) return;
  if(state.ips.length===0){ list.innerHTML = `<div class="item" style="color:#666">No IPs saved yet.</div>`; return; }
  list.innerHTML = state.ips.map(ip => `
    <div class="item">
      <span>${ip}</span>
      <div class="actions">
        <button class="btn-secondary" data-scan-ip="${ip}">Scan</button>
        <button class="btn-secondary" data-remove-ip="${ip}">Remove</button>
      </div>
    </div>`).join('');
}

/* ====== SCAN RESULTS VIEW ====== */
function renderScanResults(data){
  // se não houver dados, usa o DEMO do mock
  if(!data){
    data = {
      target:'scanme.nmap.org', scanType:'Quick Scan',
      activeHosts:5, openPorts:{open:50,total:50}, cves:15,
      ports:[
        {port:22, service:'SSH',   status:'Open'},
        {port:80, service:'HTTP',  status:'Filtered'},
        {port:443,service:'HTTPS', status:'Closed'},
      ]
    };
  }

  const wrap = qs('#view-scans');
  if(!wrap) return;

  wrap.innerHTML = `
    <div class="results-wrap">
      <div class="res-card">
        <div class="kv"><div class="label">Target</div><div class="value" id="res-target">${data.target}</div></div>
        <div class="kv"><div class="label">Scan Type</div><div class="value" id="res-type">${data.scanType}</div></div>
      </div>

      <div class="res-card">
        <div class="res-head">Summary</div>
        <div class="summary-grid">
          <div class="metric">
            <div class="num" id="m-hosts">${data.activeHosts}</div>
            <div class="label">Active Hosts</div>
          </div>

          <div class="metric gauge">
            <svg class="gauge-svg" viewBox="0 0 100 60" aria-hidden="true">
              <path class="g-track" d="M 10 50 A 40 40 0 0 1 90 50"></path>
              <path class="g-bar"  id="gbar" d="M 10 50 A 40 40 0 0 1 90 50"></path>
            </svg>
            <div class="g-value"><span id="gv-open">${data.openPorts.open}</span>/<span id="gv-total">${data.openPorts.total}</span></div>
            <div class="label">Open Ports</div>
          </div>

          <div class="metric">
            <div class="num" id="m-cves">${data.cves}</div>
            <div class="label">CVE's</div>
          </div>
        </div>
      </div>

      <div class="res-card">
        <div class="res-table">
          <div class="host-select">
            <label for="hostSel">Host</label>
            <select id="hostSel"><option>Host 1 ▾</option></select>
          </div>
          <table class="simple">
            <thead><tr><th>Port</th><th>Service</th><th>Status</th></tr></thead>
            <tbody id="portsBody"></tbody>
          </table>
        </div>
      </div>
    </div>
  `;

  // preencher tabela
  const tbody = qs('#portsBody');
  tbody.innerHTML = data.ports.map(p=>{
    const cls = p.status==='Open' ? 'status-open' : p.status==='Filtered' ? 'status-filtered' : 'status-closed';
    return `<tr><td>${p.port}</td><td>${p.service}</td><td class="${cls}">${p.status}</td></tr>`;
  }).join('');

  // desenhar gauge (semicírculo)
  const L = 126; // ~ π * R (R=40) — comprimento do arco
  const pct = Math.max(0, Math.min(1, data.openPorts.open / Math.max(1, data.openPorts.total)));
  const gbar = qs('#gbar');
  gbar.setAttribute('stroke-dasharray', `${L*pct} ${L*(1-pct)}`);
}

/* ====== USER MENU ====== */
const btnUser = qs('#btn-user');
const menuUser = qs('#menu-user');
btnUser?.addEventListener('click', ()=>{
  const open = menuUser.getAttribute('aria-hidden') === 'false';
  menuUser.setAttribute('aria-hidden', open ? 'true' : 'false');
  btnUser.setAttribute('aria-expanded', open ? 'false' : 'true');
});
menuUser?.addEventListener('click', (e)=>{
  if(e.target.matches('.menu-item')){
    const action = e.target.dataset.action;
    alert(action === 'settings' ? 'Open settings (demo)' : 'Logged out (demo)');
    menuUser.setAttribute('aria-hidden','true');
    btnUser.setAttribute('aria-expanded','false');
  }
});
document.addEventListener('click',(e)=>{
  if(!menuUser?.contains(e.target) && !btnUser?.contains(e.target)){
    menuUser?.setAttribute('aria-hidden','true');
    btnUser?.setAttribute('aria-expanded','false');
  }
});

/* ====== INIT ====== */
renderIPs();
setActiveView('home');
