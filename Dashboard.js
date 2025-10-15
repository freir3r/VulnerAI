/* ====== Dashboard.js ====== */

/* ====== STATE ====== */
const state = {
  targets: [],     // {id, kind, name, value, addedAt, scans, cves, lastScan, tags:[], risk}
  scans: [],
  lastResult: null
};

/* ====== HELPERS ====== */
const qs  = (s, el=document)=> el.querySelector(s);
const qsa = (s, el=document)=> [...el.querySelectorAll(s)];
const uid = ()=> Math.random().toString(36).slice(2,9);

/* ====== PERSISTENCE (targets/scans) ====== */
const LS_KEY   = "vulnerai.targets";
const LS_SCANS = "vulnerai.scans";

function loadTargets(){
  try{ state.targets = JSON.parse(localStorage.getItem(LS_KEY)||"[]"); }
  catch(_){ state.targets = []; }
}
function saveTargets(){
  localStorage.setItem(LS_KEY, JSON.stringify(state.targets));
}
function loadScans(){ try { return JSON.parse(localStorage.getItem(LS_SCANS)||"[]"); } catch { return []; } }
function saveScans(arr){ localStorage.setItem(LS_SCANS, JSON.stringify(arr)); }

/* ====== VALIDATION ====== */
const reIPv4   = /^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/;
const reCIDR   = /^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}\/([0-9]|[12][0-9]|3[0-2])$/;
const reHost   = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$/;

function isValidHostOrIPorCIDR(s){
  if(!s) return false;
  const v = s.trim();
  return reIPv4.test(v) || reCIDR.test(v) || reHost.test(v);
}

/* ====== VIEW SWITCHING ====== */
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
    renderScanResultsPage();
  }
}

/* ====== IP LIST RENDER ====== */
function escapeHtml(s){
  return String(s).replace(/[&<>"']/g, m=>({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[m]));
}

function renderTargets(){
  const wrap = qs("#targets-list");
  const empty = qs("#targets-empty");
  const count = qs("#targets-count");
  if(!wrap || !empty || !count) return;

  const term = (qs("#tgt-search")?.value || "").toLowerCase().trim();
  let list = state.targets.filter(t =>
    !term || t.name.toLowerCase().includes(term) || t.value.toLowerCase().includes(term)
  );

  const sort = qs("#tgt-sort")?.value || "recent";
  list.sort((a,b)=>{
    if(sort==="name") return a.name.localeCompare(b.name);
    if(sort==="scans") return (b.scans||0) - (a.scans||0);
    if(sort==="cves")  return (b.cves||0)  - (a.cves||0);
    return (b.addedAt||0) - (a.addedAt||0);
  });

  count.textContent = `${state.targets.length} saved`;
  empty.style.display = state.targets.length ? "none" : "block";

  wrap.innerHTML = "";
  list.forEach(t=>{
    const art = document.createElement("article");
    art.className = "target-card";
    art.dataset.kind = t.kind;

    art.innerHTML = `
      <label class="sel"><input type="checkbox" data-id="${t.id}" /></label>
      <div class="tgt-main">
        <div class="tgt-line">
          <span class="tgt-name">${escapeHtml(t.name)}</span>
          <span class="badge kind">${t.kind==="network" ? "Network" : "Host"}</span>
          ${t.risk ? `<span class="chip ${t.risk==='Low'?'chip-green':''}">${escapeHtml(t.risk)} risk</span>` : ""}
        </div>
        <div class="tgt-sub muted">${escapeHtml(t.value)} • Added: ${new Date(t.addedAt).toISOString().slice(0,10)}</div>
      </div>

      <div class="tgt-stats">
        <div class="stat"><span class="num">${t.scans ?? 0}</span><span class="lbl">Scans</span></div>
        <div class="stat"><span class="num">${t.cves  ?? 0}</span><span class="lbl">Unique CVEs</span></div>
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
  if(bulk){
    const any = list.length > 0;
    bulk.setAttribute("aria-hidden", any ? "false" : "true");
    qs("#tgt-selected")?.replaceChildren(document.createTextNode("0 selected"));
    const allChk = qs("#tgt-checkall");
    if(allChk) allChk.checked = false;
  }

  populateSavedTargetsDropdown();
}

function selectedTargetIds(){
  return qsa('#targets-list input[type="checkbox"]:checked').map(c=> c.dataset.id);
}
function updateBulkCount(){
  const n = selectedTargetIds().length;
  qs("#tgt-selected")?.replaceChildren(document.createTextNode(`${n} selected`));
}

/* ====== NEW SCAN DROPDOWN ====== */
function populateSavedTargetsDropdown(){
  const sel = qs("#ns-choose");
  if(!sel) return;
  const current = sel.value;
  sel.innerHTML = `<option value="">Choose from saved targets…</option>`;
  state.targets.forEach(t=>{
    const opt = document.createElement("option");
    opt.value = t.id;
    opt.textContent = `${t.name} — ${t.value}`;
    sel.appendChild(opt);
  });
  if(current && state.targets.some(t=>t.id===current)){
    sel.value = current;
  }
}

/* ====== DEMO DATA: Ports & CVEs ====== */
function simulateOpenPorts(proto){
  const commonTCP = [22, 80, 443, 8080, 3306, 5432, 6379];
  const commonUDP = [53, 123, 161];
  const pool = proto === "UDP" ? commonUDP : commonTCP;
  const n = Math.floor(Math.random()*4); // 0..3
  const shuffled = [...pool].sort(()=>Math.random()-0.5);
  return shuffled.slice(0, n);
}
function simulateCVEs(openPorts){
  const sampleScores = [0.0, 0.1, 0.7, 1.0, 2.8, 3.6, 5.4, 6.8, 7.2, 8.1, 9.8];
  const n = Math.max(0, (openPorts?.length || 0) + Math.floor(Math.random()*3) - 1);
  const picks = [];
  const used = new Set();
  while(picks.length < n){
    const idx = Math.floor(Math.random()*sampleScores.length);
    if(used.has(idx)) continue;
    used.add(idx);
    const score = sampleScores[idx];
    const year = 2015 + Math.floor(Math.random()*10);
    const num  = String(1000 + Math.floor(Math.random()*9000));
    picks.push({
      id: `CVE-${year}-${num}`,
      title: `Demo vulnerability on port ${openPorts[Math.floor(Math.random()*(openPorts.length||1))] ?? '—'}`,
      cvss: score,
      severity: cvssToSeverity(score)
    });
  }
  return picks;
}
function cvssToSeverity(score){
  if(score <= 1.0) return "TRIVIAL";
  if(score < 4.0)  return "LOW";
  if(score < 7.0)  return "MEDIUM";
  if(score < 9.0)  return "HIGH";
  return "CRITICAL";
}

/* ====== CREATE A SCAN (demo) ====== */
function addScan({targetValue, targetId=null, type="quick", proto="TCP"}){
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
    cves: cveList.length
  };
  scans.unshift(scan);
  saveScans(scans);

  if (targetId && state.targets?.length){
    const t = state.targets.find(x=>x.id===targetId);
    if(t){
      t.scans = (t.scans||0)+1;
      t.cves  = Math.max(t.cves||0, scan.cves);
      t.lastScan = "now";
      saveTargets();
      renderTargets();
    }
  }
  return scan;
}

/* ====== SCANS PAGE RENDER ====== */
function getLastScanForUI(){
  try{ const scans = loadScans(); return scans[0] || null; } catch { return null; }
}
function drawGauge(percent){
  const path = document.getElementById("g-bar");
  if(!path) return;
  const totalLen = 157;
  const val = Math.max(0, Math.min(1, percent)) * totalLen;
  path.setAttribute("stroke-dasharray", `${val} ${totalLen-val}`);
  path.setAttribute("stroke-dashoffset", "0");
}
function statusClass(s){
  return s==="open" ? "status-open" : s==="filtered" ? "status-filtered" : "status-closed";
}

function renderScanResultsPage(){
  const last = getLastScanForUI();
  const fallback = {
    targetValue: "scanme.nmap.org",
    type: "quick",
    activeHosts: 1,
    openPorts: 3,
    totalPorts: 50,
    cves: 3,
    hosts: [{
      id:"host1", name:"Host 1",
      ports: [
        {port:22,  service:"SSH",   status:"open"},
        {port:80,  service:"HTTP",  status:"filtered"},
        {port:443, service:"HTTPS", status:"closed"},
      ]
    }],
    cveList: [
      {id:"CVE-2020-1001", title:"Example issue A", cvss:0.1, severity:"TRIVIAL"},
      {id:"CVE-2021-2222", title:"Example issue B", cvss:5.4, severity:"MEDIUM"},
      {id:"CVE-2019-3333", title:"Example issue C", cvss:8.1, severity:"HIGH"},
    ]
  };

  let model;
  if(last){
    const open = last.openPorts?.length ?? 0;
    model = {
      targetValue: last.targetValue,
      type: last.type==="deep" ? "deep" : "quick",
      activeHosts: 1,
      openPorts: open,
      totalPorts: 50,
      cves: (last.cveList?.length ?? 0),
      hosts: [{
        id:"host1", name:"Host 1",
        ports: (open ? last.openPorts.map(p=>{
          if(p===22) return {port:22,service:"SSH",status:"open"};
          if(p===80) return {port:80,service:"HTTP",status:"filtered"};
          if(p===443) return {port:443,service:"HTTPS",status:"closed"};
          return {port:p,service:"",status:"open"};
        }) : [
          {port:22,service:"SSH",status:"open"},
          {port:80,service:"HTTP",status:"filtered"},
          {port:443,service:"HTTPS",status:"closed"},
        ])
      }],
      cveList: last.cveList ?? []
    };
  } else {
    model = fallback;
  }

  // resumo
  qs("#sr-target").textContent = model.targetValue;
  qs("#sr-type").textContent   = (model.type==="deep" ? "Deep Scan" : "Quick Scan");
  qs("#sr-active-hosts").textContent = model.activeHosts;
  qs("#sr-cves").textContent         = model.cves;
  qs("#sr-ports-text").textContent   = `${model.openPorts}/${model.totalPorts}`;
  drawGauge(model.totalPorts ? model.openPorts/model.totalPorts : 0);

  // hosts + tabela de portas
  const sel = qs("#sr-host");
  if(sel){
    sel.innerHTML = "";
    model.hosts.forEach((h,i)=>{
      const opt = document.createElement("option");
      opt.value = h.id;
      opt.textContent = h.name || `Host ${i+1}`;
      sel.appendChild(opt);
    });
    sel.onchange = ()=> fillPortsTable(model.hosts.find(h=>h.id===sel.value) || model.hosts[0]);
  }
  fillPortsTable(model.hosts[0]);

  // CVEs (usar sempre a tabela existente no HTML)
  renderCVETable(model.cveList);

  // manter label do botão coerente
  updateClearButtonLabel();
}

function fillPortsTable(host){
  const tb = qs("#sr-table tbody");
  if(!tb) return;
  tb.innerHTML = (host?.ports||[]).map(r=>{
    const cls = statusClass(r.status);
    const txt = r.status.charAt(0).toUpperCase()+r.status.slice(1);
    return `<tr>
      <td>${r.port}</td>
      <td>${r.service||""}</td>
      <td><span class="${cls}">${txt}</span></td>
    </tr>`;
  }).join("");
}

/* ====== CVE TABLE RENDER ====== */
function renderCVETable(cves){
  const tb = qs("#sr-cves-table tbody");
  if(!tb) return;
  const rows = (cves||[]).map(v=>{
    const sev = (v.severity || cvssToSeverity(v.cvss||0)).toUpperCase();
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
  if(counter) counter.textContent = cves?.length ?? 0;
}

/* ====== CLEAR BUTTON: threshold & label ====== */
function updateClearButtonLabel(){
  const btn = qs("#btn-clear-trivial");
  if(!btn) return;
  const THRESH = parseFloat(localStorage.getItem("vulnerai.clearThreshold") || "4.0");
  if(THRESH <= 1.0){
    btn.textContent = "Clear Trivial CVEs (CVSS ≤ 1.0)";
    btn.title = "Remove CVEs with CVSS ≤ 1.0";
  }else{
    btn.textContent = `Clear Low & Trivial (CVSS < ${THRESH})`;
    btn.title = `Remove CVEs with CVSS < ${THRESH}`;
  }
}
function cycleClearThreshold(){
  const current = parseFloat(localStorage.getItem("vulnerai.clearThreshold") || "4.0");
  const next = current <= 1.0 ? 4.0 : 1.0;
  localStorage.setItem("vulnerai.clearThreshold", String(next));
  updateClearButtonLabel();
}

/* ====== CLEAR ACTION ====== */
function handleClearTrivial(){
  const scans = loadScans();
  if(!scans.length){ alert("No scans to clean."); return; }

  const THRESH = parseFloat(localStorage.getItem("vulnerai.clearThreshold") || "4.0");

  const last = scans[0];
  if(!Array.isArray(last.cveList)) last.cveList = [];

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
function init(){
  // ---- PREFERÊNCIAS ----
  const prefs = (()=>{ try{return JSON.parse(localStorage.getItem("vulnerai.prefs")||"{}");}catch{return{}} })();

  // DARK MODE
  const themeQuick = localStorage.getItem("vulnerai.theme");
  const isDark = themeQuick ? (themeQuick === "dark") : !!prefs.themeDarkHeader;
  document.body.classList.toggle("dark", isDark);
  window.addEventListener("storage", (e)=>{
    if(e.key === "vulnerai.prefs" || e.key === "vulnerai.theme"){
      try{
        const quick = localStorage.getItem("vulnerai.theme");
        const p = JSON.parse(localStorage.getItem("vulnerai.prefs")||"{}");
        document.body.classList.toggle("dark", quick ? (quick==="dark") : !!p.themeDarkHeader);
      }catch(_){}
    }
  });

  // Threshold default (LOW+TRIVIAL)
  if(localStorage.getItem("vulnerai.clearThreshold") == null){
    localStorage.setItem("vulnerai.clearThreshold", "4.0");
  }

  loadTargets();
  renderTargets();
  populateSavedTargetsDropdown();

  /* NAV & VIEWS */
  qsa(".nav-item").forEach(btn=>{
    btn.addEventListener("click", ()=> setActiveView(btn.dataset.view));
  });
  qs("#btn-new-scan")?.addEventListener("click", ()=> setActiveView("newscan"));
  qs("#cta-new-scan")?.addEventListener("click", ()=> setActiveView("newscan"));

  /* SIDEBAR */
  const sidebar = qs("#sidebar");
  const burger  = qs("#btn-burger");
  if(localStorage.getItem("vulnerai.sidebarCollapsed") == null){
    localStorage.setItem("vulnerai.sidebarCollapsed", prefs.sidebarCollapsedDefault ? "1" : "0");
  }
  const SAVED = localStorage.getItem("vulnerai.sidebarCollapsed")==="1";
  if(SAVED) sidebar?.classList.add("collapsed");
  burger?.addEventListener("click", (e)=>{
    e.stopPropagation();
    sidebar?.classList.toggle("collapsed");
    const collapsed = sidebar?.classList.contains("collapsed");
    localStorage.setItem("vulnerai.sidebarCollapsed", collapsed ? "1" : "0");
  });

  /* USER MENU */
  const userBtn = qs("#btn-user");
  const userMenu = qs("#menu-user");
  function closeUserMenu(){ userBtn?.setAttribute("aria-expanded","false"); userMenu?.setAttribute("aria-hidden","true"); }
  function openUserMenu(){  userBtn?.setAttribute("aria-expanded","true");  userMenu?.setAttribute("aria-hidden","false"); }
  userBtn?.addEventListener("click", (e)=>{
    e.stopPropagation();
    const isOpen = userMenu?.getAttribute("aria-hidden")==="false";
    if(isOpen) closeUserMenu(); else openUserMenu();
  });
  document.addEventListener("click", (e)=>{
    const clickedInside = userMenu?.contains(e.target) || userBtn?.contains(e.target);
    if(!clickedInside) closeUserMenu();
  });
  document.addEventListener("keydown", (e)=>{ if(e.key==="Escape") closeUserMenu(); });
  userMenu?.addEventListener("click", (e)=>{
    const item = e.target.closest(".menu-item");
    if(!item) return;
    const action = item.dataset.action;
    closeUserMenu();
    if(action==="settings"){ window.location.href = "settings.html"; }
    if(action==="logout"){ alert("Logout (demo)"); }
  });

  /* PREMIUM MODAL */
  const premiumBtn = qs("#btn-premium");
  const premiumModal = qs("#modal-premium");
  const closePremium = ()=> premiumModal?.setAttribute("aria-hidden","true");
  const openPremium  = ()=> premiumModal?.setAttribute("aria-hidden","false");
  premiumBtn?.addEventListener("click", (e)=>{ e.stopPropagation(); openPremium(); });
  premiumModal?.addEventListener("click", (e)=>{
    if(e.target.hasAttribute("data-close") || e.target.classList.contains("close") || e.target.classList.contains("backdrop")){
      closePremium();
    }
  });
  document.addEventListener("keydown", (e)=>{ if(e.key==='Escape') closePremium(); });

  /* IP LIST MODAL + FORM */
  const iplistModal = qs("#iplist-modal");
  const btnOpenAdd  = qs("#iplist-open-add");
  const iplistForm  = qs("#iplist-form");

  btnOpenAdd?.addEventListener("click", ()=> iplistModal?.setAttribute("aria-hidden","false"));
  iplistModal?.addEventListener("click", (e)=>{
    if(e.target.hasAttribute("data-close") || e.target.classList.contains("iplist-close") || e.target.classList.contains("iplist-backdrop")){
      iplistModal.setAttribute("aria-hidden","true");
    }
  });

  iplistForm?.addEventListener("submit", (e)=>{
    e.preventDefault();
    const name  = qs("#iplist-name").value.trim();
    const kind  = qs("#iplist-kind").value;
    const value = qs("#iplist-value").value.trim();

    if(!name){ alert("Please enter a Name/Title."); return; }
    if(!isValidHostOrIPorCIDR(value)){ alert("Please enter a valid Host/IP, domain, or CIDR."); return; }

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
    iplistModal.setAttribute("aria-hidden","true");
  });

  /* Search & Sort */
  qs("#tgt-search")?.addEventListener("input", renderTargets);
  qs("#tgt-sort")?.addEventListener("change", renderTargets);

  /* Bulk controls */
  qs("#tgt-checkall")?.addEventListener("change", (e)=>{
    qsa('#targets-list input[type="checkbox"]').forEach(c=> c.checked = e.target.checked);
    updateBulkCount();
  });
  qs("#targets-list")?.addEventListener("change", (e)=>{
    if(e.target.type==="checkbox") updateBulkCount();
  });
  qs("#tgt-bulk-delete")?.addEventListener("click", ()=>{
    const ids = selectedTargetIds();
    if(!ids.length) return;
    if(confirm(`Delete ${ids.length} selected target(s)?`)){
      state.targets = state.targets.filter(t=> !ids.includes(t.id));
      saveTargets(); renderTargets();
    }
  });
  qs("#tgt-bulk-scan")?.addEventListener("click", ()=>{
    const ids = selectedTargetIds();
    if(!ids.length) return;
    setActiveView("newscan");
    if(ids.length===1){
      const t = state.targets.find(x=>x.id===ids[0]);
      if(t){
        const inp = qs("#ns-target"); if(inp) inp.value = t.value;
        const sel = qs("#ns-choose"); if(sel) sel.value = t.id;
      }
    }
  });
  qs("#tgt-bulk-tags")?.addEventListener("click", ()=> alert("Tagging not implemented in this demo."));

  /* IP List actions (delegation) */
  qs("#view-iplist")?.addEventListener("click",(e)=>{
    const btn = e.target.closest("button[data-action]");
    if(!btn) return;
    const id = btn.dataset.id;
    if(btn.dataset.action === "delete"){
      state.targets = state.targets.filter(t=> t.id !== id);
      saveTargets(); renderTargets();
      return;
    }
    if(btn.dataset.action === "start-scan"){
      const t = state.targets.find(x=>x.id===id);
      if(t){
        setActiveView("newscan");
        const inp = qs("#ns-target"); if(inp) inp.value = t.value;
        const sel = qs("#ns-choose"); if(sel) sel.value = t.id;
      }
      return;
    }
    if(btn.dataset.action === "view-scans"){
      setActiveView("scans");
      return;
    }
  });

  /* NEW SCAN enable/start */
  const tos = qs("#ns-tos");
  const targetInp = qs("#ns-target");
  const startBtn = qs("#ns-start");
  const chooseSel = qs("#ns-choose");

  function updateStartEnabled(){
    const hasTarget = (targetInp?.value.trim() || chooseSel?.value);
    const ok = !!(tos?.checked && hasTarget);
    if(startBtn) startBtn.disabled = !ok;
  }
  tos?.addEventListener("change", updateStartEnabled);
  targetInp?.addEventListener("input", updateStartEnabled);
  chooseSel?.addEventListener("change", ()=>{
    const id = chooseSel.value;
    const t = state.targets.find(x=>x.id===id);
    if(targetInp) targetInp.value = t ? t.value : "";
    updateStartEnabled();
  });

  // defaults de scan vindos das prefs
  (function applyScanDefaults(){
    const type  = prefs.scanType  || "quick";
    const proto = prefs.scanProto || "TCP";
    const rType  = document.querySelector(`input[name="ns-type"][value="${type}"]`);
    const rProto = document.querySelector(`input[name="ns-proto"][value="${proto}"]`);
    if(rType)  rType.checked = true;
    if(rProto) rProto.checked = true;
    if(prefs.autoAcceptTos && tos){ tos.checked = true; }
    updateStartEnabled();
  })();

  updateStartEnabled();

  qs("#newscan-form")?.addEventListener("submit", (e)=>{
    e.preventDefault();
    if(!tos?.checked) return alert("Please accept the Terms first.");

    const type  = (qs('input[name="ns-type"]:checked')?.value)  || "quick";
    const proto = (qs('input[name="ns-proto"]:checked')?.value) || "TCP";

    let finalValue = (targetInp?.value || "").trim();
    const chosenId = chooseSel?.value || null;

    if(!finalValue && chosenId){
      const t = state.targets.find(x=>x.id===chosenId);
      finalValue = t?.value || "";
    }
    if(!finalValue) return alert("Please choose or type a target.");

    addScan({ targetValue: finalValue, targetId: chooseSel?.value || null, type, proto });
    setActiveView("scans");
    alert("Scan created (demo).");
  });

  /* Scans controls */
  const btnRefresh = qs("#scan-refresh");
  if(btnRefresh){
    btnRefresh.addEventListener("click", (e)=>{
      e.preventDefault();
      renderScanResultsPage();
    });
  }
  qs("#sr-host")?.addEventListener("change", ()=> renderScanResultsPage());

  // inicializar label do clear
  updateClearButtonLabel();
}

/* ====== EVENT DELEGATION ====== */
document.addEventListener("click", (e)=>{
  const btn = e.target.closest("#btn-clear-trivial");
  if(btn){
    e.preventDefault();
    handleClearTrivial();
  }
});
// duplo-clique no botão para alternar threshold 1.0 ↔ 4.0
document.addEventListener("dblclick", (e)=>{
  const btn = e.target.closest("#btn-clear-trivial");
  if(btn){
    e.preventDefault();
    cycleClearThreshold();
  }
});

/* ====== BOOT ====== */
document.addEventListener("DOMContentLoaded", init);
