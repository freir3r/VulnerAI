// ==== LocalStorage keys ====
const K_TARGETS = "vulnerai.targets";
const K_SCANS   = "vulnerai.scans";
const K_PREFS   = "vulnerai.prefs"; // todas as prefs guardadas aqui

// ==== helpers ====
const $ = (s, el=document)=> el.querySelector(s);

function loadJSON(key, fallback){
  try{ return JSON.parse(localStorage.getItem(key) || JSON.stringify(fallback)); }
  catch{ return fallback; }
}
function saveJSON(key, val){ localStorage.setItem(key, JSON.stringify(val)); }

function applyTheme(isDark){
  document.body.classList.toggle('dark', !!isDark);
}

// ==== carregar prefs na UI ====
function hydrate(){
  const prefs = loadJSON(K_PREFS, {
    name:"", email:"", org:"",
    themeDarkHeader:true,          // representa “Dark Mode”
    sidebarCollapsedDefault:false,
    scanType:"quick",
    scanProto:"TCP",
    autoAcceptTos:false,
    telemetry:false
  });

  $("#set-name").value  = prefs.name || "";
  $("#set-email").value = prefs.email || "";
  $("#set-org").value   = prefs.org || "";

  // Dark mode
  $("#set-theme").checked = !!prefs.themeDarkHeader;
  applyTheme(!!prefs.themeDarkHeader);

  $("#set-sidebar-collapsed").checked = !!prefs.sidebarCollapsedDefault;

  $("#set-scan-type").value  = prefs.scanType || "quick";
  $("#set-scan-proto").value = prefs.scanProto || "TCP";
  $("#set-auto-accept-tos").checked = !!prefs.autoAcceptTos;

  $("#set-telemetry").checked = !!prefs.telemetry;

  // Ligar/desligar dark em tempo real no settings
  $("#set-theme").addEventListener("change", (e)=>{
    applyTheme(e.target.checked);
  });
}

// ==== recolher e guardar prefs ====
function collectPrefs(){
  return {
    name: $("#set-name").value.trim(),
    email: $("#set-email").value.trim(),
    org: $("#set-org").value,

    themeDarkHeader: $("#set-theme").checked,  // ← dark mode
    sidebarCollapsedDefault: $("#set-sidebar-collapsed").checked,

    scanType: $("#set-scan-type").value,
    scanProto: $("#set-scan-proto").value,
    autoAcceptTos: $("#set-auto-accept-tos").checked,

    telemetry: $("#set-telemetry").checked
  };
}

function save(){
  const prefs = collectPrefs();

  // guarda prefs completas
  saveJSON(K_PREFS, prefs);

  // atalho de tema (facilita leitura no Dashboard e dispara storage event)
  localStorage.setItem("vulnerai.theme", prefs.themeDarkHeader ? "dark" : "light");

  // aplica colapso por defeito (mesma flag que o dashboard usa)
  localStorage.setItem("vulnerai.sidebarCollapsed", prefs.sidebarCollapsedDefault ? "1" : "0");

  alert("Settings saved.");
  // voltar ao dashboard
  location.href = "dashboard.html";
}

// ==== export/import/clear ====
function exportData(){
  const data = {
    prefs: loadJSON(K_PREFS, {}),
    targets: loadJSON(K_TARGETS, []),
    scans: loadJSON(K_SCANS, []),
    exportedAt: new Date().toISOString()
  };
  const blob = new Blob([JSON.stringify(data, null, 2)], {type:"application/json"});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "vulnerai-export.json";
  a.click();
  URL.revokeObjectURL(url);
}

function importData(file){
  const reader = new FileReader();
  reader.onload = () => {
    try{
      const obj = JSON.parse(reader.result);
      if(obj.targets) saveJSON(K_TARGETS, obj.targets);
      if(obj.scans)   saveJSON(K_SCANS, obj.scans);
      if(obj.prefs)   saveJSON(K_PREFS, obj.prefs);

      // sincroniza atalho de tema se vier do ficheiro
      if(obj?.prefs?.themeDarkHeader !== undefined){
        localStorage.setItem("vulnerai.theme", obj.prefs.themeDarkHeader ? "dark" : "light");
        applyTheme(!!obj.prefs.themeDarkHeader);
      }

      alert("Import completed.");
      hydrate();
    }catch(e){
      alert("Invalid JSON.");
    }
  };
  reader.readAsText(file);
}

function clearData(){
  if(!confirm("Clear local targets, scans and preferences?")) return;
  localStorage.removeItem(K_TARGETS);
  localStorage.removeItem(K_SCANS);
  localStorage.removeItem(K_PREFS);
  localStorage.removeItem("vulnerai.theme");
  alert("Local data cleared.");
  hydrate();
}

// ==== boot ====
document.addEventListener("DOMContentLoaded", ()=>{
  hydrate();

  $("#btn-save")  .addEventListener("click", save);
  $("#btn-export").addEventListener("click", exportData);
  $("#btn-clear") .addEventListener("click", clearData);
  $("#file-import").addEventListener("change", (e)=>{
    const f = e.target.files?.[0];
    if(f) importData(f);
    e.target.value = "";
  });
});
