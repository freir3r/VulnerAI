// ==== Chaves do LocalStorage ====
const K_USER = "vulnerai.user";   // Perfil (Nome, Email, Org)
const K_PREFS = "vulnerai.prefs";  // Configurações (Tema, Sidebar, Scan Defaults)
const K_TARGETS = "vulnerai.targets";
const K_SCANS = "vulnerai.scans";

// ==== Helpers ====
const $ = (s) => document.querySelector(s);

function loadJSON(key, fallback) {
  try {
    const data = localStorage.getItem(key);
    return data ? JSON.parse(data) : fallback;
  } catch (e) {
    return fallback;
  }
}

function saveJSON(key, val) {
  localStorage.setItem(key, JSON.stringify(val));
}

function applyTheme(isDark) {
  if (isDark) {
    document.body.classList.add('dark');
  } else {
    document.body.classList.remove('dark');
  }
}

// ==== 1. Carregar Dados na UI (Hydrate) ====
function hydrate() {
  // A. Carregar Perfil do Utilizador
  const user = loadJSON(K_USER, {
    displayName: "",
    email: "",
    organization: ""
  });

  if ($("#set-name")) $("#set-name").value = user.displayName || "";
  if ($("#set-email")) $("#set-email").value = user.email || "";
  if ($("#set-org")) $("#set-org").value = user.organization || "";

  // B. Carregar Preferências da App
  const prefs = loadJSON(K_PREFS, {
    theme: "light", // 'dark' ou 'light'
    sidebarCollapsed: false,
    defaultScanType: "quick",
    defaultProtocol: "TCP",
    autoAcceptTos: false,
    telemetry: false
  });

  // Tema
  const isDark = prefs.theme === 'dark';
  if ($("#set-theme")) {
    $("#set-theme").checked = isDark;
    // Listener para preview imediato
    $("#set-theme").addEventListener("change", (e) => applyTheme(e.target.checked));
  }
  applyTheme(isDark);

  // Sidebar
  if ($("#set-sidebar-collapsed")) $("#set-sidebar-collapsed").checked = !!prefs.sidebarCollapsed;

  // Defaults de Scan
  if ($("#set-scan-type")) $("#set-scan-type").value = prefs.defaultScanType || "quick";
  if ($("#set-scan-proto")) $("#set-scan-proto").value = prefs.defaultProtocol || "TCP";
  if ($("#set-auto-accept-tos")) $("#set-auto-accept-tos").checked = !!prefs.autoAcceptTos;

  // Privacidade
  if ($("#set-telemetry")) $("#set-telemetry").checked = !!prefs.telemetry;
}

// ==== 2. Recolher e Guardar Dados ====
function save() {
  // A. Guardar Perfil
  const user = {
    displayName: $("#set-name").value.trim(),
    email: $("#set-email").value.trim(),
    organization: $("#set-org").value
  };
  saveJSON(K_USER, user);

  // B. Guardar Preferências
  const isDark = $("#set-theme").checked;
  const prefs = {
    theme: isDark ? 'dark' : 'light',
    sidebarCollapsed: $("#set-sidebar-collapsed").checked,
    defaultScanType: $("#set-scan-type").value,
    defaultProtocol: $("#set-scan-proto").value,
    autoAcceptTos: $("#set-auto-accept-tos").checked,
    telemetry: $("#set-telemetry").checked
  };
  saveJSON(K_PREFS, prefs);

  // Feedback Visual (Melhor que alert)
  const btn = $("#btn-save");
  const originalText = btn.innerText;
  btn.innerText = "Saved!";
  btn.style.backgroundColor = "#10b981"; // Verde sucesso

  setTimeout(() => {
    btn.innerText = originalText;
    btn.style.backgroundColor = "";
    // Opcional: Redirecionar após salvar
    // location.href = "index.html"; 
  }, 1000);

  console.log("Settings saved successfully.");
}

// ==== 3. Exportar/Importar/Limpar ====
function exportData() {
  const data = {
    user: loadJSON(K_USER, {}),
    prefs: loadJSON(K_PREFS, {}),
    targets: loadJSON(K_TARGETS, []),
    scans: loadJSON(K_SCANS, []),
    exportedAt: new Date().toISOString()
  };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `vulnerai-backup-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function importData(file) {
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const obj = JSON.parse(reader.result);
      if (obj.user) saveJSON(K_USER, obj.user);
      if (obj.prefs) saveJSON(K_PREFS, obj.prefs);
      if (obj.targets) saveJSON(K_TARGETS, obj.targets);
      if (obj.scans) saveJSON(K_SCANS, obj.scans);

      alert("Import completed successfully.");
      hydrate(); // Recarregar ecrã
    } catch (e) {
      alert("Error: Invalid JSON file.");
    }
  };
  reader.readAsText(file);
}

function clearData() {
  if (!confirm("⚠️ Are you sure? This will delete all your local targets, scan history, and settings.")) return;

  localStorage.removeItem(K_USER);
  localStorage.removeItem(K_PREFS);
  localStorage.removeItem(K_TARGETS);
  localStorage.removeItem(K_SCANS);

  alert("All local data cleared.");
  hydrate(); // Limpa os campos no ecrã
}

// ==== 4. Inicialização ====
document.addEventListener("DOMContentLoaded", () => {
  hydrate();

  // Event Listeners
  if ($("#btn-save")) $("#btn-save").addEventListener("click", save);
  if ($("#btn-export")) $("#btn-export").addEventListener("click", exportData);
  if ($("#btn-clear")) $("#btn-clear").addEventListener("click", clearData);

  if ($("#file-import")) {
    $("#file-import").addEventListener("change", (e) => {
      const f = e.target.files?.[0];
      if (f) importData(f);
      e.target.value = ""; // Reset para permitir importar o mesmo ficheiro de novo
    });
  }
});