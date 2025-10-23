// Main API server for Nmap scan management (adapted for new Firestore model)

const express = require('express');
const bodyParser = require('body-parser');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { v4: uuidv4 } = require('uuid');
const admin = require('firebase-admin');
const xml2js = require('xml2js');

const PORT = process.env.PORT || 3000;

// --- Firebase Initialization ---
const serviceAccount = require('./keys/firebase-sa.json');
try {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET || undefined
  });
} catch (e) {
  console.error('Firebase init note:', e.message || e);
}

const db = admin.firestore();
const bucket = process.env.FIREBASE_STORAGE_BUCKET ? admin.storage().bucket(process.env.FIREBASE_STORAGE_BUCKET) : null;

// --- Firestore Helper Functions ---
function cleanFirestoreData(data, _seen = new WeakSet()) {
  const seen = _seen || new WeakSet();

  // primitives
  if (data === undefined || data === null) return '';
  if (typeof data !== 'object') return data;

  // avoid infinite recursion on circular refs
  if (seen.has(data)) return '[Circular]';
  seen.add(data);

  // Firestore DocumentReference (common shape)
  if (typeof data.path === 'string' && typeof data.id === 'string') {
    return data.path; // store as path string
  }

  // Firestore Timestamp-like objects (common .toDate())
  if (typeof data.toDate === 'function') {
    try { return data.toDate().toISOString(); } catch (e) { /* fallback */ }
  }

  // Arrays
  if (Array.isArray(data)) {
    return data.map(item =>
      (typeof item === 'object' && item !== null) ? cleanFirestoreData(item, seen) : item
    );
  }

  // Plain object - walk properties safely
  const cleaned = {};
  for (const [key, value] of Object.entries(data)) {
    try {
      if (value === undefined || value === null) {
        cleaned[key] = '';
      } else if (typeof value === 'object') {
        cleaned[key] = cleanFirestoreData(value, seen);
      } else {
        cleaned[key] = value;
      }
    } catch (e) {
      cleaned[key] = `[Unserializable: ${e.message}]`;
    }
  }
  return cleaned;
}

function safeFirestoreSet(docRef, data) {
  const cleanedData = cleanFirestoreData(data);
  return docRef.set(cleanedData);
}

function safeFirestoreUpdate(docRef, data) {
  const cleanedData = cleanFirestoreData(data);
  return docRef.update(cleanedData);
}

// --- Nmap Scan Presets ---
const PRESETS = {
  quick: {
    args: [
      '-sT', '-sV', '--version-intensity', '5', '--version-all',
      '-sC',
      '--script', 'vuln,http-enum,http-security-headers,http-title,ssh2-enum-algos,ftp-anon,banner,ssl-cert,ssl-enum-ciphers',
      '-p', '80,443,8080,8443,21,22,23,25,53,110,143,993,995,3306,3389,5432,27017',
      '-T5', '--max-retries', '1', '--host-timeout', '180s', '--script-timeout', '30s',
      '--open','--reason', '-oX', '-'
    ],
    outputFormat: 'xml',
    timeoutMs: 5 * 60 * 1000,
    description: 'Quick security check on common services (improved version & banner capture)'
  },
  deep: {
    args: [
      '-sT', '-sV', '-sC', '-A',
      '--script', 'vuln,http-enum,http-security-headers,http-title,ssh2-enum-algos,ftp-anon,banner,ssl-cert,ssl-enum-ciphers',
      '-p-', '-T4', '--min-rate', '100', '--max-retries', '1',
      '--host-timeout', '45m', '--script-timeout', '2m',
      '--open', '--reason', '-oX', '-'
    ],
    outputFormat: 'xml',
    timeoutMs: 180 * 60 * 1000,
    description: 'Comprehensive security assessment of all ports'
  },
  network_discovery: {
    args: [
      '-sn',
      '-T5', '--max-retries', '1', '--host-timeout', '30s',
      '-oX', '-'
    ],
    outputFormat: 'xml',
    timeoutMs: 120 * 1000,
    description: 'Network discovery - find active devices'
  }
};

// --- Helper Functions ---

function extractHost(input) {
  if (!input || typeof input !== 'string') throw new Error('Invalid target');
  input = input.trim();
  try {
    if (/^[a-zA-Z]+:\/\//.test(input)) {
      const u = new URL(input);
      if (!u.hostname) throw new Error('No hostname in URL');
      return u.hostname;
    }
  } catch (e) { }
  input = input.replace(/^[a-zA-Z]+:\/*/, '');
  input = input.split(/[\/?#]/)[0];
  if (!/^[0-9A-Za-z.\-:\[\]]+$/.test(input)) throw new Error('Invalid characters in target');
  return input;
}

function validateNetworkTarget(input) {
  if (!input || typeof input !== 'string') throw new Error('Invalid target');
  input = input.trim();

  const networkPatterns = [
    /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/,
    /^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$/,
    /^(\d{1,3}\.){3}\d{1,3}\s*-\s*(\d{1,3}\.){3}\d{1,3}$/,
    /^(\d{1,3}\.){3}\d{1,3}\[\d+-\d+\]$/,
    /^([a-zA-Z0-9.-]+\s*,\s*)*[a-zA-Z0-9.-]+$/,
  ];

  const isValidNetwork = networkPatterns.some(pattern => pattern.test(input));

  if (!isValidNetwork) {
    return extractHost(input);
  }

  return input;
}

function isAllowedTarget(target) {
  return true;
}

function runNmap(args, target, timeoutMs, scanId) {
  return new Promise((resolve, reject) => {
    const cmdArgs = [...args, target];
    console.log(`[${scanId}] Running: nmap ${cmdArgs.join(' ')}`);

    const n = spawn('nmap', cmdArgs, { stdio: ['ignore', 'pipe', 'pipe'], detached: false });
    let stdout = '', stderr = '', isTimeout = false;
    const startTime = Date.now();

    const timer = setTimeout(() => {
      isTimeout = true;
      const elapsed = (Date.now() - startTime) / 1000;
      console.log(`[${scanId}] TIMEOUT after ${elapsed}s for ${target}`);
      if (stdout.trim().length > 0) {
        try {
          const tmpPath = path.join(os.tmpdir(), `${scanId}-${Date.now()}-partial.xml`);
          fs.writeFileSync(tmpPath, stdout, 'utf8');
          console.log(`[${scanId}] Wrote partial output to ${tmpPath}`);
        } catch (e) {
          console.error(`[${scanId}] Failed to write partial output: ${e.message}`);
        }
        resolve({ stdout, stderr, code: -1, signal: 'TIMEOUT', duration: `${elapsed}s` });
        return;
      }
      try { n.kill('SIGKILL'); } catch (e) { }
      reject(new Error(`Timeout after ${elapsed}s`));
    }, timeoutMs);

    n.stdout.on('data', d => {
      const chunk = d.toString();
      stdout += chunk;
      console.log(`[${scanId}] stdout chunk (${chunk.length} bytes) preview:\n${chunk.split('\n').slice(0, 3).join('\n')}`);
    });
    n.stderr.on('data', d => {
      const chunk = d.toString();
      stderr += chunk;
      console.log(`[${scanId}] stderr chunk (${chunk.length} bytes) preview:\n${chunk.split('\n').slice(0, 3).join('\n')}`);
    });

    n.on('error', err => {
      clearTimeout(timer);
      console.error(`[${scanId}] Process spawn failed: ${err.message}`);
      reject(new Error(`Process spawn failed: ${err.message}`));
    });

    n.on('close', (code, signal) => {
      clearTimeout(timer);
      const duration = (Date.now() - startTime) / 1000;
      console.log(`[${scanId}] nmap process closed with code ${code}, signal ${signal}, duration ${duration}s`);
      if (isTimeout) return;

      // Save raw output to a temp file for inspection
      let tmpPath = '';
      try {
        tmpPath = path.join(os.tmpdir(), `${scanId}-${Date.now()}.xml`);
        fs.writeFileSync(tmpPath, stdout || stderr, 'utf8');
        console.log(`[${scanId}] Wrote raw output to ${tmpPath}`);
      } catch (e) {
        console.error(`[${scanId}] Failed to write raw output file: ${e.message}`);
      }

      if ((stdout || '').trim().length > 0 && ((stdout || '').includes('<?xml') || (stdout || '').includes('<nmaprun'))) {
        console.log(`[${scanId}] Received XML output (${(stdout || '').length} bytes)`);
        resolve({ stdout, stderr, code, signal, duration: `${duration}s`, raw_path: tmpPath });
      } else if ((stdout || '').trim().length > 0) {
        console.log(`[${scanId}] Received non-XML output (${(stdout || '').length} bytes)`);
        resolve({ stdout, stderr, code, signal, duration: `${duration}s`, raw_path: tmpPath });
      } else {
        let errorMsg = `Scan failed - no output received`;
        if ((stderr || '').includes('Failed to resolve')) errorMsg = `DNS resolution failed for ${target}`;
        else if ((stderr || '').includes('did not match')) errorMsg = `Script error: ${stderr.split('\n')[0]}`;
        else if (code !== 0) errorMsg = `Nmap exited with code ${code}: ${stderr || 'unknown error'}`;
        console.error(`[${scanId}] ${errorMsg}`);
        // include tmpPath in error for debugging
        const e = new Error(errorMsg);
        e.raw_path = tmpPath;
        reject(e);
      }
    });
  });
}

// Enhanced XML parser with user-friendly results
async function parseNetworkScanXml(xmlText, targetNetwork) {
  try {
    if (!xmlText || typeof xmlText !== 'string' || xmlText.trim() === '') {
      console.warn('parseNetworkScanXml: empty xmlText');
      return {
        network: targetNetwork,
        hosts: [],
        totalHosts: 0,
        activeHosts: 0,
        openPortsTotal: 0,
        vulnerabilitiesTotal: 0,
        overall_security_rating: 'UNKNOWN',
        key_findings: ['Empty nmap output'],
        executive_summary: 'No output was returned by nmap',
        parse_error: 'empty output'
      };
    }

    // Quick sanity log: first 2 lines
    console.log('parseNetworkScanXml: raw xml preview:\n', xmlText.split('\n').slice(0, 6).join('\n'));

    const result = await xml2js.parseStringPromise(xmlText, {
      explicitArray: false,
      mergeAttrs: true,
      normalize: true,
      trim: true
    });

    if (!result || !result.nmaprun) {
      console.warn('parseNetworkScanXml: parsed XML does not contain nmaprun root. Keys:', Object.keys(result || {}));
      return {
        network: targetNetwork,
        hosts: [],
        totalHosts: 0,
        activeHosts: 0,
        openPortsTotal: 0,
        vulnerabilitiesTotal: 0,
        overall_security_rating: 'UNKNOWN',
        key_findings: ['Unexpected XML structure'],
        executive_summary: 'Parsed XML does not contain expected nmaprun root',
        parse_error: 'missing nmaprun root'
      };
    }

    console.log('XML Parse Result Structure:', Object.keys(result.nmaprun || {}));

    let hosts = [];
    if (result.nmaprun.host) {
      hosts = Array.isArray(result.nmaprun.host)
        ? result.nmaprun.host
        : [result.nmaprun.host];
    }

    console.log(`Found ${hosts.length} hosts in XML`);

    const scanResults = [];

    for (const hostObj of hosts) {
      // defensive checks and logging
      if (!hostObj) {
        console.warn('Skipping empty host object in parsed XML');
        continue;
      }
      // Get host information with safe defaults
      const addresses = Array.isArray(hostObj.address) ? hostObj.address : (hostObj.address ? [hostObj.address] : []);
      const ipv4 = addresses.find(addr => addr.addrtype === 'ipv4')?.addr ||
        addresses.find(addr => typeof addr === 'object' && addr.addrtype === 'ipv4')?.addr ||
        addresses.find(addr => addr.addr && /\d+\.\d+\.\d+\.\d+/.test(addr.addr))?.addr ||
        'unknown';

      const mac = addresses.find(addr => addr.addrtype === 'mac')?.addr ||
        addresses.find(addr => typeof addr === 'object' && addr.addrtype === 'mac')?.addr ||
        '';

      const vendor = addresses.find(addr => addr.addrtype === 'mac')?.vendor ||
        addresses.find(addr => typeof addr === 'object' && addr.addrtype === 'mac')?.vendor ||
        '';

      // Get hostname with safe defaults
      let hostname = '';
      if (hostObj.hostnames) {
        const hostnames = Array.isArray(hostObj.hostnames.hostname)
          ? hostObj.hostnames.hostname
          : (hostObj.hostnames.hostname ? [hostObj.hostnames.hostname] : []);
        hostname = hostnames.length > 0 ? (hostnames[0].name || '') : '';
      }

      // Get host status - this is critical for detecting active hosts
      let hostStatus = 'unknown';
      if (hostObj.status) {
        hostStatus = hostObj.status.state || 'unknown';
      }

      // Parse ports and services with safe defaults
      let portsArr = [];
      if (hostObj.ports && hostObj.ports.port) {
        portsArr = Array.isArray(hostObj.ports.port)
          ? hostObj.ports.port
          : [hostObj.ports.port];
      } else {
        // sometimes state info is in hostObj['hostscript'] or no ports
        portsArr = [];
      }

      const detectedPorts = portsArr.map(p => {
        const service = p.service || {};
        const state = p.state || {};
        const scripts = p.script ? (Array.isArray(p.script) ? p.script : [p.script]) : [];

        // pick small useful script preview if available
        const firstScriptOutput = scripts.length > 0 ? (scripts[0].output || '').split('\n')[0].trim() : '';

        // prefer explicit product, then extrainfo, then banner, then first script output
        const productCandidate = service.product || service.extrainfo || service.banner || firstScriptOutput || '';

        // build concise banner fallback
        const bannerCandidate = (service.banner && service.banner.trim()) ? service.banner.trim() : (firstScriptOutput ? firstScriptOutput.slice(0, 200) : '');

        const parsedScripts = scripts.map(s => ({
          id: s.id || 'unknown',
          name: s.id ? s.id.replace(/-/g, ' ').toUpperCase() : 'Unknown Script',
          output: s.output || '',
          risk_level: determineScriptRisk(s.id, s.output),
          description: getScriptDescription(s.id)
        }));

        const serviceCategory = categorizeService(service.name || productCandidate, p.portid);

        return {
          port: p.portid || '',
          protocol: p.protocol || 'tcp',
          state: state.state || 'unknown',
          state_reason: state.reason || '',
          service: {
            name: service.name || (productCandidate ? productCandidate.split(' ')[0].toLowerCase() : 'unknown'),
            product: productCandidate,
            version: service.version || '',
            extrainfo: service.extrainfo || '',
            ostype: service.ostype || '',
            method: service.method || 'table',
            banner: bannerCandidate
          },
          category: serviceCategory,
          risk_level: assessPortRisk(p.portid, service.name || productCandidate, state.state),
          scripts: parsedScripts,
          banner: bannerCandidate,
          summary: generatePortSummary(p.portid, service.name || productCandidate, state.state, productCandidate, service.version)
        };
      });

      // Enhanced vulnerability detection (same logic)
      let foundVulns = [];
      for (const p of portsArr) {
        if (p.script) {
          const scripts = Array.isArray(p.script) ? p.script : [p.script];
          for (const s of scripts) {
            const vulnInfo = extractVulnerabilityInfo(s, p.portid, p.service);
            if (vulnInfo) {
              foundVulns.push({
                ...vulnInfo,
                host: ipv4,
                port: p.portid,
                service: p.service?.name || 'unknown'
              });
            }
          }
        }
      }

      const openPorts = detectedPorts.filter(p => p.state === 'open').length;

      scanResults.push({
        host: ipv4,
        hostname: hostname,
        mac_address: mac,
        vendor: vendor,
        status: hostStatus,
        ports: detectedPorts,
        open_ports_count: openPorts,
        foundVulns: foundVulns,
        security_assessment: assessHostSecurity(detectedPorts, foundVulns),
        device_type: inferDeviceType(detectedPorts, vendor),
        recommendations: generateHostRecommendations(detectedPorts, foundVulns),
        scan_timestamp: new Date().toISOString()
      });
    }

    const activeHosts = scanResults.filter(host => host.status === 'up' || host.open_ports_count > 0);

    console.log(`Final Results - Total Hosts: ${scanResults.length}, Active Hosts: ${activeHosts.length}`);

    return {
      network: targetNetwork,
      hosts: scanResults,
      totalHosts: scanResults.length,
      activeHosts: activeHosts.length,
      openPortsTotal: scanResults.reduce((sum, host) => sum + host.open_ports_count, 0),
      vulnerabilitiesTotal: scanResults.reduce((sum, host) => sum + host.foundVulns.length, 0),
      overall_security_rating: calculateOverallSecurityRating(scanResults),
      key_findings: generateKeyFindings(scanResults),
      executive_summary: generateExecutiveSummary(scanResults),
      timestamp: new Date().toISOString()
    };
  } catch (error) {
    console.error('Error parsing XML:', error);
    return {
      network: targetNetwork,
      hosts: [],
      totalHosts: 0,
      activeHosts: 0,
      openPortsTotal: 0,
      vulnerabilitiesTotal: 0,
      overall_security_rating: 'UNKNOWN',
      key_findings: ['Scan failed to complete properly'],
      executive_summary: 'The scan encountered an error and could not provide security assessment.',
      parse_error: error.message
    };
  }
}

// --- User-Friendly Helper Functions ---

function categorizeService(serviceName, port) {
  const portNum = parseInt(port);
  const service = (serviceName || '').toLowerCase();

  if (service.includes('http') || service.includes('apache') || service.includes('nginx') || portNum === 80 || portNum === 443 || portNum === 8080 || portNum === 8443) {
    return 'Web Service';
  } else if (service.includes('ssh') || portNum === 22) {
    return 'Remote Access';
  } else if (service.includes('ftp') || portNum === 21) {
    return 'File Transfer';
  } else if (service.includes('smtp') || portNum === 25) {
    return 'Email Service';
  } else if (service.includes('mysql') || service.includes('postgresql') || portNum === 3306 || portNum === 5432) {
    return 'Database';
  } else if (service.includes('rdp') || portNum === 3389) {
    return 'Remote Desktop';
  } else if (service.includes('dns') || portNum === 53) {
    return 'DNS Service';
  } else if (service.includes('telnet') || portNum === 23) {
    return 'Remote Management';
  } else {
    return 'Other Service';
  }
}

function assessPortRisk(port, service, state) {
  if (state !== 'open') return 'None';

  const portNum = parseInt(port);
  const highRiskPorts = [21, 23, 135, 139, 445, 1433, 1434, 3306, 3389, 5432, 5900, 6379];
  const mediumRiskPorts = [22, 25, 53, 110, 111, 993, 995, 1723, 8080, 8443];

  if (highRiskPorts.includes(portNum)) return 'High';
  if (mediumRiskPorts.includes(portNum)) return 'Medium';

  // Service-specific risks
  if (service && (
    service.includes('ftp') && !service.includes('sftp') ||
    service.includes('telnet') ||
    service.includes('vnc') ||
    service.includes('microsoft-ds')
  )) {
    return 'High';
  }

  return 'Low';
}

function determineScriptRisk(scriptId, output) {
  if (!scriptId) return 'Unknown';

  const script = scriptId.toLowerCase();
  const out = (output || '').toLowerCase();

  const highRiskIndicators = ['vuln', 'exploit', 'vulnerable', 'cve-', 'critical', 'high'];
  const medRiskIndicators = ['warning', 'medium', 'information', 'disclosure'];

  if (highRiskIndicators.some(indicator => script.includes(indicator) || out.includes(indicator))) {
    return 'High';
  }
  if (medRiskIndicators.some(indicator => script.includes(indicator) || out.includes(indicator))) {
    return 'Medium';
  }

  return 'Low';
}

function getScriptDescription(scriptId) {
  const descriptions = {
    'http-enum': 'Discovers common web directories and files',
    'http-security-headers': 'Checks for important security headers',
    'http-title': 'Gets the title of web pages',
    'ssh2-enum-algos': 'Lists supported SSH encryption algorithms',
    'ftp-anon': 'Checks if FTP server allows anonymous login',
    'vuln': 'Checks for known vulnerabilities',
    'banner': 'Grabs service banners for identification'
  };

  return descriptions[scriptId] || `Security check: ${scriptId}`;
}

function generatePortSummary(port, service, state, product, version) {
  if (state !== 'open') return `Port ${port} is closed`;

  const serviceName = service || 'unknown service';
  const productInfo = product ? ` running ${product}${version ? ' ' + version : ''}` : '';

  return `Port ${port} (${serviceName}) is open${productInfo}. This allows ${serviceName} connections.`;
}

function extractVulnerabilityInfo(script, port, service) {
  const output = script.output || '';
  const scriptId = script.id || '';

  // Look for CVEs (return all matches)
  const cveMatches = (output.match(/CVE-\d{4}-\d{4,7}/g) || []).map(m => m.trim());

  // Look for vulnerability indicators
  const isVulnerable = output.toLowerCase().includes('vulnerable') ||
    output.toLowerCase().includes('vulnerability') ||
    output.toLowerCase().includes('exploit') ||
    output.toLowerCase().includes('risk');

  if (cveMatches.length > 0 || isVulnerable) {
    const severity = determineVulnerabilitySeverity(output, scriptId);

    return {
      CVEs: cveMatches.length > 0 ? cveMatches : ['N/A'],
      severity: severity,
      title: generateVulnerabilityTitle(scriptId, output, port, service),
      description: generateVulnerabilityDescription(scriptId, output),
      evidence: {
        script_id: scriptId,
        script_name: getScriptDescription(scriptId),
        output: output.substring(0, 1000), // limit length
        port: port
      },
      risk_level: severity,
      recommendation: generateVulnerabilityRecommendation(scriptId, port, service),
      external_links: cveMatches.length > 0 ? cveMatches.map(c => [
        `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${c}`,
        `https://nvd.nist.gov/vuln/detail/${c}`
      ]).flat() : []
    };
  }

  return null;
}

function determineVulnerabilitySeverity(output, scriptId) {
  const out = output.toLowerCase();

  if (out.includes('critical') || out.includes('high') || scriptId.includes('vuln')) {
    return 'High';
  } else if (out.includes('medium')) {
    return 'Medium';
  } else if (out.includes('low')) {
    return 'Low';
  }

  return 'Unknown';
}

function generateVulnerabilityTitle(scriptId, output, port, service) {
  const serviceName = service?.name || 'service';

  if (scriptId === 'http-security-headers') {
    return `Missing Security Headers on Web Service (Port ${port})`;
  } else if (scriptId === 'ftp-anon' && output.includes('Anonymous FTP login allowed')) {
    return `Anonymous FTP Access Allowed (Port ${port})`;
  } else if (output.includes('CVE')) {
    const cveMatch = output.match(/CVE-\d{4}-\d{4,7}/);
    return `Known Vulnerability (${cveMatch ? cveMatch[0] : 'CVE'}) in ${serviceName}`;
  }

  return `Security Issue Detected in ${serviceName} (Port ${port})`;
}

function generateVulnerabilityDescription(scriptId, output) {
  if (scriptId === 'http-security-headers') {
    return 'The web service is missing important security headers that help protect against common web attacks.';
  } else if (scriptId === 'ftp-anon' && output.includes('Anonymous FTP login allowed')) {
    return 'The FTP server allows anonymous access, which could allow unauthorized file access.';
  } else if (output.includes('CVE')) {
    return 'A known security vulnerability was detected that could potentially be exploited.';
  }

  return 'A potential security issue was identified during the scan.';
}

function generateVulnerabilityRecommendation(scriptId, port, service) {
  const serviceName = service?.name || 'the service';

  if (scriptId === 'http-security-headers') {
    return 'Configure security headers like Content-Security-Policy, X-Content-Type-Options, and Strict-Transport-Security.';
  } else if (scriptId === 'ftp-anon') {
    return 'Disable anonymous FTP access or restrict it to read-only with no write permissions.';
  } else if (service?.version) {
    return `Update ${serviceName} to the latest version to address known security issues.`;
  }

  return `Review the configuration of ${serviceName} on port ${port} and apply security best practices.`;
}

function assessHostSecurity(ports, vulnerabilities) {
  const openPorts = ports.filter(p => p.state === 'open');
  const highRiskPorts = openPorts.filter(p => p.risk_level === 'High');
  const highRiskVulns = vulnerabilities.filter(v => v.severity === 'High');

  if (highRiskVulns.length > 0 || highRiskPorts.length > 3) {
    return 'High Risk';
  } else if (vulnerabilities.length > 0 || highRiskPorts.length > 0) {
    return 'Medium Risk';
  } else if (openPorts.length > 0) {
    return 'Low Risk';
  } else {
    return 'No Open Services';
  }
}

function inferDeviceType(ports, vendor) {
  const openPorts = ports.filter(p => p.state === 'open');
  const portNumbers = openPorts.map(p => parseInt(p.port));

  // Check for common device patterns
  if (portNumbers.includes(80) || portNumbers.includes(443) || portNumbers.includes(8080)) {
    return 'Web Server';
  } else if (portNumbers.includes(22) && vendor && (vendor.includes('Cisco') || vendor.includes('Juniper'))) {
    return 'Network Device';
  } else if (portNumbers.includes(135) && portNumbers.includes(445)) {
    return 'Windows Computer';
  } else if (portNumbers.includes(22) && portNumbers.includes(25)) {
    return 'Linux Server';
  } else if (vendor && vendor.includes('Apple')) {
    return 'Apple Device';
  }

  return 'Network Device';
}

function generateHostRecommendations(ports, vulnerabilities) {
  const recommendations = [];
  const openPorts = ports.filter(p => p.state === 'open');

  // Check for unnecessary open ports
  const unnecessaryPorts = openPorts.filter(p =>
    [21, 23, 135, 139, 445].includes(parseInt(p.port)) && p.risk_level === 'High'
  );

  if (unnecessaryPorts.length > 0) {
    recommendations.push(`Consider closing unnecessary high-risk ports: ${unnecessaryPorts.map(p => p.port).join(', ')}`);
  }

  // Check for vulnerabilities
  if (vulnerabilities.length > 0) {
    const highVulns = vulnerabilities.filter(v => v.severity === 'High');
    if (highVulns.length > 0) {
      recommendations.push(`Address ${highVulns.length} high-severity security vulnerabilities immediately`);
    }
  }

  // General recommendations
  if (openPorts.length > 10) {
    recommendations.push('Reduce the number of open ports to minimize attack surface');
  }

  if (recommendations.length === 0) {
    recommendations.push('Current configuration appears reasonable. Maintain regular security updates.');
  }

  return recommendations;
}

function calculateOverallSecurityRating(scanResults) {
  const activeHosts = scanResults.filter(h => h.status === 'up');
  if (activeHosts.length === 0) return 'No Active Hosts';

  let highRiskCount = 0;
  let mediumRiskCount = 0;

  activeHosts.forEach(host => {
    const assessment = host.security_assessment;
    if (assessment === 'High Risk') highRiskCount++;
    else if (assessment === 'Medium Risk') mediumRiskCount++;
  });

  const highRiskPercentage = (highRiskCount / activeHosts.length) * 100;
  const mediumRiskPercentage = (mediumRiskCount / activeHosts.length) * 100;

  if (highRiskPercentage > 30) return 'High Risk';
  if (mediumRiskPercentage > 50 || highRiskPercentage > 10) return 'Medium Risk';
  if (mediumRiskPercentage > 20) return 'Low Risk';

  return 'Good';
}

function generateKeyFindings(scanResults) {
  const findings = [];
  const activeHosts = scanResults.filter(h => h.status === 'up');

  if (activeHosts.length === 0) {
    return ['No active hosts found on the network'];
  }

  // Count vulnerabilities
  const totalVulns = scanResults.reduce((sum, host) => sum + host.foundVulns.length, 0);
  const highRiskVulns = scanResults.reduce((sum, host) =>
    sum + host.foundVulns.filter(v => v.severity === 'High').length, 0
  );

  if (highRiskVulns > 0) {
    findings.push(`${highRiskVulns} high-severity security vulnerabilities detected`);
  }

  if (totalVulns > 0) {
    findings.push(`${totalVulns} total security issues found across ${activeHosts.length} devices`);
  }

  // Check for common issues
  const hostsWithHighRiskPorts = scanResults.filter(host =>
    host.ports.some(p => p.risk_level === 'High' && p.state === 'open')
  ).length;

  if (hostsWithHighRiskPorts > 0) {
    findings.push(`${hostsWithHighRiskPorts} devices have high-risk services exposed`);
  }

  if (findings.length === 0) {
    findings.push('No significant security issues detected in the scan');
  }

  return findings;
}

function generateExecutiveSummary(scanResults) {
  const activeHosts = scanResults.filter(h => h.status === 'up');
  const totalHosts = scanResults.length;

  if (activeHosts.length === 0) {
    return `Scan completed: No active devices found among ${totalHosts} scanned addresses.`;
  }

  const totalVulns = scanResults.reduce((sum, host) => sum + host.foundVulns.length, 0);
  const highRiskHosts = activeHosts.filter(h => h.security_assessment === 'High Risk').length;
  const securityRating = calculateOverallSecurityRating(scanResults);

  return `Network security scan completed: ${activeHosts.length} active devices found. ` +
    `Security rating: ${securityRating}. ` +
    `${totalVulns} security issues detected. ` +
    `${highRiskHosts} devices require immediate attention.`;
}

// --- Express API Setup ---
const app = express();
app.use(bodyParser.json());

// List available scan presets
app.get('/presets', (req, res) => {
  const presetsInfo = Object.keys(PRESETS).map(key => ({
    name: key,
    description: PRESETS[key].description,
    timeout: PRESETS[key].timeoutMs / 60000 + ' minutes',
    estimatedDuration: key === 'quick' ? '30-300 seconds' : '10-180 minutes',
    is_network_capable: true
  }));
  res.json({ presets: presetsInfo });
});

// Start a scan (handles both single hosts and networks)
app.post('/scan', async (req, res) => {
  try {
    const { target, preset, userId, targetId, scanName } = req.body;
    const scanType = preset === 'deep' ? 'deep' : (preset === 'network_discovery' ? 'network_discovery' : 'quick');

    if (!target || !userId) return res.status(400).json({ error: 'target and userId required' });
    if (!PRESETS[scanType]) return res.status(400).json({ error: 'unknown scan type' });

    let scanTarget;
    try {
      scanTarget = validateNetworkTarget(target);
    } catch (e) {
      return res.status(400).json({ error: 'invalid target: ' + e.message });
    }

    if (!isAllowedTarget(scanTarget)) return res.status(403).json({ error: 'target not allowed' });

    const isNetworkScan = /(\/\d{1,2}$|-\d{1,3}$|\[.*\]|,)/.test(scanTarget);

    // Create scan record in 'Scan'
    const scanId = uuidv4();
    await safeFirestoreSet(db.collection('Scan').doc(scanId), {
      status: 'ongoing',
      submitted_at: admin.firestore.FieldValue.serverTimestamp(),
      started_at: null,
      finished_at: null,
      scan_type: scanType,
      target: scanTarget,
      user_id: userId,
      scan_name: scanName || `${isNetworkScan ? 'Network' : 'Host'} Scan ${new Date().toLocaleString()}`,
      is_network_scan: isNetworkScan
    });

    // Run scan asynchronously
    (async () => {
      let runResult;
      try {
        await safeFirestoreUpdate(db.collection('Scan').doc(scanId), {
          started_at: admin.firestore.FieldValue.serverTimestamp()
        });

        console.log(`[${scanId}] Starting ${isNetworkScan ? 'network' : 'host'} scan for: ${scanTarget} with preset: ${scanType}`);
        runResult = await runNmap(PRESETS[scanType].args, scanTarget, PRESETS[scanType].timeoutMs, scanId);
        const stdout = runResult.stdout;
        console.log(`[${scanId}] Scan completed. stdout length: ${stdout.length}, raw_path: ${runResult.raw_path || 'n/a'}`);

        // store raw preview for debugging if parsing yields no hosts
        await safeFirestoreUpdate(db.collection('Scan').doc(scanId), {
          raw_output_preview: stdout.slice(0, 2000),
          raw_output_path: runResult.raw_path || ''
        });
        // Parse scan result
        const parsed = await parseNetworkScanXml(stdout, scanTarget);

        if (!parsed.hosts || parsed.hosts.length === 0) {
          console.warn(`[${scanId}] Parser returned zero hosts. Check raw_output_path and raw_output_preview on Scan doc.`);
          await safeFirestoreUpdate(db.collection('Scan').doc(scanId), {
            parse_warning: 'No hosts parsed from nmap output; raw output saved for inspection'
          });
        }
        console.log(`[${scanId}] Parsed scan result:`, {
          network: parsed.network,
          totalHosts: parsed.totalHosts,
          activeHosts: parsed.activeHosts,
          openPortsTotal: parsed.openPortsTotal,
          vulnerabilitiesTotal: parsed.vulnerabilitiesTotal,
          overall_security_rating: parsed.overall_security_rating
        });

        // Create ScanResult records for each host
        for (const hostResult of parsed.hosts) {
          const uniqueCVEs = [...new Set(
            hostResult.foundVulns.flatMap(v => (v.CVEs && v.CVEs.length) ? v.CVEs : (v.CVE ? [v.CVE] : []) )
              .filter(c => c && c !== 'N/A')
          )];

          // Create ScanResult record for this host
          const scanResultRef = db.collection('ScanResult').doc();
          const sanitizedPorts = (hostResult.ports || []).map(p => ({
            port: p.port,
            protocol: p.protocol || 'tcp',
            state: p.state,
            state_reason: p.state_reason || '',
            service: {
              name: p.service?.name || 'unknown',
              product: p.service?.product || '',
              version: p.service?.version || '',
              extrainfo: p.service?.extrainfo || '',
              ostype: p.service?.ostype || '',
              method: p.service?.method || ''
            },
            category: p.category || 'Other Service',
            risk_level: p.risk_level || 'Unknown',
            banner: p.banner || '',
            summary: p.summary || ''
          }));

          // compact summary (small, index-friendly) instead of duplicating full port objects
          const portSummaries = sanitizedPorts.map(s => ({
            port: s.port,
            service: s.service.name,
            version: s.service.version,
            product: s.service.product,
            category: s.category,
            risk_level: s.risk_level
          })).filter(s => s.service && s.service !== 'unknown');

          await safeFirestoreSet(scanResultRef, {
            scan_id: scanId,
            host: hostResult.host,
            hostname: hostResult.hostname,
            mac_address: hostResult.mac_address,
            vendor: hostResult.vendor,
            host_status: hostResult.status,

            // Technical details (detailed ports)
            ports: sanitizedPorts,
            open_ports_count: hostResult.open_ports_count,
            CVEs: uniqueCVEs,

            // User-friendly information
            security_assessment: hostResult.security_assessment,
            device_type: hostResult.device_type,
            recommendations: hostResult.recommendations,

            created_at: admin.firestore.FieldValue.serverTimestamp(),
            network_scan: isNetworkScan,
            parent_scan_id: scanId,
            scan_duration: runResult.duration,

            // small summary for queries (no duplication of full port objects)
            detected_ports_summary: portSummaries
          });

          // Create/Update FoundVulns records for this host
          for (const vuln of hostResult.foundVulns) {
            const cves = (vuln.CVEs && vuln.CVEs.length) ? vuln.CVEs : (vuln.CVE ? [vuln.CVE] : ['N/A']);
            for (const cve of cves) {
              const foundVulnQuery = await db.collection('FoundVulns')
                .where('CVE', '==', cve)
                .where('port', '==', vuln.port)
                .where('host', '==', hostResult.host)
                .get();

              if (foundVulnQuery.empty) {
                await safeFirestoreSet(db.collection('FoundVulns').doc(), {
                  CVE: cve,
                  severity: vuln.severity,
                  risk_level: vuln.risk_level,
                  title: vuln.title,
                  description: vuln.description,
                  port: vuln.port,
                  host: hostResult.host,
                  service: vuln.service,
                  evidence: vuln.evidence,
                  recommendation: vuln.recommendation,
                  external_links: vuln.external_links,
                  scan_results: [scanResultRef],
                  created_at: admin.firestore.FieldValue.serverTimestamp(),
                  network_scan: isNetworkScan,
                  parent_scan_id: scanId
                });
              } else {
                const docRef = foundVulnQuery.docs[0].ref;
                await safeFirestoreUpdate(docRef, {
                  scan_results: admin.firestore.FieldValue.arrayUnion(scanResultRef),
                  last_detected: admin.firestore.FieldValue.serverTimestamp()
                });
              }
            }
          }
        }

        // Update main scan record with comprehensive summary
        await safeFirestoreUpdate(db.collection('Scan').doc(scanId), {
          status: 'complete',
          finished_at: admin.firestore.FieldValue.serverTimestamp(),
          summary: {
            total_hosts: parsed.totalHosts,
            active_hosts: parsed.activeHosts,
            open_ports_total: parsed.openPortsTotal,
            vulnerabilities_total: parsed.vulnerabilitiesTotal,
            scan_duration: runResult.duration,
            overall_security_rating: parsed.overall_security_rating,
            key_findings: parsed.key_findings,
            executive_summary: parsed.executive_summary,
            hosts_scanned: parsed.hosts.map(h => ({
              host: h.host,
              hostname: h.hostname,
              status: h.status,
              security_assessment: h.security_assessment,
              open_ports: h.open_ports_count,
              vulnerabilities: h.foundVulns.length,
              device_type: h.device_type
            }))
          }
        });

      } catch (err) {
        console.error(`[${scanId}] Scan failed: ${err.message}`);
        await safeFirestoreUpdate(db.collection('Scan').doc(scanId), {
          status: 'failed',
          finished_at: admin.firestore.FieldValue.serverTimestamp(),
          error: err.message,
          error_details: {
            stderr: runResult?.stderr || '',
            code: runResult?.code || -1,
            signal: runResult?.signal || ''
          }
        });
      }
    })();

    return res.json({
      scanId,
      status: 'ongoing',
      scanType,
      target: scanTarget,
      is_network_scan: isNetworkScan,
      estimatedTimeout: PRESETS[scanType].timeoutMs / 1000 + ' seconds',
      message: `Scan started. Use GET /scan/${scanId} to check status.`
    });

  } catch (err) {
    return res.status(500).json({ error: 'server error', details: err.message });
  }
});

// Get scan status/result
app.get('/scan/:scanId', async (req, res) => {
  try {
    const scanId = req.params.scanId;
    const scanDoc = await db.collection('Scan').doc(scanId).get();
    if (!scanDoc.exists) return res.status(404).json({ error: 'scan not found' });
    const scanData = scanDoc.data();

    // Get all ScanResults for this scan
    const resultsSnap = await db.collection('ScanResult')
      .where('parent_scan_id', '==', scanId)
      .get();

    const scanResults = resultsSnap.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    // Get FoundVulns for all hosts in this scan
    let foundVulns = [];
    for (const result of scanResults) {
      const vulnsSnap = await db.collection('FoundVulns')
        .where('parent_scan_id', '==', scanId)
        .where('host', '==', result.host)
        .get();

      foundVulns = foundVulns.concat(vulnsSnap.docs.map(doc => ({
        id: doc.id,
        ...doc.data()
      })));
    }

    return res.json({
      scan: scanData,
      scanResults: scanResults,
      foundVulns: foundVulns,
      summary: {
        total_hosts: scanResults.length,
        hosts_with_ports: scanResults.filter(r => r.open_ports_count > 0).length,
        hosts_with_vulns: [...new Set(foundVulns.map(v => v.host))].length,
        total_vulnerabilities: foundVulns.length,
        total_open_ports: scanResults.reduce((sum, r) => sum + r.open_ports_count, 0),
        overall_security_rating: scanData.summary?.overall_security_rating || 'UNKNOWN'
      }
    });
  } catch (err) {
    return res.status(500).json({ error: 'server error', details: err.message });
  }
});

// Get all scans for a user
app.get('/scans/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    const scansSnap = await db.collection('Scan')
      .where('user_id', '==', userId)
      .orderBy('submitted_at', 'desc')
      .limit(50)
      .get();

    const scans = scansSnap.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.json({ scans });
  } catch (err) {
    res.status(500).json({ error: 'server error', details: err.message });
  }
});

// Health check endpoint
app.get('/health', (req, res) => res.json({
  ok: true,
  now: new Date().toISOString(),
  presets: Object.keys(PRESETS),
  features: ['single_host_scanning', 'network_scanning', 'vulnerability_detection', 'service_detection', 'user_friendly_reports']
}));

app.listen(PORT, () => console.log(`Nmap-Firebase API listening on ${PORT}`));