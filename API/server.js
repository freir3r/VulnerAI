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
const cors = require('cors');

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
  // Option 1: Network Discovery & Quick Port Scan
  network_scan: {
    args: [                     
      '-sn',                         
      '-T3',                     
      '-oX', '-'
    ],
    outputFormat: 'xml',
    timeoutMs: 10 * 60 * 1000,
    description: 'Network discovery followed by quick port scan on common ports',
    category: 'network_discovery',
    intensity: 'quick'
  },

  // Option 2: Deep Single Target Scan
  deep_scan: {
    args: [
      '-sT', '-sV', '--version-intensity', '7',
      '--script', 'default,safe,banner',
      '-p-', // All ports
      '-T4', '--min-rate', '500',
      '--max-retries', '2',
      '--host-timeout', '15m',
      '--open', '--reason', '-oX', '-'
    ],
    outputFormat: 'xml',
    timeoutMs: 20 * 60 * 1000, // 20 minutes max
    description: 'Comprehensive single target scan with service detection and basic scripts',
    category: 'deep_scan',
    intensity: 'comprehensive'
  },

  // Option 3: CVE Analysis (uses existing scan data)
  cve_analysis: {
    args: [
      '-sT', '-sV', '--version-intensity', '9',
      '--script', 'vuln,vulners',
      '-p', '--version-all', // Only scan ports that were previously found open
      '-T3', '--max-retries', '2',
      '--host-timeout', '10m', '--script-timeout', '1m',
      '--open', '--reason', '-oX', '-'
    ],
    outputFormat: 'xml',
    timeoutMs: 15 * 60 * 1000, // 15 minutes max
    description: 'CVE vulnerability analysis based on previous scan results',
    category: 'cve_analysis',
    intensity: 'targeted'
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

    // Enhanced XML parsing options - FIXED for your XML structure
    const result = await xml2js.parseStringPromise(xmlText, {
      explicitArray: false,
      mergeAttrs: true,
      normalize: true,
      trim: true
    });

    console.log('XML Parse Result Root Keys:', Object.keys(result || {}));

    // Handle the case where nmaprun attributes are at root level
    let hosts = [];
    let nmaprunData = result;

    // If there's a nested nmaprun, use that, otherwise use root as nmaprun
    if (result.nmaprun) {
      nmaprunData = result.nmaprun;
      console.log('Using nested nmaprun structure');
    } else {
      console.log('Using root as nmaprun structure');
    }

    console.log('nmaprunData Keys:', Object.keys(nmaprunData || {}));

    // Extract hosts from the correct location
    if (nmaprunData.host) {
      hosts = Array.isArray(nmaprunData.host)
        ? nmaprunData.host
        : [nmaprunData.host];
    }

    console.log(`Found ${hosts.length} hosts in XML`);

    // Debug: Log first host structure to understand the data
    if (hosts.length > 0) {
      console.log('First host structure:', JSON.stringify(hosts[0], null, 2).substring(0, 1000));
    }

    const ScanResults = [];

    for (const hostObj of hosts) {
      if (!hostObj) {
        console.warn('Skipping empty host object in parsed XML');
        continue;
      }

      // Enhanced hostname extraction with comprehensive debugging
      const hostname = extractHostnameEnhanced(hostObj);

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

      // Get host status
      let hostStatus = 'unknown';
      if (hostObj.status) {
        hostStatus = hostObj.status.state || 'unknown';
      }

      // Debug logging for host information
      console.log(`Host ${ipv4} - hostname: "${hostname}", status: ${hostStatus}, addresses: ${addresses.length}`);

      // Parse ports and services
      let portsArr = [];
      if (hostObj.ports && hostObj.ports.port) {
        portsArr = Array.isArray(hostObj.ports.port)
          ? hostObj.ports.port
          : [hostObj.ports.port];
      }

      const detectedPorts = portsArr.map(p => {
        const service = p.service || {};
        const state = p.state || {};
        const scripts = p.script ? (Array.isArray(p.script) ? p.script : [p.script]) : [];

        // Service detection
        const firstScriptOutput = scripts.length > 0 ? (scripts[0].output || '').split('\n')[0].trim() : '';
        const productCandidate = service.product || service.extrainfo || service.banner || firstScriptOutput || '';
        const bannerCandidate = (service.banner && service.banner.trim()) ? service.banner.trim() : (firstScriptOutput ? firstScriptOutput.slice(0, 200) : '');

        // Basic script parsing
        const parsedScripts = scripts.map(s => ({
          id: s.id || 'unknown',
          name: s.id ? s.id.replace(/-/g, ' ').toUpperCase() : 'Unknown Script',
          output: s.output || '',
          risk_level: 'unknown',
          description: ''
        }));

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
          category: 'Unknown',
          risk_level: 'unknown',
          scripts: parsedScripts,
          banner: bannerCandidate,
          summary: `Port ${p.portid} ${state.state}`
        };
      });

      // Basic vulnerability detection
      let foundVulns = [];
      for (const p of portsArr) {
        if (p.script) {
          const scripts = Array.isArray(p.script) ? p.script : [p.script];
          for (const s of scripts) {
            // Placeholder - implement your vulnerability extraction logic
            if (s.id && s.id.includes('vuln')) {
              foundVulns.push({
                title: `Potential vulnerability in ${s.id}`,
                severity: 'unknown',
                host: ipv4,
                port: p.portid,
                service: p.service?.name || 'unknown'
              });
            }
          }
        }
      }

      const openPorts = detectedPorts.filter(p => p.state === 'open').length;

      ScanResults.push({
        host: ipv4,
        hostname: hostname,
        mac_address: mac,
        vendor: vendor,
        status: hostStatus,
        ports: detectedPorts,
        open_ports_count: openPorts,
        foundVulns: foundVulns,
        scan_timestamp: new Date().toISOString()
      });
    }

    const activeHosts = ScanResults.filter(host => host.status === 'up' || host.open_ports_count > 0);

    console.log(`Final Results - Total Hosts: ${ScanResults.length}, Active Hosts: ${activeHosts.length}`);
    console.log(`Hostnames found:`, ScanResults.map(h => `${h.host}: "${h.hostname}"`));

    return {
      network: targetNetwork,
      hosts: ScanResults,
      totalHosts: ScanResults.length,
      activeHosts: activeHosts.length,
      openPortsTotal: ScanResults.reduce((sum, host) => sum + host.open_ports_count, 0),
      vulnerabilitiesTotal: ScanResults.reduce((sum, host) => sum + host.foundVulns.length, 0),
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

// Enhanced hostname extraction function
function extractHostnameEnhanced(hostObj) {
  if (!hostObj) return '';

  console.log('Extracting hostname from:', JSON.stringify(hostObj.hostnames, null, 2).substring(0, 500));

  const strategies = [
    // Strategy 1: hostnames.hostname array with attributes
    () => {
      if (hostObj.hostnames?.hostname) {
        const hostnames = Array.isArray(hostObj.hostnames.hostname)
          ? hostObj.hostnames.hostname
          : [hostObj.hostnames.hostname];

        if (hostnames.length > 0) {
          const first = hostnames[0];
          return first.name || first.$?.name || first._ || first || '';
        }
      }
      return '';
    },
    // Strategy 2: Direct hostname field
    () => hostObj.hostname?.name || hostObj.hostname?.$?.name || hostObj.hostname?._ || hostObj.hostname || '',
    // Strategy 3: From addresses with hostname type
    () => {
      const addresses = Array.isArray(hostObj.address) ? hostObj.address : (hostObj.address ? [hostObj.address] : []);
      const hostnameAddr = addresses.find(addr => addr.addrtype === 'hostname' || addr.type === 'hostname');
      return hostnameAddr?.addr || hostnameAddr?._ || '';
    },
    // Strategy 4: Check for any string in hostnames
    () => {
      if (typeof hostObj.hostnames === 'string') return hostObj.hostnames;
      return '';
    }
  ];

  for (const strategy of strategies) {
    try {
      const result = strategy();
      if (result && typeof result === 'string' && result.trim() && result !== 'unknown') {
        console.log(`Found hostname using strategy: ${result}`);
        return result.trim();
      }
    } catch (e) {
      console.warn('Hostname extraction strategy failed:', e.message);
    }
  }

  console.log('No hostname found using any strategy');
  return '';
}

// --- NEW Helper Functions for Simplified Presets ---

// Network Discovery with Sequential Port Scanning
async function runNetworkDiscoveryScan(target, scanId) {
  console.log(`[${scanId}] Starting network discovery for: ${target}`);

  // Step 1: Host discovery
  const discoveryResult = await runNmap(
    PRESETS.network_scan.args,
    target,
    PRESETS.network_scan.timeoutMs,
    `${scanId}-discovery`
  );

  // Parse discovery results to get active hosts with their hostnames
  const discoveryData = await xml2js.parseStringPromise(discoveryResult.stdout);
  let hosts = [];

  if (discoveryData.nmaprun && discoveryData.nmaprun.host) {
    hosts = Array.isArray(discoveryData.nmaprun.host)
      ? discoveryData.nmaprun.host
      : [discoveryData.nmaprun.host];
  }

  // Enhanced hostname extraction function
  const extractHostname = extractHostnameEnhanced;

  // Store host information including hostnames from discovery
  const activeHosts = hosts.filter(host =>
    host.status && host.status.state === 'up'
  ).map(host => {
    const addresses = Array.isArray(host.address) ? host.address : (host.address ? [host.address] : []);
    const ipv4 = addresses.find(addr => addr.addrtype === 'ipv4')?.addr;

    // Use enhanced hostname extraction
    const hostname = extractHostname(host);

    return {
      ip: ipv4,
      hostname: hostname,
      addresses: addresses,
      originalHostData: host // Keep original for debugging
    };
  }).filter(host => host.ip);

  console.log(`[${scanId}] Found ${activeHosts.length} active hosts:`, activeHosts.map(h => `${h.ip} (${h.hostname || 'no hostname'})`));

  // Debug: Log raw hostname data for first host
  if (activeHosts.length > 0) {
    console.log(`[${scanId}] Debug - First host raw data:`, JSON.stringify(activeHosts[0].originalHostData?.hostnames, null, 2).substring(0, 500));
  }

  if (activeHosts.length === 0) {
    return discoveryResult; // Return discovery results if no hosts found
  }

  // Step 2: Quick port scan on each discovered host
  let combinedXml = `<?xml version="1.0" encoding="UTF-8"?>\n<nmaprun scanner="nmap" args="network-scan" start="${Math.floor(Date.now() / 1000)}">\n`;
  let totalHostsScanned = 0;

  for (const hostInfo of activeHosts) {
    try {
      console.log(`[${scanId}] Scanning ports on host: ${hostInfo.ip} (${hostInfo.hostname || 'no hostname'})`);
      const portResult = await runNmap(
        PRESETS.network_scan.post_discovery_args,
        hostInfo.ip,
        2 * 60 * 1000, // 2 minutes per host
        `${scanId}-${hostInfo.ip}`
      );

      // Extract and combine host data, preserving hostname from discovery
      if (portResult.stdout.includes('<host>')) {
        let hostContent = portResult.stdout.match(/<host>[\s\S]*?<\/host>/);
        if (hostContent) {
          let hostXml = hostContent[0];

          // Enhanced hostname injection
          if (hostInfo.hostname) {
            try {
              const hostData = await xml2js.parseStringPromise(hostXml);
              if (hostData.host) {
                // Ensure proper hostnames structure
                if (!hostData.host.hostnames) {
                  hostData.host.hostnames = { hostname: [] };
                }

                // Create hostname entry
                const hostnameEntry = {
                  $: { name: hostInfo.hostname, type: 'user' }
                };

                // Handle different hostname array structures
                if (Array.isArray(hostData.host.hostnames.hostname)) {
                  // Add to existing array
                  hostData.host.hostnames.hostname.push(hostnameEntry);
                } else if (hostData.host.hostnames.hostname) {
                  // Convert single object to array
                  hostData.host.hostnames.hostname = [hostData.host.hostnames.hostname, hostnameEntry];
                } else {
                  // Create new array
                  hostData.host.hostnames.hostname = [hostnameEntry];
                }

                // Convert back to XML
                const builder = new xml2js.Builder();
                hostXml = builder.buildObject(hostData);
                // Remove the XML declaration since we're combining
                hostXml = hostXml.replace(/<\?xml[^?]*\?>\n?/, '');

                console.log(`[${scanId}] Successfully injected hostname "${hostInfo.hostname}" for ${hostInfo.ip}`);
              }
            } catch (e) {
              console.error(`[${scanId}] Failed to inject hostname for ${hostInfo.ip}:`, e.message);
              // Fallback: manually add hostnames section
              if (!hostXml.includes('<hostnames>')) {
                const hostnamesSection = `<hostnames><hostname name="${hostInfo.hostname}" type="user"/></hostnames>`;
                // Insert after addresses but before ports
                const addressEnd = hostXml.indexOf('</address>');
                if (addressEnd !== -1) {
                  const insertPos = hostXml.indexOf('>', addressEnd) + 1;
                  hostXml = hostXml.slice(0, insertPos) + hostnamesSection + hostXml.slice(insertPos);
                }
              }
            }
          }

          combinedXml += hostXml + '\n';
          totalHostsScanned++;

          // Debug: Log the modified XML for this host
          console.log(`[${scanId}] Modified host XML preview for ${hostInfo.ip}:`, hostXml.substring(0, 300));
        }
      } else {
        console.warn(`[${scanId}] No <host> tag found in port scan results for ${hostInfo.ip}`);
      }
    } catch (err) {
      console.error(`[${scanId}] Failed to scan host ${hostInfo.ip}:`, err.message);
      // Create error host entry with hostname
      let errorHostXml = `<host starttime="${Math.floor(Date.now() / 1000)}" endtime="${Math.floor(Date.now() / 1000)}">`;
      errorHostXml += `<status state="down" reason="scan-failed"/>`;
      errorHostXml += `<address addr="${hostInfo.ip}" addrtype="ipv4"/>`;

      // Include all addresses from discovery
      hostInfo.addresses.forEach(addr => {
        if (addr.addr !== hostInfo.ip) {
          errorHostXml += `<address addr="${addr.addr}" addrtype="${addr.addrtype}"/>`;
        }
      });

      // Include hostname
      if (hostInfo.hostname) {
        errorHostXml += `<hostnames><hostname name="${hostInfo.hostname}" type="user"/></hostnames>`;
      }

      errorHostXml += `<ports/>`;
      errorHostXml += `</host>`;
      combinedXml += errorHostXml + '\n';
    }
  }

  combinedXml += `</nmaprun>`;

  console.log(`[${scanId}] Combined XML generated with ${totalHostsScanned} hosts scanned`);

  return {
    ...discoveryResult,
    stdout: combinedXml,
    hosts_discovered: activeHosts.length,
    hosts_scanned: totalHostsScanned,
    active_hosts: activeHosts // Include for debugging
  };
}

// CVE Analysis based on previous scan
async function runCveAnalysisScan(target, scanId, userId) {
  console.log(`[${scanId}] Starting CVE analysis for: ${target}`);

  // Get previous scan results for this target
  const previousScans = await db.collection('Scan')
    .where('user_id', '==', userId)
    .where('target', '==', target)
    .where('status', '==', 'complete')
    .orderBy('finished_at', 'desc')
    .limit(1)
    .get();

  if (previousScans.empty) {
    throw new Error(`No previous scan found for target: ${target}. Please run a network or deep scan first.`);
  }

  const previousScan = previousScans.docs[0].data();
  const previousScanId = previousScans.docs[0].id;

  // Get open ports from previous scan results
  const previousResults = await db.collection('ScanResults')
    .where('parent_scan_id', '==', previousScanId)
    .where('host', '==', target)
    .get();

  if (previousResults.empty) {
    throw new Error(`No scan results found for target: ${target}`);
  }

  // Build port list from previous results
  const portSet = new Set();
  previousResults.docs.forEach(doc => {
    const data = doc.data();
    if (data.ports && Array.isArray(data.ports)) {
      data.ports.forEach(port => {
        if (port.state === 'open' && port.port) {
          portSet.add(port.port);
        }
      });
    }
  });

  const ports = Array.from(portSet);
  if (ports.length === 0) {
    throw new Error(`No open ports found in previous scan for target: ${target}`);
  }

  console.log(`[${scanId}] Running CVE scan on ports:`, ports);

  // Run targeted CVE scan on previously found open ports
  const cveArgs = [
    '-sT', '-sV', '--version-intensity', '9',
    '--script', 'vuln,vulners',
    '-p', ports.join(','),
    '-T3', '--max-retries', '2',
    '--host-timeout', '10m', '--script-timeout', '1m',
    '--open', '--reason', '-oX', '-'
  ];

  return await runNmap(cveArgs, target, PRESETS.cve_analysis.timeoutMs, scanId);
}

// Store scan results in Firestore
async function storeScanResults(scanId, parsed, runResult, preset) {
  for (const hostResult of parsed.hosts) {
    const uniqueCVEs = [...new Set(
      hostResult.foundVulns.flatMap(v => (v.CVEs && v.CVEs.length) ? v.CVEs : (v.CVE ? [v.CVE] : []))
        .filter(c => c && c !== 'N/A')
    )];

    // Create ScanResult record for this host
    const scanResultRef = db.collection('ScanResults').doc();
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

    await safeFirestoreSet(scanResultRef, {
      scan_id: scanId,
      host: hostResult.host,
      hostname: hostResult.hostname,
      mac_address: hostResult.mac_address,
      vendor: hostResult.vendor,
      host_status: hostResult.status,
      ports: sanitizedPorts,
      open_ports_count: hostResult.open_ports_count,
      CVEs: uniqueCVEs,
      security_assessment: hostResult.security_assessment,
      device_type: hostResult.device_type,
      recommendations: hostResult.recommendations,
      created_at: admin.firestore.FieldValue.serverTimestamp(),
      network_scan: preset === 'network_scan',
      parent_scan_id: scanId,
      scan_duration: runResult.duration,
      preset_used: preset
    });

    // Store vulnerabilities
    for (const vuln of hostResult.foundVulns) {
      const cves = (vuln.CVEs && v.CVEs.length) ? v.CVEs : (v.CVE ? [v.CVE] : ['N/A']);
      for (const cve of cves) {
        if (cve !== 'N/A') {
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
            parent_scan_id: scanId,
            preset_used: preset
          });
        }
      }
    }
  }
}


// --- Express API Setup ---
const app = express();
app.use(cors());
app.use(bodyParser.json());

// List available scan presets
app.get('/presets', (req, res) => {
  const presetsInfo = {
    network_scan: {
      name: 'network_scan',
      description: 'Discover all active hosts on a network and perform quick port scans on common ports',
      timeout: '10 minutes',
      best_for: 'Network inventory and quick security assessment',
      example_targets: ['192.168.1.0/24', '10.0.0.1-100', 'scanme.nmap.org']
    },
    deep_scan: {
      name: 'deep_scan',
      description: 'Comprehensive single target scan with service detection and basic security checks',
      timeout: '20 minutes',
      best_for: 'Detailed analysis of individual systems',
      example_targets: ['192.168.1.100', 'example.com', '10.0.0.50']
    },
    cve_analysis: {
      name: 'cve_analysis',
      description: 'CVE vulnerability analysis using previous scan results (requires existing scan data)',
      timeout: '15 minutes',
      best_for: 'Targeted vulnerability assessment',
      requirements: 'Must have previously scanned the target',
      example_targets: ['192.168.1.100'] // Must be previously scanned
    }
  };

  res.json({ presets: presetsInfo });
});

// Helper function for estimated duration


// Helper function for scan type categorization


app.post('/scan', async (req, res) => {
  try {
    const { target, preset, userId, targetId, scanName } = req.body;

    if (!target || !userId) return res.status(400).json({ error: 'target and userId required' });
    if (!PRESETS[preset]) return res.status(400).json({ error: 'unknown preset' });

    let scanTarget;
    try {
      scanTarget = validateNetworkTarget(target);
    } catch (e) {
      return res.status(400).json({ error: 'invalid target: ' + e.message });
    }

    if (!isAllowedTarget(scanTarget)) return res.status(403).json({ error: 'target not allowed' });

    const isNetworkScan = preset === 'network_scan' || /(\/\d{1,2}$|-\d{1,3}$|\[.*\]|,)/.test(scanTarget);

    // Create scan record in 'Scan'
    const scanId = uuidv4();
    await safeFirestoreSet(db.collection('Scan').doc(scanId), {
      status: 'ongoing',
      submitted_at: admin.firestore.FieldValue.serverTimestamp(),
      started_at: null,
      finished_at: null,
      scan_type: preset,
      target: scanTarget,
      user_id: userId,
      scan_name: scanName || `${preset} - ${scanTarget}`,
      is_network_scan: isNetworkScan,
      preset_used: preset
    });

    // Run scan asynchronously
    (async () => {
      let runResult;
      try {
        await safeFirestoreUpdate(db.collection('Scan').doc(scanId), {
          started_at: admin.firestore.FieldValue.serverTimestamp()
        });

        console.log(`[${scanId}] Starting ${preset} scan for: ${scanTarget}`);

        // Special handling for network scans
        if (preset === 'network_scan') {
          runResult = await runNetworkDiscoveryScan(scanTarget, scanId);
        }
        // Special handling for CVE analysis (requires previous scan)
        else if (preset === 'cve_analysis') {
          runResult = await runCveAnalysisScan(scanTarget, scanId, userId);
        }
        // Regular deep scan
        else {
          runResult = await runNmap(PRESETS[preset].args, scanTarget, PRESETS[preset].timeoutMs, scanId);
        }

        const stdout = runResult.stdout;
        console.log(`[${scanId}] Scan completed. stdout length: ${stdout.length}`);

        // Parse scan result
        const parsed = await parseNetworkScanXml(stdout, scanTarget);

        // Store results in Firestore
        await storeScanResults(scanId, parsed, runResult, preset);

        // Update main scan record
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
            executive_summary: parsed.executive_summary
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
      preset,
      target: scanTarget,
      is_network_scan: isNetworkScan,
      estimatedTimeout: PRESETS[preset].timeoutMs / 1000 + ' seconds',
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
    const resultsSnap = await db.collection('ScanResults')
      .where('parent_scan_id', '==', scanId)
      .get();

    const ScanResults = resultsSnap.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    // Get FoundVulns for all hosts in this scan
    let foundVulns = [];
    for (const result of ScanResults) {
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
      ScanResults: ScanResults,
      foundVulns: foundVulns,
      summary: {
        total_hosts: ScanResults.length,
        hosts_with_ports: ScanResults.filter(r => r.open_ports_count > 0).length,
        hosts_with_vulns: [...new Set(foundVulns.map(v => v.host))].length,
        total_vulnerabilities: foundVulns.length,
        total_open_ports: ScanResults.reduce((sum, r) => sum + r.open_ports_count, 0),
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
  features: ['network_discovery', 'deep_single_scan', 'cve_analysis'],
  simplicity: '3-option-scan-system'
}));

app.listen(PORT, () => console.log(`Nmap-Firebase API listening on ${PORT}`));