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
const cors = require('cors'); // ADDED from file 1

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
function cleanFirestoreData(data, _seen = new WeakSet()) {
  const seen = _seen || new WeakSet();
  if (data === undefined || data === null) return '';
  if (typeof data !== 'object') return data;
  if (seen.has(data)) return '[Circular]';
  seen.add(data);

  // Handle Firestore DocumentReference
  if (typeof data.path === 'string' && typeof data.id === 'string' && data.firestore) {
    return {
      _firestore_type: 'DocumentReference',
      path: data.path,
      id: data.id
    };
  }

  if (typeof data.toDate === 'function') {
    try { return data.toDate().toISOString(); } catch (e) { }
  }

  if (Array.isArray(data)) {
    return data.map(item =>
      (typeof item === 'object' && item !== null) ? cleanFirestoreData(item, seen) : item
    );
  }

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
  // Ultra Quick Scan: Just IPs and hostnames (30-60 seconds)
  quick_scan: {
    args: [
      '-sn',                   // Host discovery only
      '-PR',                   // ARP discovery (this works!)
      '-n',
      '-oX', '-'
    ],
    calculateTimeout: function (target) {
      const hostCount = estimateHostCount(target);
      const perHostTime = 1000; // 1 second per host (aggressive)
      const baseTime = 20000; // 20 seconds base
      return Math.min(baseTime + (hostCount * perHostTime), 300000); // Max 5 min
    },
    description: 'Fast network discovery - finds IPs, MAC addresses, hostnames, and device types',
    category: 'network_discovery',
    intensity: 'quick'
  },

  // Deep Scan: Unchanged
  deep_scan: {
    args: [
      '-sS', '-sV', '--version-intensity', '7', '-O', '-A',
      '--script', 'default,safe,banner,discovery',
      '-p1-1000,3389,5985,5986,1433,1521,3306,5432,27017',
      '-T4', '--min-rate', '500', '--max-retries', '2',
      '--host-timeout', '10m', '--open', '--reason',
      '--system-dns', '-oX', '-'
    ],
    calculateTimeout: function (target) {
      const hostCount = estimateHostCount(target);
      const perHostTime = 300000; // 5 minutes per host (deep scan is slow)
      const baseTime = 60000; // 1 minute base
      return Math.min(baseTime + (hostCount * perHostTime), 3600000); // Max 1 hour
    },
    description: 'Comprehensive single target scan',
    category: 'deep_scan',
    intensity: 'comprehensive'
  }
};

// Add this RIGHT AFTER the PRESETS object definition:
// Ensure all presets have calculateTimeout method
Object.values(PRESETS).forEach(preset => {
  if (!preset.calculateTimeout || typeof preset.calculateTimeout !== 'function') {
    console.warn(`Preset ${preset.description || 'unknown'} missing calculateTimeout, adding default`);
    preset.calculateTimeout = function (target) {
      const hostCount = estimateHostCount(target);
      const baseTime = 60000; // 1 minute base
      const perHostTime = 5000; // 5 seconds per host
      return Math.min(baseTime + (hostCount * perHostTime), 1800000); // Max 30 minutes
    };
  }
});

// --- Helper Functions ---

// Add these helper functions right before your app.post('/scan'):

function extractSampleIP(target) {
  console.log(`[Pre-scan] Extracting sample IP from: ${target}`);

  // Handle subnet notation (e.g., 10.208.192.0/26 → 10.208.192.1)
  const subnetMatch = target.match(/^(\d+\.\d+\.\d+)\.0\/(\d+)$/);
  if (subnetMatch) {
    return `${subnetMatch[1]}.1`; // Always use .1 for subnet gateways
  }

  // Handle IP ranges (e.g., 10.208.192.1-50 → 10.208.192.1)
  if (target.includes('-')) {
    return target.split('-')[0];
  }

  // Handle single IPs or other formats
  return target;
}

function checkNetworkReachable(ip) {
  return new Promise((resolve) => {
    console.log(`[Pre-scan] Pinging ${ip}...`);

    // Cross-platform ping command
    const isWindows = process.platform === 'win32';
    const pingArgs = isWindows
      ? ['-n', '2', '-w', '2000', ip]  // Windows: 2 packets, 2 second timeout
      : ['-c', '2', '-W', '2', ip];    // Linux/Mac: 2 packets, 2 second timeout

    const ping = spawn('ping', pingArgs);

    let isReachable = false;

    ping.on('close', (code) => {
      // On Windows, ping returns 0 even for unreachable hosts
      // So we need to check the output instead
      console.log(`[Pre-scan] Ping process exited with code: ${code}`);
      resolve(isReachable);
    });

    ping.stdout.on('data', (data) => {
      const output = data.toString();
      console.log(`[Pre-scan] Ping output: ${output.substring(0, 100)}...`);

      // Check for successful ping responses
      if (output.includes('TTL=') || output.includes('time=') || output.includes('bytes from')) {
        isReachable = true;
        console.log(`[Pre-scan] ✅ Host ${ip} is reachable!`);
      }
    });

    ping.stderr.on('data', (data) => {
      console.log(`[Pre-scan] Ping stderr: ${data.toString()}`);
    });

    // Timeout after 5 seconds
    setTimeout(() => {
      try {
        ping.kill();
        console.log(`[Pre-scan] Ping timeout for ${ip}`);
      } catch (e) { }
      resolve(isReachable);
    }, 5000);
  });
}

function estimateHostCount(target) {
  if (!target || typeof target !== 'string') return 1;

  // CIDR notation (e.g., 10.208.192.0/24)
  const cidrMatch = target.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
  if (cidrMatch) {
    const prefixBits = parseInt(cidrMatch[2]);
    return Math.pow(2, 32 - prefixBits) - 2; // Subtract network & broadcast
  }

  // IP range (e.g., 10.208.192.1-50)
  const rangeMatch = target.match(/^(\d+\.\d+\.\d+\.\d+)-(\d+)$/);
  if (rangeMatch) {
    const start = parseInt(rangeMatch[1].split('.').pop());
    const end = parseInt(rangeMatch[2]);
    return Math.max(1, end - start + 1);
  }

  // Multiple IPs (e.g., 10.208.192.1,10.208.192.2)
  if (target.includes(',')) {
    return Math.max(1, target.split(',').length);
  }

  // Single host
  return 1;
}

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
  if (!isValidNetwork) return extractHost(input);
  return input;
}

function isAllowedTarget(target) {
  return true;
}

function classifyDevice(ipv4, mac, vendor, hostname) {
  // Default classification
  let deviceType = 'Unknown Device';
  let deviceCategory = 'unknown';
  let confidence = 'low';

  // Convert to lowercase for easier matching
  const macUpper = mac ? mac.toUpperCase() : '';
  const vendorLower = vendor ? vendor.toLowerCase() : '';
  const hostnameLower = hostname ? hostname.toLowerCase() : '';

  console.log(`Classifying: IP=${ipv4}, MAC=${mac}, Vendor=${vendor}, Hostname=${hostname}`);

  // Classification by VENDOR first (most reliable)
  if (vendorLower.includes('fortinet') || vendorLower.includes('fortigate')) {
    deviceType = 'Network Firewall';
    deviceCategory = 'network_security';
    confidence = 'high';
  }
  else if (vendorLower.includes('cisco') || vendorLower.includes('juniper') || vendorLower.includes('aruba')) {
    deviceType = 'Network Switch/Router';
    deviceCategory = 'networking';
    confidence = 'high';
  }
  else if (vendorLower.includes('dell') || vendorLower.includes('hp') || vendorLower.includes('lenovo') ||
    vendorLower.includes('microsoft') || vendorLower.includes('asus') || vendorLower.includes('acer')) {
    deviceType = 'Windows PC/Server';
    deviceCategory = 'computer';
    confidence = 'high';
  }
  else if (vendorLower.includes('apple')) {
    deviceType = 'Apple Device';
    deviceCategory = 'computer';
    confidence = 'high';
  }
  else if (vendorLower.includes('vmware') || vendorLower.includes('parallels')) {
    deviceType = 'Virtual Machine';
    deviceCategory = 'virtualization';
    confidence = 'high';
  }
  else if (vendorLower.includes('samsung') || vendorLower.includes('lg') || vendorLower.includes('sony')) {
    deviceType = 'Smart Device/Phone';
    deviceCategory = 'iot';
    confidence = 'medium';
  }
  else if (vendorLower.includes('intel') || vendorLower.includes('broadcom') || vendorLower.includes('realtek')) {
    deviceType = 'Network Interface Card';
    deviceCategory = 'networking';
    confidence = 'medium';
  }

  // Classification by MAC OUI (if no vendor or low confidence)
  else if (macUpper.startsWith('00:09:0F')) { // Fortinet
    deviceType = 'Network Firewall';
    deviceCategory = 'network_security';
    confidence = 'high';
  }
  else if (macUpper.startsWith('F2:16') || macUpper.startsWith('F2:00') || macUpper.startsWith('F2:1C')) {
    deviceType = 'Virtual Machine';
    deviceCategory = 'virtualization';
    confidence = 'high';
  }
  else if (macUpper.startsWith('00:50:56') || macUpper.startsWith('005056')) { // VMware
    deviceType = 'VMware Virtual Machine';
    deviceCategory = 'virtualization';
    confidence = 'high';
  }
  else if (macUpper.startsWith('00:1C:42') || macUpper.startsWith('001C42')) { // Parallels
    deviceType = 'Parallels Virtual Machine';
    deviceCategory = 'virtualization';
    confidence = 'high';
  }
  else if (macUpper.startsWith('30:86:2D') || macUpper.startsWith('000D3A')) { // Microsoft
    deviceType = 'Microsoft/Hyper-V Virtual Machine';
    deviceCategory = 'virtualization';
    confidence = 'high';
  }
  else if (macUpper.startsWith('00:0C:29')) { // VMware ESX
    deviceType = 'VMware ESX Server';
    deviceCategory = 'virtualization';
    confidence = 'high';
  }
  else if (macUpper.startsWith('00:15:5D')) { // Hyper-V
    deviceType = 'Hyper-V Virtual Machine';
    deviceCategory = 'virtualization';
    confidence = 'high';
  }

  // Classification by hostname patterns
  else if (hostnameLower.includes('router') || hostnameLower.includes('gateway')) {
    deviceType = 'Network Router';
    deviceCategory = 'networking';
    confidence = 'medium';
  }
  else if (hostnameLower.includes('switch')) {
    deviceType = 'Network Switch';
    deviceCategory = 'networking';
    confidence = 'medium';
  }
  else if (hostnameLower.includes('firewall') || hostnameLower.includes('fw-')) {
    deviceType = 'Network Firewall';
    deviceCategory = 'network_security';
    confidence = 'medium';
  }
  else if (hostnameLower.includes('server') || hostnameLower.includes('srv-')) {
    deviceType = 'Server';
    deviceCategory = 'server';
    confidence = 'medium';
  }
  else if (hostnameLower.includes('print') || hostnameLower.includes('prn-')) {
    deviceType = 'Network Printer';
    deviceCategory = 'peripheral';
    confidence = 'medium';
  }
  else if (hostnameLower.includes('ap-') || hostnameLower.includes('wifi') || hostnameLower.includes('wireless')) {
    deviceType = 'Wireless Access Point';
    deviceCategory = 'networking';
    confidence = 'medium';
  }

  // Default classifications based on common patterns
  else {
    deviceType = 'Network Device';
    deviceCategory = 'networking';
    confidence = 'low';
  }

  console.log(`Classification: ${deviceType} (${deviceCategory}) - Confidence: ${confidence}`);

  return {
    device_type: deviceType,
    device_category: deviceCategory,
    confidence: confidence,
    classification_basis: vendor ? 'vendor' : (mac ? 'mac_oui' : 'default')
  };
}

function runNmap(args, target, presetName, scanId) {
  return new Promise((resolve, reject) => {
    // Validate preset exists
    const preset = PRESETS[presetName];
    if (!preset) {
      return reject(new Error(`Unknown preset: ${presetName}`));
    }

    // Calculate dynamic timeout based on preset and target size
    const timeoutMs = preset.calculateTimeout(target);

    const cmdArgs = [...args, target];
    console.log(`[${scanId}] Running: nmap ${cmdArgs.join(' ')}`);
    console.log(`[${scanId}] Dynamic timeout: ${timeoutMs}ms (${timeoutMs / 1000}s) for preset: ${presetName}`);

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
        const e = new Error(errorMsg);
        e.raw_path = tmpPath;
        reject(e);
      }
    });
  });
}

// --- Fixed XML Parser with Device Classification ---
async function parseNetworkScanXml(xmlText, targetNetwork, preset) {
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
        parse_error: 'empty output'
      };
    }

    console.log('Starting XML parsing, length:', xmlText.length);
    const hasHostData = xmlText.includes('<host>') && xmlText.includes('</host>');
    console.log('Has host data:', hasHostData);

    if (!hasHostData) {
      console.log('No host tags found in XML');
      return {
        network: targetNetwork,
        hosts: [],
        totalHosts: 0,
        activeHosts: 0,
        openPortsTotal: 0,
        vulnerabilitiesTotal: 0,
        parse_error: 'no host data'
      };
    }

    const result = await xml2js.parseStringPromise(xmlText, {
      explicitArray: false,
      mergeAttrs: false,
      normalize: true,
      trim: true,
      strict: false
    });

    console.log('XML parsed successfully, root keys:', Object.keys(result || {}));

    let hosts = [];

    // Handle UPPERCASE structure from xml2js
    if (result.NMAPRUN && result.NMAPRUN.HOST) {
      console.log('Found hosts in NMAPRUN.HOST (UPPERCASE)');
      hosts = Array.isArray(result.NMAPRUN.HOST) ? result.NMAPRUN.HOST : [result.NMAPRUN.HOST];
    } else if (result.nmaprun && result.nmaprun.host) {
      console.log('Found hosts in nmaprun.host (lowercase)');
      hosts = Array.isArray(result.nmaprun.host) ? result.nmaprun.host : [result.nmaprun.host];
    } else if (result.host) {
      console.log('Found hosts in root.host');
      hosts = Array.isArray(result.host) ? result.host : [result.host];
    }

    console.log(`Found ${hosts.length} hosts in XML structure`);

    const ScanResults = [];

    for (const hostObj of hosts) {
      if (!hostObj) {
        console.warn('Skipping empty host object');
        continue;
      }

      console.log('Processing host object structure:', Object.keys(hostObj));

      // Extract addresses - handle UPPERCASE structure
      let ipv4 = 'unknown';
      let mac = '';
      let vendor = '';
      let hostStatus = 'unknown';

      // Extract status - handle UPPERCASE STATUS
      if (hostObj.STATUS && hostObj.STATUS.$ && hostObj.STATUS.$.STATE) {
        hostStatus = hostObj.STATUS.$.STATE;
      }

      // Extract addresses - handle UPPERCASE ADDRESS array
      if (hostObj.ADDRESS) {
        const addresses = Array.isArray(hostObj.ADDRESS) ? hostObj.ADDRESS : [hostObj.ADDRESS];

        for (const addr of addresses) {
          if (addr.$ && addr.$.ADDRTYPE === 'ipv4') {
            ipv4 = addr.$.ADDR;
          } else if (addr.$ && addr.$.ADDRTYPE === 'mac') {
            mac = addr.$.ADDR;
            vendor = addr.$.VENDOR || '';
          }
        }
      }

      // Extract hostname - handle UPPERCASE HOSTNAMES
      let hostname = '';
      if (hostObj.HOSTNAMES) {
        // Check if it's empty (just whitespace) or has content
        if (typeof hostObj.HOSTNAMES === 'string' && hostObj.HOSTNAMES.trim() === '') {
          hostname = '';
        } else if (hostObj.HOSTNAMES.HOSTNAME) {
          const hostnames = Array.isArray(hostObj.HOSTNAMES.HOSTNAME)
            ? hostObj.HOSTNAMES.HOSTNAME
            : [hostObj.HOSTNAMES.HOSTNAME];

          if (hostnames.length > 0 && hostnames[0].$ && hostnames[0].$.NAME) {
            hostname = hostnames[0].$.NAME;
          }
        }
      }

      console.log(`Extracted - IP: ${ipv4}, Status: ${hostStatus}, MAC: ${mac}, Vendor: ${vendor}, Hostname: ${hostname || 'none'}`);

      // === ADD THIS: CALL THE DEVICE CLASSIFIER ===
      const deviceInfo = classifyDevice(ipv4, mac, vendor, hostname);
      console.log(`🎯 CLASSIFICATION: ${deviceInfo.device_type} (${deviceInfo.device_category}) - Confidence: ${deviceInfo.confidence}`);

      // Extract ports (quick scan won't have ports)
      let portsArr = [];
      if (hostObj.PORTS && hostObj.PORTS.PORT) {
        portsArr = Array.isArray(hostObj.PORTS.PORT) ? hostObj.PORTS.PORT : [hostObj.PORTS.PORT];
      }

      const detectedPorts = portsArr.map(p => {
        const service = p.SERVICE || {};
        const state = p.STATE || {};

        return {
          port: p.PORTID || '',
          protocol: p.PROTOCOL || 'tcp',
          state: state.STATE || 'unknown',
          state_reason: state.REASON || '',
          service: {
            name: service.NAME || 'unknown',
            product: service.PRODUCT || '',
            version: service.VERSION || '',
            extrainfo: service.EXTRAINFO || '',
            method: service.METHOD || 'table'
          },
          summary: `Port ${p.PORTID} ${state.STATE} - ${service.NAME || 'unknown'}`
        };
      });

      const openPorts = detectedPorts.filter(p => p.state === 'open').length;

      // === REPLACE the old device type detection with this ===
      ScanResults.push({
        host: ipv4,
        hostname: hostname,
        mac_address: mac,
        vendor: vendor,
        status: hostStatus,
        ports: detectedPorts,
        open_ports_count: openPorts,
        foundVulns: [],
        // Use the classified device info instead of the old deviceType
        device_type: deviceInfo.device_type,
        device_category: deviceInfo.device_category,
        classification_confidence: deviceInfo.confidence,
        classification_basis: deviceInfo.classification_basis,
        scan_timestamp: new Date().toISOString()
      });
    }

    const activeHosts = ScanResults.filter(host => host.status === 'up' || host.open_ports_count > 0);

    console.log(`Final Results - Total Hosts: ${ScanResults.length}, Active Hosts: ${activeHosts.length}`);

    if (ScanResults.length > 0) {
      console.log('Host details:', ScanResults.map(h => ({
        host: h.host,
        hostname: h.hostname,
        mac: h.mac_address,
        vendor: h.vendor,
        device_type: h.device_type,
        device_category: h.device_category,
        confidence: h.classification_confidence,
        status: h.status
      })));
    }

    return {
      network: targetNetwork,
      hosts: ScanResults,
      totalHosts: ScanResults.length,
      activeHosts: activeHosts.length,
      openPortsTotal: ScanResults.reduce((sum, host) => sum + host.open_ports_count, 0),
      vulnerabilitiesTotal: ScanResults.reduce((sum, host) => sum + host.foundVulns.length, 0),
      device_types: [...new Set(ScanResults.map(h => h.device_type))],
      timestamp: new Date().toISOString()
    };

  } catch (error) {
    console.error('Error parsing XML:', error);
    console.error('Error stack:', error.stack);
    return {
      network: targetNetwork,
      hosts: [],
      totalHosts: 0,
      activeHosts: 0,
      openPortsTotal: 0,
      vulnerabilitiesTotal: 0,
      parse_error: error.message
    };
  }
}

// Store scan results in Firestore
async function storeScanResults(scanId, parsed, runResult, preset) {
  for (const hostResult of parsed.hosts) {
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
        method: p.service?.method || ''
      },
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
      device_type: hostResult.device_type,
      created_at: admin.firestore.FieldValue.serverTimestamp(),
      network_scan: preset === 'quick_scan',
      parent_scan_id: scanId,
      scan_duration: runResult.duration,
      preset_used: preset
    });
  }
}

// --- Express API Setup ---
const app = express();
app.use(cors()); // ADDED from file 1
app.use(express.json()); // ADDED from file 1 (better than bodyParser.json())

// List available scan presets
app.get('/presets', (req, res) => {
  const presetsInfo = {
    quick_scan: {
      name: 'quick_scan',
      description: 'Ultra-fast network discovery - finds IPs, MAC addresses, hostnames, and device types in under 1 minute',
      timeout: '1 minute',
      best_for: 'Quick network inventory and device discovery',
      example_targets: ['192.168.1.0/24', '10.208.192.0/24', '10.0.0.1-100'],
      finds: ['IP addresses', 'MAC addresses', 'Hostnames', 'Device types', 'Network topology']
    },
    deep_scan: {
      name: 'deep_scan',
      description: 'Comprehensive single target scan with service detection, OS detection, and security scripts',
      timeout: '15 minutes',
      best_for: 'Detailed analysis of individual systems',
      example_targets: ['192.168.1.100', 'example.com', '10.208.195.132'],
      finds: ['Open ports', 'Service versions', 'Operating system', 'Security vulnerabilities', 'Service banners']
    }
  };

  res.json({ presets: presetsInfo });
});

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

    const isNetworkScan = preset === 'quick_scan' || /(\/\d{1,2}$|-\d{1,3}$|\[.*\]|,)/.test(scanTarget);

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

    // Check if it's a network scan and do pre-scan reachability check
    if (isNetworkScan) {
      console.log(`[${scanId}] Pre-scan reachability check...`);
      const sampleIP = extractSampleIP(scanTarget);
      const canPing = await checkNetworkReachable(sampleIP);

      if (!canPing) {
        await safeFirestoreUpdate(db.collection('Scan').doc(scanId), {
          status: 'failed',
          finished_at: admin.firestore.FieldValue.serverTimestamp(),
          error: 'Network unreachable - pre-scan check failed',
          error_details: { sample_ip: sampleIP }
        });
        return res.status(400).json({
          error: 'Network unreachable',
          message: `Cannot reach ${sampleIP}. The network segment may be firewalled or offline.`,
          suggestion: 'Try a different subnet or verify network connectivity'
        });
      }
      console.log(`[${scanId}] Network is reachable, proceeding with scan...`);
    }

    // Run scan asynchronously
    (async () => {
      let runResult;
      try {
        await safeFirestoreUpdate(db.collection('Scan').doc(scanId), {
          started_at: admin.firestore.FieldValue.serverTimestamp()
        });

        console.log(`[${scanId}] Starting ${preset} scan for: ${scanTarget}`);

        // Use appropriate scan function based on preset
        if (preset === 'quick_scan') {
          runResult = await runNmap(PRESETS.quick_scan.args, scanTarget, 'quick_scan', scanId);
        } else if (preset === 'deep_scan') {
          runResult = await runNmap(PRESETS.deep_scan.args, scanTarget, 'deep_scan', scanId);
        }

        const stdout = runResult.stdout;
        console.log(`[${scanId}] Scan completed. stdout length: ${stdout.length}`);

        // Parse scan result
        const parsed = await parseNetworkScanXml(stdout, scanTarget, preset);

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
            device_types: parsed.device_types,
            scan_duration: runResult.duration
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
      estimatedTimeout: PRESETS[preset].calculateTimeout(scanTarget) / 1000 + ' seconds',
      message: `Scan started. Use GET /scan/${scanId} to check status.`
    });

  } catch (err) {
    return res.status(500).json({ error: 'server error', details: err.message });
  }
});

// POST /scan/deep-single
app.post('/scan/deep-single', async (req, res) => {
  try {
    const { targetId, userId, scanName } = req.body;

    if (!targetId) {
      return res.status(400).json({ error: 'targetId required' });
    }

    // Get target details
    const targetDoc = await db.collection('Targets').doc(targetId).get();
    if (!targetDoc.exists) {
      return res.status(404).json({ error: 'Target not found' });
    }

    const target = targetDoc.data();

    // Use your existing scan endpoint logic
    const scanResponse = await fetch(`http://localhost:${PORT}/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: target.host,
        preset: 'deep_scan',
        userId: userId,
        scanName: scanName || `Deep scan of ${target.hostname || target.host}`
      })
    });

    const result = await scanResponse.json();

    // Update target scan count
    await safeFirestoreUpdate(db.collection('Targets').doc(targetId), {
      scan_count: admin.firestore.FieldValue.increment(1),
      last_seen: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json(result);

  } catch (err) {
    res.status(500).json({ error: 'server error', details: err.message });
  }
});

app.post('/scan/deep-multiple', async (req, res) => {
  try {
    const { targetIds, userId, scanName } = req.body;

    if (!targetIds || !Array.isArray(targetIds) || targetIds.length === 0) {
      return res.status(400).json({ error: 'targetIds array required' });
    }

    // Add limit check
    if (targetIds.length > 10) {
      return res.status(400).json({
        error: 'Too many targets selected',
        message: 'Please select 10 or fewer targets for deep scanning'
      });
    }

    // Get target details
    const targetsSnap = await db.collection('Targets')
      .where('target_id', 'in', targetIds)
      .get();

    if (targetsSnap.empty) {
      return res.status(404).json({ error: 'No targets found' });
    }

    const targets = targetsSnap.docs.map(doc => doc.data());
    const targetHosts = targets.map(t => t.host).join(',');

    // Create scan record
    const scanId = uuidv4();
    await safeFirestoreSet(db.collection('Scan').doc(scanId), {
      status: 'ongoing',
      submitted_at: admin.firestore.FieldValue.serverTimestamp(),
      started_at: null,
      finished_at: null,
      scan_type: 'deep_scan',
      target: targetHosts,
      target_ids: targetIds, // Store which targets were scanned
      user_id: userId,
      scan_name: scanName || `Deep scan of ${targets.length} targets`,
      is_network_scan: false,
      preset_used: 'deep_scan'
    });

    // Run deep scan asynchronously
    (async () => {
      let runResult;
      try {
        await safeFirestoreUpdate(db.collection('Scan').doc(scanId), {
          started_at: admin.firestore.FieldValue.serverTimestamp()
        });

        console.log(`[${scanId}] Starting deep scan for: ${targetHosts}`);
        runResult = await runNmap(PRESETS.deep_scan.args, targetHosts, 'deep_scan', scanId);

        const stdout = runResult.stdout;
        console.log(`[${scanId}] Deep scan completed`);

        // Parse and store results (your existing function)
        const parsed = await parseNetworkScanXml(stdout, targetHosts, 'deep_scan');
        await storeScanResults(scanId, parsed, runResult, 'deep_scan');

        // Update target scan counts
        for (const targetId of targetIds) {
          const targetRef = db.collection('Targets').doc(targetId);
          await safeFirestoreUpdate(targetRef, {
            scan_count: admin.firestore.FieldValue.increment(1),
            last_seen: admin.firestore.FieldValue.serverTimestamp()
          });
        }

        // Update main scan record
        await safeFirestoreUpdate(db.collection('Scan').doc(scanId), {
          status: 'complete',
          finished_at: admin.firestore.FieldValue.serverTimestamp(),
          summary: {
            total_hosts: parsed.totalHosts,
            active_hosts: parsed.activeHosts,
            open_ports_total: parsed.openPortsTotal,
            vulnerabilities_total: parsed.vulnerabilitiesTotal,
            device_types: parsed.device_types,
            scan_duration: runResult.duration
          }
        });

      } catch (err) {
        console.error(`[${scanId}] Deep scan failed: ${err.message}`);
        await safeFirestoreUpdate(db.collection('Scan').doc(scanId), {
          status: 'failed',
          finished_at: admin.firestore.FieldValue.serverTimestamp(),
          error: err.message
        });
      }
    })();

    res.json({
      scanId,
      status: 'ongoing',
      targets: targets.map(t => ({ host: t.host, hostname: t.hostname })),
      count: targets.length,
      message: `Deep scan started for ${targets.length} targets`
    });

  } catch (err) {
    res.status(500).json({ error: 'server error', details: err.message });
  }
});

// POST /targets/add-from-scan - WITH FIRESTORE REFERENCES
app.post('/targets/add-from-scan', async (req, res) => {
  try {
    const { scanId, userId, listName = "Discovered Targets" } = req.body;

    if (!scanId || !userId) {
      return res.status(400).json({ error: 'scanId and userId required' });
    }

    // Get scan details first - using Reference
    const scanRef = db.collection('Scan').doc(scanId);
    const scanDoc = await scanRef.get();
    if (!scanDoc.exists) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    const scanData = scanDoc.data();

    // Get scan results
    const resultsSnap = await db.collection('ScanResults')
      .where('parent_scan_id', '==', scanId)
      .get();

    if (resultsSnap.empty) {
      return res.status(404).json({ error: 'No scan results found' });
    }

    const targetRefs = []; // Store Firestore References
    const targetDetails = []; // Store basic info for quick display

    const targetListRef = db.collection('TargetLists').doc();

    // Create target list with proper References
    await safeFirestoreSet(targetListRef, {
      list_id: targetListRef.id,
      name: listName,
      description: `Targets discovered from scan ${scanId}`,
      targets: targetRefs, // Firestore References array
      target_details: targetDetails, // Basic info for quick access
      user_id: userId,
      source_scan: scanRef, // ← Firestore Reference to Scan
      source_scan_id: scanId, // Also keep string ID for convenience
      source_scan_name: scanData.scan_name,
      source_scan_target: scanData.target,
      created_at: admin.firestore.FieldValue.serverTimestamp(),
      target_count: 0,
      scan_count: 0,
      last_updated: admin.firestore.FieldValue.serverTimestamp()
    });

    // Add each host as a target with proper References
    for (const doc of resultsSnap.docs) {
      const hostData = doc.data();
      const targetRef = db.collection('Targets').doc();

      const target = {
        target_id: targetRef.id,
        host: hostData.host,
        hostname: hostData.hostname || '',
        mac_address: hostData.mac_address || '',
        vendor: hostData.vendor || '',
        device_type: hostData.device_type || 'Unknown',
        device_category: hostData.device_category || 'unknown',
        classification_confidence: hostData.classification_confidence || 'low',
        first_seen: admin.firestore.FieldValue.serverTimestamp(),
        last_seen: admin.firestore.FieldValue.serverTimestamp(),
        scan_count: 0,
        user_id: userId,
        discovered_in_scan: scanRef, // ← Firestore Reference to Scan
        discovered_in_scan_id: scanId, // Also keep string ID
        tags: ['discovered'],
        notes: `Discovered during ${scanData.scan_name} on ${new Date().toLocaleDateString()}`,
        classification_data: {
          basis: hostData.classification_basis || 'unknown',
          confidence: hostData.classification_confidence || 'low',
          device_type: hostData.device_type || 'Unknown',
          device_category: hostData.device_category || 'unknown'
        },
        // Reference to the parent target list
        target_lists: [targetListRef]
      };

      await safeFirestoreSet(targetRef, target);

      // Add Firestore Reference to the array
      targetRefs.push(targetRef);

      // Also store basic info for quick display
      targetDetails.push({
        target_id: targetRef.id,
        host: target.host,
        hostname: target.hostname,
        device_type: target.device_type,
        device_category: target.device_category,
        confidence: target.classification_confidence,
        added_at: admin.firestore.FieldValue.serverTimestamp()
      });
    }

    // Update target list with References
    await safeFirestoreUpdate(targetListRef, {
      targets: targetRefs,
      target_details: targetDetails,
      target_count: targetRefs.length,
      last_updated: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({
      success: true,
      targetsAdded: targetRefs.length,
      listId: targetListRef.id,
      scanReference: {
        scan_id: scanId,
        scan_name: scanData.scan_name,
        original_target: scanData.target
      },
      message: `Added ${targetRefs.length} targets to "${listName}" from scan ${scanId}`
    });

  } catch (err) {
    console.error('Error adding targets from scan:', err);
    res.status(500).json({ error: 'Failed to add targets', details: err.message });
  }
});

// GET /targets/lists/:userId - WITH REFERENCE RESOLUTION
app.get('/targets/lists/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    const listsSnap = await db.collection('TargetLists')
      .where('user_id', '==', userId)
      .orderBy('created_at', 'desc')
      .get();

    const lists = await Promise.all(
      listsSnap.docs.map(async (doc) => {
        const listData = doc.data();

        // Resolve Firestore References to get full target data
        const resolvedTargets = await Promise.all(
          (listData.targets || []).map(async (targetRef) => {
            const targetDoc = await targetRef.get();
            if (targetDoc.exists) {
              return {
                id: targetDoc.id,
                ...targetDoc.data(),
                // Include the reference itself
                _ref: targetRef
              };
            }
            return null;
          })
        );

        // Resolve scan reference if needed
        let sourceScanData = null;
        if (listData.source_scan) {
          const scanDoc = await listData.source_scan.get();
          if (scanDoc.exists) {
            sourceScanData = {
              id: scanDoc.id,
              ...scanDoc.data()
            };
          }
        }

        return {
          id: doc.id,
          ...listData,
          targets: resolvedTargets.filter(t => t !== null), // Full target objects
          target_details: listData.target_details || [], // Quick info fallback
          source_scan_data: sourceScanData, // Resolved scan data
          // Keep the references for frontend use
          _target_refs: listData.targets || [],
          _scan_ref: listData.source_scan
        };
      })
    );

    res.json({ lists });

  } catch (err) {
    console.error('Error getting target lists:', err);
    res.status(500).json({ error: 'Failed to get target lists', details: err.message });
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

    return res.json({
      scan: scanData,
      ScanResults: ScanResults,
      summary: {
        total_hosts: ScanResults.length,
        hosts_with_ports: ScanResults.filter(r => r.open_ports_count > 0).length,
        total_open_ports: ScanResults.reduce((sum, r) => sum + r.open_ports_count, 0),
        device_types: [...new Set(ScanResults.map(r => r.device_type))],
        overall_security_rating: scanData.summary?.overall_security_rating || 'UNKNOWN'
      }
    });
  } catch (err) {
    return res.status(500).json({ error: 'server error', details: err.message });
  }
});

// Get all scans for a user - FIXED from file 2
app.get('/scans/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    const scansSnap = await db.collection('Scan')
      .where('user_id', '==', userId)
      //.orderBy('submitted_at', 'desc')
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
  features: ['quick_discovery', 'deep_analysis', 'target_management']
}));

app.listen(PORT, () => console.log(`Enhanced Nmap-Firebase API listening on ${PORT}`));