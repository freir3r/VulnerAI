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
// Use this only when sending data to frontend, not when storing to Firestore
function cleanForResponse(data) {
  if (data === undefined || data === null) return null;
  if (typeof data !== 'object') return data;

  // Convert Firestore Timestamp to ISO string
  if (typeof data.toDate === 'function') {
    return data.toDate().toISOString();
  }

  // Handle DocumentReference
  if (data.path && data.id && data.firestore) {
    return { path: data.path, id: data.id };
  }

  if (Array.isArray(data)) {
    return data.map(cleanForResponse);
  }

  const cleaned = {};
  for (const [key, value] of Object.entries(data)) {
    cleaned[key] = cleanForResponse(value);
  }
  return cleaned;
}

function safeFirestoreSet(docRef, data) {
  const cleanedData = cleanForResponse(data);
  return docRef.set(cleanedData);
}

function safeFirestoreUpdate(docRef, data) {
  const cleanedData = cleanForResponse(data);
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
      '-n',
      '-PR',
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
      '-T3', '--min-rate', '500', '--max-retries', '2',
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

const { toVendor, isRandomMac } = require('@network-utils/vendor-lookup');

function classifyDevice(ipv4, mac, vendor, hostname) {
  // Default classification
  let deviceType = 'Unknown Device';
  let deviceCategory = 'unknown';
  let confidence = 'low';
  let detectedVendor = vendor;
  let classificationBasis = 'default';

  // Use MAC lookup to enhance vendor information
  if (!vendor && mac) {
    try {
      // Check if it's a random MAC first
      if (isRandomMac(mac)) {
        console.log(`[MAC Lookup] ${mac} is a random MAC address (mobile device privacy)`);
        detectedVendor = 'Random MAC (Mobile Device)';
        classificationBasis = 'random_mac';
      } else {
        const vendorResult = toVendor(mac);
        if (vendorResult && vendorResult !== '') {
          detectedVendor = vendorResult;
          classificationBasis = 'mac_oui';
          console.log(`[MAC Lookup] ${mac} → ${detectedVendor}`);
        } else {
          console.log(`[MAC Lookup] ${mac} → No vendor found in database`);
        }
      }
    } catch (error) {
      console.log(`[MAC Lookup] Error for ${mac}: ${error.message}`);
    }
  } else if (vendor) {
    classificationBasis = 'vendor';
  }

  // Convert to lowercase for easier matching
  const vendorLower = (detectedVendor || '').toLowerCase();
  const macUpper = mac ? mac.toUpperCase() : '';
  const hostnameLower = (hostname || '').toLowerCase();

  console.log(`Classifying: IP=${ipv4}, MAC=${mac}, Vendor=${detectedVendor}, Hostname=${hostname}`);

  // ENHANCED CLASSIFICATION LOGIC
  if (vendorLower.includes('huawei')) {
    deviceType = 'Network Router/Gateway';
    deviceCategory = 'networking';
    confidence = 'high';
  }
  else if (vendorLower.includes('fortinet') || vendorLower.includes('fortigate')) {
    deviceType = 'Network Firewall';
    deviceCategory = 'network_security';
    confidence = 'high';
  }
  else if (vendorLower.includes('cisco') || vendorLower.includes('juniper') || vendorLower.includes('aruba')) {
    deviceType = 'Network Switch/Router';
    deviceCategory = 'networking';
    confidence = 'high';
  }
  else if (vendorLower.includes('palo') && vendorLower.includes('alto')) {
    deviceType = 'Network Firewall';
    deviceCategory = 'network_security';
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
  else if (vendorLower.includes('google') || vendorLower.includes('nest')) {
    deviceType = 'Smart Home Device';
    deviceCategory = 'iot';
    confidence = 'high';
  }
  else if (vendorLower.includes('intel') || vendorLower.includes('broadcom') || vendorLower.includes('realtek')) {
    deviceType = 'Network Interface Card';
    deviceCategory = 'networking';
    confidence = 'medium';
  }
  else if (vendorLower.includes('canon') || vendorLower.includes('epson') || vendorLower.includes('brother')) {
    deviceType = 'Network Printer';
    deviceCategory = 'peripheral';
    confidence = 'high';
  }
  else if (vendorLower.includes('raspberry') || vendorLower.includes('arduino')) {
    deviceType = 'Embedded/IoT Device';
    deviceCategory = 'iot';
    confidence = 'high';
  }
  else if (vendorLower.includes('netgear') || vendorLower.includes('tplink') || vendorLower.includes('d-link')) {
    deviceType = 'Network Device';
    deviceCategory = 'networking';
    confidence = 'medium';
  }
  else if (vendorLower.includes('sagemcom')) {
    deviceType = 'Network Router/Gateway';
    deviceCategory = 'networking';
    confidence = 'high';
  }
  else if (vendorLower.includes('asrock') || vendorLower.includes('micro-star')) {
    deviceType = 'Computer Motherboard';
    deviceCategory = 'computer';
    confidence = 'high';
  }
  else if (vendorLower.includes('lg innotek')) {
    deviceType = 'Smart Device/Phone';
    deviceCategory = 'iot';
    confidence = 'high';
  }
  else if (vendorLower.includes('random mac')) {
    deviceType = 'Mobile Device (Random MAC)';
    deviceCategory = 'mobile';
    confidence = 'medium';
  }

  // Default classification based on available data
  else if (!mac && !detectedVendor) {
    deviceType = 'Unknown Host';
    deviceCategory = 'unknown';
    confidence = 'very-low';
  }
  else if (mac || detectedVendor) {
    deviceType = 'Network Device';
    deviceCategory = 'networking';
    confidence = 'low';
  }

  console.log(`🎯 CLASSIFICATION: ${deviceType} (${deviceCategory}) - Confidence: ${confidence}`);

  return {
    device_type: deviceType,
    device_category: deviceCategory,
    confidence: confidence,
    vendor: detectedVendor,
    classification_basis: classificationBasis
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
async function parseDeepScanXml(xmlText, targetNetwork, uidRef = null, targetIdOrRef = null) {
  console.log('🎯 [parseDeepScanXml] FUNCTION CALLED - Starting XML parsing');
  console.log(`📏 XML length: ${xmlText.length} chars`);
  
  try {
    if (!xmlText || typeof xmlText !== 'string' || xmlText.trim() === '') {
      console.warn('❌ [parseDeepScanXml] Empty XML text provided');
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

    // FIX: Look for <host (with space) instead of <host>
    const hasHostStart = xmlText.includes('<host ');
    const hasHostEnd = xmlText.includes('</host>');
    console.log(`🔍 [parseDeepScanXml] XML contains <host : ${hasHostStart}`);
    console.log(`🔍 [parseDeepScanXml] XML contains </host>: ${hasHostEnd}`);
    
    console.log('🔄 [parseDeepScanXml] Starting XML parsing with xml2js...');
    
    const result = await xml2js.parseStringPromise(xmlText, {
      explicitArray: false,
      mergeAttrs: true,
      normalize: true,
      trim: true,
      strict: false
    });

    console.log('✅ [parseDeepScanXml] XML parsed successfully');
    console.log('📋 [parseDeepScanXml] Root object keys:', Object.keys(result));

    // FIX: Handle both uppercase and lowercase root elements
    const root = result.nmaprun || result.NMAPRUN;
    if (!root) {
      console.log('❌ [parseDeepScanXml] No nmaprun/NMAPRUN found in parsed result');
      console.log('🔍 [parseDeepScanXml] Available keys:', Object.keys(result));
      return {
        network: targetNetwork,
        hosts: [],
        totalHosts: 0,
        activeHosts: 0,
        openPortsTotal: 0,
        vulnerabilitiesTotal: 0,
        parse_error: 'no nmaprun data'
      };
    }

    console.log('🔍 [parseDeepScanXml] Root element keys:', Object.keys(root));

    // FIX: Handle both uppercase and lowercase host elements
    let hostsArray = [];
    
    if (root.host || root.HOST) {
      const hostData = root.host || root.HOST;
      hostsArray = Array.isArray(hostData) ? hostData : [hostData];
      console.log(`🎯 [parseDeepScanXml] Found ${hostsArray.length} hosts`);
    } else {
      console.log('❌ [parseDeepScanXml] No host/HOST data found in root');
      console.log('🔍 [parseDeepScanXml] Available keys in root:', Object.keys(root));
      return {
        network: targetNetwork,
        hosts: [],
        totalHosts: 0,
        activeHosts: 0,
        openPortsTotal: 0,
        vulnerabilitiesTotal: 0,
        parse_error: 'no host data in XML'
      };
    }

    const ScanResults = [];

    for (const [index, hostObj] of hostsArray.entries()) {
      try {
        console.log(`\n🔍 [parseDeepScanXml] Processing host ${index + 1}/${hostsArray.length}`);
        console.log('📋 [parseDeepScanXml] Host object keys:', Object.keys(hostObj));

        // FIX: Handle both uppercase and lowercase properties
        const status = hostObj.status?.state || hostObj.STATUS?.STATE || 'unknown';
        console.log(`📊 [parseDeepScanXml] Host status: ${status}`);

        // === ADDRESSES ===
        let ipv4 = 'unknown', mac = '', vendor = '';
        const addressesRaw = hostObj.address || hostObj.ADDRESS || [];
        const addresses = Array.isArray(addressesRaw) ? addressesRaw : (addressesRaw ? [addressesRaw] : []);
        
        console.log(`📍 [parseDeepScanXml] Found ${addresses.length} addresses`);
        
        for (const addr of addresses) {
          // FIX: Handle both uppercase and lowercase address properties
          const addrType = addr.addrtype || addr.ADDRTYPE;
          const addrVal = addr.addr || addr.ADDR;
          const addrVendor = addr.vendor || addr.VENDOR || '';
          
          console.log(`   📍 Address: ${addrVal} (${addrType}) vendor: ${addrVendor}`);
          
          if (addrType === 'ipv4') {
            ipv4 = addrVal;
          } else if (addrType === 'mac') {
            mac = addrVal;
            vendor = vendor || addrVendor;
          }
        }

        // === HOSTNAMES ===
        let hostname = '';
        const hostnamesRaw = hostObj.hostnames || hostObj.HOSTNAMES || {};
        
        if (hostnamesRaw.hostname || hostnamesRaw.HOSTNAME) {
          const hostnameData = hostnamesRaw.hostname || hostnamesRaw.HOSTNAME;
          const hostnamesList = Array.isArray(hostnameData) ? hostnameData : [hostnameData];
          if (hostnamesList.length > 0) {
            const firstHostname = hostnamesList[0];
            hostname = firstHostname.name || firstHostname.NAME || '';
            console.log(`🏷️  [parseDeepScanXml] Found hostname: ${hostname}`);
          }
        }

        // === PORTS ===
        let portsArr = [];
        const portsRoot = hostObj.ports || hostObj.PORTS || {};
        
        if (portsRoot.port || portsRoot.PORT) {
          const portData = portsRoot.port || portsRoot.PORT;
          portsArr = Array.isArray(portData) ? portData : [portData];
          console.log(`🔌 [parseDeepScanXml] Found ${portsArr.length} ports`);
        }

        const detectedPorts = portsArr.map(p => {
          // FIX: Handle both uppercase and lowercase port properties
          const portid = p.portid || p.PORTID || '';
          const protocol = p.protocol || p.PROTOCOL || 'tcp';
          
          const stateObj = p.state || p.STATE || {};
          const state_state = stateObj.state || stateObj.STATE || 'unknown';
          const state_reason = stateObj.reason || stateObj.REASON || '';
          const state_reason_ttl = stateObj.reason_ttl || stateObj.REASON_TTL || '';

          const serviceObj = p.service || p.SERVICE || {};
          const service = {
            name: serviceObj.name || serviceObj.NAME || 'unknown',
            product: serviceObj.product || serviceObj.PRODUCT || '',
            version: serviceObj.version || serviceObj.VERSION || '',
            extrainfo: serviceObj.extrainfo || serviceObj.EXTRAINFO || '',
            ostype: serviceObj.ostype || serviceObj.OSTYPE || '',
            method: serviceObj.method || serviceObj.METHOD || 'table',
            conf: serviceObj.conf || serviceObj.CONF || '0',
            cpe: serviceObj.cpe || serviceObj.CPE || '',
            tunnel: serviceObj.tunnel || serviceObj.TUNNEL || ''
          };

          console.log(`   🔌 Port ${portid}: ${state_state} - ${service.name} ${service.version}`);

          return {
            port: portid,
            protocol,
            state: state_state,
            state_reason,
            state_reason_ttl,
            service,
            scripts: p.script || p.SCRIPT || {},
            banner: '',
            summary: `Port ${portid} ${state_state} - ${service.name} ${service.version}`.trim()
          };
        });

        const openPorts = detectedPorts.filter(p => p.state === 'open').length;

        // === DEVICE CLASSIFICATION ===
        const deviceInfo = classifyDevice(ipv4, mac, vendor, hostname);

        // Build host result
        const hostResult = {
          host: ipv4,
          hostname: hostname || '',
          mac_address: mac || '',
          vendor: vendor || '',
          status,
          ports: detectedPorts,
          open_ports_count: openPorts,
          foundVulns: [],
          device_type: deviceInfo.device_type,
          device_category: deviceInfo.device_category,
          classification_confidence: deviceInfo.confidence,
          classification_basis: deviceInfo.classification_basis,
          scan_timestamp: new Date().toISOString(),
          scan_type: 'deep_scan'
        };

        console.log(`✅ [parseDeepScanXml] Successfully parsed host: ${ipv4} with ${openPorts} open ports`);
        ScanResults.push(hostResult);

      } catch (hostError) {
        console.error(`❌ [parseDeepScanXml] Error processing host ${index + 1}:`, hostError.message);
      }
    }

    console.log(`\n🎉 [parseDeepScanXml] COMPLETED: ${ScanResults.length} hosts parsed successfully`);
    
    const activeHosts = ScanResults.filter(h => h.status === 'up' || h.open_ports_count > 0);

    return {
      network: targetNetwork,
      hosts: ScanResults,
      totalHosts: ScanResults.length,
      activeHosts: activeHosts.length,
      openPortsTotal: ScanResults.reduce((sum, h) => sum + (h.open_ports_count || 0), 0),
      vulnerabilitiesTotal: ScanResults.reduce((sum, h) => sum + (h.foundVulns?.length || 0), 0),
      device_types: [...new Set(ScanResults.map(h => h.device_type))],
      timestamp: new Date().toISOString(),
      scan_type: 'deep_scan'
    };

  } catch (err) {
    console.error('💥 [parseDeepScanXml] CRITICAL XML parse error:', err.message);
    console.error('🔍 [parseDeepScanXml] Error stack:', err.stack);
    return {
      network: targetNetwork,
      hosts: [],
      totalHosts: 0,
      activeHosts: 0,
      openPortsTotal: 0,
      vulnerabilitiesTotal: 0,
      parse_error: err.message,
      scan_type: 'deep_scan'
    };
  }
}



// --------------------------------------------------
// NEW: Store results functions (Quick vs Deep)
// --------------------------------------------------

// Store quick scan results: keep it lean (fewer fields)
// Store scan results for quick scans
async function storeQuickScanResults(scanId, parsed, runResult, preset, userId = null, targetId = null) {
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

    const docData = {
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
      preset_used: preset,
      // New fields requested:
      requested_by: userId ? db.collection('User').doc(userId) : null,
      target_id: targetId || null
    };

    await safeFirestoreSet(scanResultRef, docData);
  }
}


// Add this helper function for security metrics
function calculateSecurityMetrics(hosts) {
  let vulnerabilities = 0;
  let highRiskPorts = 0;
  let unusualServices = 0;

  const riskPorts = [21, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986];
  const unusualServicesList = ['vmware-auth', 'unknown', 'unusual-port'];

  hosts.forEach(host => {
    host.ports.forEach(port => {
      // Count vulnerabilities from scripts
      if (port.scripts) {
        Object.values(port.scripts).forEach(output => {
          if (output.toLowerCase().includes('vulnerable') ||
            output.toLowerCase().includes('exploit') ||
            output.toLowerCase().includes('cve')) {
            vulnerabilities++;
          }
        });
      }

      // Count high risk ports
      if (riskPorts.includes(parseInt(port.port)) && port.state === 'open') {
        highRiskPorts++;
      }

      // Count unusual services
      if (unusualServicesList.includes(port.service.name) && port.state === 'open') {
        unusualServices++;
      }
    });
  });

  return {
    vulnerabilities,
    high_risk_ports: highRiskPorts,
    unusual_services: unusualServices,
    overall_risk_level: calculateRiskLevel(vulnerabilities, highRiskPorts)
  };
}

function calculateRiskLevel(vulns, riskPorts) {
  const score = vulns * 10 + riskPorts * 5;
  if (score >= 20) return 'HIGH';
  if (score >= 10) return 'MEDIUM';
  if (score >= 5) return 'LOW';
  return 'VERY_LOW';
}

// Add this helper function for security metrics
function calculateSecurityMetrics(hosts) {
  let vulnerabilities = 0;
  let highRiskPorts = 0;
  let unusualServices = 0;

  const riskPorts = [21, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986];
  const unusualServicesList = ['vmware-auth', 'unknown', 'unusual-port'];

  hosts.forEach(host => {
    host.ports.forEach(port => {
      // Count vulnerabilities from scripts
      if (port.scripts) {
        Object.values(port.scripts).forEach(output => {
          if (output.toLowerCase().includes('vulnerable') ||
            output.toLowerCase().includes('exploit') ||
            output.toLowerCase().includes('cve')) {
            vulnerabilities++;
          }
        });
      }

      // Count high risk ports
      if (riskPorts.includes(parseInt(port.port)) && port.state === 'open') {
        highRiskPorts++;
      }

      // Count unusual services
      if (unusualServicesList.includes(port.service.name) && port.state === 'open') {
        unusualServices++;
      }
    });
  });

  return {
    vulnerabilities,
    high_risk_ports: highRiskPorts,
    unusual_services: unusualServices,
    overall_risk_level: calculateRiskLevel(vulnerabilities, highRiskPorts)
  };
}

function calculateRiskLevel(vulns, riskPorts) {
  const score = vulns * 10 + riskPorts * 5;
  if (score >= 20) return 'HIGH';
  if (score >= 10) return 'MEDIUM';
  if (score >= 5) return 'LOW';
  return 'VERY_LOW';
}


// --------------------------------------------------
// END store functions
// --------------------------------------------------


// --- Express API Setup ---
const app = express();
app.use(bodyParser.json());

// List available scan presets
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
    const { target, preset, userId, targetId: providedTargetId, scanName } = req.body;

    // Require userId and preset, but allow either target OR targetId
    if (!userId) return res.status(400).json({ error: 'userId required' });
    if (!PRESETS[preset]) return res.status(400).json({ error: 'unknown preset' });

    // Resolve target: either direct target string or lookup by targetId
    let scanTarget = target && typeof target === 'string' && target.trim().length > 0 ? target.trim() : null;
    let targetId = providedTargetId || null;

    if (!scanTarget && targetId) {
      // fetch target doc
      const tdoc = await db.collection('Targets').doc(targetId).get();
      if (!tdoc.exists) {
        return res.status(404).json({ error: 'Target ID not found' });
      }
      const tdata = tdoc.data();
      if (!tdata || !tdata.host) {
        return res.status(400).json({ error: 'Target document missing host field' });
      }
      scanTarget = tdata.host;
    }

    if (!scanTarget) return res.status(400).json({ error: 'target (IP/host) or targetId required' });

    // Validate network target string (this will throw if invalid)
    try {
      scanTarget = validateNetworkTarget(scanTarget);
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
      preset_used: preset,
      // store targetId if provided so we keep linkage at scan level too
      target_id: targetId || null
    });

    // pre-scan reachability check
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

    // Run scan asynchronously (rest unchanged)...
    (async () => {
      let runResult;
      try {
        await safeFirestoreUpdate(db.collection('Scan').doc(scanId), {
          started_at: admin.firestore.FieldValue.serverTimestamp()
        });

        console.log(`[${scanId}] Starting ${preset} scan for: ${scanTarget}`);

        if (preset === 'quick_scan') {
          runResult = await runNmap(PRESETS.quick_scan.args, scanTarget, 'quick_scan', scanId);
        } else if (preset === 'deep_scan') {
          runResult = await runNmap(PRESETS.deep_scan.args, scanTarget, 'deep_scan', scanId);
        }

        const stdout = runResult.stdout || '';
        console.log(`[${scanId}] Scan completed. stdout length: ${stdout.length}`);

        const parsed = await parseNetworkScanXml(stdout, scanTarget, preset);

        // Pass userId and targetId into the store call so ScanResults include references
        if (preset === 'quick_scan') {
          await storeQuickScanResults(scanId, parsed, runResult, preset, userId, targetId);
        } else {
          await storeDeepScanResults(scanId, parsed, runResult, preset, userId, targetId);
        }

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
      targetId: targetId || null,
      is_network_scan: isNetworkScan,
      estimatedTimeout: PRESETS[preset].calculateTimeout(scanTarget) / 1000 + ' seconds',
      message: `Scan started. Use GET /scan/${scanId} to check status.`
    });

  } catch (err) {
    return res.status(500).json({ error: 'server error', details: err.message });
  }
});

app.post('/scan/deep', async (req, res) => {
  try {
    const { targetId, targetIds, ipList, target: directTarget, userId, scanName } = req.body;

    console.log('=== DEEP SCAN REQUEST ===');
    console.log('Request body:', JSON.stringify(req.body, null, 2));

    // Validate input
    if (!userId) {
      return res.status(400).json({ error: 'userId required' });
    }

    // Accept either: ipList OR targetIds/targetId OR a direct single target (target)
    const hasTargetIds = targetId || (targetIds && Array.isArray(targetIds) && targetIds.length > 0);
    const hasIpList = ipList && typeof ipList === 'string' && ipList.trim().length > 0;
    const hasDirectTarget = directTarget && typeof directTarget === 'string' && directTarget.trim().length > 0;

    if (!hasTargetIds && !hasIpList && !hasDirectTarget) {
      return res.status(400).json({
        error: 'Either target, targetId, targetIds, or ipList required',
        usage: {
          single_target: '{"targetId": "target123", "userId": "user123", "scanName": "..."}',
          multiple_targets: '{"targetIds": ["target1", "target2"], "userId": "user123", "scanName": "..."}',
          direct_ips: '{"ipList": "192.168.1.1,192.168.1.100-150,10.0.0.0/24", "userId": "user123", "scanName": "..."}',
          single_ip: '{"target": "192.168.1.123", "userId": "user123", "scanName": "..."}'
        }
      });
    }

    let targets = [];
    let targetHosts = '';
    let scanMode = '';
    let resolvedTargetId = null; // will hold single targetId when scanning one known target

    // Direct IP/host provided
    if (hasDirectTarget) {
      scanMode = 'single_target';
      targetHosts = directTarget.trim();
      targets = [{ host: targetHosts, hostname: '' }];
      console.log(`[Deep Scan] Direct single target provided: ${targetHosts}`);
    }
    // IP list
    else if (hasIpList) {
      scanMode = 'ip_list';
      targetHosts = ipList.trim();
      const sampleIps = extractSampleIPsFromList(targetHosts);
      targets = sampleIps.map(ip => ({ host: ip, hostname: '' }));
      console.log(`[Deep Scan] Direct IP list scan: ${targetHosts}`);
    }
    // Single targetId
    else if (targetId) {
      scanMode = 'single_target';
      resolvedTargetId = targetId;
      const targetDoc = await db.collection('Targets').doc(targetId).get();
      if (!targetDoc.exists) {
        return res.status(404).json({ error: 'Target not found' });
      }
      const target = targetDoc.data();
      targets = [target];
      targetHosts = target.host;
      console.log(`[Deep Scan] Single targetId scan: ${targetHosts} (id=${targetId})`);
    }
    // Multiple targets
    else {
      // targetIds must be an array here (we validated earlier)
      scanMode = 'multiple_targets';
      if (!targetIds || !Array.isArray(targetIds)) {
        return res.status(400).json({ error: 'targetIds must be an array for multiple_targets' });
      }
      if (targetIds.length > 10) {
        return res.status(400).json({
          error: 'Too many targets selected',
          message: 'Please select 10 or fewer targets for deep scanning'
        });
      }

      const targetsSnap = await db.collection('Targets')
        .where('target_id', 'in', targetIds)
        .get();

      if (targetsSnap.empty) {
        return res.status(404).json({ error: 'No targets found' });
      }

      targets = targetsSnap.docs.map(doc => doc.data());
      targetHosts = targets.map(t => t.host).join(',');
      console.log(`[Deep Scan] Multiple targetIds scan for ${targets.length} targets`);
    }

    // Validate/normalize targetHosts (only for single host or composed host string)
    try {
      // Only attempt validation for non-ip_list (ip_list can be CIDR/ranges which validateNetworkTarget handles too)
      targetHosts = validateNetworkTarget(targetHosts);
    } catch (e) {
      return res.status(400).json({ error: 'invalid target: ' + e.message });
    }

    // Create scan record
    const scanId = uuidv4();
    console.log(`[${scanId}] Creating scan record...`);

    await safeFirestoreSet(db.collection('Scan').doc(scanId), {
      status: 'ongoing',
      submitted_at: admin.firestore.FieldValue.serverTimestamp(),
      started_at: null,
      finished_at: null,
      scan_type: 'deep_scan',
      target: targetHosts,
      target_ids: scanMode === 'multiple_targets' ? targetIds : (scanMode === 'single_target' && resolvedTargetId ? [resolvedTargetId] : []),
      ip_list_used: scanMode === 'ip_list',
      user_id: userId,
      scan_name: scanName || generateScanName(scanMode, targets, targetHosts),
      is_network_scan: false,
      preset_used: 'deep_scan',
      scan_mode: scanMode
    });

    console.log(`[${scanId}] Scan record created, starting async scan...`);

    // Run deep scan asynchronously with better debugging
    (async () => {
      let runResult;
      try {
        console.log(`[${scanId}] Updating scan to started...`);
        await safeFirestoreUpdate(db.collection('Scan').doc(scanId), {
          started_at: admin.firestore.FieldValue.serverTimestamp()
        });

        console.log(`[${scanId}] Starting deep scan (${scanMode}): ${targetHosts}`);
        runResult = await runNmap(PRESETS.deep_scan.args, targetHosts, 'deep_scan', scanId);

        const stdout = runResult.stdout || '';
        console.log(`[${scanId}] Deep scan completed, stdout length: ${stdout.length}`);
        console.log(`[${scanId}] Run result keys:`, Object.keys(runResult));

        // Parse and store results with debugging
        console.log(`[${scanId}] === DEBUG XML CONTENT ===`);
        console.log(`[${scanId}] Full XML length: ${stdout.length}`);
        console.log(`[${scanId}] XML contains <host>: ${stdout.includes('<host>')}`);
        console.log(`[${scanId}] XML contains </host>: ${stdout.includes('</host>')}`);
        console.log(`[${scanId}] Host start position: ${stdout.indexOf('<host>')}`);
        console.log(`[${scanId}] Host end position: ${stdout.indexOf('</host>')}`);

        // Show a sample of the host section
        const hostStart = stdout.indexOf('<host');
        if (hostStart !== -1) {
          const hostEnd = stdout.indexOf('</host>', hostStart);
          if (hostEnd !== -1) {
            console.log(`[${scanId}] Host section sample (first 300 chars):`);
            console.log(stdout.substring(hostStart, Math.min(hostStart + 300, hostEnd + 7)));
          }
        }
        console.log(`[${scanId}] Starting XML parsing...`);
        const parsed = await parseDeepScanXml(stdout, targetHosts);
        console.log(`[${scanId}] XML parsing completed, found ${parsed.hosts ? parsed.hosts.length : 0} hosts`);

        // Debug the parsed data
        if (parsed.hosts && parsed.hosts.length > 0) {
          console.log(`[${scanId}] First host sample:`, {
            host: parsed.hosts[0].host,
            ports_count: parsed.hosts[0].ports ? parsed.hosts[0].ports.length : 0,
            device_type: parsed.hosts[0].device_type
          });
        } else {
          console.log(`[${scanId}] WARNING: No hosts found in parsed data`);
        }

        // Use the new store function with debugging
        const usedTargetIdForResults = scanMode === 'single_target' ? (resolvedTargetId || null) : (scanMode === 'multiple_targets' ? null : null);

        console.log(`[${scanId}] Calling storeDeepScanResults...`);
        console.log(`[${scanId}] Parameters:`, {
          scanId,
          hostsCount: parsed.hosts ? parsed.hosts.length : 0,
          userId,
          targetId: usedTargetIdForResults,
          preset: 'deep_scan'
        });

        // Add try-catch around the store function call
        try {
          await storeDeepScanResults(scanId, parsed, runResult, 'deep_scan', userId, usedTargetIdForResults);
          console.log(`[${scanId}] storeDeepScanResults completed successfully`);
        } catch (storeError) {
          console.error(`[${scanId}] storeDeepScanResults failed:`, storeError.message);
          console.error(`[${scanId}] Store error stack:`, storeError.stack);
          throw storeError; // Re-throw to be caught by outer catch
        }

        // Update target scan counts
        if (scanMode !== 'ip_list' && scanMode !== 'single_target' || (scanMode === 'single_target' && resolvedTargetId)) {
          const targetIdsToUpdate = scanMode === 'single_target' && resolvedTargetId ? [resolvedTargetId] : (scanMode === 'multiple_targets' ? targetIds : []);
          console.log(`[${scanId}] Updating ${targetIdsToUpdate.length} target scan counts`);
          for (const tId of targetIdsToUpdate) {
            const targetRef = db.collection('Targets').doc(tId);
            await safeFirestoreUpdate(targetRef, {
              scan_count: admin.firestore.FieldValue.increment(1),
              last_seen: admin.firestore.FieldValue.serverTimestamp()
            });
          }
        }

        // Update main scan record
        console.log(`[${scanId}] Updating scan record to complete`);
        await safeFirestoreUpdate(db.collection('Scan').doc(scanId), {
          status: 'complete',
          finished_at: admin.firestore.FieldValue.serverTimestamp(),
          summary: {
            total_hosts: parsed.totalHosts,
            active_hosts: parsed.activeHosts,
            open_ports_total: parsed.openPortsTotal,
            vulnerabilities_total: parsed.vulnerabilitiesTotal,
            device_types: parsed.device_types,
            scan_duration: runResult.duration,
            scan_mode: scanMode
          }
        });

        console.log(`[${scanId}] Deep scan process completed successfully`);

      } catch (err) {
        console.error(`[${scanId}] Deep scan failed:`, err.message);
        console.error(`[${scanId}] Error stack:`, err.stack);
        await safeFirestoreUpdate(db.collection('Scan').doc(scanId), {
          status: 'failed',
          finished_at: admin.firestore.FieldValue.serverTimestamp(),
          error: err.message,
          error_details: {
            step: 'async_processing',
            stack: err.stack
          }
        });
      }
    })();

    res.json({
      scanId,
      status: 'ongoing',
      scan_mode: scanMode,
      targets: targets.map(t => ({
        host: t.host,
        hostname: t.hostname,
        target_id: t.target_id
      })),
      target_count: targets.length,
      scan_target: targetHosts,
      message: generateScanMessage(scanMode, targets, targetHosts)
    });

  } catch (err) {
    console.error('Error in deep scan endpoint:', err);
    res.status(500).json({ error: 'server error', details: err.message });
  }
});

async function storeDeepScanResults(scanId, parsed, runResult, preset, userId, targetId) {
  console.log(`[DEBUG storeDeepScanResults] Starting storage for scan: ${scanId}`);
  console.log(`[DEBUG] userId: ${userId}, targetId: ${targetId}`);
  console.log(`[DEBUG] Number of hosts to store: ${parsed.hosts ? parsed.hosts.length : 0}`);

  // Check if we have hosts to process
  if (!parsed.hosts || !Array.isArray(parsed.hosts) || parsed.hosts.length === 0) {
    console.log('[DEBUG] No hosts to store, exiting function');
    return;
  }

  let storedCount = 0;
  let errorCount = 0;

  for (const [index, hostResult] of parsed.hosts.entries()) {
    try {
      console.log(`[DEBUG] Processing host ${index + 1}/${parsed.hosts.length}: ${hostResult.host}`);

      const scanResultRef = db.collection('ScanResults').doc();
      console.log(`[DEBUG] Created document reference: ${scanResultRef.id}`);

      // Handle userId reference safely
      let userRef = null;
      if (userId) {
        try {
          console.log(`[DEBUG] Checking if user ${userId} exists...`);
          const userDoc = await db.collection('User').doc(userId).get();
          if (userDoc.exists) {
            userRef = db.collection('User').doc(userId);
            console.log(`[DEBUG] User ${userId} exists, creating reference`);
          } else {
            console.warn(`[DEBUG] User ${userId} does not exist, skipping user reference`);
            userRef = null;
          }
        } catch (userError) {
          console.error(`[DEBUG] Error checking user ${userId}:`, userError.message);
          userRef = null;
        }
      }

      // Handle targetId reference safely
      let targetRef = null;
      if (targetId) {
        try {
          console.log(`[DEBUG] Checking if target ${targetId} exists...`);
          const targetDoc = await db.collection('Targets').doc(targetId).get();
          if (targetDoc.exists) {
            targetRef = db.collection('Targets').doc(targetId);
            console.log(`[DEBUG] Target ${targetId} exists, creating reference`);
          } else {
            console.warn(`[DEBUG] Target ${targetId} does not exist, skipping target reference`);
            targetRef = null;
          }
        } catch (targetError) {
          console.error(`[DEBUG] Error checking target ${targetId}:`, targetError.message);
          targetRef = null;
        }
      }

      // Prepare ports data
      const sanitizedPorts = (hostResult.ports || []).map((p, portIndex) => {
        console.log(`[DEBUG] Processing port ${portIndex + 1}: ${p.port}`);
        return {
          port: p.port || 'unknown',
          protocol: p.protocol || 'tcp',
          state: p.state || 'unknown',
          state_reason: p.state_reason || '',
          state_reason_ttl: p.state_reason_ttl || '',
          service: {
            name: p.service?.name || 'unknown',
            product: p.service?.product || '',
            version: p.service?.version || '',
            extrainfo: p.service?.extrainfo || '',
            ostype: p.service?.ostype || '',
            method: p.service?.method || '',
            conf: p.service?.conf || '0',
            cpe: p.service?.cpe || '',
            tunnel: p.service?.tunnel || ''
          },
          scripts: p.scripts || {},
          banner: p.banner || '',
          summary: p.summary || ''
        };
      });

      console.log(`[DEBUG] Prepared ${sanitizedPorts.length} ports for ${hostResult.host}`);

      const docData = {
        scan_id: scanId,
        host: hostResult.host || 'unknown',
        hostname: hostResult.hostname || '',
        mac_address: hostResult.mac_address || '',
        vendor: hostResult.vendor || '',
        host_status: hostResult.status || 'unknown',
        start_time: hostResult.starttime || null,
        end_time: hostResult.endtime || null,
        ports: sanitizedPorts,
        open_ports_count: hostResult.open_ports_count || 0,
        device_type: hostResult.device_type || 'Unknown Device',
        device_category: hostResult.device_category || 'unknown',
        classification_confidence: hostResult.classification_confidence || 'low',
        classification_basis: hostResult.classification_basis || 'default',
        os_detection: hostResult.os_detection || {},
        host_scripts: hostResult.host_scripts || {},
        uptime: hostResult.uptime || null,
        distance: hostResult.distance || null,
        tcp_sequence: hostResult.tcpsequence || null,
        ipid_sequence: hostResult.ipidsequence || null,
        security_metrics: parsed.security_metrics || {},
        created_at: admin.firestore.FieldValue.serverTimestamp(),
        network_scan: false,
        parent_scan_id: scanId,
        scan_duration: runResult.duration || 'unknown',
        preset_used: preset,
        scan_type: 'deep',
        requested_by: userRef,
        target_id: targetRef ? targetId : null
      };

      console.log(`[DEBUG] Attempting to store data for ${hostResult.host}...`);

      // Use direct Firestore set for debugging
      await scanResultRef.set(docData);

      storedCount++;
      console.log(`✅ Successfully stored deep scan result for ${hostResult.host} with ${hostResult.open_ports_count || 0} open ports`);

    } catch (hostError) {
      errorCount++;
      console.error(`❌ Failed to store host ${hostResult.host}:`, hostError.message);
      console.error(`[DEBUG] Host error details:`, {
        host: hostResult.host,
        error: hostError.message,
        stack: hostError.stack
      });
    }
  }

  console.log(`[DEBUG storeDeepScanResults] Completed: ${storedCount} stored, ${errorCount} errors`);
}
// Helper function to extract sample IPs from list for display
function extractSampleIPsFromList(ipList) {
  try {
    // Handle comma-separated IPs
    if (ipList.includes(',')) {
      return ipList.split(',').slice(0, 3).map(ip => ip.trim());
    }
    // Handle CIDR - just show the network
    else if (ipList.includes('/')) {
      const baseIp = ipList.split('/')[0];
      return [baseIp];
    }
    // Handle range
    else if (ipList.includes('-')) {
      const startIp = ipList.split('-')[0].trim();
      return [startIp];
    }
    // Single IP
    else {
      return [ipList.trim()];
    }
  } catch (error) {
    return [ipList];
  }
}

// Helper function to generate scan names
function generateScanName(scanMode, targets, targetHosts) {
  switch (scanMode) {
    case 'single_target':
      return `Deep scan of ${targets[0].hostname || targets[0].host}`;
    case 'multiple_targets':
      return `Deep scan of ${targets.length} targets`;
    case 'ip_list':
      // Truncate long IP lists for the name
      const displayIps = targetHosts.length > 30 ? targetHosts.substring(0, 30) + '...' : targetHosts;
      return `Deep scan of ${displayIps}`;
    default:
      return 'Deep Security Scan';
  }
}

// Helper function to generate user messages
function generateScanMessage(scanMode, targets, targetHosts) {
  switch (scanMode) {
    case 'single_target':
      return `Deep scan started for ${targets[0].hostname || targets[0].host}`;
    case 'multiple_targets':
      return `Deep scan started for ${targets.length} targets`;
    case 'ip_list':
      return `Deep scan started for IP range: ${targetHosts}`;
    default:
      return 'Deep scan started';
  }
}

app.post('/targets/add-selected', async (req, res) => {
  try {
    const { scanResultIds, userId, groupName = "Custom Group" } = req.body;

    if (!scanResultIds || !Array.isArray(scanResultIds) || scanResultIds.length === 0) {
      return res.status(400).json({ error: 'scanResultIds array required' });
    }

    if (!userId) {
      return res.status(400).json({ error: 'userId required' });
    }

    console.log(`[Targets] Adding ${scanResultIds.length} selected scan results to Targets for user ${userId}, group: "${groupName}"`);

    // Get the selected ScanResults
    const scanResultsSnap = await db.collection('ScanResults')
      .where(admin.firestore.FieldPath.documentId(), 'in', scanResultIds)
      .get();

    if (scanResultsSnap.empty) {
      return res.status(404).json({ error: 'No scan results found with the provided IDs' });
    }

    const addedTargets = [];
    const failedTargets = [];

    // Add each selected ScanResult as a Target
    for (const doc of scanResultsSnap.docs) {
      try {
        const scanResult = doc.data();

        // Create target document
        const targetRef = db.collection('Targets').doc();

        const targetData = {
          target_id: targetRef.id,
          host: scanResult.host,
          hostname: scanResult.hostname || '',
          mac_address: scanResult.mac_address || '',
          vendor: scanResult.vendor || '',
          device_type: scanResult.device_type || 'Unknown',
          device_category: scanResult.device_category || 'unknown',
          classification_confidence: scanResult.classification_confidence || 'low',
          open_ports_count: scanResult.open_ports_count || 0,
          ports: scanResult.ports || [],
          first_seen: admin.firestore.FieldValue.serverTimestamp(),
          last_seen: admin.firestore.FieldValue.serverTimestamp(),
          added_by: userId,
          added_at: admin.firestore.FieldValue.serverTimestamp(),
          source_scan_result: doc.ref,
          source_scan_id: scanResult.scan_id,
          target_group: groupName,
          tags: ['imported-from-scan', `group-${groupName.toLowerCase().replace(/\s+/g, '-')}`],
          notes: `Imported from scan ${scanResult.scan_id} as part of "${groupName}" on ${new Date().toLocaleDateString()}`,
          scan_count: 0,
          is_active: true
        };

        // Use direct Firestore set without cleaning for server timestamps
        await targetRef.set(targetData);

        addedTargets.push({
          target_id: targetRef.id,
          host: targetData.host,
          hostname: targetData.hostname,
          device_type: targetData.device_type,
          target_group: targetData.target_group
        });

        console.log(`[Targets] Added target: ${targetData.host} to group "${groupName}"`);

      } catch (error) {
        console.error(`[Targets] Failed to add target from scan result ${doc.id}:`, error);
        failedTargets.push({
          scan_result_id: doc.id,
          host: scanResult.host,
          error: error.message
        });
      }
    }

    res.json({
      success: true,
      added: addedTargets.length,
      failed: failedTargets.length,
      group_name: groupName,
      added_targets: addedTargets,
      failed_targets: failedTargets,
      message: `Successfully added ${addedTargets.length} targets to group "${groupName}"`
    });

  } catch (err) {
    console.error('Error adding selected targets:', err);
    res.status(500).json({ error: 'Failed to add selected targets', details: err.message });
  }
});
//FUNCIONA DEVOLVE TODOS OS TARGETS DE UM CERTO GRUPO PARA O USER QUE O OWNS
app.get('/targets/by-group/:userId/:groupName', async (req, res) => {
  try {
    const { userId, groupName } = req.params;

    const targetsSnap = await db.collection('Targets')
      .where('added_by', '==', userId)
      .where('target_group', '==', groupName)
      .orderBy('added_at', 'desc')
      .get();

    const targets = targetsSnap.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.json({
      group_name: groupName,
      targets: targets,
      count: targets.length
    });

  } catch (err) {
    console.error('Error getting targets by group:', err);
    res.status(500).json({ error: 'Failed to get targets', details: err.message });
  }
});

// FUNCIONA Get all unique group names for a user
app.get('/targets/groups/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    const targetsSnap = await db.collection('Targets')
      .where('added_by', '==', userId)
      .select('target_group')
      .get();

    const groups = [...new Set(targetsSnap.docs
      .map(doc => doc.data().target_group)
      .filter(Boolean))];

    res.json({
      user_id: userId,
      groups: groups,
      count: groups.length
    });

  } catch (err) {
    console.error('Error getting user groups:', err);
    res.status(500).json({ error: 'Failed to get groups', details: err.message });
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

//GET ALL TARGETS FOR A USER
app.get('/targets/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    const targetsSnap = await db.collection('Targets')
      .where('added_by', '==', userId)
      .orderBy('added_at', 'desc')
      .get();

    const targets = targetsSnap.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.json({
      user_id: userId,
      targets: targets,
      count: targets.length
    });

  } catch (err) {
    console.error('Error getting user targets:', err);
    res.status(500).json({ error: 'Failed to get targets', details: err.message });
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
// Health check endpoint
app.get('/health', (req, res) => res.json({
  ok: true,
  now: new Date().toISOString(),
  presets: Object.keys(PRESETS),
  features: ['quick_discovery', 'deep_analysis', 'target_management']
}));

app.listen(PORT, () => console.log(`Enhanced Nmap-Firebase API listening on ${PORT}`));
