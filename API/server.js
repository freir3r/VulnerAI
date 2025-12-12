// Main API server for Nmap scan management (adapted for new Firestore model)

const express = require('express');
const bodyParser = require('body-parser');
const { spawn } = require('child_process');
const fs = require('fs');
const http = require('http');
const path = require('path');
const os = require('os');
const { v4: uuidv4 } = require('uuid');
const admin = require('firebase-admin');
const xml2js = require('xml2js');
const cors = require('cors');
const socketIo = require('socket.io');

const PORT = process.env.PORT || 3000;

// --- Firebase Initialization ---
let serviceAccount;
try {
  serviceAccount = require('./keys/firebase-sa.json');
} catch (e) {
  console.error("❌ ERRO CRÍTICO: O ficheiro './keys/firebase-sa.json' não foi encontrado!");
  console.error("Certifica-te que o ficheiro está na pasta API/keys/ antes de iniciar o Docker.");
  process.exit(1);
}

try {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    storageBucket: process.env.FIREBASE_STORAGE_BUCKET || undefined
  });
  console.log('✅ Firebase initialized successfully via file.');
} catch (e) {
  console.error('❌ Error during Firebase initialization:', e.message || e);
  throw e;
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

// --- AI Risk Assessment Expert System ---
const RISK_RULES = {
  // Regras baseadas em portas e serviços
  PORT_RULES: [
    {
      condition: (port, service) => port === 22 && service.version && parseFloat(service.version) < 8.0,
      risk: 'HIGH',
      points: 30,
      description: 'SSH version outdated - potential vulnerabilities'
    },
    {
      condition: (port, service) => port === 80 && service.name === 'http',
      risk: 'MEDIUM',
      points: 20,
      description: 'HTTP without TLS - data transmitted in cleartext'
    },
    {
      condition: (port, service) => [135, 139, 445].includes(port) && service.ostype === 'Windows',
      risk: 'MEDIUM',
      points: 25,
      description: 'Windows SMB services exposed - potential network attacks'
    },
    {
      condition: (port, service) => port === 23 && service.name === 'telnet',
      risk: 'HIGH',
      points: 35,
      description: 'Telnet service exposed - credentials transmitted in cleartext'
    },
    {
      condition: (port, service) => port === 21 && service.name === 'ftp',
      risk: 'MEDIUM',
      points: 20,
      description: 'FTP service exposed - potential credential exposure'
    },
    {
      condition: (port, service) => port === 3389 && service.name === 'ms-wbt-server',
      risk: 'MEDIUM',
      points: 25,
      description: 'RDP service exposed - potential brute force attacks'
    },
    {
      condition: (port, service) => port === 443 && service.name === 'http',
      risk: 'LOW',
      points: -10,
      description: 'HTTPS enabled - encrypted communication'
    },
    {
      condition: (port, service) => [3306, 5432, 1433, 1521].includes(port) && service.state === 'open',
      risk: 'HIGH',
      points: 25,
      description: 'Database service exposed - high value target for attackers'
    }
  ],

  // Regras baseadas em serviços específicos
  SERVICE_RULES: [
    {
      condition: (service) => service.name === 'vmware-auth' && service.version === '1.0',
      risk: 'HIGH',
      points: 35,
      description: 'VMware Authentication Daemon v1.0 - potentially vulnerable version'
    },
    {
      condition: (service) => service.name === 'vmware-auth' && service.version === '1.10',
      risk: 'MEDIUM',
      points: 25,
      description: 'VMware Authentication Daemon v1.10 - check for updates'
    },
    {
      condition: (service) => service.product && service.product.includes('Node.js'),
      risk: 'MEDIUM',
      points: 15,
      description: 'Node.js service detected - check for framework vulnerabilities'
    },
    {
      condition: (service) => service.name === 'microsoft-ds' && service.product === '',
      risk: 'MEDIUM',
      points: 20,
      description: 'Windows file sharing service exposed'
    },
    {
      condition: (service) => service.name === 'netbios-ssn',
      risk: 'MEDIUM',
      points: 20,
      description: 'NetBIOS service exposed - potential information disclosure'
    },
    {
      condition: (service) => service.name === 'msrpc',
      risk: 'MEDIUM',
      points: 15,
      description: 'Microsoft RPC service exposed'
    },
    {
      condition: (service) => service.name === 'mysql',
      risk: 'HIGH',
      points: 30,
      description: 'MySQL database exposed - potential credential attacks'
    },
    {
      condition: (service) => service.name === 'hotline' || service.name === 'unknown',
      risk: 'MEDIUM',
      points: 20,
      description: 'Uncommon or unknown service - potential security risk'
    },
    {
      condition: (service) => service.extrainfo && service.extrainfo.includes('too many connection errors'),
      risk: 'MEDIUM',
      points: 15,
      description: 'Service blocking connections - potential misconfiguration'
    }
  ],

  // Regras baseadas em configurações de serviço
  CONFIG_RULES: [
    {
      condition: (service) => service.tunnel === 'ssl',
      risk: 'LOW',
      points: -5,
      description: 'SSL/TLS encryption enabled'
    },
    {
      condition: (service) => service.extrainfo && service.extrainfo.includes('weak'),
      risk: 'HIGH',
      points: 30,
      description: 'Weak encryption or configuration detected'
    }
  ]
};

// --- Motor de Inferência do Sistema Especialista ---
class RiskAssessmentExpert {
  constructor(scanResults) {
    this.scanResults = scanResults;
    this.riskScore = 0;
    this.findings = [];
    this.finalRisk = 'LOW';
  }

  assessHost(host) {
    let hostRiskScore = 0;
    const hostFindings = [];

    console.log(`🔍 [AI Risk Assessment] Analyzing host: ${host.host}`);

    // Analisar cada porta do host
    host.ports.forEach(port => {
      const portNum = parseInt(port.port);
      const service = port.service || {};

      console.log(`   📊 Analyzing port ${portNum}: ${service.name} ${service.version}`);

      // Aplicar regras de porta
      RISK_RULES.PORT_RULES.forEach(rule => {
        if (rule.condition(portNum, service)) {
          hostRiskScore += rule.points;
          hostFindings.push({
            type: 'PORT_RISK',
            port: port.port,
            risk: rule.risk,
            description: rule.description,
            points: rule.points,
            service: service.name,
            evidence: `Port ${port.port} (${service.name})`
          });
          console.log(`     ⚠️  PORT RULE: ${rule.description} [${rule.points} points]`);
        }
      });

      // Aplicar regras de serviço
      RISK_RULES.SERVICE_RULES.forEach(rule => {
        if (rule.condition(service)) {
          hostRiskScore += rule.points;
          hostFindings.push({
            type: 'SERVICE_RISK',
            port: port.port,
            risk: rule.risk,
            description: rule.description,
            points: rule.points,
            service: service.name,
            version: service.version,
            evidence: `${service.name} ${service.version}`
          });
          console.log(`     ⚠️  SERVICE RULE: ${rule.description} [${rule.points} points]`);
        }
      });

      // Aplicar regras de configuração
      RISK_RULES.CONFIG_RULES.forEach(rule => {
        if (rule.condition(service)) {
          hostRiskScore += rule.points;
          hostFindings.push({
            type: 'CONFIG_RISK',
            port: port.port,
            risk: rule.risk,
            description: rule.description,
            points: rule.points,
            service: service.name,
            evidence: service.extrainfo || service.tunnel || 'configuration'
          });
          console.log(`     ✅ CONFIG RULE: ${rule.description} [${rule.points} points]`);
        }
      });
    });

    // Determinar risco final baseado no score acumulado
    const finalRisk = this.calculateFinalRisk(hostRiskScore);

    console.log(`🎯 [AI Risk Assessment] ${host.host} - Final Score: ${hostRiskScore}, Risk: ${finalRisk}`);

    return {
      host: host.host,
      hostname: host.hostname,
      riskScore: hostRiskScore,
      finalRisk: finalRisk,
      findings: hostFindings,
      openPorts: host.open_ports_count,
      device_type: host.device_type,
      assessment_timestamp: new Date().toISOString()
    };
  }

  calculateFinalRisk(score) {
    if (score >= 60) return 'CRITICAL';
    if (score >= 40) return 'HIGH';
    if (score >= 20) return 'MEDIUM';
    if (score >= 10) return 'LOW';
    return 'INFO';
  }

  // Avaliar todos os hosts do scan
  assessAllHosts() {
    const assessedHosts = this.scanResults.map(host => this.assessHost(host));

    // Calcular estatísticas globais - CORRIGIDO
    const hostsWithRisk = assessedHosts.filter(h => h.riskScore !== undefined);
    const totalRiskScore = hostsWithRisk.reduce((sum, host) => sum + host.riskScore, 0);
    const averageRiskScore = hostsWithRisk.length > 0 ? totalRiskScore / hostsWithRisk.length : 0;
    const riskDistribution = this.calculateRiskDistribution(assessedHosts);

    return {
      assessedHosts,
      summary: {
        totalHosts: assessedHosts.length,
        averageRiskScore: Math.round(averageRiskScore * 100) / 100,
        riskDistribution,
        overallRisk: this.calculateOverallRisk(assessedHosts),
        totalFindings: assessedHosts.reduce((sum, host) => sum + (host.findings ? host.findings.length : 0), 0)
      }
    };
  }

  calculateRiskDistribution(hosts) {
    const distribution = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0
    };

    hosts.forEach(host => {
      if (host.finalRisk && distribution.hasOwnProperty(host.finalRisk)) {
        distribution[host.finalRisk]++;
      }
    });

    return distribution;
  }

  calculateOverallRisk(hosts) {
    if (!hosts || hosts.length === 0) return 'UNKNOWN';

    const riskWeights = {
      CRITICAL: 5,
      HIGH: 4,
      MEDIUM: 3,
      LOW: 2,
      INFO: 1
    };

    const weightedSum = hosts.reduce((sum, host) => {
      return host.finalRisk && riskWeights[host.finalRisk]
        ? sum + riskWeights[host.finalRisk]
        : sum;
    }, 0);

    const averageWeight = weightedSum / hosts.length;

    if (averageWeight >= 4.5) return 'CRITICAL';
    if (averageWeight >= 3.5) return 'HIGH';
    if (averageWeight >= 2.5) return 'MEDIUM';
    if (averageWeight >= 1.5) return 'LOW';
    return 'INFO';
  }

  // Gerar recomendações baseadas nos findings
  generateRecommendations(assessedHosts) {
    const recommendations = [];

    assessedHosts.forEach(host => {
      host.findings.forEach(finding => {
        if (finding.risk === 'HIGH' || finding.risk === 'CRITICAL') {
          recommendations.push({
            host: host.host,
            priority: finding.risk,
            issue: finding.description,
            action: this.generateAction(finding),
            port: finding.port
          });
        }
      });
    });

    // Ordenar por prioridade
    return recommendations.sort((a, b) => {
      const priorityOrder = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
      return priorityOrder[b.priority] - priorityOrder[a.priority];
    });
  }

  generateAction(finding) {
    const actions = {
      'SSH version outdated': 'Upgrade SSH to latest version and disable weak algorithms',
      'HTTP without TLS': 'Implement HTTPS with valid certificate',
      'Windows SMB services exposed': 'Restrict SMB access, disable if not needed',
      'Telnet service exposed': 'Replace Telnet with SSH immediately',
      'FTP service exposed': 'Use SFTP or FTPS instead of plain FTP',
      'VMware Authentication Daemon vulnerable version': 'Update VMware tools to latest version',
      'Node.js service detected': 'Update Node.js and dependencies, security audit'
    };

    return actions[finding.description.split(' - ')[0]] || 'Review configuration and apply security best practices';
  }
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

  // Deep Scan: Updated from file 2
  deep_scan: {
    args: [
      '-sS',                        // TCP SYN scan (fast, stealthy)
      '-sV',
      '-O',
      '--osscan-limit',                        // Service/version detection
      '--version-intensity', '5',   // Aggressive version detection
      '--script-timeout', '40s',  // Script timeout
      '--script', 'default,vuln,banner', // Focused scripts for CVEs and banners
      '--top-ports', '1000',                        // Scan all ports
      '-T4',                        // Faster timing for LAN/in-lab
      '--min-rate', '700',          // Minimum packet rate
      '--max-retries', '2',         // Avoid excessive retries
      '--host-timeout', '10m',      // Timeout per host
      '--open',                     // Show only open ports
      '--reason',                   // Show reason why port is open/closed
      '-PR',
      '--system-dns',                // Use system DNS
      '-R',
      '-oX', '-'                     // Output in XML (can be parsed)
    ],
    calculateTimeout: function (target) {
      const hostCount = estimateHostCount(target);
      const perHostTime = 180000; // 3 minutes per host (deep scan optimized)
      const baseTime = 60000;      // 1 minute base
      return Math.min(baseTime + (hostCount * perHostTime), 1800000); // Max 30 min
    },
    description: 'Focused deep scan for open ports, service versions, and CVEs',
    category: 'deep_scan',
    intensity: 'high'
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
  const macUpper = mac ? mac.toUpperCase() : '';

  // Enhanced vendor detection from MAC
  if (!vendor && mac) {
    try {
      // Check if it's a random MAC first
      if (isRandomMac(mac)) {
        detectedVendor = classifyRandomMac(macUpper);
        if (detectedVendor !== 'Random MAC (Mobile Device)') {
          classificationBasis = 'random_mac_pattern';
          console.log(`📱 Mobile device detected: ${mac} → ${detectedVendor}`);
        } else {
          console.log(`[MAC Lookup] ${mac} is a random MAC address (mobile device privacy)`);
          classificationBasis = 'random_mac';
        }
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
  const hostnameLower = (hostname || '').toLowerCase();

  console.log(`Classifying: IP=${ipv4}, MAC=${mac}, Vendor=${detectedVendor}, Hostname=${hostname}`);

  // ENHANCED CLASSIFICATION LOGIC WITH PRIORITY ORDER
  const classification = classifyByMultipleFactors(vendorLower, hostnameLower, macUpper, ipv4);

  if (classification) {
    deviceType = classification.deviceType;
    deviceCategory = classification.deviceCategory;
    confidence = classification.confidence;
    classificationBasis = classification.basis || classificationBasis;
  }

  // Fallback classifications
  if (deviceType === 'Unknown Device') {
    if (!mac && !detectedVendor) {
      deviceType = 'Unknown Host';
      deviceCategory = 'unknown';
      confidence = 'very-low';
      classificationBasis = 'no_identifying_data';
    } else if (mac || detectedVendor) {
      deviceType = 'Network Device';
      deviceCategory = 'networking';
      confidence = 'low';
      classificationBasis = 'generic_mac_or_vendor';
    }
  }

  console.log(`🎯 CLASSIFICATION: ${deviceType} (${deviceCategory}) - Confidence: ${confidence} - Basis: ${classificationBasis}`);

  return {
    device_type: deviceType,
    device_category: deviceCategory,
    confidence: confidence,
    vendor: detectedVendor,
    classification_basis: classificationBasis
  };
}

// Enhanced random MAC classification
function classifyRandomMac(macUpper) {
  // Apple iOS patterns (more comprehensive)
  const applePatterns = [
    'F2:16:', 'F2:1A:', 'F2:12:', 'F2:01:', 'F2:16:F', 'F2:1A:5',
    'F2:12:4', 'F2:01:F', 'F2:0A:', 'F2:1B:', 'F2:1C:', 'F2:1D:',
    'F2:1E:', 'F2:1F:', 'F2:20:', 'F2:21:', 'F2:22:', 'F2:23:'
  ];

  // Android patterns
  const androidPatterns = [
    'F2:00:', 'F2:1D:', 'F2:16:DB', 'F2:00:E5', 'F2:00:9', 'F2:1D:0',
    'F2:02:', 'F2:03:', 'F2:04:', 'F2:05:', 'F2:06:', 'F2:07:',
    'F2:08:', 'F2:09:', 'F2:0B:', 'F2:0C:', 'F2:0D:', 'F2:0E:'
  ];

  // Windows patterns
  const windowsPatterns = [
    'F2:24:', 'F2:25:', 'F2:26:', 'F2:27:', 'F2:28:', 'F2:29:'
  ];

  for (const pattern of applePatterns) {
    if (macUpper.startsWith(pattern)) {
      return 'Apple Inc.';
    }
  }

  for (const pattern of androidPatterns) {
    if (macUpper.startsWith(pattern)) {
      return 'Various Android Manufacturers';
    }
  }

  for (const pattern of windowsPatterns) {
    if (macUpper.startsWith(pattern)) {
      return 'Microsoft Corporation';
    }
  }

  return 'Random MAC (Mobile Device)';
}

// Enhanced multi-factor classification
function classifyByMultipleFactors(vendorLower, hostnameLower, macUpper, ipv4) {
  // Network Infrastructure (Highest priority)
  if (matchesNetworkInfrastructure(vendorLower, hostnameLower)) {
    return {
      deviceType: getNetworkDeviceType(vendorLower, hostnameLower),
      deviceCategory: 'networking',
      confidence: 'high',
      basis: 'network_infrastructure'
    };
  }

  // Computers and Servers
  if (matchesComputer(vendorLower, hostnameLower)) {
    return {
      deviceType: getComputerType(vendorLower, hostnameLower),
      deviceCategory: 'computer',
      confidence: 'high',
      basis: 'computer_hardware'
    };
  }

  // Mobile Devices
  if (matchesMobileDevice(vendorLower, hostnameLower, macUpper)) {
    return {
      deviceType: getMobileDeviceType(vendorLower, hostnameLower),
      deviceCategory: 'mobile',
      confidence: 'medium-high',
      basis: 'mobile_device'
    };
  }

  // IoT and Smart Devices
  if (matchesIoTDevice(vendorLower, hostnameLower)) {
    return {
      deviceType: getIoTDeviceType(vendorLower, hostnameLower),
      deviceCategory: 'iot',
      confidence: 'medium',
      basis: 'iot_device'
    };
  }

  // Peripherals
  if (matchesPeripheral(vendorLower, hostnameLower)) {
    return {
      deviceType: getPeripheralType(vendorLower, hostnameLower),
      deviceCategory: 'peripheral',
      confidence: 'high',
      basis: 'peripheral_device'
    };
  }

  // Virtualization
  if (matchesVirtualization(vendorLower, hostnameLower)) {
    return {
      deviceType: getVirtualizationType(vendorLower, hostnameLower),
      deviceCategory: 'virtualization',
      confidence: 'high',
      basis: 'virtualization'
    };
  }

  return null;
}

// Enhanced matching functions
function matchesNetworkInfrastructure(vendor, hostname) {
  const networkVendors = [
    'cisco', 'juniper', 'aruba', 'huawei', 'fortinet', 'fortigate',
    'palo alto', 'paloalto', 'check point', 'checkpoint', 'brocade',
    'extreme networks', 'ruckus', 'ubiquiti', 'mikrotik', 'netgear',
    'tplink', 'd-link', 'dlink', 'linksys', 'zyxel', 'sophos', 'watchguard',
    'sonicwall', 'meraki', 'a10', 'f5', 'citrix', 'barracuda'
  ];

  const networkHostnamePatterns = [
    'router', 'switch', 'firewall', 'fw-', 'fw.', 'gateway', 'gw-', 'gw.',
    'core', 'dist', 'access', 'wlc', 'controller', 'ap-', 'ap.', 'wireless',
    'cisco', 'juniper', 'fortinet', 'palo', 'checkpoint'
  ];

  return networkVendors.some(v => vendor.includes(v)) ||
    networkHostnamePatterns.some(pattern => hostname.includes(pattern));
}

function matchesComputer(vendor, hostname) {
  const computerVendors = [
    'dell', 'hp', 'hewlett', 'lenovo', 'microsoft', 'asus', 'acer',
    'toshiba', 'fujitsu', 'samsung', 'lg', 'sony', 'panasonic',
    'intel', 'amd', 'supermicro', 'ibm', 'apple', 'macbook', 'imac'
  ];

  const computerHostnamePatterns = [
    'pc-', 'laptop-', 'desktop-', 'workstation', 'server', 'srv-',
    'dc-', 'domain', 'win-', 'mac-', 'macbook', 'imac', 'thinkpad'
  ];

  return computerVendors.some(v => vendor.includes(v)) ||
    computerHostnamePatterns.some(pattern => hostname.includes(pattern));
}

function matchesMobileDevice(vendor, hostname, mac) {
  const mobileVendors = [
    'apple', 'samsung', 'google', 'oneplus', 'xiaomi', 'oppo', 'vivo',
    'realme', 'motorola', 'nokia', 'sony', 'lg', 'htc', 'huawei',
    'honor', 'meizu', 'zte', 'alcatel'
  ];

  const mobileHostnamePatterns = [
    'iphone', 'ipad', 'android', 'samsung', 'galaxy', 'pixel',
    'oneplus', 'xiaomi', 'redmi', 'oppo', 'vivo'
  ];

  const isRandomMac = mac && (mac.startsWith('F2:') || mac.startsWith('F6:') || mac.startsWith('FA:'));

  return mobileVendors.some(v => vendor.includes(v)) ||
    mobileHostnamePatterns.some(pattern => hostname.includes(pattern)) ||
    isRandomMac;
}

function matchesIoTDevice(vendor, hostname) {
  const iotVendors = [
    'raspberry', 'arduino', 'google', 'nest', 'amazon', 'echo', 'alexa',
    'ring', 'philips', 'hue', 'smartthings', 'wyze', 'tuya', 'shelly',
    'tp-link', 'kasa', 'wemo', 'belkin', 'logitech', 'harmony',
    'roku', 'chromecast', 'fire tv', 'apple tv', 'sonos', 'bose'
  ];

  const iotHostnamePatterns = [
    'raspberrypi', 'rpi-', 'arduino', 'iot-', 'smart-', 'sensor-',
    'camera', 'cam-', 'thermostat', 'hue', 'philips-hue', 'nest-',
    'alexa', 'echo', 'google-home', 'chromecast', 'roku', 'fire-tv',
    'apple-tv', 'sonos', 'smartthings', 'wyze', 'tuya'
  ];

  return iotVendors.some(v => vendor.includes(v)) ||
    iotHostnamePatterns.some(pattern => hostname.includes(pattern));
}

function matchesPeripheral(vendor, hostname) {
  const peripheralVendors = [
    'canon', 'epson', 'brother', 'hp', 'hewlett', 'xerox', 'lexmark',
    'ricoh', 'kyocera', 'sharp', 'konica', 'minolta', 'samsung',
    'logitech', 'microsoft', 'apple', 'dell', 'lenovo'
  ];

  const peripheralHostnamePatterns = [
    'printer', 'print-', 'prn-', 'scanner', 'scan-', 'plotter',
    'mouse', 'keyboard', 'webcam', 'camera', 'speaker', 'headset'
  ];

  return peripheralVendors.some(v => vendor.includes(v)) ||
    peripheralHostnamePatterns.some(pattern => hostname.includes(pattern));
}

function matchesVirtualization(vendor, hostname) {
  const virtualizationVendors = [
    'vmware', 'parallels', 'microsoft', 'hyper-v', 'citrix',
    'oracle', 'virtualbox', 'proxmox', 'xen', 'kvm', 'qemu',
    'docker', 'container', 'kubernetes'
  ];

  const virtualizationHostnamePatterns = [
    'vm-', 'virtual-', 'esxi', 'vcenter', 'hyperv', 'xen-',
    'kvm-', 'docker', 'container', 'k8s', 'kubernetes',
    'proxmox', 'pve'
  ];

  return virtualizationVendors.some(v => vendor.includes(v)) ||
    virtualizationHostnamePatterns.some(pattern => hostname.includes(pattern));
}

// Device type specific functions
function getNetworkDeviceType(vendor, hostname) {
  if (vendor.includes('fortinet') || vendor.includes('fortigate') ||
    vendor.includes('palo') || vendor.includes('checkpoint')) {
    return 'Network Firewall';
  }
  if (vendor.includes('cisco') || vendor.includes('juniper') || vendor.includes('aruba')) {
    if (hostname.includes('switch') || hostname.includes('sw-')) return 'Network Switch';
    if (hostname.includes('router') || hostname.includes('rt-')) return 'Network Router';
    if (hostname.includes('firewall') || hostname.includes('fw-')) return 'Network Firewall';
    if (hostname.includes('wireless') || hostname.includes('wlc') || hostname.includes('ap-')) return 'Wireless Controller/Access Point';
    return 'Network Switch/Router';
  }
  if (vendor.includes('ubiquiti') || vendor.includes('unifi')) {
    if (hostname.includes('ap-')) return 'Wireless Access Point';
    return 'Network Gateway/Router';
  }
  if (hostname.includes('ap-') || hostname.includes('access-point')) {
    return 'Wireless Access Point';
  }
  if (hostname.includes('switch') || hostname.includes('sw-')) {
    return 'Network Switch';
  }
  if (hostname.includes('router') || hostname.includes('rt-') || hostname.includes('gw-')) {
    return 'Network Router/Gateway';
  }
  if (hostname.includes('firewall') || hostname.includes('fw-')) {
    return 'Network Firewall';
  }
  return 'Network Infrastructure Device';
}

function getComputerType(vendor, hostname) {
  if (vendor.includes('apple') || hostname.includes('mac')) {
    return 'Apple Computer';
  }
  if (hostname.includes('server') || hostname.includes('srv-') || hostname.includes('dc-')) {
    return 'Server';
  }
  if (hostname.includes('laptop') || hostname.includes('notebook')) {
    return 'Laptop';
  }
  if (hostname.includes('workstation')) {
    return 'Workstation';
  }
  return 'Desktop Computer';
}

function getMobileDeviceType(vendor, hostname) {
  if (vendor.includes('apple') || hostname.includes('iphone') || hostname.includes('ipad')) {
    return hostname.includes('ipad') ? 'Tablet (iPad)' : 'Smartphone (iPhone)';
  }
  if (vendor.includes('samsung') || hostname.includes('galaxy')) {
    return hostname.includes('tab') ? 'Tablet (Samsung)' : 'Smartphone (Samsung)';
  }
  if (vendor.includes('google') || hostname.includes('pixel')) {
    return 'Smartphone (Google Pixel)';
  }
  return hostname.includes('tablet') ? 'Tablet' : 'Smartphone';
}

function getIoTDeviceType(vendor, hostname) {
  if (vendor.includes('raspberry')) return 'Raspberry Pi';
  if (vendor.includes('arduino')) return 'Arduino Device';
  if (vendor.includes('google') || vendor.includes('nest')) {
    if (hostname.includes('thermostat')) return 'Smart Thermostat';
    if (hostname.includes('speaker') || hostname.includes('home')) return 'Smart Speaker';
    return 'Google Smart Device';
  }
  if (vendor.includes('amazon') || hostname.includes('echo') || hostname.includes('alexa')) {
    return 'Amazon Echo Device';
  }
  if (hostname.includes('camera') || hostname.includes('cam-')) return 'IP Camera';
  if (hostname.includes('sensor')) return 'IoT Sensor';
  if (hostname.includes('thermostat')) return 'Smart Thermostat';
  if (hostname.includes('light') || hostname.includes('bulb')) return 'Smart Light';
  return 'IoT/Smart Device';
}

function getPeripheralType(vendor, hostname) {
  if (hostname.includes('printer') || hostname.includes('print-')) return 'Network Printer';
  if (hostname.includes('scanner')) return 'Scanner';
  return 'Computer Peripheral';
}

function getVirtualizationType(vendor, hostname) {
  if (vendor.includes('vmware')) return 'VMware Virtual Machine';
  if (vendor.includes('microsoft') || hostname.includes('hyperv')) return 'Hyper-V Virtual Machine';
  if (vendor.includes('virtualbox')) return 'VirtualBox VM';
  if (hostname.includes('docker') || hostname.includes('container')) return 'Container';
  return 'Virtual Machine';
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

// --- Deep Scan XML Parser from File 2 ---
async function parseDeepScanXml(xmlText, targetNetwork, uidRef = null, targetIdOrRef = null) {
  console.log('🎯 [parseDeepScanXml] FUNCTION CALLED - Starting XML parsing');
  console.log(`📏 XML length: ${xmlText?.length || 0} chars`);

  // small helpers
  const toArray = v => (v === undefined || v === null ? [] : (Array.isArray(v) ? v : [v]));
  const get = (obj, ...keys) => {
    for (const k of keys) {
      if (!obj) continue;
      if (obj[k] !== undefined) return obj[k];
      const up = k.toUpperCase();
      if (obj[up] !== undefined) return obj[up];
    }
    return undefined;
  };

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

        // status
        const status = get(hostObj, 'status')?.state || get(hostObj, 'STATUS')?.STATE || 'unknown';
        console.log(`📊 [parseDeepScanXml] Host status: ${status}`);

        // addresses
        let ipv4 = 'unknown', mac = '', vendor = '';
        const addressesRaw = get(hostObj, 'address') || [];
        const addresses = toArray(addressesRaw);
        console.log(`📍 [parseDeepScanXml] Found ${addresses.length} addresses`);

        for (const addr of addresses) {
          const addrType = addr.addrtype || addr.ADDRTYPE;
          const addrVal = addr.addr || addr.ADDR;
          const addrVendor = addr.vendor || addr.VENDOR || '';
          console.log(`   📍 Address: ${addrVal} (${addrType}) vendor: ${addrVendor}`);

          if (addrType === 'ipv4') ipv4 = addrVal;
          else if (addrType === 'mac') {
            mac = addrVal;
            vendor = vendor || addrVendor;
          }
        }

        // hostnames
        let hostname = '';
        const hostnamesRaw = get(hostObj, 'hostnames') || get(hostObj, 'HOSTNAMES') || {};
        const hostnameData = hostnamesRaw.hostname || hostnamesRaw.HOSTNAME;
        const hostnamesList = toArray(hostnameData);
        if (hostnamesList.length > 0) {
          const firstHostname = hostnamesList[0];
          hostname = firstHostname.name || firstHostname.NAME || '';
          console.log(`🏷️  [parseDeepScanXml] Found hostname: ${hostname}`);
        }

        // Prepare hostResult early so scripts/ports can push into it
        const deviceInfo = classifyDevice(ipv4, mac, vendor, hostname);
        const hostResult = {
          host: ipv4,
          hostname: hostname || '',
          mac_address: mac || '',
          vendor: vendor || '',
          status,
          ports: [],
          open_ports_count: 0,
          foundVulns: [],
          banner: '',
          device_type: deviceInfo.device_type,
          device_category: deviceInfo.device_category,
          classification_confidence: deviceInfo.confidence,
          classification_basis: deviceInfo.classification_basis,
          scan_timestamp: new Date().toISOString(),
          scan_type: 'deep_scan'
        };

        // ports (only parse ports if present)
        const portsRoot = get(hostObj, 'ports') || get(hostObj, 'PORTS') || {};
        const portData = portsRoot.port || portsRoot.PORT;
        const portsArr = toArray(portData);
        console.log(`🔌 [parseDeepScanXml] Found ${portsArr.length} raw port entries`);

        for (const p of portsArr) {
          // normalize state
          const stateObj = p.state || p.STATE || {};
          const state_state = stateObj.state || stateObj.STATE || (typeof stateObj === 'string' ? stateObj : 'unknown');

          // only keep open ports (you already filtered earlier, but keep defensive)
          if (state_state !== 'open') continue;

          const portid = p.portid || p.PORTID || '';
          const protocol = p.protocol || p.PROTOCOL || 'tcp';

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

          // scripts: can be object or array
          const scriptsRaw = p.script || p.SCRIPT || [];
          const scriptsArr = toArray(scriptsRaw);
          const parsedScripts = scriptsArr.map(s => ({
            id: s.id || s.ID || '',
            output: s.output || s.OUTPUT || ''
          }));

          // collect vulns and banners from scripts
          for (const s of parsedScripts) {
            if (!s.id) continue;
            // vulnerability scripts often include 'vuln' or cve ids in output; store raw
            if (s.output && /cve|vulnerab|exploit|CVE-/i.test(s.output)) {
              hostResult.foundVulns.push({ id: s.id, output: s.output });
            }
            // banner-like script ids often include 'banner' or 'http-title' etc.
            if (/banner|http-title|server|product|fingerprint/i.test(s.id) || /server|title|banner/i.test(s.output)) {
              hostResult.banner += (s.output || '') + '\n';
            }
          }

          // also check service.product/version for likely CVE mapping later (optional)
          // push port result
          const portRecord = {
            port: portid,
            protocol,
            state: state_state,
            state_reason,
            state_reason_ttl,
            service,
            scripts: parsedScripts,
            summary: `Port ${portid} ${state_state} - ${service.name} ${service.version}`.trim()
          };

          hostResult.ports.push(portRecord);
        }

        hostResult.open_ports_count = hostResult.ports.length;

        console.log(`✅ [parseDeepScanXml] Successfully parsed host: ${ipv4} with ${hostResult.open_ports_count} open ports and ${hostResult.foundVulns.length} script vulns`);
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

// Store quick scan results: keep it lean (fewer fields)
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

// Store deep scan results with AI risk assessment
async function storeDeepScanResults(scanId, parsed, runResult, preset, userId, targetId) {
  console.log(`[DEBUG storeDeepScanResults] Starting storage for scan: ${scanId}`);
  console.log(`[DEBUG] userId: ${userId}, targetId: ${targetId}`);
  console.log(`[DEBUG] Number of hosts to store: ${parsed.hosts ? parsed.hosts.length : 0}`);

  // === NOVO: EXECUTAR AVALIAÇÃO DE RISCO COM AI ===
  console.log(`[AI] Starting risk assessment for ${parsed.hosts.length} hosts...`);
  const riskExpert = new RiskAssessmentExpert(parsed.hosts);
  const riskAssessment = riskExpert.assessAllHosts();
  const recommendations = riskExpert.generateRecommendations(riskAssessment.assessedHosts);

  console.log(`[AI] Risk assessment completed:`);
  console.log(`[AI] - Overall Risk: ${riskAssessment.summary.overallRisk}`);
  console.log(`[AI] - Total Findings: ${riskAssessment.summary.totalFindings}`);
  console.log(`[AI] - Recommendations: ${recommendations.length}`);

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

      // Encontrar a avaliação de risco correspondente para este host
      const hostRiskAssessment = riskAssessment.assessedHosts.find(h => h.host === hostResult.host);

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

        // === NOVO: DADOS DA AVALIAÇÃO DE RISCO AI ===
        risk_assessment: hostRiskAssessment ? {
          riskScore: hostRiskAssessment.riskScore,
          finalRisk: hostRiskAssessment.finalRisk,
          findings: hostRiskAssessment.findings,
          assessment_timestamp: hostRiskAssessment.assessment_timestamp
        } : null,

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
      console.log(`🎯 [AI] Risk assessment: ${hostRiskAssessment?.finalRisk || 'UNKNOWN'} (Score: ${hostRiskAssessment?.riskScore || 0})`);

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

  // === NOVO: GUARDAR SUMÁRIO DA AVALIAÇÃO DE RISCO NO SCAN PRINCIPAL ===
  try {
    const scanRef = db.collection('Scan').doc(scanId);
    const scanDoc = await scanRef.get();

    if (scanDoc.exists) {
      const currentData = scanDoc.data();

      // Debug: ver o que temos atualmente
      console.log(`[AI DEBUG] Current scan summary:`, currentData.summary);
      console.log(`[AI DEBUG] Risk assessment to store:`, riskAssessment.summary);

      // Criar novo summary com merge
      const updatedSummary = {
        ...(currentData.summary || {}), // mantém dados existentes
        risk_assessment: riskAssessment.summary,
        recommendations: recommendations.slice(0, 10),
        overall_security_rating: riskAssessment.summary.overallRisk
      };

      console.log(`[AI DEBUG] Final summary to save:`, updatedSummary);

      // Atualizar apenas o campo summary
      await safeFirestoreUpdate(scanRef, {
        summary: updatedSummary
      });

      console.log(`[AI] ✅ Risk assessment summary stored successfully in scan document`);
    } else {
      console.error(`[AI] ❌ Scan document ${scanId} does not exist`);
    }
  } catch (updateError) {
    console.error(`[AI] ❌ Failed to store risk assessment summary:`, updateError.message);

    // Fallback: tentar método direto
    try {
      console.log(`[AI] 🔄 Trying direct Firestore update as fallback...`);
      await db.collection('Scan').doc(scanId).update({
        'summary.risk_assessment': riskAssessment.summary,
        'summary.recommendations': recommendations.slice(0, 10),
        'summary.overall_security_rating': riskAssessment.summary.overallRisk
      });
      console.log(`[AI] ✅ Risk assessment stored via direct Firestore update`);
    } catch (directError) {
      console.error(`[AI] ❌ Direct update also failed:`, directError.message);

      // Último fallback: log completo para debug
      console.log(`[AI FINAL DEBUG] Data that failed to save:`, {
        risk_assessment: riskAssessment.summary,
        recommendations_count: recommendations.length,
        overall_risk: riskAssessment.summary.overallRisk,
        risk_distribution: riskAssessment.summary.riskDistribution
      });
    }
  }
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

// --- Express API Setup ---
const app = express();
const server = http.createServer(app);
const io = socketIo(server);
io.sockets.setMaxListeners(40);
require('events').EventEmitter.defaultMaxListeners = 40;
app.use(cors());
app.use(express.json());

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

        // Parse scan result - use appropriate parser
        let parsed;
        if (preset === 'deep_scan') {
          parsed = await parseDeepScanXml(stdout, scanTarget);
        } else {
          parsed = await parseNetworkScanXml(stdout, scanTarget, preset);
        }

        // Store results in Firestore - use appropriate storage function
        if (preset === 'quick_scan') {
          await storeQuickScanResults(scanId, parsed, runResult, preset, userId, targetId);
        } else if (preset === 'deep_scan') {
          await storeDeepScanResults(scanId, parsed, runResult, preset, userId, targetId);
        } else {
          await storeScanResults(scanId, parsed, runResult, preset);
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

// NEW: Unified deep scan endpoint from file 2
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

    // Validate/normalize targetHosts (only for non-ip_list (ip_list can be CIDR/ranges which validateNetworkTarget handles too)
    try {
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

// NEW: Risk analysis endpoint from file 2
app.get('/scan/:scanId/risk-analysis', async (req, res) => {
  try {
    const scanId = req.params.scanId;

    // Get all ScanResults for this scan with risk assessment
    const resultsSnap = await db.collection('ScanResults')
      .where('parent_scan_id', '==', scanId)
      .get();

    if (resultsSnap.empty) {
      return res.status(404).json({ error: 'No scan results found' });
    }

    const ScanResults = resultsSnap.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    // CALCULAR risk_summary A PARTIR DOS HOSTS INDIVIDUAIS
    const hostsWithRisk = ScanResults.filter(r => r.risk_assessment);

    // Calcular estatísticas
    const totalRiskScore = hostsWithRisk.reduce((sum, host) => sum + (host.risk_assessment.riskScore || 0), 0);
    const averageRiskScore = hostsWithRisk.length > 0 ? totalRiskScore / hostsWithRisk.length : 0;

    // Calcular risk distribution
    const riskDistribution = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0
    };

    hostsWithRisk.forEach(host => {
      const riskLevel = host.risk_assessment.finalRisk;
      if (riskDistribution.hasOwnProperty(riskLevel)) {
        riskDistribution[riskLevel]++;
      }
    });

    // Calcular overall risk
    const calculateOverallRisk = () => {
      if (hostsWithRisk.length === 0) return 'UNKNOWN';

      const riskWeights = {
        CRITICAL: 5,
        HIGH: 4,
        MEDIUM: 3,
        LOW: 2,
        INFO: 1
      };

      const weightedSum = hostsWithRisk.reduce((sum, host) => {
        return sum + (riskWeights[host.risk_assessment.finalRisk] || 1);
      }, 0);

      const averageWeight = weightedSum / hostsWithRisk.length;

      if (averageWeight >= 4.5) return 'CRITICAL';
      if (averageWeight >= 3.5) return 'HIGH';
      if (averageWeight >= 2.5) return 'MEDIUM';
      if (averageWeight >= 1.5) return 'LOW';
      return 'INFO';
    };

    // Extrair recomendações
    const recommendations = [];
    hostsWithRisk.forEach(host => {
      host.risk_assessment.findings?.forEach(finding => {
        if (finding.risk === 'HIGH' || finding.risk === 'CRITICAL') {
          recommendations.push({
            host: host.host,
            priority: finding.risk,
            issue: finding.description,
            action: generateActionFromFinding(finding),
            port: finding.port
          });
        }
      });
    });

    // Helper function para ações
    function generateActionFromFinding(finding) {
      const actions = {
        'SSH version outdated': 'Upgrade SSH to latest version',
        'HTTP without TLS': 'Implement HTTPS with valid certificate',
        'Windows SMB services exposed': 'Restrict SMB access',
        'MySQL database exposed': 'Secure MySQL with strong passwords and firewall rules',
        'Node.js service detected': 'Update Node.js and dependencies',
        'Uncommon or unknown service': 'Investigate and secure unknown service',
        'Service blocking connections': 'Fix service configuration'
      };

      return actions[finding.description.split(' - ')[0]] || 'Review configuration and apply security best practices';
    }

    const risk_summary = {
      totalHosts: hostsWithRisk.length,
      averageRiskScore: Math.round(averageRiskScore * 100) / 100,
      riskDistribution,
      overallRisk: calculateOverallRisk(),
      totalFindings: hostsWithRisk.reduce((sum, host) => sum + (host.risk_assessment.findings?.length || 0), 0)
    };

    res.json({
      scan_id: scanId,
      risk_summary, // ✅ AGORA CALCULADO A PARTIR DOS HOSTS REAIS
      recommendations: recommendations.sort((a, b) => {
        const priorityOrder = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
        return priorityOrder[b.priority] - priorityOrder[a.priority];
      }),
      hosts: hostsWithRisk.map(h => ({
        host: h.host,
        hostname: h.hostname,
        device_type: h.device_type,
        risk_assessment: h.risk_assessment,
        open_ports: h.open_ports_count
      })),
      detailed_findings: hostsWithRisk.flatMap(h =>
        (h.risk_assessment.findings || []).map(f => ({
          host: h.host,
          ...f
        }))
      )
    });

  } catch (err) {
    console.error('Error getting risk analysis:', err);
    res.status(500).json({ error: 'Failed to get risk analysis', details: err.message });
  }
});

// NEW: Add selected targets endpoint from file 2
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

// NEW: Get targets by group from file 2
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

// NEW: Get all unique group names for a user from file 2
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

// NEW: Get all targets for a user from file 2
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

// Keep existing endpoints from file 1
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

// Keep existing endpoints
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

// GET all scans for a user - VERSÃO CORRIGIDA
app.get('/scans/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    console.log(`[API] Fetching scans for user: ${userId}`);

    const scansSnap = await db.collection('Scan')
      .where('user_id', '==', userId)
      .orderBy('submitted_at', 'desc')
      .limit(50)
      .get();

    console.log(`[API] Found ${scansSnap.size} scans for user ${userId}`);

    const scans = scansSnap.docs.map(doc => {
      const data = doc.data();
      return {
        id: doc.id,
        ...data,
        // Garantir que os timestamps são convertidos corretamente
        submitted_at: data.submitted_at ? null : null,
        started_at: data.started_at ? null : null,
        finished_at: data.finished_at ? null : null
      };
    });

    console.log(`[API] Successfully processed ${scans.length} scans`);
    res.json({ scans });

  } catch (err) {
    console.error('❌ Error in /scans/:userId:', err);
    res.status(500).json({
      error: 'Failed to get scans',
      details: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => res.json({
  ok: true,
  now: new Date().toISOString(),
  presets: Object.keys(PRESETS),
  features: ['quick_discovery', 'deep_analysis', 'target_management', 'ai_risk_assessment']
}));

server.listen(PORT, () => console.log(`Enhanced Nmap-Firebase API with AI Risk Assessment listening on ${PORT}`));