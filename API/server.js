// Main API server for Nmap scan management (adapted for new Firestore model)

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
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
  // Throw error so the process fails fast without using process.exit()
  throw new Error("Missing firebase-sa.json service account file. Place it in API/keys/ or set GOOGLE_APPLICATION_CREDENTIALS.");
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

// Simplified Firestore helper functions
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
  ],

  CVE_RULES: [
    {
      condition: (cve) => cve.CVSS?.score >= 9.0,
      risk: 'CRITICAL',
      points: 50,
      description: 'Critical severity CVE detected'
    },
    {
      condition: (cve) => cve.CVSS?.score >= 7.0 && cve.CVSS?.score < 9.0,
      risk: 'HIGH',
      points: 35,
      description: 'High severity CVE detected'
    },
    {
      condition: (cve) => cve.CVSS?.score >= 4.0 && cve.CVSS?.score < 7.0,
      risk: 'MEDIUM',
      points: 20,
      description: 'Medium severity CVE detected'
    },
    {
      condition: (cve) => cve.exploit_available === true,
      risk: 'HIGH',
      points: 30,
      description: 'CVE with known exploit available'
    },
    {
      condition: (cve) => {
        const currentYear = new Date().getFullYear();
        const cveYear = parseInt(cve.cve_id.match(/CVE-(\d{4})/)?.[1]) || currentYear;
        return currentYear - cveYear <= 1; // CVE from last year
      },
      risk: 'HIGH',
      points: 25,
      description: 'Recent CVE (less than 1 year old)'
    },
    {
      condition: (cve) => {
        const currentYear = new Date().getFullYear();
        const cveYear = parseInt(cve.cve_id.match(/CVE-(\d{4})/)?.[1]) || currentYear;
        return currentYear - cveYear >= 5; // Old CVE
      },
      risk: 'MEDIUM',
      points: 15,
      description: 'Old CVE (5+ years) - likely unpatched system'
    }
  ],
  WEB_SERVER_RULES: [
    {
      condition: (service) => service.name === 'http' && !service.tunnel,
      risk: 'MEDIUM',
      points: 20,
      description: 'HTTP without encryption'
    },
    {
      condition: (service) => service.name === 'http' && service.product?.includes('nginx'),
      risk: 'MEDIUM',
      points: 15,
      description: 'Nginx web server detected'
    },
    {
      condition: (service) => service.name === 'http' && service.version &&
        (service.product?.includes('Apache') || service.product?.includes('httpd')),
      risk: 'MEDIUM',
      points: 15,
      description: 'Apache web server detected'
    },
    {
      condition: (service) => service.name === 'http' && service.version &&
        parseFloat(service.version) < 2.4,
      risk: 'HIGH',
      points: 25,
      description: 'Outdated Apache version'
    },
    {
      condition: (service) => service.name === 'http' && service.version &&
        service.product?.includes('nginx') && parseFloat(service.version) < 1.18,
      risk: 'HIGH',
      points: 25,
      description: 'Outdated Nginx version'
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

    // ===== 1. ANALYZE PORTS AND SERVICES (existing code) =====
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

    // ===== 2. NEW: ANALYZE CVEs (MISSING IN YOUR CODE!) =====
    const cveAssessment = this.assessCVEsForHost(host);
    hostRiskScore += cveAssessment.cveRiskScore;
    hostFindings.push(...cveAssessment.cveFindings);

    console.log(`📊 [CVE Analysis] ${host.host} - Found ${cveAssessment.totalCVEs} CVEs, CVE Risk Score: ${cveAssessment.cveRiskScore}`);

    // ===== 3. DETERMINE FINAL RISK (updated with CVE weighting) =====
    const finalRisk = this.calculateFinalRiskWithCVEs(hostRiskScore, cveAssessment);

    console.log(`🎯 [AI Risk Assessment] ${host.host} - Final Score: ${hostRiskScore}, Risk: ${finalRisk}`);

    return {
      host: host.host,
      hostname: host.hostname,
      riskScore: hostRiskScore,
      finalRisk: finalRisk,
      findings: hostFindings,
      openPorts: host.open_ports_count,
      device_type: host.device_type,
      assessment_timestamp: new Date().toISOString(),
      // NEW: Include CVE summary
      cve_summary: {
        total: cveAssessment.totalCVEs,
        critical: cveAssessment.criticalCVEs,
        high: cveAssessment.highCVEs,
        medium: cveAssessment.mediumCVEs
      }
    };
  }

  // ===== NEW: CVE ASSESSMENT METHOD =====
  assessCVEsForHost(host) {
    const cveFindings = [];
    let cveRiskScore = 0;

    // Extract all CVEs from all ports
    const allCVEs = [];
    host.ports.forEach(port => {
      if (port.cves && Array.isArray(port.cves)) {
        allCVEs.push(...port.cves.map(cve => ({
          ...cve,
          port: port.port,
          service: port.service?.name
        })));
      }
    });

    // Remove duplicate CVEs (same CVE might appear in multiple scripts)
    const uniqueCVEs = [];
    allCVEs.forEach(cve => {
      if (!uniqueCVEs.some(uc => uc.cve_id === cve.cve_id)) {
        uniqueCVEs.push(cve);
      }
    });

    // Count CVEs by severity
    let criticalCVEs = 0;
    let highCVEs = 0;
    let mediumCVEs = 0;
    let lowCVEs = 0;

    // Assess each CVE
    uniqueCVEs.forEach(cve => {
      const cvssScore = cve.CVSS?.score || 0;

      // Count by severity
      if (cvssScore >= 9.0) criticalCVEs++;
      else if (cvssScore >= 7.0) highCVEs++;
      else if (cvssScore >= 4.0) mediumCVEs++;
      else if (cvssScore > 0) lowCVEs++;

      // Calculate CVE risk points
      if (cvssScore >= 9.0) {
        cveRiskScore += 50; // Critical CVE
        cveFindings.push({
          type: 'CVE_RISK',
          cve_id: cve.cve_id,
          risk: 'CRITICAL',
          description: `Critical CVE detected: ${cve.cve_id} (CVSS: ${cvssScore})`,
          points: 50,
          cvss_score: cvssScore,
          port: cve.port,
          service: cve.service,
          evidence: `CVE ${cve.cve_id} on port ${cve.port}`
        });
      } else if (cvssScore >= 7.0) {
        cveRiskScore += 35; // High CVE
        cveFindings.push({
          type: 'CVE_RISK',
          cve_id: cve.cve_id,
          risk: 'HIGH',
          description: `High severity CVE: ${cve.cve_id} (CVSS: ${cvssScore})`,
          points: 35,
          cvss_score: cvssScore,
          port: cve.port,
          service: cve.service,
          evidence: `CVE ${cve.cve_id} on port ${cve.port}`
        });
      } else if (cvssScore >= 4.0) {
        cveRiskScore += 20; // Medium CVE
        cveFindings.push({
          type: 'CVE_RISK',
          cve_id: cve.cve_id,
          risk: 'MEDIUM',
          description: `Medium severity CVE: ${cve.cve_id} (CVSS: ${cvssScore})`,
          points: 20,
          cvss_score: cvssScore,
          port: cve.port,
          service: cve.service,
          evidence: `CVE ${cve.cve_id} on port ${cve.port}`
        });
      }

      // Extra points for exploits
      if (cve.exploit_available) {
        cveRiskScore += 30;
        cveFindings.push({
          type: 'CVE_EXPLOIT',
          cve_id: cve.cve_id,
          risk: 'HIGH',
          description: `CVE with known exploit available: ${cve.cve_id}`,
          points: 30,
          cvss_score: cvssScore,
          evidence: 'Known exploit in wild'
        });
      }
    });

    return {
      cveFindings,
      cveRiskScore,
      totalCVEs: uniqueCVEs.length,
      criticalCVEs,
      highCVEs,
      mediumCVEs,
      lowCVEs
    };
  }

  // ===== UPDATED: FINAL RISK CALCULATION WITH CVEs =====
  calculateFinalRiskWithCVEs(totalScore, cveAssessment) {
    // Base risk from your existing calculation
    let risk = this.calculateFinalRisk(totalScore);

    // Adjust risk based on CVEs
    if (cveAssessment.criticalCVEs > 0) {
      // Critical CVEs automatically make it HIGH or CRITICAL
      if (risk === 'LOW') risk = 'HIGH';
      if (risk === 'MEDIUM') risk = 'CRITICAL';
    } else if (cveAssessment.highCVEs >= 3) {
      // Multiple high CVEs increase risk
      if (risk === 'LOW') risk = 'MEDIUM';
      if (risk === 'MEDIUM') risk = 'HIGH';
    }

    return risk;
  }

  calculateFinalRisk(score) {
    if (score >= 60) return 'CRITICAL';
    if (score >= 40) return 'HIGH';
    if (score >= 20) return 'MEDIUM';
    if (score >= 10) return 'LOW';
    return 'INFO';
  }

  // ===== UPDATED: ASSESS ALL HOSTS WITH CVE SUMMARY =====
  assessAllHosts() {
    const assessedHosts = this.scanResults.map(host => this.assessHost(host));

    // Calculate statistics including CVEs
    const hostsWithRisk = assessedHosts.filter(h => h.riskScore !== undefined);
    const totalRiskScore = hostsWithRisk.reduce((sum, host) => sum + host.riskScore, 0);
    const averageRiskScore = hostsWithRisk.length > 0 ? totalRiskScore / hostsWithRisk.length : 0;
    const riskDistribution = this.calculateRiskDistribution(assessedHosts);

    // CVE statistics across all hosts
    const totalCVEs = assessedHosts.reduce((sum, host) => sum + (host.cve_summary?.total || 0), 0);
    const criticalCVEs = assessedHosts.reduce((sum, host) => sum + (host.cve_summary?.critical || 0), 0);
    const highCVEs = assessedHosts.reduce((sum, host) => sum + (host.cve_summary?.high || 0), 0);

    return {
      assessedHosts,
      summary: {
        totalHosts: assessedHosts.length,
        averageRiskScore: Math.round(averageRiskScore * 100) / 100,
        riskDistribution,
        overallRisk: this.calculateOverallRiskWithCVEs(assessedHosts),
        totalFindings: assessedHosts.reduce((sum, host) => sum + (host.findings ? host.findings.length : 0), 0),
        // NEW: CVE statistics
        cve_statistics: {
          total_cves: totalCVEs,
          critical_cves: criticalCVEs,
          high_cves: highCVEs,
          hosts_with_cves: assessedHosts.filter(h => h.cve_summary?.total > 0).length
        }
      }
    };
  }

  // ===== NEW: OVERALL RISK CALCULATION WITH CVEs =====
  calculateOverallRiskWithCVEs(hosts) {
    if (!hosts || hosts.length === 0) return 'UNKNOWN';

    const riskWeights = {
      CRITICAL: 5,
      HIGH: 4,
      MEDIUM: 3,
      LOW: 2,
      INFO: 1
    };

    let weightedSum = 0;
    let totalCriticalCVEs = 0;

    hosts.forEach(host => {
      weightedSum += riskWeights[host.finalRisk] || 1;

      // Count critical CVEs across all hosts
      if (host.cve_summary?.critical) {
        totalCriticalCVEs += host.cve_summary.critical;
      }
    });

    const averageWeight = weightedSum / hosts.length;

    // Adjust based on critical CVEs
    let adjustedWeight = averageWeight;
    if (totalCriticalCVEs > 0) {
      adjustedWeight += 0.5; // Critical CVEs increase overall risk
    }

    if (adjustedWeight >= 4.5) return 'CRITICAL';
    if (adjustedWeight >= 3.5) return 'HIGH';
    if (adjustedWeight >= 2.5) return 'MEDIUM';
    if (adjustedWeight >= 1.5) return 'LOW';
    return 'INFO';
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

  // ===== UPDATED: RECOMMENDATIONS WITH CVE SUPPORT =====
  generateRecommendations(assessedHosts) {
    const recommendations = [];

    assessedHosts.forEach(host => {
      // Port/service based recommendations
      host.findings.forEach(finding => {
        if (finding.risk === 'HIGH' || finding.risk === 'CRITICAL') {
          recommendations.push({
            host: host.host,
            priority: finding.risk,
            issue: finding.description,
            action: this.generateAction(finding),
            port: finding.port,
            type: finding.type,
            cve_id: finding.cve_id || null,
            cvss_score: finding.cvss_score || 0
          });
        }
      });

      // NEW: CVE summary recommendations
      if (host.cve_summary?.critical > 0) {
        recommendations.push({
          host: host.host,
          priority: 'CRITICAL',
          issue: `Found ${host.cve_summary.critical} critical CVEs on this host`,
          action: 'Apply emergency patches immediately. Consider isolating from network.',
          type: 'CVE_SUMMARY',
          cve_count: host.cve_summary.critical
        });
      }

      if (host.cve_summary?.high >= 3) {
        recommendations.push({
          host: host.host,
          priority: 'HIGH',
          issue: `Found ${host.cve_summary.high} high severity CVEs`,
          action: 'Prioritize patching within 7 days. Review security configuration.',
          type: 'CVE_SUMMARY',
          cve_count: host.cve_summary.high
        });
      }
    });

    // Sort by priority, then CVSS score
    return recommendations.sort((a, b) => {
      const priorityOrder = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
      const priorityDiff = priorityOrder[b.priority] - priorityOrder[a.priority];

      if (priorityDiff !== 0) return priorityDiff;

      // If same priority, sort by CVSS score (for CVEs)
      return (b.cvss_score || 0) - (a.cvss_score || 0);
    });
  }

  // ===== UPDATED: ACTION GENERATOR WITH CVE SUPPORT =====
  generateAction(finding) {
    const actions = {
      'SSH version outdated': 'Upgrade SSH to latest version and disable weak algorithms',
      'HTTP without TLS': 'Implement HTTPS with valid certificate',
      'Windows SMB services exposed': 'Restrict SMB access, disable if not needed',
      'Telnet service exposed': 'Replace Telnet with SSH immediately',
      'FTP service exposed': 'Use SFTP or FTPS instead of plain FTP',
      'VMware Authentication Daemon vulnerable version': 'Update VMware tools to latest version',
      'Node.js service detected': 'Update Node.js and dependencies, security audit',
      // NEW: CVE-specific actions
      'Critical CVE detected': 'Apply emergency patch immediately. If no patch exists, implement workarounds or isolate system.',
      'High severity CVE': 'Apply patch within 24 hours. Monitor for exploitation attempts.',
      'Medium severity CVE': 'Apply patch within 7 days. Assess business impact.',
      'CVE with known exploit available': 'HIGH PRIORITY - Patch immediately as exploit is publicly available.'
    };

    // Try to match the full description first
    if (actions[finding.description]) {
      return actions[finding.description];
    }

    // Try to match by prefix
    const prefix = finding.description.split(' - ')[0];
    if (actions[prefix]) {
      return actions[prefix];
    }

    // CVE-specific default actions
    if (finding.type === 'CVE_RISK') {
      return `Apply security patch for ${finding.cve_id}. Review vendor advisory for mitigation steps.`;
    }

    if (finding.type === 'CVE_EXPLOIT') {
      return `URGENT: Patch ${finding.cve_id} immediately - known exploit in wild.`;
    }

    return 'Review configuration and apply security best practices';
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

  // Deep Scan: Updated from file 2 with CVE scanning
deep_scan: {
    args: [
      '--unprivileged',       // Evita erros de permissões
      '-sT',                  // Connect Scan (Obrigatório em Docker)
      '-Pn',                  // Não faz Ping
      '-n',                   // Não resolve DNS (Crucial!)
      
      '-sV',                  // Detetar Versão
      '--version-intensity', '2', // Intensidade Leve (Para o Nginx não rejeitar)
      
      '--script', 'vulners,http-title,banner',
      '--script-args', 'vulners.showall',
      '--script-timeout', '2m',
      
      '--top-ports', '1000',  // Podes usar as 1000 portas mais comuns
      
      '--open',
      '-oX', '-'
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

// FIXED: Single improved parseVulnersOutput function
function parseVulnersOutput(outputText) {
  const cveList = [];
  if (!outputText || typeof outputText !== 'string') return cveList;

  console.log(`[CVE Parser] Raw vulners output length: ${outputText.length}`);

  const lines = outputText.split('\n');

  // Multiple patterns to catch different vulners output formats
  const patterns = [
    // Pattern 1: CVE-YYYY-XXXXXX   SCORE    https://vulners.com/cve/CVE-YYYY-XXXXXX
    /(CVE-(\d{4})-\d+)\s+(\d+\.\d+|\d+)\s+https:\/\/vulners\.com\/cve\/\1/,

    // Pattern 2: CVE-YYYY-XXXXXX   SCORE
    /(CVE-(\d{4})-\d+)\s+(\d+\.\d+|\d+)/,

    // Pattern 3: [CVE-YYYY-XXXXXX] Score: SCORE
    /\[(CVE-(\d{4})-\d+)\].*?Score:\s*(\d+\.\d+|\d+)/i,

    // Pattern 4: CVE-YYYY-XXXXXX (CVSS: SCORE)
    /(CVE-(\d{4})-\d+).*?\(CVSS:?\s*(\d+\.\d+|\d+)\)/i
  ];

  for (const line of lines) {
    const trimmedLine = line.trim();
    if (!trimmedLine) continue;

    // Try each pattern
    for (const pattern of patterns) {
      const match = trimmedLine.match(pattern);
      if (match) {
        const cveId = match[1].toUpperCase();
        const year = parseInt(match[2]) || new Date().getFullYear();
        const cvssScore = parseFloat(match[3]) || 0;

        // Skip if we already have this CVE
        if (cveList.some(cve => cve.cve_id === cveId)) continue;

        // Use June 15th of the CVE year as the published date (mid-year default)
        const publishedDate = `${year}-06-15T00:00:00Z`;

        // Check for exploit mentions
        const exploitAvailable = trimmedLine.toLowerCase().includes('exploit') ||
          trimmedLine.toLowerCase().includes('metasploit');

        cveList.push({
          cve_id: cveId,
          CVSS: {
            score: cvssScore,
            vector: 'N/A'
          },
          exploit_available: exploitAvailable,
          publishedDate: publishedDate,
          year: year
        });

        console.log(`[CVE Parser] Found CVE: ${cveId} (Year: ${year}, Score: ${cvssScore})`);
        break; // Found with this pattern, move to next line
      }
    }

    // Also look for bare CVE IDs (no score) - this is a fallback
    const bareCvePattern = /(CVE-\d{4}-\d+)/gi;
    const bareMatches = trimmedLine.match(bareCvePattern);
    if (bareMatches) {
      for (const cveId of bareMatches) {
        const cveIdUpper = cveId.toUpperCase();
        if (!cveList.some(cve => cve.cve_id === cveIdUpper)) {
          const yearMatch = cveIdUpper.match(/CVE-(\d{4})-\d+/);
          const year = yearMatch ? parseInt(yearMatch[1]) : new Date().getFullYear();

          cveList.push({
            cve_id: cveIdUpper,
            CVSS: {
              score: 0,
              vector: 'N/A'
            },
            exploit_available: false,
            publishedDate: `${year}-06-15T00:00:00Z`,
            year: year
          });
          console.log(`[CVE Parser] Found bare CVE: ${cveIdUpper} (Year: ${year})`);
        }
      }
    }
  }

  console.log(`[CVE Parser] Total CVEs from vulners: ${cveList.length}`);
  return cveList;
}

// Extract CVEs from any script output
function extractCVEsFromAnyScript(outputText) {
  const cveList = [];
  if (!outputText) return cveList;

  // Look for CVE patterns
  const cvePattern = /CVE-\d{4}-\d+/gi;
  const matches = outputText.match(cvePattern);

  if (matches) {
    const uniqueCVEs = [...new Set(matches.map(m => m.toUpperCase()))];

    uniqueCVEs.forEach(cveId => {
      const yearMatch = cveId.match(/CVE-(\d{4})-\d+/);
      const year = yearMatch ? parseInt(yearMatch[1]) : new Date().getFullYear();

      // Try to extract CVSS score if present
      let cvssScore = 0;
      const cveIndex = outputText.indexOf(cveId);
      if (cveIndex !== -1) {
        const context = outputText.substring(cveIndex, cveIndex + 100);
        const scoreMatch = context.match(/(\d+\.\d+|\d+)(?=\s*\)|\s*$|\s*,|\s*-)/);
        if (scoreMatch) {
          cvssScore = parseFloat(scoreMatch[1]) || 0;
        }
      }

      cveList.push({
        cve_id: cveId,
        CVSS: {
          score: cvssScore,
          vector: 'N/A'
        },
        exploit_available: outputText.toLowerCase().includes('exploit') ||
          outputText.toLowerCase().includes('metasploit'),
        publishedDate: `${year}-06-15T00:00:00Z`,
        year: year
      });
    });
  }

  return cveList;
}

// Helper to extract ALL CVEs from ports for a host
function extractAllCVEsFromPorts(ports) {
  const allCVEs = [];
  if (!ports || !Array.isArray(ports)) return allCVEs;

  ports.forEach(port => {
    if (port.cves && Array.isArray(port.cves)) {
      port.cves.forEach(cve => {
        // Avoid duplicates within same host
        if (!allCVEs.some(existing => existing.cve_id === cve.cve_id)) {
          allCVEs.push({
            ...cve,
            port: port.port,
            service: port.service?.name || 'unknown'
          });
        }
      });
    }
  });

  return allCVEs;
}

// Network helper functions
function extractSampleIP(target) {
  console.log(`[Pre-scan] Extracting sample IP from: ${target}`);

  const subnetMatch = target.match(/^(\d+\.\d+\.\d+)\.0\/(\d+)$/);
  if (subnetMatch) {
    return `${subnetMatch[1]}.1`;
  }

  if (target.includes('-')) {
    return target.split('-')[0];
  }

  return target;
}

function checkNetworkReachable(ip) {
  return new Promise((resolve) => {
    console.log(`[Pre-scan] Pinging ${ip}...`);

    const isWindows = process.platform === 'win32';
    const pingArgs = isWindows
      ? ['-n', '2', '-w', '2000', ip]
      : ['-c', '2', '-W', '2', ip];

    const ping = spawn('ping', pingArgs);
    let isReachable = false;

    ping.on('close', (code) => {
      console.log(`[Pre-scan] Ping process exited with code: ${code}`);
      resolve(isReachable);
    });

    ping.stdout.on('data', (data) => {
      const output = data.toString();
      if (output.includes('TTL=') || output.includes('time=') || output.includes('bytes from')) {
        isReachable = true;
        console.log(`[Pre-scan] ✅ Host ${ip} is reachable!`);
      }
    });

    setTimeout(() => {
      try { ping.kill(); } catch (e) { }
      resolve(isReachable);
    }, 5000);
  });
}

function estimateHostCount(target) {
  if (!target || typeof target !== 'string') return 1;

  const cidrMatch = target.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
  if (cidrMatch) {
    const prefixBits = parseInt(cidrMatch[2]);
    return Math.pow(2, 32 - prefixBits) - 2;
  }

  const rangeMatch = target.match(/^(\d+\.\d+\.\d+\.\d+)-(\d+)$/);
  if (rangeMatch) {
    const start = parseInt(rangeMatch[1].split('.').pop());
    const end = parseInt(rangeMatch[2]);
    return Math.max(1, end - start + 1);
  }

  if (target.includes(',')) {
    return Math.max(1, target.split(',').length);
  }

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

// Device classification (keeping your existing functions but removing duplicates)
const { toVendor, isRandomMac } = require('@network-utils/vendor-lookup');

// Load OUI overrides (local file to improve vendor detection)
const OUI_OVERRIDES_PATH = path.join(__dirname, 'oui-overrides-clean.json');
let ouiOverrides = {};
try {
  const raw = fs.readFileSync(OUI_OVERRIDES_PATH, 'utf8');
  ouiOverrides = JSON.parse(raw || '{}');
  console.log('[OUI Overrides] Loaded', Object.keys(ouiOverrides).length, 'entries');
} catch (e) {
  console.log('[OUI Overrides] No overrides file found or failed to parse');
  ouiOverrides = {};
}

// Load discovered OUI map to persist unknown OUIs seen at runtime
const OUI_DISCOVERED_PATH = path.join(__dirname, 'oui-discovered.json');
let ouiDiscovered = {};
try {
  const rawD = fs.readFileSync(OUI_DISCOVERED_PATH, 'utf8');
  ouiDiscovered = JSON.parse(rawD || '{}');
  console.log('[OUI Discovered] Loaded', Object.keys(ouiDiscovered).length, 'entries');
} catch (e) {
  ouiDiscovered = {};
}

// Load full OUI DB (optional, populated by tools/convert-ouitxt-to-json.js)
const OUI_DB_PATH = path.join(__dirname, 'oui-db.json');
let ouiDb = {};
try {
  const rawDb = fs.readFileSync(OUI_DB_PATH, 'utf8');
  ouiDb = JSON.parse(rawDb || '{}');
  console.log('[OUI DB] Loaded', Object.keys(ouiDb).length, 'entries');
} catch (e) {
  ouiDb = {};
  console.log('[OUI DB] No OUI DB found at', OUI_DB_PATH);
}

// Attempt to load a maintained OUI library as another lookup option
let ouiLib = null;
try {
  ouiLib = require('mac-oui-lookup');
  console.log('[OUI Lib] loaded `mac-oui-lookup` package');
} catch (e) {
  ouiLib = null;
  console.log('[OUI Lib] `mac-oui-lookup` not installed; using local DB and vendor-lookup fallback');
}

// ===== DEVICE CLASSIFICATION FUNCTIONS =====
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
      // Normalize MAC: ensure uppercase and colon-separated
      const normalizedMac = macUpper.includes(':') ? macUpper : macUpper.match(/.{1,2}/g) ? macUpper.match(/.{1,2}/g).join(':') : macUpper;

      // Check if it's a random MAC first (mobile/device privacy)
      if (isRandomMac(normalizedMac)) {
        detectedVendor = classifyRandomMac(normalizedMac);
        // Treat random MACs as mobile devices by default
        classificationBasis = 'random_mac';
        console.log(`[MAC Lookup] ${mac} appears to be a randomized MAC (privacy) → ${detectedVendor}`);
        // Set preliminary device classification to mobile so UI shows phone/tablet
        deviceType = 'Smartphone/Tablet';
        deviceCategory = 'mobile';
        confidence = 'medium-high';
      } else {
        // Check local overrides and local DB first (use plain hex OUI)
        const ouiPrefix = normalizedMac.replace(/:/g, '').slice(0, 6);
        if (ouiPrefix && ouiOverrides[ouiPrefix]) {
          detectedVendor = ouiOverrides[ouiPrefix];
          classificationBasis = 'oui_override';
          console.log(`[OUI Override] ${normalizedMac} (${ouiPrefix}) → ${detectedVendor}`);
        } else if (ouiPrefix && ouiDb[ouiPrefix]) {
          detectedVendor = ouiDb[ouiPrefix];
          classificationBasis = 'oui_db';
          console.log(`[OUI DB] ${normalizedMac} (${ouiPrefix}) → ${detectedVendor}`);
        } else {
          // Try offline OUI library first (if installed), then vendor-lookup package
          let vendorName = '';
          if (ouiLib) {
            try {
              let libRes = null;
              if (typeof ouiLib === 'function') {
                libRes = ouiLib(normalizedMac);
              } else if (typeof ouiLib.parse === 'function') {
                libRes = ouiLib.parse(normalizedMac);
              } else if (typeof ouiLib.get === 'function') {
                libRes = ouiLib.get(normalizedMac);
              }

              if (libRes) {
                if (typeof libRes === 'string') vendorName = libRes;
                else if (typeof libRes === 'object') vendorName = libRes.company || libRes.org || libRes.vendor || libRes.name || '';
              }
            } catch (e) {
              // ignore library errors and fall back
              vendorName = '';
            }
          }

          // Fallback to existing vendor-lookup package if library didn't produce a name
          if (!vendorName) {
            const vendorResult = toVendor(normalizedMac);
            if (vendorResult) {
              if (typeof vendorResult === 'string') vendorName = vendorResult;
              else if (typeof vendorResult === 'object') {
                vendorName = vendorResult.company || vendorResult.org || vendorResult.vendor || vendorResult.name || '';
              }
            }
          }

          if (vendorName) {
            detectedVendor = vendorName;
            classificationBasis = 'mac_oui';
            console.log(`[MAC Lookup] ${normalizedMac} → ${detectedVendor}`);
          } else {
            // Fallback: basic OUI prefix map for common consumer vendors
            const fallbackMap = {
              '1A56E1': 'Unknown Vendor (OUI 1A:56:E1)',
              'AC6175': 'Huawei Technologies',
              '58687A': 'Sagemcom Broadband SAS',
              '7A29D9': 'Unknown Vendor (OUI 7A:29:D9)'
            };
            if (fallbackMap[ouiPrefix]) {
              detectedVendor = fallbackMap[ouiPrefix];
              classificationBasis = 'oui_fallback';
              console.log(`[OUI Fallback] ${normalizedMac} → ${detectedVendor}`);
            } else {
              console.log(`[MAC Lookup] ${normalizedMac} → No vendor found in database`);
            }
          }
        }
      }

      // Persist unseen OUI prefixes to discovered file for later review
      try {
        if (typeof ouiPrefix !== 'undefined' && ouiPrefix && !ouiOverrides[ouiPrefix]) {
          if (!ouiDiscovered[ouiPrefix]) {
            ouiDiscovered[ouiPrefix] = { vendor: detectedVendor || null, first_seen: new Date().toISOString() };
            try {
              fs.writeFileSync(OUI_DISCOVERED_PATH, JSON.stringify(ouiDiscovered, null, 2), 'utf8');
              console.log(`[OUI Discovered] Recorded new OUI ${ouiPrefix} -> ${detectedVendor || 'unknown'}`);
            } catch (wErr) {
              console.log(`[OUI Discovered] Write failed for ${ouiPrefix}: ${wErr.message}`);
            }
          }
        }
      } catch (persistErr) {
        console.log(`[OUI Discovered] Persist error: ${persistErr.message}`);
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

  // Vendor-based heuristics to refine classification when possible
  const vendorHeuristic = applyVendorHeuristics(vendorLower, hostnameLower, ipv4);
  if (vendorHeuristic) {
    // Only override when heuristic confidence is higher than current
    const levels = { 'very-low': 0, low: 1, 'medium-low': 2, medium: 3, 'medium-high': 4, high: 5 };
    const currentLevel = levels[confidence] || 1;
    const heuristicLevel = levels[vendorHeuristic.confidence] || 3;
    if (heuristicLevel >= currentLevel) {
      deviceType = vendorHeuristic.deviceType || deviceType;
      deviceCategory = vendorHeuristic.deviceCategory || deviceCategory;
      confidence = vendorHeuristic.confidence || confidence;
      classificationBasis = vendorHeuristic.basis || classificationBasis;
      console.log(`[Vendor Heuristic] Applied heuristic for vendor=${vendorLower}: ${deviceType} (${deviceCategory})`);
    }
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

  // If classified as mobile but vendor is missing, provide a clear fallback label
  try {
    const vendorMissing = !detectedVendor || String(detectedVendor).toLowerCase().includes('unknown');
    const isMobileCategory = deviceCategory === 'mobile' || deviceType.toLowerCase().includes('smartphone') || classificationBasis === 'random_mac';
    if (isMobileCategory && vendorMissing) {
      detectedVendor = 'Random/Private MAC (likely mobile)';
      classificationBasis = classificationBasis === 'random_mac' ? classificationBasis : `${classificationBasis}|random_mac_fallback`;
    }
  } catch (e) { /* ignore */ }

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

// Vendor-based heuristics: quick rules for common home/ISP devices
function applyVendorHeuristics(vendorLower, hostnameLower, ipv4) {
  if (!vendorLower && !hostnameLower) return null;

  // Sagemcom devices are typically ISP-provided gateways/routers
  if (vendorLower.includes('sagemcom') || vendorLower.includes('sagem')) {
    return { deviceType: 'Network Gateway/Router', deviceCategory: 'networking', confidence: 'high', basis: 'vendor_heuristic' };
  }

  // Huawei often indicates network infrastructure or ISP gateway
  if (vendorLower.includes('huawei')) {
    return { deviceType: 'Network Infrastructure Device', deviceCategory: 'networking', confidence: 'high', basis: 'vendor_heuristic' };
  }

  // TP-Link, D-Link, Linksys, Netgear often are home routers or access points
  if (vendorLower.includes('tplink') || vendorLower.includes('tp-link') || vendorLower.includes('d-link') || vendorLower.includes('dlink') || vendorLower.includes('linksys') || vendorLower.includes('netgear')) {
    return { deviceType: 'Network Gateway/Router', deviceCategory: 'networking', confidence: 'high', basis: 'vendor_heuristic' };
  }

  // Generic consumer OUIs we couldn't map but that appear in home networks — assume gateway/device
  if (vendorLower.includes('unknown vendor (oui') || vendorLower.includes('unknown vendor')) {
    return { deviceType: 'Network Device', deviceCategory: 'networking', confidence: 'medium', basis: 'oui_heuristic' };
  }

  // If hostname suggests access point / router
  if (hostnameLower && (hostnameLower.includes('router') || hostnameLower.includes('gateway') || hostnameLower.includes('ap-') || hostnameLower.includes('wifi'))) {
    return { deviceType: 'Network Gateway/Router', deviceCategory: 'networking', confidence: 'high', basis: 'hostname_heuristic' };
  }

  return null;
}

// Run nmap scan
function runNmap(args, target, presetName, scanId) {
  return new Promise((resolve, reject) => {
    const preset = PRESETS[presetName];
    if (!preset) {
      return reject(new Error(`Unknown preset: ${presetName}`));
    }

    const timeoutMs = preset.calculateTimeout(target);
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
        } catch (e) { }
        resolve({ stdout, stderr, code: -1, signal: 'TIMEOUT', duration: `${elapsed}s` });
        return;
      }
      try { n.kill('SIGKILL'); } catch (e) { }
      reject(new Error(`Timeout after ${elapsed}s`));
    }, timeoutMs);

    n.stdout.on('data', d => {
      stdout += d.toString();
    });

    n.stderr.on('data', d => {
      stderr += d.toString();
    });

    n.on('error', err => {
      clearTimeout(timer);
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
      } catch (e) { }

      if ((stdout || '').trim().length > 0 && ((stdout || '').includes('<?xml') || (stdout || '').includes('<nmaprun'))) {
        resolve({ stdout, stderr, code, signal, duration: `${duration}s`, raw_path: tmpPath });
      } else if ((stdout || '').trim().length > 0) {
        resolve({ stdout, stderr, code, signal, duration: `${duration}s`, raw_path: tmpPath });
      } else {
        let errorMsg = `Scan failed - no output received`;
        if ((stderr || '').includes('Failed to resolve')) errorMsg = `DNS resolution failed for ${target}`;
        else if ((stderr || '').includes('did not match')) errorMsg = `Script error: ${stderr.split('\n')[0]}`;
        else if (code !== 0) errorMsg = `Nmap exited with code ${code}: ${stderr || 'unknown error'}`;
        const e = new Error(errorMsg);
        e.raw_path = tmpPath;
        reject(e);
      }
    });
  });
}

// Fixed parseNetworkScanXml function
async function parseNetworkScanXml(xmlText, targetNetwork, preset) {
  try {
    if (!xmlText || typeof xmlText !== 'string' || xmlText.trim() === '') {
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

    const result = await xml2js.parseStringPromise(xmlText, {
      explicitArray: false,
      mergeAttrs: false,
      normalize: true,
      trim: true,
      strict: false
    });

    let hosts = [];
    if (result.NMAPRUN && result.NMAPRUN.HOST) {
      hosts = Array.isArray(result.NMAPRUN.HOST) ? result.NMAPRUN.HOST : [result.NMAPRUN.HOST];
    } else if (result.nmaprun && result.nmaprun.host) {
      hosts = Array.isArray(result.nmaprun.host) ? result.nmaprun.host : [result.nmaprun.host];
    } else if (result.host) {
      hosts = Array.isArray(result.host) ? result.host : [result.host];
    }

    const ScanResults = [];

    for (const hostObj of hosts) {
      if (!hostObj) continue;

      // Extract addresses
      let ipv4 = 'unknown', mac = '', vendor = '', hostStatus = 'unknown';

      if (hostObj.STATUS && hostObj.STATUS.$ && hostObj.STATUS.$.STATE) {
        hostStatus = hostObj.STATUS.$.STATE;
      }

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

      // Extract hostname
      let hostname = '';
      if (hostObj.HOSTNAMES && hostObj.HOSTNAMES.HOSTNAME) {
        const hostnames = Array.isArray(hostObj.HOSTNAMES.HOSTNAME)
          ? hostObj.HOSTNAMES.HOSTNAME
          : [hostObj.HOSTNAMES.HOSTNAME];
        if (hostnames.length > 0 && hostnames[0].$ && hostnames[0].$.NAME) {
          hostname = hostnames[0].$.NAME;
        }
      }

      const deviceInfo = classifyDevice(ipv4, mac, vendor, hostname);

      // Extract ports
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

      ScanResults.push({
        host: ipv4,
        hostname: hostname,
        mac_address: mac,
        vendor: vendor,
        status: hostStatus,
        ports: detectedPorts,
        open_ports_count: openPorts,
        device_type: deviceInfo.device_type,
        device_category: deviceInfo.device_category,
        classification_confidence: deviceInfo.confidence,
        classification_basis: deviceInfo.classification_basis,
        scan_timestamp: new Date().toISOString()
      });
    }

    const activeHosts = ScanResults.filter(host => host.status === 'up' || host.open_ports_count > 0);

    return {
      network: targetNetwork,
      hosts: ScanResults,
      totalHosts: ScanResults.length,
      activeHosts: activeHosts.length,
      openPortsTotal: ScanResults.reduce((sum, host) => sum + host.open_ports_count, 0),
      vulnerabilitiesTotal: 0,
      cvesTotal: 0,
      device_types: [...new Set(ScanResults.map(h => h.device_type))],
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
      cvesTotal: 0,
      parse_error: error.message
    };
  }
}

// FIXED: parseDeepScanXml with proper CVE handling
async function parseDeepScanXml(xmlText, targetNetwork) {
  console.log('🎯 [parseDeepScanXml] Starting XML parsing');
  console.log(`📏 XML length: ${xmlText?.length || 0} chars`);

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

    const result = await xml2js.parseStringPromise(xmlText, {
      explicitArray: false,
      mergeAttrs: true,
      normalize: true,
      trim: true,
      strict: false
    });

    const root = result.nmaprun || result.NMAPRUN;
    if (!root) {
      console.log('❌ [parseDeepScanXml] No nmaprun/NMAPRUN found');
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

    let hostsArray = [];
    if (root.host || root.HOST) {
      const hostData = root.host || root.HOST;
      hostsArray = Array.isArray(hostData) ? hostData : [hostData];
      console.log(`🎯 [parseDeepScanXml] Found ${hostsArray.length} hosts`);
    } else {
      console.log('❌ [parseDeepScanXml] No host/HOST data found');
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

        // status
        const status = get(hostObj, 'status')?.state || get(hostObj, 'STATUS')?.STATE || 'unknown';

        // addresses
        let ipv4 = 'unknown', mac = '', vendor = '';
        const addressesRaw = get(hostObj, 'address') || [];
        const addresses = toArray(addressesRaw);

        for (const addr of addresses) {
          const addrType = addr.addrtype || addr.ADDRTYPE;
          const addrVal = addr.addr || addr.ADDR;
          const addrVendor = addr.vendor || addr.VENDOR || '';

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
        }

        const deviceInfo = classifyDevice(ipv4, mac, vendor, hostname);

        // REMOVED: foundVulns array - we only store CVEs in ports[].cves
        const hostResult = {
          host: ipv4,
          hostname: hostname || '',
          mac_address: mac || '',
          vendor: vendor || '',
          status,
          ports: [],          // CVEs stored ONLY here at port level
          open_ports_count: 0,
          device_type: deviceInfo.device_type,
          device_category: deviceInfo.device_category,
          classification_confidence: deviceInfo.confidence,
          classification_basis: deviceInfo.classification_basis,
          scan_timestamp: new Date().toISOString(),
          scan_type: 'deep_scan'
        };

        // ports
        const portsRoot = get(hostObj, 'ports') || get(hostObj, 'PORTS') || {};
        const portData = portsRoot.port || portsRoot.PORT;
        const portsArr = toArray(portData);

        for (const p of portsArr) {
          const stateObj = p.state || p.STATE || {};
          const state_state = stateObj.state || stateObj.STATE || (typeof stateObj === 'string' ? stateObj : 'unknown');

          if (state_state !== 'open') continue;

          const portid = p.portid || p.PORTID || '';
          const protocol = p.protocol || p.PROTOCOL || 'tcp';
          const state_reason = stateObj.reason || stateObj.REASON || '';

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

          // scripts
          const scriptsRaw = p.script || p.SCRIPT || [];
          const scriptsArr = toArray(scriptsRaw);
          const parsedScripts = scriptsArr.map(s => ({
            id: s.id || s.ID || '',
            output: s.output || s.OUTPUT || ''
          }));

          // Extract CVEs from ALL scripts (not just vulners)
          const portCVEs = [];

          for (const s of parsedScripts) {
            if (!s.id || !s.output) continue;

            // Use the unified parseVulnersOutput for vulners script
            if (s.id === 'vulners') {
              const vulnersCVEs = parseVulnersOutput(s.output);
              if (vulnersCVEs.length > 0) {
                console.log(`✅ [CVE Parser] Found ${vulnersCVEs.length} CVEs via vulners script for port ${portid}`);
                vulnersCVEs.forEach(cve => {
                  if (!portCVEs.some(existing => existing.cve_id === cve.cve_id)) {
                    portCVEs.push(cve);
                  }
                });
              }
            }
            // For other scripts, extract CVEs if present
            else if (s.output.includes('CVE-')) {
              const otherCVEs = extractCVEsFromAnyScript(s.output);
              if (otherCVEs.length > 0) {
                otherCVEs.forEach(cve => {
                  if (!portCVEs.some(existing => existing.cve_id === cve.cve_id)) {
                    portCVEs.push(cve);
                  }
                });
              }
            }
          }

          const portRecord = {
            port: portid,
            protocol,
            state: state_state,
            state_reason,
            service,
            scripts: parsedScripts,
            cves: portCVEs, // Store CVEs ONLY here
            summary: `Port ${portid} ${state_state} - ${service.name} ${service.version}`.trim()
          };

          hostResult.ports.push(portRecord);
        }

        hostResult.open_ports_count = hostResult.ports.length;

        // Log CVE details
        const totalPortCVEs = hostResult.ports.reduce((sum, port) => sum + (port.cves?.length || 0), 0);
        if (totalPortCVEs > 0) {
          console.log(`✅ [parseDeepScanXml] Host ${ipv4} has ${totalPortCVEs} CVEs across ${hostResult.ports.length} ports`);
        }

        ScanResults.push(hostResult);

      } catch (hostError) {
        console.error(`❌ [parseDeepScanXml] Error processing host ${index + 1}:`, hostError.message);
      }
    }

    console.log(`\n🎉 [parseDeepScanXml] COMPLETED: ${ScanResults.length} hosts parsed`);

    // Calculate totals
    const cveTotal = ScanResults.reduce((sum, h) =>
      sum + h.ports.reduce((portSum, port) => portSum + (port.cves?.length || 0), 0), 0);

    const activeHosts = ScanResults.filter(h => h.status === 'up' || h.open_ports_count > 0);

    return {
      network: targetNetwork,
      hosts: ScanResults,
      totalHosts: ScanResults.length,
      activeHosts: activeHosts.length,
      openPortsTotal: ScanResults.reduce((sum, h) => sum + (h.open_ports_count || 0), 0),
      vulnerabilitiesTotal: 0, // We're not using foundVulns anymore
      cvesTotal: cveTotal,
      device_types: [...new Set(ScanResults.map(h => h.device_type))],
      timestamp: new Date().toISOString(),
      scan_type: 'deep_scan'
    };

  } catch (err) {
    console.error('💥 [parseDeepScanXml] CRITICAL XML parse error:', err.message);
    return {
      network: targetNetwork,
      hosts: [],
      totalHosts: 0,
      activeHosts: 0,
      openPortsTotal: 0,
      vulnerabilitiesTotal: 0,
      cvesTotal: 0,
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

// Store quick scan results
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
      requested_by: userId ? db.collection('User').doc(userId) : null,
      target_id: targetId || null
    };

    await safeFirestoreSet(scanResultRef, docData);
  }
}

// FIXED: Store deep scan results with proper CVE handling
async function storeDeepScanResults(scanId, parsed, runResult, preset, userId, targetId) {
  console.log(`[DEBUG storeDeepScanResults] Starting storage for scan: ${scanId}`);
  console.log(`[DEBUG] Number of hosts to store: ${parsed.hosts ? parsed.hosts.length : 0}`);

  // Run AI risk assessment
  console.log(`[AI] Starting risk assessment for ${parsed.hosts.length} hosts...`);
  const riskExpert = new RiskAssessmentExpert(parsed.hosts);
  const riskAssessment = riskExpert.assessAllHosts();
  const recommendations = riskExpert.generateRecommendations(riskAssessment.assessedHosts);

  console.log(`[AI] Risk assessment completed:`);
  console.log(`[AI] - Overall Risk: ${riskAssessment.summary.overallRisk}`);
  console.log(`[AI] - Total Findings: ${riskAssessment.summary.totalFindings}`);

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

      // Find risk assessment for this host
      const hostRiskAssessment = riskAssessment.assessedHosts.find(h => h.host === hostResult.host);

      // Handle userId reference
      let userRef = null;
      if (userId) {
        try {
          const userDoc = await db.collection('User').doc(userId).get();
          if (userDoc.exists) {
            userRef = db.collection('User').doc(userId);
          }
        } catch (userError) {
          console.error(`[DEBUG] Error checking user ${userId}:`, userError.message);
        }
      }

      // Handle targetId reference
      let targetRef = null;
      if (targetId) {
        try {
          const targetDoc = await db.collection('Targets').doc(targetId).get();
          if (targetDoc.exists) {
            targetRef = targetId;
          }
        } catch (targetError) {
          console.error(`[DEBUG] Error checking target ${targetId}:`, targetError.message);
        }
      }

      // Prepare ports data with CVEs
      const sanitizedPorts = (hostResult.ports || []).map((p, portIndex) => {
        const portCVEs = [];

        // Extract CVEs from scripts
        if (p.scripts) {
          for (const script of p.scripts) {
            if (script.id === 'vulners' && script.output) {
              const cveList = parseVulnersOutput(script.output);
              portCVEs.push(...cveList);
            } else if (script.output && script.output.includes('CVE-')) {
              const otherCVEs = extractCVEsFromAnyScript(script.output);
              portCVEs.push(...otherCVEs);
            }
          }
        }

        // Remove duplicates
        const uniqueCVEs = [];
        portCVEs.forEach(cve => {
          if (!uniqueCVEs.some(existing => existing.cve_id === cve.cve_id)) {
            uniqueCVEs.push(cve);
          }
        });

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
          cves: uniqueCVEs, // Store CVEs at port level
          banner: p.banner || '',
          summary: p.summary || ''
        };
      });

      console.log(`[DEBUG] Prepared ${sanitizedPorts.length} ports for ${hostResult.host}`);

      // Extract ALL CVEs from all ports for this host
      const allHostCVEs = extractAllCVEsFromPorts(sanitizedPorts);

      const docData = {
        scan_id: scanId,
        host: hostResult.host || 'unknown',
        hostname: hostResult.hostname || '',
        mac_address: hostResult.mac_address || '',
        vendor: hostResult.vendor || '',
        host_status: hostResult.status || 'unknown',
        ports: sanitizedPorts,
        open_ports_count: hostResult.open_ports_count || 0,
        device_type: hostResult.device_type || 'Unknown Device',
        device_category: hostResult.device_category || 'unknown',
        classification_confidence: hostResult.classification_confidence || 'low',
        classification_basis: hostResult.classification_basis || 'default',

        // AI Risk Assessment
        risk_assessment: hostRiskAssessment ? {
          riskScore: hostRiskAssessment.riskScore,
          finalRisk: hostRiskAssessment.finalRisk,
          findings: hostRiskAssessment.findings,
          assessment_timestamp: hostRiskAssessment.assessment_timestamp
        } : null,

        // Store CVEs aggregated at host level (for easy querying)
        foundCVEs: allHostCVEs, // Now properly populated

        created_at: admin.firestore.FieldValue.serverTimestamp(),
        network_scan: false,
        parent_scan_id: scanId,
        scan_duration: runResult.duration || 'unknown',
        preset_used: preset,
        scan_type: 'deep',
        requested_by: userRef,
        target_id: targetRef
      };

      console.log(`[DEBUG] Attempting to store data for ${hostResult.host}...`);

      // Use direct Firestore set
      await scanResultRef.set(docData);

      storedCount++;
      console.log(`✅ Successfully stored deep scan result for ${hostResult.host}`);
      console.log(`📊 Host has ${allHostCVEs.length} CVEs and ${hostResult.open_ports_count || 0} open ports`);
      console.log(`🎯 [AI] Risk assessment: ${hostRiskAssessment?.finalRisk || 'UNKNOWN'} (Score: ${hostRiskAssessment?.riskScore || 0})`);

    } catch (hostError) {
      errorCount++;
      console.error(`❌ Failed to store host ${hostResult.host}:`, hostError.message);
    }
  }

  // Store risk assessment summary in the main scan document
  try {
    const scanRef = db.collection('Scan').doc(scanId);
    const scanDoc = await scanRef.get();

    if (scanDoc.exists) {
      const currentData = scanDoc.data();

      // Calculate overall security rating
      const calculateOverallRating = () => {
        if (!riskAssessment.assessedHosts || riskAssessment.assessedHosts.length === 0) return 'UNKNOWN';

        const riskWeights = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
        const weightedSum = riskAssessment.assessedHosts.reduce((sum, h) => {
          return sum + (riskWeights[h.finalRisk] || 1);
        }, 0);

        const average = weightedSum / riskAssessment.assessedHosts.length;
        if (average >= 4.5) return 'CRITICAL';
        if (average >= 3.5) return 'HIGH';
        if (average >= 2.5) return 'MEDIUM';
        if (average >= 1.5) return 'LOW';
        return 'INFO';
      };

      const overallRating = calculateOverallRating();

      await safeFirestoreUpdate(scanRef, {
        'summary.overall_security_rating': overallRating,
        'summary.risk_assessment': riskAssessment.summary,
        'summary.recommendations': recommendations.slice(0, 10)
      });

      console.log(`[AI] ✅ Risk assessment summary stored successfully`);
    }
  } catch (updateError) {
    console.error(`[AI] ❌ Failed to store risk assessment summary:`, updateError.message);
  }
}

// Helper functions for scan naming
function extractSampleIPsFromList(ipList) {
  try {
    if (ipList.includes(',')) {
      return ipList.split(',').slice(0, 3).map(ip => ip.trim());
    } else if (ipList.includes('/')) {
      const baseIp = ipList.split('/')[0];
      return [baseIp];
    } else if (ipList.includes('-')) {
      const startIp = ipList.split('-')[0].trim();
      return [startIp];
    } else {
      return [ipList.trim()];
    }
  } catch (error) {
    return [ipList];
  }
}

function generateScanName(scanMode, targets, targetHosts) {
  switch (scanMode) {
    case 'single_target':
      return `Deep scan of ${targets[0].hostname || targets[0].host}`;
    case 'multiple_targets':
      return `Deep scan of ${targets.length} targets`;
    case 'ip_list':
      const displayIps = targetHosts.length > 30 ? targetHosts.substring(0, 30) + '...' : targetHosts;
      return `Deep scan of ${displayIps}`;
    default:
      return 'Deep Security Scan';
  }
}

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
// Security middlewares
// CORS configuration: allow extra local dev origins by default and
// support CORS_ALLOW_ALL=true to disable origin checks (useful for local testing).
const defaultOrigins = 'http://localhost:3000,http://127.0.0.1:5500,http://localhost:5500,http://127.0.0.1:3000';
const rawOrigins = (process.env.CORS_ORIGINS || defaultOrigins).split(',').map(s => s.trim()).filter(Boolean);
// Normalize origins (strip trailing slash, ensure protocol+host+port form)
function normalizeOriginString(o) {
  if (!o || typeof o !== 'string') return o;
  try {
    const u = new URL(o);
    return `${u.protocol}//${u.hostname}${u.port ? `:${u.port}` : ''}`;
  } catch (e) {
    // fallback: remove trailing slash
    return o.replace(/\/$/, '');
  }
}
const allowedOrigins = rawOrigins.map(normalizeOriginString);
// Allow all origins in development by default to ease testing from different frontends.
// In production, CORS must be explicitly configured via CORS_ALLOW_ALL or CORS_ORIGINS.
const allowAllEnv = String(process.env.CORS_ALLOW_ALL || 'false').toLowerCase() === 'true';
const isProduction = String(process.env.NODE_ENV || '').toLowerCase() === 'production';
const allowAll = allowAllEnv || !isProduction;
if (allowAll) console.log('[CORS] permissive mode enabled (allow all origins) — disable in production');
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);

    // In development, allow all origins
    if (process.env.NODE_ENV !== 'production') {
      return callback(null, true);
    }

    // In production, use the configured origins
    const allowedOrigins = (process.env.CORS_ORIGINS || 'http://localhost:3000').split(',').map(s => s.trim());
    if (allowedOrigins.indexOf(origin) !== -1) {
      return callback(null, true);
    }

    console.log(`[CORS] Rejected origin: ${origin}`);
    return callback(new Error('CORS policy: Origin not allowed'));
  },
  credentials: true,
  exposedHeaders: ['Authorization']
}));

app.use(helmet());

// Basic rate limiter to protect endpoints from abuse
const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minutes
  max: 1500, // Increase the limit
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  message: 'Too many requests, please try again later.',
  skip: (req) => {
    // Skip rate limiting for these endpoints:
    if (req.path === '/health') return true;
    if (req.path.startsWith('/scan/') && req.method === 'GET') {
      // This is likely a polling request for scan status
      return true;
    }

    if (req.method === 'OPTIONS') return true;
    return false;
  }
});
app.use(apiLimiter);

// Limit JSON body size
app.use(express.json({ limit: process.env.JSON_LIMIT || '1mb' }));

// Simple redact helper for logs
function redactBearer(str) {
  if (!str || typeof str !== 'string') return str;
  return str.replace(/Bearer\s+[A-Za-z0-9\-_.=]+/g, 'Bearer [REDACTED]');
}
// exported for tests or external logging wrapper

// --- OUI helper & test endpoints ---
function lookupVendorForMac(rawMac) {
  if (!rawMac || typeof rawMac !== 'string') return { error: 'invalid mac' };
  const normalized = rawMac.toUpperCase().replace(/[^A-F0-9]/g, '').slice(0, 12);
  const oui = normalized.slice(0, 6);
  let vendor = null;
  let source = null;

  if (oui && ouiOverrides[oui]) {
    vendor = ouiOverrides[oui];
    source = 'overrides';
  } else if (oui && ouiDb[oui]) {
    vendor = ouiDb[oui];
    source = 'local_db';
  } else {
    // try library if available
    if (ouiLib) {
      try {
        let libRes = null;
        if (typeof ouiLib.lookup === 'function') libRes = ouiLib.lookup(rawMac);
        else if (typeof ouiLib.find === 'function') libRes = ouiLib.find(rawMac);
        else if (typeof ouiLib.get === 'function') libRes = ouiLib.get(rawMac);
        else if (typeof ouiLib === 'function') libRes = ouiLib(rawMac);
        else if (typeof ouiLib.parse === 'function') libRes = ouiLib.parse(rawMac);
        if (libRes) {
          vendor = typeof libRes === 'string' ? libRes : (libRes.vendor || libRes.org || libRes.company || libRes.name || JSON.stringify(libRes));
          source = 'library';
        }
      } catch (e) { /* fall through */ }
    }

    // fallback to vendor-lookup package
    if (!vendor) {
      try {
        const vr = toVendor(rawMac);
        if (vr) vendor = typeof vr === 'string' ? vr : (vr.vendor || vr.organization || vr.company || vr.name || null);
        if (vendor) source = 'vendor-lookup';
      } catch (e) { }
    }
  }

  // last-resort fallback map
  const fallbackMap = {
    '1A56E1': 'Generic Consumer Vendor',
    'AC6175': 'Huawei Technologies',
    '58687A': 'Sagemcom Broadband SAS',
    '7A29D9': 'Unknown Vendor (OUI 7A:29:D9)'
  };
  if (!vendor && oui && fallbackMap[oui]) {
    vendor = fallbackMap[oui];
    source = 'fallback';
  }

  return { mac: rawMac, hex: normalized, oui, vendor: vendor || null, source: source || null };
}

app.get('/oui/status', (req, res) => {
  res.json({
    ouiLibLoaded: !!ouiLib,
    ouiDbEntries: Object.keys(ouiDb || {}).length,
    overridesEntries: Object.keys(ouiOverrides || {}).length,
    discoveredEntries: Object.keys(ouiDiscovered || {}).length
  });
});

app.get('/oui/lookup', (req, res) => {
  const mac = req.query.mac || req.query.m;
  if (!mac) return res.status(400).json({ error: 'query param `mac` required' });
  try {
    const out = lookupVendorForMac(String(mac));
    return res.json(out);
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});
exports.redactBearer = redactBearer;

// Firebase ID token verification middleware
// Public paths that should remain accessible without auth
const PUBLIC_PATHS = new Set(['/health', '/presets']);

// Async wrapper for routes to surface errors to Express error handler
function asyncHandler(fn) {
  return function (req, res, next) {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}
exports.asyncHandler = asyncHandler;

async function verifyFirebaseIdToken(req, res, next) {
  // allow public paths
  if (PUBLIC_PATHS.has(req.path)) return next();

  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (!authHeader) return res.status(401).json({ error: 'Missing Authorization header' });
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid Authorization header format' });
  const idToken = parts[1];

  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    // attach Firebase uid and claims
    req.user = { uid: decoded.uid, email: decoded.email, claims: decoded };
    return next();
  } catch (err) {
    // Provide clearer error payloads for token expiration and other auth errors
    const code = err && err.code ? err.code : (err && err.message ? err.message : 'auth/unknown-error');
    console.error('Firebase token verification failed:', code);
    if (String(code).includes('id-token-expired') || String(code).includes('auth/id-token-expired')) {
      return res.status(401).json({ error: 'ID token expired', code: 'TOKEN_EXPIRED' });
    }
    return res.status(401).json({ error: 'Invalid Firebase ID token', code: 'TOKEN_INVALID' });
  }
}

// Protect all routes after this middleware
app.use(verifyFirebaseIdToken);



// Main scan endpoint
app.post('/scan', async (req, res) => {
  try {
    const { target, preset, userId, targetId: providedTargetId, scanName } = req.body;

    if (!userId) return res.status(400).json({ error: 'userId required' });
    if (!PRESETS[preset]) return res.status(400).json({ error: 'unknown preset' });

    let scanTarget = target && typeof target === 'string' && target.trim().length > 0 ? target.trim() : null;
    let targetId = providedTargetId || null;

    if (!scanTarget && targetId) {
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

    try {
      scanTarget = validateNetworkTarget(scanTarget);
    } catch (e) {
      return res.status(400).json({ error: 'invalid target: ' + e.message });
    }

    if (!isAllowedTarget(scanTarget)) return res.status(403).json({ error: 'target not allowed' });

    const isNetworkScan = preset === 'quick_scan' || /(\/\d{1,2}$|-\d{1,3}$|\[.*\]|,)/.test(scanTarget);

    // Create scan record
    const scanId = uuidv4();
    await safeFirestoreSet(db.collection('Scan').doc(scanId), {
      status: 'ongoing',
      submitted_at: new Date().toISOString(),
      started_at: null,
      finished_at: null,
      scan_type: preset,
      target: scanTarget,
      user_id: userId,
      scan_name: scanName || `${preset} - ${scanTarget}`,
      is_network_scan: isNetworkScan,
      preset_used: preset,
      target_id: targetId || null
    });

    // Check network reachability for network scans
    if (isNetworkScan) {
      console.log(`[${scanId}] Pre-scan reachability check...`);
      const sampleIP = extractSampleIP(scanTarget);
      const canPing = await checkNetworkReachable(sampleIP);

      if (!canPing) {
        await safeFirestoreUpdate(db.collection('Scan').doc(scanId), {
          status: 'failed',
          finished_at: new Date().toISOString,
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
          started_at: new Date().toISOString(),
        });

        console.log(`[${scanId}] Starting ${preset} scan for: ${scanTarget}`);

        if (preset === 'quick_scan') {
          runResult = await runNmap(PRESETS.quick_scan.args, scanTarget, 'quick_scan', scanId);
        } else if (preset === 'deep_scan') {
          runResult = await runNmap(PRESETS.deep_scan.args, scanTarget, 'deep_scan', scanId);
        }

        const stdout = runResult.stdout;
        console.log(`[${scanId}] Scan completed. stdout length: ${stdout.length}`);

        // Parse scan result
        let parsed;
        if (preset === 'deep_scan') {
          parsed = await parseDeepScanXml(stdout, scanTarget);
        } else {
          parsed = await parseNetworkScanXml(stdout, scanTarget, preset);
        }

        // Store results in Firestore
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
          finished_at: new Date().toISOString(),
          summary: {
            total_hosts: parsed.totalHosts,
            active_hosts: parsed.activeHosts,
            open_ports_total: parsed.openPortsTotal,
            vulnerabilities_total: 0, // We're not using vulnerabilitiesTotal anymore
            cves_total: parsed.cvesTotal || 0,
            device_types: parsed.device_types,
            scan_duration: runResult.duration
          }
        });

      } catch (err) {
        console.error(`[${scanId}] Scan failed: ${err.message}`);
        await safeFirestoreUpdate(db.collection('Scan').doc(scanId), {
          status: 'failed',
          finished_at: new Date().toISOString(),
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

// Deep scan endpoint
app.post('/scan/deep', async (req, res) => {
  try {
    const { targetId, targetIds, ipList, target: directTarget, userId, scanName } = req.body;

    console.log('=== DEEP SCAN REQUEST ===');

    // Validate input
    if (!userId) {
      return res.status(400).json({ error: 'userId required' });
    }

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
    let resolvedTargetId = null;

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

    // Validate/normalize targetHosts
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

    // Run deep scan asynchronously
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

        // Parse and store results
        console.log(`[${scanId}] Starting XML parsing...`);
        const parsed = await parseDeepScanXml(stdout, targetHosts);
        console.log(`[${scanId}] XML parsing completed, found ${parsed.hosts ? parsed.hosts.length : 0} hosts`);

        // Store results
        const usedTargetIdForResults = scanMode === 'single_target' ? (resolvedTargetId || null) : null;

        console.log(`[${scanId}] Calling storeDeepScanResults...`);
        await storeDeepScanResults(scanId, parsed, runResult, 'deep_scan', userId, usedTargetIdForResults);

        // Update target scan counts
        if (scanMode === 'single_target' && resolvedTargetId) {
          const targetRef = db.collection('Targets').doc(resolvedTargetId);
          await safeFirestoreUpdate(targetRef, {
            scan_count: admin.firestore.FieldValue.increment(1),
            last_seen: admin.firestore.FieldValue.serverTimestamp()
          });
        } else if (scanMode === 'multiple_targets' && targetIds) {
          for (const tId of targetIds) {
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
            vulnerabilities_total: 0, // Not using this field
            cves_total: parsed.cvesTotal || 0,
            device_types: parsed.device_types,
            scan_duration: runResult.duration,
            scan_mode: scanMode
          }
        });

        console.log(`[${scanId}] Deep scan process completed successfully`);

      } catch (err) {
        console.error(`[${scanId}] Deep scan failed:`, err.message);
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

// Get scan status/result - FIXED to handle CVEs properly
app.get('/scan/:scanId', async (req, res) => {
  try {
    const scanId = req.params.scanId;
    const scanDoc = await db.collection('Scan').doc(scanId).get();
    if (!scanDoc.exists) return res.status(404).json({ error: 'scan not found' });
    const scanData = scanDoc.data();

    // Helper function to safely convert Firestore timestamps
    const convertTimestamp = (timestamp) => {
      if (!timestamp) return null;

      if (timestamp._seconds !== undefined && timestamp._nanoseconds !== undefined) {
        return new Date(timestamp._seconds * 1000 + timestamp._nanoseconds / 1000000).toISOString();
      }

      if (timestamp.toDate && typeof timestamp.toDate === 'function') {
        return timestamp.toDate().toISOString();
      }

      return timestamp;
    };

    // Get all ScanResults for this scan
    const resultsSnap = await db.collection('ScanResults')
      .where('parent_scan_id', '==', scanId)
      .get();

    // Collect all CVEs from all hosts
    const allCVEsAcrossHosts = [];
    const ScanResults = resultsSnap.docs.map(doc => {
      const data = doc.data();

      // Extract CVEs from foundCVEs field (already aggregated at host level)
      const hostCVEs = data.foundCVEs || [];

      // Also add to global collection
      hostCVEs.forEach(cve => {
        if (!allCVEsAcrossHosts.some(existing =>
          existing.cve_id === cve.cve_id && existing.host === data.host)) {
          allCVEsAcrossHosts.push({
            ...cve,
            host: data.host,
            hostname: data.hostname,
            device_type: data.device_type
          });
        }
      });

      return {
        id: doc.id,
        ...data,
        host_status: data.host_status || 'unknown',
        open_ports_count: data.open_ports_count || 0,
        device_category: data.device_category || 'unknown'
      };
    });

    // Calculate summary statistics
    const totalCVEs = allCVEsAcrossHosts.length;
    const hostsWithCVEs = ScanResults.filter(r => (r.foundCVEs?.length || 0) > 0).length;

    // Calculate CVE severity breakdown
    const cveSeverity = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };

    // Year analysis data structures
    const cveByYear = {};
    const cveYears = [];

    allCVEsAcrossHosts.forEach(cve => {
      const score = cve.CVSS?.score || 0;

      // Severity calculation
      if (score >= 9.0) cveSeverity.critical++;
      else if (score >= 7.0) cveSeverity.high++;
      else if (score >= 4.0) cveSeverity.medium++;
      else if (score > 0) cveSeverity.low++;
      else cveSeverity.info++;

      // Year analysis
      if (cve.year) {
        cveByYear[cve.year] = (cveByYear[cve.year] || 0) + 1;
        cveYears.push(cve.year);
      } else {
        // Extract year from CVE ID
        const yearMatch = cve.cve_id.match(/CVE-(\d{4})-\d+/);
        if (yearMatch) {
          const year = parseInt(yearMatch[1]);
          cve.year = year;
          cveByYear[year] = (cveByYear[year] || 0) + 1;
          cveYears.push(year);
        }
      }
    });

    // Calculate year stats
    let oldestCveYear = null;
    let newestCveYear = null;

    if (cveYears.length > 0) {
      oldestCveYear = Math.min(...cveYears);
      newestCveYear = Math.max(...cveYears);
    }

    // Age analysis
    const currentYear = new Date().getFullYear();
    const cveAgeAnalysis = {
      current_year: cveByYear[currentYear] || 0,
      last_year: cveByYear[currentYear - 1] || 0,
      "2_years_old": cveByYear[currentYear - 2] || 0,
      older_than_2_years: Object.entries(cveByYear)
        .filter(([year]) => parseInt(year) < currentYear - 2)
        .reduce((sum, [, count]) => sum + count, 0)
    };

    return res.json({
      scan: {
        id: scanId,
        ...scanData,
        // Safely convert timestamps
        submitted_at: convertTimestamp(scanData.submitted_at),
        started_at: convertTimestamp(scanData.started_at),
        finished_at: convertTimestamp(scanData.finished_at)
      },
      ScanResults: ScanResults,
      summary: {
        total_hosts: ScanResults.length,
        hosts_with_ports: ScanResults.filter(r => r.open_ports_count > 0).length,
        hosts_with_cves: hostsWithCVEs,
        total_open_ports: ScanResults.reduce((sum, r) => sum + (r.open_ports_count || 0), 0),
        total_cves: totalCVEs,
        cve_severity: cveSeverity,
        cve_by_year: cveByYear,
        oldest_cve_year: oldestCveYear,
        newest_cve_year: newestCveYear,
        cve_age_analysis: cveAgeAnalysis,
        device_types: [...new Set(ScanResults.map(r => r.device_type))],
        overall_security_rating: scanData.summary?.overall_security_rating || 'UNKNOWN',
        risk_assessment: scanData.summary?.risk_assessment || null
      }
    });
  } catch (err) {
    console.error('Error in /scan/:scanId:', err);
    return res.status(500).json({
      error: 'server error',
      details: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
  }
});

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

      // Helper function to safely convert timestamps
      const convertTimestamp = (timestamp) => {
        if (!timestamp) return null;

        // If it's a Firestore Timestamp object
        if (timestamp._seconds !== undefined && timestamp._nanoseconds !== undefined) {
          return new Date(timestamp._seconds * 1000 + timestamp._nanoseconds / 1000000).toISOString();
        }

        // If it's already a Firestore Timestamp object with toDate method
        if (timestamp.toDate && typeof timestamp.toDate === 'function') {
          return timestamp.toDate().toISOString();
        }

        // If it's already a string or other format
        return timestamp;
      };

      return {
        id: doc.id,
        ...data,
        // Convert timestamps safely
        submitted_at: convertTimestamp(data.submitted_at),
        started_at: convertTimestamp(data.started_at),
        finished_at: convertTimestamp(data.finished_at)
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

app.get('/health', (req, res) => res.json({
  ok: true,
  now: new Date().toISOString(),
  presets: Object.keys(PRESETS),
  features: ['quick_discovery', 'deep_analysis', 'target_management', 'ai_risk_assessment', 'cve_detection']
}));

// NEW: CVE-specific endpoint
app.get('/scan/:scanId/cves', async (req, res) => {
  try {
    const scanId = req.params.scanId;

    const resultsSnap = await db.collection('ScanResults')
      .where('parent_scan_id', '==', scanId)
      .where('foundCVEs', '!=', [])
      .get();

    if (resultsSnap.empty) {
      return res.json({
        scan_id: scanId,
        total_cves: 0,
        hosts_with_cves: 0,
        all_cves: [],
        hosts: []
      });
    }

    const allCVEs = [];
    const hostsWithCVEs = resultsSnap.docs.map(doc => {
      const data = doc.data();
      const hostCVEs = data.foundCVEs || [];

      // Add host info to each CVE
      hostCVEs.forEach(cve => {
        allCVEs.push({
          ...cve,
          host: data.host,
          hostname: data.hostname,
          device_type: data.device_type,
          device_category: data.device_category
        });
      });

      return {
        host: data.host,
        hostname: data.hostname,
        device_type: data.device_type,
        cve_count: hostCVEs.length,
        cves: hostCVEs.map(cve => ({
          cve_id: cve.cve_id,
          CVSS: cve.CVSS,
          exploit_available: cve.exploit_available,
          publishedDate: cve.publishedDate
        }))
      };
    });

    // Sort CVEs by severity (CVSS score)
    allCVEs.sort((a, b) => (b.CVSS?.score || 0) - (a.CVSS?.score || 0));

    res.json({
      scan_id: scanId,
      total_cves: allCVEs.length,
      hosts_with_cves: hostsWithCVEs.length,
      cves_by_severity: {
        critical: allCVEs.filter(c => c.CVSS?.score >= 9.0).length,
        high: allCVEs.filter(c => c.CVSS?.score >= 7.0 && c.CVSS?.score < 9.0).length,
        medium: allCVEs.filter(c => c.CVSS?.score >= 4.0 && c.CVSS?.score < 7.0).length,
        low: allCVEs.filter(c => c.CVSS?.score < 4.0 && c.CVSS?.score > 0).length,
        unknown: allCVEs.filter(c => !c.CVSS?.score || c.CVSS?.score === 0).length
      },
      all_cves: allCVEs,
      hosts: hostsWithCVEs
    });
  } catch (err) {
    console.error('Error getting CVE data:', err);
    res.status(500).json({ error: 'Failed to get CVE data', details: err.message });
  }
});

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
        open_ports: h.open_ports_count,
        cve_count: h.foundCVEs?.length || 0
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
// ===== HEURISTICAS DE IA PARA A ENTREGA FINAL =====
class AIHeuristicEngine {
  constructor() {
    // Fatores de ponderação (ajustáveis)
    this.WEIGHTS = {
      cvssScore: 0.4,
      cveAge: 0.25,
      networkExposure: 0.20,
      exploitAvailable: 0.15,
      serviceCriticality: 0.10
    };
  }

  // Calcular probabilidade baseada na idade do CVE
  calcularProbabilidade(cveYear) {
    const anoAtual = new Date().getFullYear();
    const diffAnos = anoAtual - cveYear;

    // Probabilidade decrescente com a idade
    if (diffAnos === 0) return 1.0;   // Publicado este ano → probabilidade alta
    if (diffAnos === 1) return 0.7;   // Ano passado → média
    if (diffAnos === 2) return 0.4;   // Há dois anos → baixa
    if (diffAnos === 3) return 0.3;   // 3 anos → muito baixa
    if (diffAnos === 4) return 0.2;   // 4 anos
    return 0.1;                       // Mais de 4 anos → probabilidade mínima
  }

  // Calcular exposição de rede baseada em portas abertas
  calcularExposicaoRede(ports = []) {
    let exposureScore = 0;
    const portasAbertas = ports.filter(p => p.state === "open");

    if (portasAbertas.length === 0) return 0;

    // Base: número de portas abertas
    exposureScore += Math.min(portasAbertas.length * 0.3, 3.0);

    // Serviços críticos/expostos
    const criticalServices = {
      'http': 1.5,    // HTTP sem TLS
      'https': 0.5,   // HTTPS é mais seguro
      'ssh': 1.0,
      'telnet': 2.0,
      'ftp': 1.5,
      'rdp': 1.8,
      'vnc': 1.7,
      'smb': 1.3,
      'mysql': 1.6,
      'postgresql': 1.6,
      'oracle': 1.7
    };

    // Análise detalhada por porta
    portasAbertas.forEach(port => {
      const serviceName = (port.service?.name || '').toLowerCase();
      const summary = (port.summary || '').toLowerCase();

      // Serviços críticos
      if (criticalServices[serviceName]) {
        exposureScore += criticalServices[serviceName];
      }

      // Verificar versões desatualizadas
      if (port.service?.version) {
        const version = port.service.version;

        // Heurística para versões antigas
        if (this.isOutdatedVersion(serviceName, version)) {
          exposureScore += 1.0;
        }
      } else if (summary.includes('unknown') || summary.includes('n/a')) {
        // Serviço desconhecido → maior risco
        exposureScore += 0.8;
      }

      // HTTP sem TLS/SSL
      if ((serviceName === 'http' || summary.includes('http')) &&
        !summary.includes('https') &&
        !port.service?.tunnel) {
        exposureScore += 1.5;
      }
    });

    // Normalizar para escala 0-10
    return Math.min(10, Number(exposureScore.toFixed(2)));
  }

  // Verificar se versão está desatualizada
  isOutdatedVersion(service, version) {
    const versionPattern = version.match(/(\d+\.\d+(\.\d+)?)/);
    if (!versionPattern) return false;

    const versionNum = parseFloat(versionPattern[1]);
    const thresholds = {
      'nginx': 1.18,
      'apache': 2.4,
      'openssh': 8.0,
      'mysql': 8.0,
      'postgresql': 13.0,
      'node.js': 16.0
    };

    for (const [serviceName, minVersion] of Object.entries(thresholds)) {
      if (service.includes(serviceName) && versionNum < minVersion) {
        return true;
      }
    }

    return false;
  }

  // Calcular heurística completa para um CVE específico
  calcularHeuristicaCVE(cve, hostData) {
    console.log(`🧮 [AI] Calculando heurística para ${cve.cve_id}`);

    const cvssScore = cve.CVSS?.score || 0;
    const cveYear = cve.year || this.extractYearFromCVE(cve.cve_id);
    const exploitAvailable = cve.exploit_available || false;

    // === CORREÇÃO 1: Fatores NORMALIZADOS (0-1) ===

    // 1. CVSS: 0-10 → normalizar para 0-1
    const fatorCVSS = Math.min(cvssScore / 10, 1);

    // 2. Idade: probabilidade 0-1
    const fatorIdade = this.calcularProbabilidade(cveYear);

    // 3. Exposição rede: 0-10 → normalizar para 0-1
    const exposicaoRede = this.calcularExposicaoRede(hostData.ports || []);
    const fatorExposicao = Math.min(exposicaoRede / 10, 1);

    // 4. Exploit: 1.0 se disponível, 0.2 se não
    const fatorExploit = exploitAvailable ? 1.0 : 0.2;

    // 5. Criticidade serviço: 0-10 → normalizar
    const criticidadeServico = this.calcularCriticidadeServico(hostData.ports || []);
    const fatorCriticidade = Math.min(criticidadeServico / 10, 1);

    // === CORREÇÃO 2: Cálculo CORRETO com pesos ===
    const heuristicScore = (
      (fatorCVSS * 100 * this.WEIGHTS.cvssScore) +
      (fatorIdade * 100 * this.WEIGHTS.cveAge) +
      (fatorExposicao * 100 * this.WEIGHTS.networkExposure) +
      (fatorExploit * 100 * this.WEIGHTS.exploitAvailable) +
      (fatorCriticidade * 100 * this.WEIGHTS.serviceCriticality)
    );

    const finalScore = Math.min(100, Math.round(heuristicScore * 100) / 100);

    console.log(`📊 [AI] ${cve.cve_id}:`);
    console.log(`   CVSS: ${cvssScore} → fator: ${fatorCVSS.toFixed(2)}`);
    console.log(`   Ano: ${cveYear} → idade: ${fatorIdade.toFixed(2)}`);
    console.log(`   Exposição: ${exposicaoRede.toFixed(2)}/10 → fator: ${fatorExposicao.toFixed(2)}`);
    console.log(`   Exploit: ${exploitAvailable} → fator: ${fatorExploit}`);
    console.log(`   Criticidade: ${criticidadeServico.toFixed(2)}/10 → fator: ${fatorCriticidade.toFixed(2)}`);
    console.log(`   SCORE FINAL: ${finalScore}/100`);

    return {
      score: finalScore,
      factors: {
        cvss: Math.round(fatorCVSS * 100),        // 0-100
        cveAge: Math.round(fatorIdade * 100),     // 0-100  
        networkExposure: Math.round(fatorExposicao * 100),  // 0-100
        exploitAvailable: Math.round(fatorExploit * 100),   // 0-100
        serviceCriticality: Math.round(fatorCriticidade * 100)  // 0-100
      },
      breakdown: {
        cvssContribution: Math.round(fatorCVSS * 100 * this.WEIGHTS.cvssScore),
        ageContribution: Math.round(fatorIdade * 100 * this.WEIGHTS.cveAge),
        exposureContribution: Math.round(fatorExposicao * 100 * this.WEIGHTS.networkExposure),
        exploitContribution: Math.round(fatorExploit * 100 * this.WEIGHTS.exploitAvailable),
        serviceContribution: Math.round(fatorCriticidade * 100 * this.WEIGHTS.serviceCriticality)
      }
    };
  }
  // Extrair ano do CVE
  extractYearFromCVE(cveId) {
    const match = cveId.match(/CVE-(\d{4})-\d+/);
    return match ? parseInt(match[1]) : new Date().getFullYear();
  }

  // Calcular criticidade do serviço
  calcularCriticidadeServico(ports) {
    let criticality = 0;
    const criticalServices = ['ssh', 'rdp', 'vnc', 'mysql', 'postgresql', 'oracle', 'sql'];

    ports.forEach(port => {
      const serviceName = (port.service?.name || '').toLowerCase();

      // Serviços de administração
      if (criticalServices.some(cs => serviceName.includes(cs))) {
        criticality += 2.0;
      }

      // Serviços web
      if (serviceName.includes('http') || serviceName.includes('web')) {
        criticality += 1.0;
      }

      // Serviços de banco de dados
      if (serviceName.includes('sql') || serviceName.includes('db')) {
        criticality += 1.5;
      }
    });

    return Math.min(10, criticality);
  }

  // Gerar recomendação priorizada com base nas heurísticas
  gerarRecomendacaoPriorizada(cveAnalysis, hostData) {
    const heuristic = this.calcularHeuristicaCVE(cveAnalysis, hostData);
    const cvssScore = cveAnalysis.CVSS?.score || 0;

    // Determinar urgência baseada na heurística
    let urgency = 'LOW';
    let timeframe = '30 dias';

    if (heuristic.score >= 80) {
      urgency = 'CRITICAL';
      timeframe = 'IMEDIATO (24h)';
    } else if (heuristic.score >= 60) {
      urgency = 'HIGH';
      timeframe = '7 dias';
    } else if (heuristic.score >= 40) {
      urgency = 'MEDIUM';
      timeframe = '14 dias';
    } else if (heuristic.score >= 20) {
      urgency = 'LOW';
      timeframe = '30 dias';
    }

    // Gerar recomendação específica
    const recommendation = {
      cve_id: cveAnalysis.cve_id,
      host: hostData.host,
      hostname: hostData.hostname,
      urgency: urgency,
      timeframe: timeframe,
      heuristic_score: Math.round(heuristic.score),
      cvss_score: cvssScore,
      exploit_available: cveAnalysis.exploit_available || false,
      factors: heuristic.factors,
      action_items: this.gerarItensAcao(cveAnalysis, hostData, heuristic),
      justification: this.gerarJustificativa(heuristic, cveAnalysis, hostData)
    };

    return recommendation;
  }

  getPatchRecommendation(cve) {
    if (!cve || !cve.cve_id) {
      return 'Atualizar para a versão mais recente disponível do software afetado';
    }

    const service = (cve.service || '').toLowerCase();
    const cvss = cve.CVSS?.score || 0;
    const exploit = cve.exploit_available === true;
    const year = cve.year || this.extractYearFromCVE(cve.cve_id);
    const currentYear = new Date().getFullYear();
    const age = currentYear - year;
    const product = cve.service_product || '';
    // Build specific recommendation based on all factors
    let recommendation = '';
    
    // 1. Start with service-specific actions
    if (service.includes('ssh') || service.includes('openssh')) {
      if (age <= 1) {
        recommendation = 'ATUALIZAÇÃO URGENTE OpenSSH: ';
        if (cvss >= 9.0) {
          recommendation += 'Update imediato para OpenSSH 9.8+ (CVE crítico). Desative agent forwarding não necessário e configure autenticação por chaves apenas.';
        } else if (cvss >= 7.0) {
          recommendation += 'Update para OpenSSH 8.9+ e configure: Protocol 2 apenas, desative root login, use fail2ban.';
        } else {
          recommendation += 'Update OpenSSH e revise configurações de segurança (sshd_config).';
        }
      } else {
        recommendation = 'Versão de OpenSSH muito antiga. Update para versão suportada e execute ssh-audit para análise.';
      }
    }
    else if (service.includes('http') || service.includes('apache')) {
      if (age <= 1) {
        recommendation = 'PATCH HTTP CRÍTICO: ';
        if (cvss >= 9.0) {
          recommendation += 'Update Apache 2.4.58+ IMEDIATO. Desative mod_info/mod_status, configure security headers (CSP, HSTS), e implemente WAF temporário.';
        } else if (cvss >= 7.0) {
          recommendation += 'Update Apache 2.4.55+ dentro de 7 dias. Configure TLS 1.2+, limite request size, e habilite mod_security.';
        } else {
          recommendation += 'Update Apache e configure hardening básico.';
        }
      } else {
        recommendation = 'Apache versão desatualizada. Migre para versão suportada ou considere alternativas (nginx).';
      }
    }
    else if (service.includes('nginx')) {
      recommendation = 'Update Nginx para versão 1.24+. Desative server tokens, configure SSL/TLS moderno, e implemente rate limiting.';
    }
    else if (service.includes('mysql')) {
      recommendation = 'Update MySQL para 8.0.36+. Desative acesso remoto se não necessário, configure strong passwords, e habilite logging.';
    }
    else if (service.includes('postgresql')) {
      recommendation = 'Update PostgreSQL para 13.12+. Configure pg_hba.conf para restringir acesso e habilite SSL.';
    }
    else if (service.includes('rdp')) {
      recommendation = 'APLICAÇÃO IMEDIATA: Configure Network Level Authentication (NLA), limite tentativas de login, e use VPN para acesso.';
    }
    else if (service.includes('telnet')) {
      recommendation = 'SUBSTITUA IMEDIATAMENTE por SSH. Telnet é inseguro por design - migração urgente requerida.';
    }
    else if (service.includes('ftp')) {
      recommendation = 'Migre para SFTP/SCP. Se FTP necessário, use FTPS com certificados válidos e limite acessos.';
    }
    else {
      // Generic but more specific based on CVSS
      if (cvss >= 9.0) {
        recommendation = 'PATCH DE EMERGÊNCIA: Aplicar correção oficial dentro de 24h. Isole sistema se patch não disponível.';
      } else if (cvss >= 7.0) {
        recommendation = 'PATCH PRIORITÁRIO: Atualizar software afetado dentro de 7 dias. Configure compensações temporárias.';
      } else {
        recommendation = 'Atualizar para versão corrigida na próxima janela de manutenção.';
      }
    }

    // 2. Add exploit warning
    if (exploit) {
      recommendation += ' ⚠️ EXPLOIT PÚBLICO DISPONÍVEL - Prioridade máxima!';
    }

    // 3. Add age context
    if (age > 3) {
      recommendation += ' Sistema extremamente desatualizado (' + age + ' anos). Considere substituição completa.';
    }

    return recommendation;
  }

  // Gerar itens de ação específicos
  gerarItensAcao(cve, hostData, heuristic) {
    const actions = [];
    const portasAfetadas = this.identificarPortasAfetadas(cve, hostData);
    const service = (cve.service || '').toLowerCase();
    const cvss = cve.CVSS?.score || 0;
    const exploit = cve.exploit_available;

    // Priority 1: Patch action (ALWAYS)
    const patchDetails = this.getPatchRecommendation(cve);
    actions.push({
      priority: 1,
      action: 'Aplicar patch de segurança',
      details: patchDetails,
      estimated_time: cvss >= 9.0 ? '1-2 horas (emergência)' : '2-4 horas',
      immediate: cvss >= 9.0 || exploit
    });

    // Priority 2: Exploit-specific actions
    if (exploit) {
      actions.push({
        priority: 2,
        action: 'Mitigação de exploit ativo',
        details: 'Exploit público disponível - Implementar: ' + this.getExploitMitigation(cve),
        estimated_time: '1-3 horas',
        immediate: true
      });
    }

    // Priority 3: Network containment
    if (portasAfetadas.length > 0 && heuristic.factors.networkExposure > 50) {
      const exposureAction = this.getNetworkContainment(portasAfetadas, service, hostData);
      actions.push({
        priority: 3,
        action: 'Contenção de rede',
        details: exposureAction,
        estimated_time: '30-60 minutos',
        immediate: cvss >= 7.0
      });
    }

    // Priority 4: Service-specific hardening
    const hardeningAction = this.getServiceHardening(service, cvss);
    if (hardeningAction) {
      actions.push({
        priority: 4,
        action: 'Hardening do serviço',
        details: hardeningAction,
        estimated_time: '1-2 horas',
        immediate: false
      });
    }

    // Priority 5: Monitoring enhancements
    actions.push({
      priority: 5,
      action: 'Monitoramento aprimorado',
      details: this.getMonitoringRecommendation(cve, service),
      estimated_time: 'Contínuo',
      immediate: false
    });

    // Priority 6: Verification steps
    actions.push({
      priority: 6,
      action: 'Verificação do patch',
      details: this.getVerificationSteps(service),
      estimated_time: '15-30 minutos',
      immediate: false
    });

    return actions;
  }
  getExploitMitigation(cve) {
    const cveId = cve.cve_id;

    // Common exploit mitigations
    if (cveId.includes('2023-38408')) { // OpenSSH RCE
      return 'Desative SSH Agent Forwarding, configure AllowAgentForwarding no, limite tempo do ssh-agent';
    }
    if (cveId.includes('2022-22720')) { // Apache HTTP smuggling
      return 'Desative HTTP/2 temporariamente, configure mod_reqtimeout, use mod_security';
    }
    if (cveId.includes('2021-44228')) { // Log4Shell
      return 'Remova JndiLookup.class, configure log4j2.formatMsgNoLookups=true, bloqueie conexões LDAP externas';
    }

    return 'Isolar sistema da internet, implementar regras de firewall específicas, aumentar logging';
  }

  // NEW HELPER: Get network containment recommendations
  getNetworkContainment(ports, service, hostData) {
    let details = `Portas ${ports.join(', ')} expostas. `;

    if (service.includes('ssh')) {
      details += 'Restrinja SSH a IPs de administração via firewall, considere usar VPN jump host.';
    }
    else if (service.includes('http')) {
      details += 'Configure WAF (Cloudflare/ModSecurity), limite rate por IP, use CDN para proteção.';
    }
    else if (service.includes('rdp') || service.includes('vnc')) {
      details += 'REMOVA acesso direto à internet! Use VPN obrigatória para acesso remoto.';
    }
    else if (service.includes('mysql') || service.includes('postgresql')) {
      details += 'Database NUNCA exposto à internet. Restrinja a sub-rede de aplicação apenas.';
    }
    else {
      details += 'Avaliar se serviço precisa de acesso externo. Restringir por geolocalização se possível.';
    }

    return details;
  }

  // NEW HELPER: Get service-specific hardening
  getServiceHardening(service, cvss) {
    if (service.includes('ssh')) {
      return 'Configure: PermitRootLogin no, PasswordAuthentication no, MaxAuthTries 3, LoginGraceTime 1m';
    }
    if (service.includes('http')) {
      return 'Configure headers: Content-Security-Policy, X-Frame-Options DENY, X-Content-Type-Options nosniff';
    }
    if (service.includes('mysql')) {
      return 'Configure: skip-name-resolve, local-infile=0, log_warnings=2, secure_file_priv=/tmp';
    }

    return cvss >= 7.0 ? 'Aplique princípio de menor privilégio e segmente rede' : null;
  }

  // NEW HELPER: Get monitoring recommendations
  getMonitoringRecommendation(cve, service) {
    const cveId = cve.cve_id;
    let details = 'Monitorar logs para tentativas de exploit. ';

    if (cveId.includes('2023-38408') || service.includes('ssh')) {
      details += 'Alertar sobre: múltiplas falhas SSH, agent forwarding suspeito, conexões de IPs desconhecidos';
    }
    else if (service.includes('http')) {
      details += 'Monitorar: requests anormais, padrões de ataque conhecidos, consumo anormal de recursos';
    }
    else if (service.includes('database')) {
      details += 'Alertar sobre: queries lentas, muitas conexões, exportação de dados grande';
    }

    details += ' Configurar alertas para qualquer atividade suspeita nas portas afetadas.';
    return details;
  }

  // NEW HELPER: Get verification steps
  getVerificationSteps(service) {
    if (service.includes('ssh')) {
      return 'Verificar: ssh -V (versão), sudo sshd -T | grep permitroot, analisar /var/log/auth.log';
    }
    if (service.includes('http')) {
      return 'Verificar: apache2 -v, testar headers de segurança, scan com nikto/sslscan';
    }
    if (service.includes('mysql')) {
      return 'Verificar: SELECT VERSION();, SHOW VARIABLES LIKE "%version%";, revisar usuários';
    }

    return 'Testar serviço após patch, verificar logs de erro, confirmar funcionamento normal';
  }
  // Identificar portas afetadas por um CVE
  identificarPortasAfetadas(cve, hostData) {
    const affectedPorts = [];

    hostData.ports?.forEach(port => {
      // Verificar se o serviço na porta é afetado pelo CVE
      if (port.cves?.some(pcve => pcve.cve_id === cve.cve_id)) {
        affectedPorts.push(port.port);
      }
    });

    return affectedPorts;
  }

  // Gerar justificativa para a priorização
  gerarJustificativa(heuristic, cve, hostData) {
    const justifications = [];
    const cvss = cve.CVSS?.score || 0;
    const exploit = cve.exploit_available;
    const year = cve.year || this.extractYearFromCVE(cve.cve_id);
    const age = new Date().getFullYear() - year;
    const exposure = heuristic.factors.networkExposure;

    // CVSS with more context
    if (cvss >= 9.0) justifications.push('CVSS CRÍTICO ' + cvss + ' - RCE/PrivEsc possível');
    else if (cvss >= 7.0) justifications.push('CVSS ALTO ' + cvss + ' - Impacto significativo');
    else if (cvss >= 4.0) justifications.push('CVSS MÉDIO ' + cvss + ' - Risco moderado');
    else justifications.push('CVSS BAIXO ' + cvss + ' - Impacto limitado');

    // Age with context
    if (age === 0) justifications.push('CVE RECENTE (2025) - Ativo em ataques');
    else if (age === 1) justifications.push('CVE 2024 - Ainda relevante');
    else if (age <= 3) justifications.push(`CVE ${year} - ${age} anos, ainda explorável`);
    else justifications.push(`CVE ANTIGO ${year} - ${age} anos, mas sistema desatualizado`);

    // Exploit availability
    if (exploit) justifications.push('EXPLOIT PÚBLICO - Risco imediato');
    else justifications.push('Sem exploit público conhecido');

    // Network exposure
    if (exposure >= 80) justifications.push('EXPOSIÇÃO ALTA - Serviço acessível na internet');
    else if (exposure >= 60) justifications.push('Exposição moderada');
    else justifications.push('Exposição limitada');

    return justifications.join(' | ');
  }
  // Analisar todos os CVEs de um host e priorizá-los
  // DENTRO DA CLASSE AIHeuristicEngine (procure este método e substitua)

  analisarEPriorizarCVEs(hostData) {
    console.log(`🔍 [AI Heuristics] Analisando host: ${hostData.host || 'unknown'}`);

    // DEBUG: Log completo da estrutura
    console.log(`📊 [AI Debug] Estrutura do hostData:`);
    console.log(`   - Tem foundCVEs?`, 'foundCVEs' in hostData);
    console.log(`   - foundCVEs length:`, hostData.foundCVEs?.length || 0);
    console.log(`   - Tem ports?`, 'ports' in hostData);
    console.log(`   - ports length:`, hostData.ports?.length || 0);

    // EXTRAIR CVEs de todas as fontes possíveis
    let allCVEs = [];

    // FONTE 1: foundCVEs direto
    if (hostData.foundCVEs && Array.isArray(hostData.foundCVEs) && hostData.foundCVEs.length > 0) {
      console.log(`✅ [AI Debug] Encontrei ${hostData.foundCVEs.length} CVEs em foundCVEs`);
      allCVEs = [...hostData.foundCVEs];
    }

    // FONTE 2: Extrair de ports[].cves
    if (hostData.ports && Array.isArray(hostData.ports)) {
      console.log(`🔍 [AI Debug] Verificando ${hostData.ports.length} portas...`);

      let cvesFromPorts = 0;
      hostData.ports.forEach((port, idx) => {
        if (port.cves && Array.isArray(port.cves) && port.cves.length > 0) {
          console.log(`   Porta ${port.port} tem ${port.cves.length} CVEs`);
          cvesFromPorts += port.cves.length;

          port.cves.forEach(cve => {
            // Criar objeto CVE completo
            const cveObj = {
              cve_id: cve.cve_id || 'UNKNOWN-CVE',
              CVSS: cve.CVSS || { score: 0, vector: 'N/A' },
              exploit_available: cve.exploit_available || false,
              publishedDate: cve.publishedDate || null,
              year: cve.year || this.extractYearFromCVE(cve.cve_id),
              port: port.port,
              service: port.service?.name || 'unknown'
            };

            allCVEs.push(cveObj);
          });
        }
      });

      if (cvesFromPorts > 0) {
        console.log(`✅ [AI Debug] Extraí ${cvesFromPorts} CVEs das portas`);
      }
    }

    // FONTE 3: Verificar se tem CVEs no risk_assessment findings
    if ((!allCVEs || allCVEs.length === 0) &&
      hostData.risk_assessment &&
      hostData.risk_assessment.findings) {

      console.log(`🔍 [AI Debug] Procurando CVEs em risk_assessment.findings`);

      const cveFindings = hostData.risk_assessment.findings.filter(f =>
        f.type === 'CVE_RISK' && f.cve_id
      );

      if (cveFindings.length > 0) {
        console.log(`✅ [AI Debug] Encontrei ${cveFindings.length} CVEs em findings`);

        cveFindings.forEach(finding => {
          const cveObj = {
            cve_id: finding.cve_id,
            CVSS: { score: finding.cvss_score || 0, vector: 'N/A' },
            exploit_available: false, // Não sabemos pelos findings
            publishedDate: null,
            year: this.extractYearFromCVE(finding.cve_id),
            port: finding.port || 'unknown',
            service: finding.service || 'unknown'
          };

          allCVEs.push(cveObj);
        });
      }
    }

    // Remover duplicados (pelo cve_id)
    const uniqueCVEs = [];
    const seenCVEIds = new Set();

    allCVEs.forEach(cve => {
      if (cve.cve_id && cve.cve_id !== 'UNKNOWN-CVE') {
        if (!seenCVEIds.has(cve.cve_id)) {
          seenCVEIds.add(cve.cve_id);
          uniqueCVEs.push(cve);
        }
      }
    });

    console.log(`📊 [AI Heuristics] Total de CVEs únicos encontrados: ${uniqueCVEs.length}`);

    if (uniqueCVEs.length === 0) {
      console.log(`⚠️ [AI Heuristics] Nenhum CVE encontrado para análise`);
      return {
        host: hostData.host || 'unknown',
        hostname: hostData.hostname || '',
        total_cves: 0,
        overall_heuristic_score: 0,
        prioritized_cves: [],
        summary_by_urgency: {
          CRITICAL: 0,
          HIGH: 0,
          MEDIUM: 0,
          LOW: 0
        }
      };
    }

    // Log dos CVEs encontrados
    console.log(`📋 [AI Debug] CVEs encontrados:`);
    uniqueCVEs.forEach((cve, idx) => {
      console.log(`   ${idx + 1}. ${cve.cve_id} - CVSS: ${cve.CVSS?.score || 0} - Ano: ${cve.year}`);
    });

    // ANALISAR cada CVE com heurísticas
    console.log(`🧠 [AI Heuristics] Aplicando heurísticas em ${uniqueCVEs.length} CVEs...`);

    const analyzedCVEs = uniqueCVEs.map(cve => {
      try {
        const analysis = this.calcularHeuristicaCVE(cve, hostData);
        const recommendation = this.gerarRecomendacaoPriorizada(cve, hostData);

        return {
          ...cve,
          heuristic_analysis: analysis,
          recommendation: recommendation
        };
      } catch (error) {
        console.error(`❌ [AI Error] Erro ao analisar CVE ${cve.cve_id}:`, error.message);
        return {
          ...cve,
          heuristic_analysis: { score: 0, factors: {}, breakdown: {} },
          recommendation: {
            urgency: 'UNKNOWN',
            timeframe: 'N/A',
            action_items: [],
            justification: 'Erro na análise'
          }
        };
      }
    });

    // Ordenar por score heurístico (maior primeiro)
    analyzedCVEs.sort((a, b) =>
      (b.heuristic_analysis?.score || 0) - (a.heuristic_analysis?.score || 0)
    );

    // Calcular score geral do host
    const validScores = analyzedCVEs
      .map(cve => cve.heuristic_analysis?.score || 0)
      .filter(score => score > 0);

    const overallScore = validScores.length > 0
      ? validScores.reduce((sum, score) => sum + score, 0) / validScores.length
      : 0;

    console.log(`🎯 [AI Heuristics] Análise completada - Score geral: ${overallScore.toFixed(2)}`);

    return {
      host: hostData.host || 'unknown',
      hostname: hostData.hostname || '',
      total_cves: uniqueCVEs.length,
      overall_heuristic_score: Math.round(overallScore * 100) / 100,
      prioritized_cves: analyzedCVEs.slice(0, 10), // Top 10 mais críticos
      summary_by_urgency: this.gerarSumarioUrgencia(analyzedCVEs)
    };
  }

  // Gerar sumário por urgência
  gerarSumarioUrgencia(analyzedCVEs) {
    const summary = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0
    };

    analyzedCVEs.forEach(cve => {
      const urgency = cve.recommendation?.urgency || 'LOW';
      if (summary.hasOwnProperty(urgency)) {
        summary[urgency]++;
      }
    });

    return summary;
  }

  // Integrar com o RiskAssessmentExpert existente
  integrarComRiskAssessment(riskExpertResults) {
    const enhancedResults = {
      ...riskExpertResults,
      ai_heuristic_analysis: {}
    };

    // Aplicar heurísticas a cada host
    if (riskExpertResults.assessedHosts) {
      enhancedResults.assessedHosts = riskExpertResults.assessedHosts.map(host => {
        const heuristicAnalysis = this.analisarEPriorizarCVEs(host);

        return {
          ...host,
          ai_heuristic_analysis: heuristicAnalysis,
          // Atualizar risco final com base nas heurísticas
          enhanced_finalRisk: this.atualizarRiscoComHeuristica(
            host.finalRisk,
            heuristicAnalysis.overall_heuristic_score
          )
        };
      });
    }

    // Recalcular estatísticas gerais
    enhancedResults.ai_heuristic_analysis = this.calcularEstatisticasHeuristicas(
      enhancedResults.assessedHosts
    );

    return enhancedResults;
  }

  // Atualizar risco final com base nas heurísticas
  atualizarRiscoComHeuristica(originalRisk, heuristicScore) {
    const riskLevels = {
      'INFO': 0,
      'LOW': 20,
      'MEDIUM': 40,
      'HIGH': 60,
      'CRITICAL': 80
    };

    // Se a heurística indica risco maior, ajustar
    if (heuristicScore > riskLevels[originalRisk] + 15) {
      // Subir um nível
      const levels = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
      const currentIndex = levels.indexOf(originalRisk);
      if (currentIndex < levels.length - 1) {
        return levels[currentIndex + 1];
      }
    }

    return originalRisk;
  }

  // Calcular estatísticas heurísticas
  calcularEstatisticasHeuristicas(hosts) {
    const hostsWithHeuristics = hosts.filter(h => h.ai_heuristic_analysis);

    if (hostsWithHeuristics.length === 0) {
      return null;
    }

    const totalHeuristicScore = hostsWithHeuristics.reduce(
      (sum, h) => sum + (h.ai_heuristic_analysis.overall_heuristic_score || 0),
      0
    );

    const averageHeuristicScore = totalHeuristicScore / hostsWithHeuristics.length;

    // Contar CVEs por urgência
    const urgencySummary = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0
    };

    hostsWithHeuristics.forEach(host => {
      const summary = host.ai_heuristic_analysis.summary_by_urgency;
      if (summary) {
        Object.keys(urgencySummary).forEach(key => {
          urgencySummary[key] += summary[key] || 0;
        });
      }
    });

    // Identificar top 5 CVEs mais críticos
    const allCVEs = [];
    hostsWithHeuristics.forEach(host => {
      if (host.ai_heuristic_analysis.prioritized_cves) {
        host.ai_heuristic_analysis.prioritized_cves.forEach(cve => {
          allCVEs.push({
            ...cve,
            host: host.host,
            hostname: host.hostname
          });
        });
      }
    });

    allCVEs.sort((a, b) =>
      (b.heuristic_analysis?.score || 0) - (a.heuristic_analysis?.score || 0)
    );

    return {
      total_hosts_analyzed: hostsWithHeuristics.length,
      average_heuristic_score: Math.round(averageHeuristicScore * 100) / 100,
      total_critical_cves: urgencySummary.CRITICAL,
      total_high_cves: urgencySummary.HIGH,
      urgency_summary: urgencySummary,
      top_critical_cves: allCVEs.slice(0, 5).map(cve => ({
        cve_id: cve.cve_id,
        heuristic_score: cve.heuristic_analysis?.score || 0,
        cvss_score: cve.CVSS?.score || 0,
        host: cve.host,
        urgency: cve.recommendation?.urgency || 'UNKNOWN'
      })),
      risk_level_distribution: this.calcularDistribuicaoRisco(hostsWithHeuristics)
    };
  }

  // Calcular distribuição de risco
  calcularDistribuicaoRisco(hosts) {
    const distribution = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0
    };

    hosts.forEach(host => {
      const riskLevel = host.enhanced_finalRisk || host.finalRisk;
      if (distribution.hasOwnProperty(riskLevel)) {
        distribution[riskLevel]++;
      }
    });

    return distribution;
  }

  // Método para gerar recomendações inteligentes
  gerarRecomendacoesInteligentes(enhancedResults) {
    const recommendations = [];

    enhancedResults.assessedHosts?.forEach(host => {
      if (host.ai_heuristic_analysis?.prioritized_cves) {
        host.ai_heuristic_analysis.prioritized_cves.forEach(cve => {
          if (cve.recommendation?.urgency === 'CRITICAL') {
            recommendations.push({
              type: 'CRITICAL_CVE',
              host: host.host,
              hostname: host.hostname,
              cve_id: cve.cve_id,
              heuristic_score: cve.heuristic_analysis?.score || 0,
              action: `Patch imediato para ${cve.cve_id}`,
              justification: cve.recommendation?.justification,
              timeframe: cve.recommendation?.timeframe,
              estimated_effort: 'Alto',
              business_impact: 'Crítico'
            });
          }
        });
      }
    });

    return recommendations.sort((a, b) => b.heuristic_score - a.heuristic_score);
  }

  // Método para gerar resumo executivo
  gerarResumoExecutivo(enhancedResults) {
    const aiAnalysis = enhancedResults.ai_heuristic_analysis;

    if (!aiAnalysis) {
      return { error: 'No AI analysis available' };
    }

    return {
      overall_risk_score: aiAnalysis.average_heuristic_score,
      risk_level: this.determinarNivelRiscoGeral(aiAnalysis.average_heuristic_score),
      critical_findings: aiAnalysis.total_critical_cves,
      high_priority_items: aiAnalysis.total_high_cves,
      top_concerns: aiAnalysis.top_critical_cves?.map(cve => ({
        cve: cve.cve_id,
        risk_score: cve.heuristic_score,
        affected_host: cve.host
      })),
      recommended_actions: [
        {
          priority: 1,
          action: 'Address critical CVEs',
          count: aiAnalysis.total_critical_cves
        },
        {
          priority: 2,
          action: 'Review high exposure hosts',
          count: enhancedResults.assessedHosts?.filter(h =>
            h.ai_heuristic_analysis?.overall_heuristic_score >= 70
          ).length || 0
        }
      ],
      timeline_recommendation: this.recomendarTimeline(aiAnalysis)
    };
  }

  // Determinar nível de risco geral
  determinarNivelRiscoGeral(score) {
    if (score >= 80) return 'CRÍTICO';
    if (score >= 60) return 'ALTO';
    if (score >= 40) return 'MÉDIO';
    if (score >= 20) return 'BAIXO';
    return 'MÍNIMO';
  }

  // Recomendar timeline
  recomendarTimeline(aiAnalysis) {
    if (aiAnalysis.total_critical_cves > 0) {
      return 'AÇÃO IMEDIATA REQUERIDA (dentro de 24h)';
    }
    if (aiAnalysis.total_high_cves > 5) {
      return 'AÇÃO PRIORITÁRIA (dentro de 7 dias)';
    }
    return 'AÇÃO PLANEJADA (dentro de 30 dias)';
  }
} // Fim da classe AIHeuristicEngine

// ===== ADICIONAR MÉTODO AO RiskAssessmentExpert =====
RiskAssessmentExpert.prototype.enhanceWithAIHeuristics = function () {
  const aiEngine = new AIHeuristicEngine();
  return aiEngine.integrarComRiskAssessment(this.assessAllHosts());
};

// ===== REMOVER AS FUNÇÕES SOLTAS (já estão dentro da classe) =====
// (Remover estas funções que estão fora da classe)

// ===== ENDPOINT PARA ANÁLISE DE HEURÍSTICAS DE IA =====
app.get('/scan/:scanId/ai-heuristics', async (req, res) => {
  try {
    const scanId = req.params.scanId;

    // 1. Buscar dados EXATAMENTE como no endpoint /cves
    const resultsSnap = await db.collection('ScanResults')
      .where('parent_scan_id', '==', scanId)
      .get();

    if (resultsSnap.empty) {
      return res.status(404).json({ error: 'No scan results found' });
    }

    // 2. Extrair todos os CVEs
    const allCVEs = [];
    const hostsData = resultsSnap.docs.map(doc => {
      const data = doc.data();
      const hostCVEs = data.foundCVEs || [];

      // Adicionar informações do host a cada CVE
      hostCVEs.forEach(cve => {
        allCVEs.push({
          ...cve,
          host: data.host,
          hostname: data.hostname,
          device_type: data.device_type,
          port: cve.port || 'unknown',
          service: cve.service || 'unknown',
          // Garantir que tem year
          year: cve.year || parseInt(cve.cve_id?.match(/CVE-(\d{4})/)?.[1]) || new Date().getFullYear()
        });
      });

      return {
        host: data.host,
        hostname: data.hostname,
        ports: data.ports || [],
        foundCVEs: hostCVEs,
        open_ports_count: data.open_ports_count || 0,
        device_type: data.device_type
      };
    });

    // 3. Se não tem CVEs, retornar vazio
    if (allCVEs.length === 0) {
      return res.json({
        scan_id: scanId,
        message: "No CVEs found for AI analysis",
        total_cves: 0
      });
    }

    // 4. Aplicar IA em CADA CVE individualmente
    const aiEngine = new AIHeuristicEngine();
    const analyzedCVEs = [];

    allCVEs.forEach(cve => {
      // Encontrar dados do host correspondente
      const hostData = hostsData.find(h => h.host === cve.host) || {};

      // Analisar CVE com IA
      const analysis = aiEngine.calcularHeuristicaCVE(cve, hostData);
      const recommendation = aiEngine.gerarRecomendacaoPriorizada(cve, hostData);

      analyzedCVEs.push({
        ...cve,
        heuristic_analysis: analysis,
        recommendation: recommendation
      });
    });

    // 5. Ordenar por score
    analyzedCVEs.sort((a, b) =>
      (b.heuristic_analysis?.score || 0) - (a.heuristic_analysis?.score || 0)
    );

    // 6. Agrupar por host
    const enhancedHosts = hostsData.map(host => {
      const hostCVEs = analyzedCVEs.filter(cve => cve.host === host.host);
      const scores = hostCVEs.map(cve => cve.heuristic_analysis?.score || 0);
      const avgScore = scores.length > 0 ? scores.reduce((a, b) => a + b) / scores.length : 0;

      return {
        ...host,
        ai_heuristic_analysis: {
          host: host.host,
          hostname: host.hostname,
          total_cves: hostCVEs.length,
          overall_heuristic_score: Math.round(avgScore * 100) / 100,
          prioritized_cves: hostCVEs.slice(0, 5),
          summary_by_urgency: aiEngine.gerarSumarioUrgencia(hostCVEs)
        }
      };
    });

    // 7. Gerar recomendações
    const smartRecommendations = analyzedCVEs
      .filter(cve => cve.recommendation?.urgency === 'HIGH' || cve.recommendation?.urgency === 'CRITICAL')
      .map(cve => ({
        type: 'AI_RECOMMENDATION',
        host: cve.host,
        cve_id: cve.cve_id,
        heuristic_score: cve.heuristic_analysis?.score || 0,
        action: cve.recommendation?.action_items?.[0]?.action || 'Apply security patch',
        timeframe: cve.recommendation?.timeframe || '7 dias',
        justification: cve.recommendation?.justification || 'AI heuristic analysis'
      }));

    // 8. Retornar
    res.json({
      scan_id: scanId,
      total_cves_analyzed: analyzedCVEs.length,
      top_cves: analyzedCVEs.slice(0, 10),
      enhanced_hosts: enhancedHosts,
      smart_recommendations: smartRecommendations,
      executive_summary: {
        overall_risk_score: Math.round(analyzedCVEs.reduce((sum, cve) => sum + (cve.heuristic_analysis?.score || 0), 0) / analyzedCVEs.length),
        risk_level: aiEngine.determinarNivelRiscoGeral(analyzedCVEs.reduce((sum, cve) => sum + (cve.heuristic_analysis?.score || 0), 0) / analyzedCVEs.length),
        critical_findings: analyzedCVEs.filter(cve => cve.heuristic_analysis?.score >= 80).length,
        top_concerns: analyzedCVEs.slice(0, 3).map(cve => ({
          cve: cve.cve_id,
          risk_score: cve.heuristic_analysis?.score,
          affected_host: cve.host
        }))
      }
    });

  } catch (err) {
    console.error('Error in AI heuristics:', err);
    res.status(500).json({ error: err.message });
  }
});

// ===== ENDPOINT PARA TESTE DAS HEURÍSTICAS =====
app.post('/ai-heuristics/test', async (req, res) => {
  try {
    const { cves, ports } = req.body;

    if (!cves || !Array.isArray(cves)) {
      return res.status(400).json({ error: 'cves array is required' });
    }

    const aiEngine = new AIHeuristicEngine();
    const testHost = {
      host: 'test-host',
      hostname: 'test.example.com',
      ports: ports || [],
      foundCVEs: cves || []
    };

    const analysis = aiEngine.analisarEPriorizarCVEs(testHost);

    res.json({
      success: true,
      analysis: analysis,
      heuristic_engine: {
        weights: aiEngine.WEIGHTS,
        version: '1.0'
      }
    });

  } catch (err) {
    console.error('Error testing AI heuristics:', err);
    res.status(500).json({ error: 'Failed to test AI heuristics', details: err.message });
  }
});

// ===== ENDPOINT PARA ESTATÍSTICAS DAS HEURÍSTICAS =====
app.get('/ai-heuristics/stats', (req, res) => {
  const aiEngine = new AIHeuristicEngine();

  res.json({
    heuristic_engine: {
      name: 'AIHeuristicEngine',
      version: '1.0',
      weights: aiEngine.WEIGHTS,
      capabilities: [
        'CVE age probability calculation',
        'Network exposure scoring',
        'Service criticality assessment',
        'Exploit availability weighting',
        'Priority-based recommendations',
        'Timeline estimation'
      ],
      thresholds: {
        critical: 80,
        high: 60,
        medium: 40,
        low: 20
      }
    }
  });
});

// ===== FUNÇÃO AUXILIAR PARA CALCULAR RATING A PARTIR DE HEURÍSTICAS =====
function calculateOverallRatingFromHeuristics(riskDistribution) {
  const { CRITICAL = 0, HIGH = 0, MEDIUM = 0, LOW = 0, INFO = 0 } = riskDistribution;
  const total = CRITICAL + HIGH + MEDIUM + LOW + INFO;

  if (total === 0) return 'UNKNOWN';

  const weightedScore = (CRITICAL * 5 + HIGH * 4 + MEDIUM * 3 + LOW * 2 + INFO * 1) / total;

  if (weightedScore >= 4.5) return 'CRITICAL';
  if (weightedScore >= 3.5) return 'HIGH';
  if (weightedScore >= 2.5) return 'MEDIUM';
  if (weightedScore >= 1.5) return 'LOW';
  return 'INFO';
}

// Process-level handlers for crashes and promise rejections
process.on('unhandledRejection', (reason, p) => {
  console.error('Unhandled Rejection at Promise', p, 'reason:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  // Log and allow supervisor (PM2/systemd) to handle restarts. Avoid calling process.exit() directly.
  // If you prefer to exit on uncaught exceptions, replace this with `process.exit(1)` behind an environment flag.
});

server.listen(PORT, () => console.log(`Enhanced Nmap-Firebase API with AI Risk Assessment and CVE Detection listening on ${PORT}`));