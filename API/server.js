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

// --- Nmap Scan Presets ---
const PRESETS = {
  quick: {
    args: [
      '-sT', '-sV', '-sC',
      '--script', 'vuln,http-enum,http-security-headers,http-title,ssh2-enum-algos,ftp-anon',
      '-p', '80,443,8080,8443,21,22,23,25,53,110,143,993,995,3306,3389,5432,27017',
      '-T4', '--max-retries', '1', '--host-timeout', '120s', '--script-timeout', '30s',
      '--open', '--reason', '-oX', '-'
    ],
    outputFormat: 'xml',
    timeoutMs: 120 * 1000,
    description: 'Quick scan with vulnerability detection on common ports'
  },
  deep: {
    args: [
      '-sT', '-sV', '-sC', '-A',
      '--script', 'vuln,http-enum,http-security-headers,http-title,ssh2-enum-algos,ftp-anon,banner',
      '-p-', '-T4', '--min-rate', '100', '--max-retries', '1',
      '--host-timeout', '45m', '--script-timeout', '2m',
      '--open', '--reason', '-oX', '-'
    ],
    outputFormat: 'xml',
    timeoutMs: 90 * 60 * 1000,
    description: 'Deep comprehensive scan with extensive vulnerability detection'
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
        resolve({ stdout, stderr, code: -1, signal: 'TIMEOUT', duration: `${elapsed}s` });
        return;
      }
      try { n.kill('SIGKILL'); } catch (e) { }
      reject(new Error(`Timeout after ${elapsed}s`));
    }, timeoutMs);

    n.stdout.on('data', d => { stdout += d.toString(); });
    n.stderr.on('data', d => { stderr += d.toString(); });

    n.on('error', err => {
      clearTimeout(timer);
      reject(new Error(`Process spawn failed: ${err.message}`));
    });

    n.on('close', (code, signal) => {
      clearTimeout(timer);
      const duration = (Date.now() - startTime) / 1000;
      if (isTimeout) return;
      if (stdout.trim().length > 0 && (stdout.includes('<?xml') || stdout.includes('<nmaprun>'))) {
        resolve({ stdout, stderr, code, signal, duration: `${duration}s` });
      } else if (stdout.trim().length > 0) {
        resolve({ stdout, stderr, code, signal, duration: `${duration}s` });
      } else {
        let errorMsg = `Scan failed - no output received`;
        if (stderr.includes('Failed to resolve')) errorMsg = `DNS resolution failed for ${target}`;
        else if (stderr.includes('did not match')) errorMsg = `Script error: ${stderr.split('\n')[0]}`;
        else if (code !== 0) errorMsg = `Nmap exited with code ${code}: ${stderr || 'unknown error'}`;
        reject(new Error(errorMsg));
      }
    });
  });
}

// Parse nmap XML output to ScanResult and FoundVulns format
async function parseScanXml(xmlText) {
  try {
    const result = await xml2js.parseStringPromise(xmlText, { explicitArray: false, mergeAttrs: true });
    const hostObj = result.nmaprun.host;
    const address = hostObj.address?.addr || null;
    const portsArr = Array.isArray(hostObj.ports?.port) ? hostObj.ports.port : (hostObj.ports?.port ? [hostObj.ports.port] : []);
    const detectedPorts = portsArr.map(p => ({
      port: p.portid,
      protocol: p.protocol,
      service: p.service?.name || '',
      status: p.state?.state || '',
      banner: p.service?.banner || '',
      fingerprint: p.service?.fingerprint || ''
    }));

    // Vulnerabilities from scripts
    let foundVulns = [];
    for (const p of portsArr) {
      if (p.script) {
        const scripts = Array.isArray(p.script) ? p.script : [p.script];
        for (const s of scripts) {
          const cveMatches = (s.output || '').match(/CVE-\d{4}-\d{4,7}/g) || [];
          for (const cve of cveMatches) {
            foundVulns.push({
              CVE: cve,
              severity: 'Unknown', // You can parse severity from output if available
              evidence: { output: s.output },
              port: p.portid
            });
          }
        }
      }
    }

    return {
      host: address,
      ports: detectedPorts,
      service: detectedPorts.map(p => p.service),
      protocol: detectedPorts.map(p => p.protocol),
      banner: detectedPorts.map(p => p.banner).filter(b => b),
      fingerprint: detectedPorts.map(p => p.fingerprint).filter(f => f),
      foundVulns
    };
  } catch (error) {
    return {
      host: null,
      ports: [],
      service: [],
      protocol: [],
      banner: [],
      fingerprint: [],
      foundVulns: [],
      parse_error: error.message
    };
  }
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
    estimatedDuration: key === 'quick' ? '30-120 seconds' : '10-90 minutes'
  }));
  res.json({ presets: presetsInfo });
});

// Start a scan
app.post('/scan', async (req, res) => {
  try {
    const { target, preset, userId, targetId } = req.body;
    const scanType = preset === 'deep' ? 'deep' : 'quick';
    if (!target || !userId) return res.status(400).json({ error: 'target and userId required' });
    if (!PRESETS[scanType]) return res.status(400).json({ error: 'unknown scan type' });

    let host;
    try { host = extractHost(target); }
    catch (e) { return res.status(400).json({ error: 'invalid target: ' + e.message }); }
    if (!isAllowedTarget(host)) return res.status(403).json({ error: 'target not allowed' });

    // Create scan record in 'Scan'
    const scanId = uuidv4();
    await db.collection('Scan').doc(scanId).set({
      status: 'ongoing',
      submitted_at: admin.firestore.FieldValue.serverTimestamp(),
      started_at: null,
      finished_at: null,
      scan_type: scanType,
      target: host,
      user_id: userId
    });

    // Run scan asynchronously
    (async () => {
      let runResult;
      try {
        await db.collection('Scan').doc(scanId).update({
          started_at: admin.firestore.FieldValue.serverTimestamp()
        });
        runResult = await runNmap(PRESETS[scanType].args, host, PRESETS[scanType].timeoutMs, scanId);
        const stdout = runResult.stdout;

        // Parse scan result
        const parsed = await parseScanXml(stdout);

        // Create ScanResult record (use Firestore doc ID, not ScanResult_id field)
        const uniqueCVEs = [...new Set(parsed.foundVulns.map(v => v.CVE))];

        // Create ScanResult record (add CVEs array)
        const scanResultRef = db.collection('ScanResult').doc();
        await scanResultRef.set({
          scan_id: db.collection('Scan').doc(scanId), // Firestore reference
          host: parsed.host,
          ports: parsed.ports,
          CVEs: uniqueCVEs, // Array of CVE IDs
          created_at: admin.firestore.FieldValue.serverTimestamp()
        });

        // Create FoundVulns records (with external links)
        for (const vuln of parsed.foundVulns) {
          const foundVulnQuery = await db.collection('FoundVulns')
            .where('CVE', '==', vuln.CVE)
            .where('port', '==', vuln.port)
            .where('host', '==', parsed.host)
            .get();

          if (foundVulnQuery.empty) {
            // Create new FoundVulns document
            await db.collection('FoundVulns').add({
              CVE: vuln.CVE,
              severity: vuln.severity,
              port: vuln.port,
              host: parsed.host,
              scan_results: [scanResultRef], // array of references
              external_links: [
                `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vuln.CVE}`,
                `https://nvd.nist.gov/vuln/detail/${vuln.CVE}`
              ],
              created_at: admin.firestore.FieldValue.serverTimestamp()
            });
          } else {
            // Update existing document to add new scan result reference
            const docRef = foundVulnQuery.docs[0].ref;
            await docRef.update({
              scan_results: admin.firestore.FieldValue.arrayUnion(scanResultRef)
            });
          }
        }

        await db.collection('Scan').doc(scanId).update({
          status: 'complete',
          finished_at: admin.firestore.FieldValue.serverTimestamp()
        });
      } catch (err) {
        await db.collection('Scan').doc(scanId).update({
          status: 'failed',
          finished_at: admin.firestore.FieldValue.serverTimestamp(),
          error: err.message
        });
      }
    })();

    return res.json({
      scanId,
      status: 'ongoing',
      scanType,
      target: host,
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

    // Get ScanResult(s)
    const resultsSnap = await db.collection('ScanResult').where('scan_id', '==', scanId).get();
    const ScanResult = resultsSnap.docs.map(doc => doc.data());

    // Get FoundVulns for each ScanResult
    let foundVulns = [];
    for (const result of ScanResult) {
      const vulnsSnap = await db.collection('FoundVulns').where('ScanResult_id', '==', result.ScanResult_id).get();
      foundVulns = foundVulns.concat(vulnsSnap.docs.map(doc => doc.data()));
    }

    return res.json({
      scan: scanData,
      ScanResult: ScanResult,
      FoundVulns: foundVulns
    });
  } catch (err) {
    return res.status(500).json({ error: 'server error' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => res.json({
  ok: true,
  now: new Date().toISOString(),
  presets: Object.keys(PRESETS)
}));

app.listen(PORT, () => console.log(`Nmap-Firebase API listening on ${PORT}`));