# VulnerAI: Automated Vulnerability Scanning Framework
![Status](https://img.shields.io/badge/Status-Active-success)
![Security](https://img.shields.io/badge/Focus-Cybersecurity-red)

---

## Overview

**VulnerAI** is a cybersecurity tool designed to automate the discovery of common system and network vulnerabilities. It performs intelligent reconnaissance by identifying exposed services, detecting insecure configurations, and flagging potential entry points for attackers.

This project was built as part of a hands-on approach to learning **offensive security fundamentals**, focusing on practical vulnerability assessment techniques.

---

##  Features

*  **Port Scanning**

  * Fast multi-threaded scanning of target hosts
  * Detects open TCP ports and responsive services

*  **Service Enumeration**

  * Banner grabbing for service/version detection
  * Identifies protocols like HTTP, FTP, SSH, etc.

---

##  Technical Deep Dive

###  Scanning Pipeline

VulnerAI follows a layered scanning architecture:

1. **Port Discovery Layer**

   * Uses Python sockets with multithreading
   * Quickly identifies open ports across configurable ranges

2. **Service Fingerprinting Layer**

   * Performs banner grabbing
   * Identifies service types and versions


3. **Correlation Engine**

   * Maps services → vulnerabilities → severity levels

---

### Network Intelligence & Optimization

To improve efficiency and reduce noise:

* Prioritizes high-risk ports (21, 22, 80, 443, 3306)
* Skips unresponsive ports after timeout thresholds
* Adjustable scan depth (fast vs full scan modes)

---

##  Example Output

```json
{
  "target": "192.168.1.1",
  "open_ports": [22, 80],
  "services": {
    "22": "SSH - OpenSSH 7.9",
    "80": "HTTP - Apache 2.4.41"
  },
  "vulnerabilities": [
    {
      "port": 22,
      "issue": "Default credentials possible",
      "severity": "High"
    }
  ]
}
```

---
