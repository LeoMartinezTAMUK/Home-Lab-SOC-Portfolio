# 🛡️ Home Lab SOC Portfolio
**Analyst:** Leo Martinez III
**Contact:** mtz3.leo@gmail.com
**Environment:** Oracle VirtualBox | Security Onion | Kali Linux | Metasploitable

## 📖 Project Overview
This repository documents a simulated Security Operations Center (SOC) environment designed to test Network Intrusion Detection Systems (NIDS) against real-world attack vectors. The goal was to execute "Kill Chain" scenarios—ranging from reconnaissance to data exfiltration—and validate detection signatures using **Suricata** and **Zeek**.

### 🏗️ Lab Architecture
| Role | OS | IP Address | Function |
|:---:|:---:|:---:|:---|
| **Analyst** | Security Onion | `192.168.1.50` | NIDS sensor, Kibana dashboard, Elasticsearch backend. |
| **Attacker** | Kali Linux | `10.10.10.6` | Red Team operations, penetration testing tools. |
| **Victim** | Metasploitable | `10.10.10.5` | Vulnerable target running legacy services (DVWA, FTP, SSH). |

---

## 📂 Laboratory Reports

### 1️⃣ Network Reconnaissance & Enumeration
**Objective:** Map the attack surface of the victim machine to identify open ports, running services, and OS versions.
* **Tools Used:** `nmap`, `ping`
* **Methodology:** Executed an aggressive scan (`nmap -A`) to fingerprint the target.
* **Detection:** Validated Suricata alerts for "Nmap OS Detection" and high-volume connection attempts.
* **📄 View Report:** [Network Recon Report](./reports/nmap-scan-attack_demo.pdf)

### 2️⃣ Authentication Brute Force Attacks
**Objective:** Simulate credential stuffing attacks against remote access protocols.
* **Tools Used:** `hydra`, `rockyou.txt`
* **Methodology:**
    * Attempted SSH brute force (Failed due to legacy encryption mismatch).
    * **Pivoted** to FTP (Port 21) to bypass encryption and successfully crack credentials.
* **Detection:** Analyzed "Possible FTP Brute Force" alerts triggered by repeated `530 Login incorrect` responses from the victim.
* **📄 View Report:** [Brute Force Report](./reports/hyrdra-brute-force-attack_demo.pdf)

### 3️⃣ Web Application Exploitation (Command Injection)
**Objective:** Exploit input sanitization vulnerabilities to achieve Remote Code Execution (RCE).
* **Tools Used:** DVWA (Damn Vulnerable Web App), Firefox, Linux Shell
* **Methodology:** Injected a malicious payload (`127.0.0.1; cat /etc/passwd`) into a ping tool to force the server to reveal sensitive system files.
* **Detection:** Confirmed **Data Exfiltration** via PCAP analysis, capturing the `/etc/passwd` file content in the HTTP response body.
* **📄 View Report:** [Web Attack Report](./reports/web-app-command-injection-attack_demo.pdf)

---

## 🛠️ Skills & Technologies Demonstrated
* **Traffic Analysis:** Correlating raw packet captures (PCAP) with IDS alerts.
* **Incident Response:** Identifying Indicators of Compromise (IoCs) across the kill chain.
* **Network Security:** Configuring Promiscuous Mode, internal virtual networks, and static addressing.
* **Tools:** Nmap, Hydra, Wireshark/Tcpdump, Suricata, Kibana.

---

### ⚠️ Disclaimer
*This repository contains documentation of simulated cyber attacks performed in an isolated, sandboxed environment for educational purposes. No live networks were targeted.*
