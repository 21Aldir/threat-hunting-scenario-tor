# threat-hunting-scenario-tor
# 🕵️ TOR Network Threat Hunting Lab

**Threat Hunting Exercise | Microsoft Defender for Endpoint | KQL Analysis**

> A comprehensive threat hunting investigation detecting unauthorized TOR browser installation and usage within a corporate endpoint environment.

---

## 📋 Table of Contents
- [Scenario Overview](#scenario-overview)
- [Investigation Objective](#investigation-objective)
- [Initial Indicators](#initial-indicators)
- [Target Device & User](#target-device--user)
- [Methodology](#methodology)
- [Key Findings](#key-findings)
- [Evidence & Artifacts](#evidence--artifacts)
- [KQL Queries](#kql-queries)
- [Timeline](#timeline)
- [Risk Assessment](#risk-assessment)
- [Conclusion](#conclusion)

---

## 🎯 Scenario Overview

This lab exercise simulates a real-world threat hunting scenario where suspicious network activity and user behavior indicate potential use of TOR (The Onion Router) for evading corporate security controls and accessing restricted content.

**Lab Environment:** Controlled, isolated network with Microsoft Defender for Endpoint telemetry collection enabled.

---

## 🎪 Investigation Objective

**Primary Goal:**  
Detect and confirm unauthorized TOR network usage on corporate endpoint `aldir-1` and attribute activity to user `aldir`.

**Secondary Goals:**
- Correlate file system events with process execution and network connections
- Identify compromise timeline and progression
- Document indicators of compromise (IoCs)
- Demonstrate pivot techniques across Defender tables

---

## 🚨 Initial Indicators

The investigation was triggered by:

| Indicator | Source |
|-----------|--------|
| 🔐 Encrypted traffic patterns | Network monitoring alerts |
| 🌐 Connections to suspected TOR exit nodes | IP reputation feeds |
| 📝 Anonymous employee reports | Internal tip-off |
| ⏱️ Unusual off-hours activity | Behavioral analytics |

---

## 🖥️ Target Device & User

| Attribute | Value |
|-----------|-------|
| **Device Name** | `aldir-1` |
| **Operating System** | Windows 10/11 |
| **User Account** | `aldir` |
| **Device Type** | Corporate Workstation |
| **Monitoring Agent** | Microsoft Defender for Endpoint |

---

## 🔍 Methodology

This investigation followed a structured approach using Microsoft Defender data tables to build evidence across three vectors: **file system**, **process execution**, and **network activity**.

### 1️⃣ File System Analysis (DeviceFileEvents)

**Objective:** Identify TOR-related files and suspicious artifacts  
**Search Criteria:** TOR binary executables, configuration files, and related browser artifacts

**Artifacts Detected:**
```
✓ tor.exe                    - TOR network client executable
✓ firefox.exe               - Bundled Tor Browser Firefox instance
✓ Tor Browser.lnk           - Shortcut to TOR browser
✓ tor-shopping-list.txt     - Suspicious user-created file
✓ tor-browser-...-15.0.9.exe - TOR Browser installer (portable)
```

**File Creation Timeline:**
- **7:06:28 PM** - TOR Browser installer downloaded (`tor-browser-windows-x86_64-portable-15.0.9.exe`)
- **7:09:19 PM** - `firefox.exe` extracted from installer
- **7:09:30 PM** - Documentation and license files created
- **7:51:17 PM** - Suspicious `.txt` file with TOR-related naming created on Desktop

### 2️⃣ Process Execution Analysis (DeviceProcessEvents)

**Objective:** Detect TOR-related process execution  
**Search Criteria:** Process creation events for TOR and bundled Firefox

**Processes Identified:**

| Process | Parent | Account | Path | Status |
|---------|--------|---------|------|--------|
| `firefox.exe` | TOR Browser launcher | `aldir` | `C:\Users\Aldir\Desktop\Tor Browser\Browser\firefox.exe` | 🔴 Executed |
| Multiple firefox.exe child processes | firefox.exe | `aldir` | Same path | 🔴 Spawned for tab management |

**Process Command Line Sample:**
```
"firefox.exe" -contentproc -isForBrowser -prefsHandle 6072:29743 
-parentBuildID 20260404073000 -appDir "C:\Users\Aldir\Desktop\Tor Browser\Browser\browser"
```

### 3️⃣ Network Activity Analysis (DeviceNetworkEvents)

**Objective:** Detect suspicious outbound connections to TOR infrastructure  
**Search Criteria:** Unusual remote IPs, port 9001 (TOR relay), and ConnectionAcknowledged status

**Suspicious Connections Identified:**

| Remote IP | Remote Port | Connection Status | Process | Timestamp |
|-----------|-------------|-------------------|---------|-----------|
| `82.67.111.215` | 9001 | ConnectionAcknowledged | tor.exe | Apr 15, 7:25+ PM |
| `51.91.241.137` | 9001 | ConnectionAcknowledged | tor.exe | Apr 15, 7:26+ PM |
| `23.53.11.244` | 443 | ConnectionAcknowledged | Unknown | Apr 15, 6:53 PM |
| `20.189.173.17` | 443 | ConnectionAcknowledged | Unknown | Apr 15, 6:53 PM |

**Port 9001 Significance:**  
Port 9001 is the standard port for TOR relay nodes, indicating direct communication with TOR infrastructure rather than client usage (which typically routes through port 443 or other channels).

---

## 🔑 Key Findings

### ✅ Confirmed Indicators of Compromise

| Finding | Severity | Evidence |
|---------|----------|----------|
| TOR binary execution | 🔴 **Critical** | `tor.exe` process creation detected |
| TOR relay node connections | 🔴 **Critical** | Connections to 82.67.111.215 and 51.91.241.137 on port 9001 |
| TOR Browser installation | 🟠 **High** | Portable TOR Browser extracted to Desktop |
| Suspicious file artifacts | 🟠 **High** | `tor-shopping-list.txt` created on Desktop |
| Firefox child processes | 🟠 **High** | Multiple firefox.exe instances for tab management |
| Non-standard application location | 🟠 **High** | TOR binaries in user Desktop, not Program Files |

### 🎯 Attack Pattern Analysis

**Progression:**
1. **Stage 1 (7:06 PM):** TOR Browser installer downloaded to user Downloads folder
2. **Stage 2 (7:09 PM):** Portable TOR Browser extracted to Desktop
3. **Stage 3 (7:25+ PM):** `tor.exe` and `firefox.exe` execution initiated
4. **Stage 4 (7:25+ PM):** Active connections to TOR relay nodes established
5. **Stage 5 (7:51 PM):** Suspicious files created, indicating active TOR browsing

**Attack Surface Identified:**
- ❌ User bypassed application whitelisting
- ❌ Portable executable circumvented installation controls
- ❌ Desktop location suggests intentional obfuscation from standard app directories
- ❌ Multiple connections indicate sustained TOR network usage, not one-time testing

---

## 📊 Evidence & Artifacts

### Recovered Data Sources

| Table | Records | Key Columns |
|-------|---------|------------|
| `DeviceFileEvents` | 11 | Timestamp, FileName, FolderPath, SHA256, ActionType |
| `DeviceNetworkEvents` | 100+ | RemoteIP, RemotePort, InitiatingProcessFileName, ConnectionStatus |
| `DeviceProcessEvents` | 50+ | ProcessCommandLine, SHA256, ParentProcessFileName |

### File Hashes (SHA256)

Identified TOR-related binaries:

```
TOR Browser Installer:
  2f7dea5cb68c538ed0cf257b5fe3f0e6dd4cdb82d065dd099c82790e2b101622
  
firefox.exe (bundled):
  ef09a491d65b51f1f304145f6914a6682acd5c6226d0a241361730881134de35
  
tor.exe:
  176c9cb6131fb49fa5e982e823766947e5ce673177c7fff339f5e7a9d330ebf3

Suspicious .txt files:
  cbf296b83e566387289eecc30fa3ee3b1636c95da204124e849e6d358390a398 (tor-shopping-list.txt)
```

> ⚠️ **Recommendation:** Query hash reputation with VirusTotal, AlienVault OTX, and Defender's threat intelligence feeds.

---

## 🔎 KQL Queries

### Query 1: Detect TOR-Related File Creation

```kusto
DeviceFileEvents
| where DeviceName == "aldir-1"
| where FileName in ("tor.exe", "firefox.exe", "Tor Browser.lnk", "torbrowser.exe")
  or FolderPath contains "Tor" 
  or FileName contains "tor-"
| project Timestamp, ActionType, FileName, FolderPath, SHA256, Account
| sort by Timestamp desc
```

**Purpose:** Identify all TOR-related file system artifacts on the device.

---

### Query 2: Detect TOR Process Execution

```kusto
DeviceProcessEvents
| where DeviceName == "aldir-1"
| where (InitiatingProcessFileName in ("tor.exe", "firefox.exe") 
    and InitiatingProcessFolderPath contains "Tor Browser")
  or ProcessCommandLine contains "tor.exe"
| project Timestamp, InitiatingProcessFileName, ProcessCommandLine, SHA256, AccountName
| sort by Timestamp desc
```

**Purpose:** Find process creation events for TOR and the bundled Firefox browser.

---

### Query 3: Detect TOR Relay Node Connections

```kusto
DeviceNetworkEvents
| where DeviceName == "aldir-1"
| where RemotePort == 9001
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, ConnectionDirection
| sort by Timestamp asc
```

**Purpose:** Identify connections to TOR relay infrastructure (port 9001 is reserved for TOR relays).

---

### Query 4: Correlation - Pivot on Remote IPs

```kusto
DeviceNetworkEvents
| where DeviceName == "aldir-1"
| where RemoteIP in ("82.67.111.215", "51.91.241.137")
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| sort by Timestamp asc
```

**Purpose:** Confirm that `tor.exe` is the initiating process for suspicious remote connections.

---

### Query 5: Timeline Correlation (File → Process → Network)

```kusto
let FileCreationTime = toscalar(
  DeviceFileEvents
  | where DeviceName == "aldir-1" and FileName == "tor.exe"
  | summarize max(Timestamp)
);
let ProcessStartTime = toscalar(
  DeviceProcessEvents
  | where DeviceName == "aldir-1" and InitiatingProcessFileName == "tor.exe"
  | summarize min(Timestamp)
);
let NetworkActivityTime = toscalar(
  DeviceNetworkEvents
  | where DeviceName == "aldir-1" and RemotePort == 9001
  | summarize min(Timestamp)
);
union 
  (DeviceFileEvents | where Timestamp == FileCreationTime and DeviceName == "aldir-1" | extend EventType = "File Created"),
  (DeviceProcessEvents | where Timestamp >= ProcessStartTime - 5m and DeviceName == "aldir-1" | extend EventType = "Process Spawned"),
  (DeviceNetworkEvents | where Timestamp >= NetworkActivityTime - 5m and DeviceName == "aldir-1" | extend EventType = "Network Activity")
| sort by Timestamp asc
```

**Purpose:** Create a comprehensive timeline showing the progression of the attack across all three vectors.

---

## 📅 Timeline

```
2026-04-15

19:06:28 - [FILE] TOR Browser installer downloaded
           └─ File: tor-browser-windows-x86_64-portable-15.0.9.exe
           └─ Location: C:\Users\Aldir\Downloads\
           
19:09:19 - [FILE] Portable TOR Browser extracted
           ├─ firefox.exe extracted
           ├─ tor.exe extracted
           └─ Location: C:\Users\Aldir\Desktop\Tor Browser\
           
19:09:30 - [FILE] Documentation files created
           └─ License and supporting files
           
19:25+ PM - [PROCESS] tor.exe execution initiated
            └─ Parent: TOR Browser launcher
            └─ Command: tor.exe -f C:\Users\Aldir\...
            
19:25+ PM - [PROCESS] firefox.exe execution initiated
            └─ Parent: tor.exe or TOR launcher
            └─ Purpose: Browse through TOR network
            
19:25+ PM - [NETWORK] Connections to TOR relay nodes
            ├─ 82.67.111.215:9001 ✓ Connected
            ├─ 51.91.241.137:9001 ✓ Connected
            └─ Status: ConnectionAcknowledged (successful)
            
19:51:17 - [FILE] Suspicious user-created file
           └─ tor-shopping-list.txt created on Desktop
           └─ Indicates active TOR browsing activity
```

---

## ⚠️ Risk Assessment

### Severity: 🔴 **CRITICAL**

| Risk Category | Impact | Probability | Notes |
|---------------|--------|-------------|-------|
| **Compliance Violation** | High | High | TOR usage violates acceptable use policies |
| **Data Exfiltration** | Critical | Medium | TOR enables anonymous data transfer |
| **Malware/C2 Communication** | Critical | Medium | TOR relay connectivity can indicate C2 infrastructure |
| **Access to Restricted Content** | High | High | Anonymous browsing circumvents web filters |
| **Monitoring Evasion** | High | High | TOR encrypts traffic, hiding from DLP solutions |

### Recommended Actions

**Immediate (Within 1 hour):**
- [ ] Isolate device from network
- [ ] Initiate endpoint forensics collection
- [ ] Preserve memory dump for analysis
- [ ] Interview user `aldir` regarding TOR usage

**Short-term (Within 24 hours):**
- [ ] Conduct full forensic analysis of device
- [ ] Recover browser history and cached content
- [ ] Analyze file timestamps and metadata
- [ ] Check for additional suspicious files/processes
- [ ] Review user's recent access logs to sensitive systems

**Long-term (Within 1 week):**
- [ ] Implement application whitelisting to prevent TOR installation
- [ ] Deploy network-level filtering for known TOR exit nodes
- [ ] Add TOR-related IoCs to threat intelligence feeds
- [ ] Conduct security awareness training
- [ ] Review and strengthen access controls

---

## 💡 Conclusion

### Summary

This threat hunting exercise successfully identified and confirmed **unauthorized TOR network usage** on corporate endpoint `aldir-1` associated with user `aldir`. The investigation leveraged Microsoft Defender for Endpoint telemetry across file system, process, and network domains to build a comprehensive evidence chain.

### Key Takeaways

✅ **What Worked Well:**
- Multi-domain correlation (files → processes → network) provided strong evidence
- File timestamps established clear progression timeline
- Port 9001 was a high-confidence TOR indicator
- Portable TOR Browser circumvented standard installation controls

🔍 **Investigation Gaps:**
- Could not recover deleted browsing history
- TOR network hides destination sites and data transferred
- User file creation timestamps were our only activity indicator post-execution

📌 **Lessons Learned:**
1. **Monitor Desktop/Downloads folders** for executable deposits
2. **Alert on port 9001** connections (TOR relay indicator)
3. **Track portable executables** - they bypass traditional AV and controls
4. **Correlate across tables** - no single data source tells the whole story
5. **Timeline is critical** - sequential events tell a story of intent

---

## 📚 References & Resources

### Microsoft Defender Documentation
- [DeviceFileEvents](https://learn.microsoft.com/en-us/defender/advanced-hunting-devicefileevents-table)
- [DeviceProcessEvents](https://learn.microsoft.com/en-us/defender/advanced-hunting-deviceprocessevents-table)
- [DeviceNetworkEvents](https://learn.microsoft.com/en-us/defender/advanced-hunting-devicenetworksevents-table)
- [KQL Query Language](https://learn.microsoft.com/en-us/kusto/query/index)

### TOR Network Information
- [TOR Project Documentation](https://www.torproject.org/about/overview/)
- [TOR Relay Operations](https://docs.torproject.org/relay-operations)
- [Common TOR Ports](https://en.wikipedia.org/wiki/Tor_(network)#Ports)

### Threat Intelligence
- [MITRE ATT&CK - Proxy (T1090)](https://attack.mitre.org/techniques/T1090/)
- [MITRE ATT&CK - Hide Infrastructure (T1518.001)](https://attack.mitre.org/techniques/T1518/001/)

---

## 📎 Appendices

### Appendix A: Raw Evidence

**CSV Data Files Analyzed:**
- `DeviceFileEvents.csv` - 11 records of TOR-related file creation
- `DeviceProcessEvents.csv` - 50+ records of process execution
- `DeviceNetworkEvents.csv` - 100+ records of network connections
- `DeviceNetworkEvents_2.csv` - Additional network telemetry

**Evidence Retention:** All raw CSV files are preserved in this repository for forensic review and training purposes.

### Appendix B: Network Indicators of Compromise (IoCs)

**TOR Relay Node IPs Detected:**
```
82.67.111.215    (Reputation: TOR Relay)
51.91.241.137    (Reputation: TOR Relay)
```

**Suspicious Ports:**
```
9001   - TOR Relay Communication Port
```

---

## 📸 Screenshots & Visualizations

> **[Screenshot 1: KQL Query Results]**
> Insert screenshot of DeviceNetworkEvents showing connections to TOR relay nodes here
>
> **[Screenshot 2: Timeline Visualization]**
> Insert timeline diagram showing progression from file download → execution → network activity here
>
> **[Screenshot 3: Evidence Dashboard]**
> Insert Microsoft Defender dashboard or custom visualization showing correlated events here

---

## 👤 Author

**Investigation Conducted By:** Threat Hunting Lab Exercise  
**Date:** April 15, 2026  
**Lab Environment:** Controlled, Isolated Network  
**Lab ID:** `aldir-1`

---

## 📝 Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-04-15 | Initial documentation of threat hunting exercise |

---

**Status:** ✅ Investigation Complete | 📋 Evidence Preserved | 📊 Ready for Review

---

*This documentation is provided for educational and training purposes as part of a controlled threat hunting lab exercise.*
