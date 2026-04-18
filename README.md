# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/21Aldir/tor-threat-hunting-lab/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

## Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "aldir" downloaded a TOR installer, extracted many TOR-related files to the desktop, and created a file called `tor-shopping-list.txt` on the desktop at `2026-04-15T19:51:17Z`. These events began at `2026-04-15T19:06:28Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "aldir-1"  
| where Account == "aldir"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2026-04-15T19:06:28Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account
```
<img width="1212" alt="image" src="">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.9.exe". Based on the logs returned, at `2026-04-15T19:09:19Z`, the user "aldir" on the "aldir-1" device ran the file `tor-browser-windows-x86_64-portable-15.0.9.exe` from their Desktop Tor Browser folder, using a command that triggered the portable installation.

**Query used to locate event:**

```kql
DeviceProcessEvents  
| where DeviceName == "aldir-1"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.9.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "aldir" actually opened the TOR browser. There was evidence that they did open it at `2026-04-15T19:25:00Z` or later. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "aldir-1"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1212" alt="image" src="">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-04-15T19:25:00Z` or later, the user "aldir" on the "aldir-1" device successfully established connections to remote IP addresses including `82.67.111.215` and `51.91.241.137` on port `9001`. The connections were initiated by the process `tor.exe`, located in the folder `C:\Users\Aldir\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`. There were also other connections over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "aldir-1"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1212" alt="image" src="">

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-04-15T19:06:28Z`
- **Event:** The user "aldir" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.9.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\Aldir\Downloads\tor-browser-windows-x86_64-portable-15.0.9.exe`

### 2. File Extraction - TOR Browser Setup

- **Timestamp:** `2026-04-15T19:09:19Z` - `2026-04-15T19:09:30Z`
- **Event:** The user "aldir" extracted the portable TOR Browser to their Desktop. Multiple files including `firefox.exe`, `tor.exe`, and license documentation were created.
- **Action:** Multiple file creation events detected.
- **File Path:** `C:\Users\Aldir\Desktop\Tor Browser\Browser\`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-04-15T19:25:00Z` or later
- **Event:** User "aldir" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\Aldir\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Relay Node #1

- **Timestamp:** `2026-04-15T19:25:00Z` or later
- **Event:** A network connection to IP `82.67.111.215` on port `9001` by user "aldir" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection acknowledged (successful).
- **Process:** `tor.exe`
- **File Path:** `C:\Users\Aldir\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 5. Network Connection - TOR Relay Node #2

- **Timestamp:** `2026-04-15T19:25:00Z` or later
- **Event:** A network connection to IP `51.91.241.137` on port `9001` by user "aldir" was established using `tor.exe`.
- **Action:** Connection acknowledged (successful).
- **Process:** `tor.exe`
- **File Path:** `C:\Users\Aldir\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 6. Additional Network Connections - TOR Browser Activity

- **Timestamps:** `2026-04-15T19:25:00Z` - `2026-04-15T19:51:17Z`
- **Event:** Additional network connections were established to various IPs on port `443` and other ports, indicating ongoing activity by user "aldir" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 7. File Creation - TOR Shopping List

- **Timestamp:** `2026-04-15T19:51:17Z`
- **Event:** The user "aldir" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\Aldir\Desktop\tor-shopping-list.txt`
- **SHA256:** `cbf296b83e566387289eecc30fa3ee3b1636c95da204124e849e6d358390a398`

---

## Summary

The user "aldir" on the "aldir-1" device downloaded, extracted, and executed the portable TOR browser. They proceeded to launch the browser, establish multiple connections within the TOR network via relay nodes on port 9001, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `aldir-1` by the user `aldir`. The device was isolated, and management was notified of the unauthorized activity.

---
