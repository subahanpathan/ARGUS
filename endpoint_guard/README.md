# Endpoint Guard: Host Detection & Response (EDR / HIDS)

**Endpoint Guard** is a defense-only, host-based intrusion detection and response system designed specifically for Windows 10/11 endpoints. It protects laptops and workstations against live remote exploits, reverse shells, unauthorized document harvesting, and peripheral surveillance (webcam/microphone eavesdropping) in real time.

All response actions run **strictly on the protected host** and are entirely passive with respect to remote systems. The tool never scans, probes, or hacks back into external networks or attacker machines.

---

## Architecture Diagram

```
+---------------------------------------------------------------------------------------+
|                               PROTECTED WINDOWS HOST                                  |
|                                                                                       |
|  [ Network Monitor ]     [ Process Monitor ]    [ File & Canary ]    [ Peripherals ]   |
|  - Sockets & psutil      - Parent/Child trees   - Watchdog events    - ConsentStore    |
|  - Reverse Shells        - LOLBin abuse         - Honeypot files     - Webcam / Mic    |
|  - Port scans            - Encoded PowerShell   - Bulk file reads    - Device Handles  |
|         |                        |                     |                    |         |
|         +------------------------+----------+----------+--------------------+         |
|                                             |                                         |
|                                  [ Central Event Bus ]                                |
|                                             |                                         |
|                                 [ Detection Rule Engine ]                             |
|                                 (NET, PROC, FILE, PERIPH)                             |
|                                             |                                         |
|                             [ Master Response Orchestrator ]                          |
|                                             |                                         |
|         +--------------------+--------------+---------------+-------------------+     |
|         |                    |                              |                   |     |
|  [ Process Killer ]   [ Windows Firewall ]         [ Quarantine Vault ]   [ UI & Reports ]
|  - taskkill /F /T     - New-NetFirewallRule        - C:\ProgramData\...   - Flask Web SOC 
|  - Zero-touch kill    - Auto-block Attacker IP     - AES / Read-only      - Tray Panic btn
|  - Process tree purge - Panic Host Isolation       - Reversible restore   - HTML Reports  |
|                                                                                       |
|                      [ Cryptographic Tamper-Evident Ledger ]                          |
|                      - SQLite Database (endpoint_guard.db)                            |
|                      - SHA-256 Hash Chaining across all events                        |
+---------------------------------------------------------------------------------------+
```

---

## Core Capabilities

### 1. Network & Attacker Detection
- Continuous socket polling correlates connections with owning process names, command lines, and PIDs.
- Detects reverse shells (`cmd.exe`, `powershell.exe`, `python.exe`, `nc.exe` connected to external IPs).
- Identifies horizontal/vertical port scans and brute force bursts targeting management ports (SMB 445, RDP 3389, WinRM 5985).
- Resolves local subnet attacker hardware MAC addresses via ARP cache and hostnames via reverse DNS/NetBIOS.

### 2. Process & Persistence Monitoring
- Flags suspicious parent-child chains (Office documents or browsers spawning command shells).
- Catches obfuscated and Base64-encoded PowerShell execution (`-enc`, `-ep bypass`, `-w hidden`).
- Intercepts Living-off-the-Land Binary (LOLBin) misuse (`certutil -urlcache`, `bitsadmin /transfer`, `mshta http://`, `regsvr32`).
- Monitors Windows persistence locations: Registry `Run`/`RunOnce` keys and Startup folders.

### 3. File Protection & Anti-Exfiltration
- Deploys decoy honeypot canary files (`passwords.xlsx`, `corporate_secrets.docx`). Any unauthorized access immediately trips high-severity containment.
- Detects rapid bulk access patterns across sensitive file extensions (`.docx`, `.xlsx`, `.pdf`, `.key`, `.env`).
- Flags archive staging (`.zip`, `.7z`, `.tar.gz` creation in temporary directories).
- Quarantines suspicious payloads into `C:\ProgramData\EndpointGuard\quarantine\` with metadata and full restore capability.

### 4. Peripheral Surveillance Interception (Camera & Microphone)
- Monitors the Windows OS `CapabilityAccessManager\ConsentStore` registry keys (`webcam` and `microphone`).
- Distinguishes approved conferencing tools (Zoom, Teams, Chrome) from unauthorized binaries (`python.exe`, `meterpreter.exe`).
- Kills unauthorized processes attempting video or audio eavesdropping and notifies the user.

### 5. Automated Response Playbooks & Panic Button
- **Low**: Forensic logging in the SQLite event ledger.
- **Medium**: High-visibility alert, system process/network snapshot, and user notification.
- **High**: Immediate process tree termination (`taskkill /F /T /PID`) + Attacker IP blocked in Windows Firewall.
- **Critical**: Zero-touch active containment: process kill + attacker IP block + payload quarantine + optional emergency network isolation.
- **Panic Button**: Available in both the Web Console and the System Tray Icon to instantly sever all inbound/outbound external communication.

### 6. Forensic Evidence & Cryptographic Hash Chaining
- Immutable audit trail: every event record contains `prev_hash` and `entry_hash` via SHA-256 chaining.
- CLI verification utility (`scripts/verify_hash_chain.py`) mathematically detects any tampering.
- Captures process snapshots, active socket dumps, and optional targeted PCAP packet captures in `C:\ProgramData\EndpointGuard\incidents\<date>_<attacker_ip>\`.
- Generates standalone, dark-themed HTML forensic incident reports with MITRE ATT&CK mappings and Indicators of Compromise (IOCs).

---

## Quick Start & Installation

### Requirements
- Windows 10 or Windows 11 (64-bit)
- Python 3.11+
- Administrator privileges

### Step 1: Automated Installation (PowerShell as Administrator)
Open PowerShell as **Administrator** and run:
```powershell
cd d:\Mini\endpoint_guard
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```
The installer:
1. Validates administrative privileges.
2. Creates secure directories under `C:\ProgramData\EndpointGuard\`.
3. Locks NTFS ACL permissions to `SYSTEM` and `Administrators`.
4. Deploys honeypot canary files.
5. Registers `EndpointGuardDefenseService` in Windows Task Scheduler to start on boot.

### Step 2: Running the Interactive Console & Tray
```powershell
python endpoint_guard\main.py
```
- **Web Console**: Open `http://127.0.0.1:8443` in any browser.
- **System Tray Icon**: Right-click the shield icon in the Windows taskbar for instant Panic isolation and shortcuts.

### Step 3: Verifying Forensic Integrity
To verify that no log entries have been modified or deleted:
```powershell
python scripts\verify_hash_chain.py
```

---

## Why Administrator Privileges Are Required
Operating an effective endpoint defense tool on Windows requires elevated privileges:
1. **Windows Firewall Rule Injection**: Creating and removing firewall rules (`New-NetFirewallRule`) to block attacking IPs or isolate the host requires administrative elevation.
2. **Process Tree Termination**: Terminating unprivileged or multi-session attacker processes requires `SeDebugPrivilege` (Administrator).
3. **Socket Inspection**: Correlating all system-wide TCP/UDP sockets with PIDs in `psutil` requires administrative access.
4. **NTFS ACL Protection**: Restricting `C:\ProgramData\EndpointGuard` exclusively to `SYSTEM` and `Administrators` prevents an attacker from altering logs or tampering with quarantined payloads.

---

## Defense-in-Depth & Honest Limitations
Endpoint Guard is an essential host-level layer, but no single defensive tool can stop all threats:
- **User-Mode Scope**: Endpoint Guard operates in Windows user-mode. It does **not** install third-party kernel drivers (`.sys`), which means kernel-level rootkits or Ring 0 exploits could conceal processes before user-mode tools observe them.
- **Recommended Security Layers**: For production protection, always pair Endpoint Guard with:
  1. **Windows Defender / Antivirus**: For real-time signature and cloud-delivered ML file scanning.
  2. **BitLocker Drive Encryption**: To protect data at rest against physical extraction.
  3. **Multi-Factor Authentication (MFA)**: To stop credential stuffing.
  4. **Regular Windows Updates**: To patch OS-level and SMB/RDP vulnerabilities.
