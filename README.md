# Windows Persistence & LOLBIN Techniques: Simulation, Detection & Documentation

A hands-on SOC (Security Operations Center) home lab project: a self-built SIEM environment used to simulate six real-world adversary techniques mapped to MITRE ATT&CK, analyze detection gaps, and implement fixes — all documented from an analyst's perspective.

## Overview

This project was built to bridge the gap between theoretical cybersecurity knowledge and practical, hands-on experience. Rather than following a pre-built lab (e.g., a training platform), the entire environment — SIEM server, endpoint, and monitoring stack — was built independently from scratch, then used to simulate attacker behavior and evaluate real detection coverage.

**Goal:** Deploy a working SIEM, generate real attacker-style activity on a monitored endpoint, and document — with evidence — what was detected, what wasn't, why, and how gaps were closed.

## Lab Architecture

| Component | Role | Details |
|---|---|---|
| **Wazuh Server** | Central SIEM (Manager + Indexer + Dashboard) | Ubuntu Server 26.04 LTS VM, deployed via VMware Workstation |
| **Windows 10 Endpoint** | Monitored client | Windows 10 Pro VM, connected via Wazuh Agent |
| **Sysmon** | Enhanced endpoint telemetry | Installed with the SwiftOnSecurity configuration profile |

**Network:** Both VMs run on the same virtual network (NAT), communicating over the Wazuh Agent protocol (port 1514) and HTTPS dashboard access (port 443).

## Setup Summary

1. Provisioned an Ubuntu Server VM and installed Wazuh (Manager, Indexer, Dashboard) via the official install script
2. Provisioned a Windows 10 VM as the monitored endpoint
3. Installed Sysmon on the endpoint using the SwiftOnSecurity config (community-maintained, security-focused ruleset)
4. Deployed the Wazuh Agent (MSI) on the endpoint and connected it to the Wazuh Manager
5. Verified agent connectivity (Active status) via the Wazuh dashboard
6. Extended the default agent configuration (`ossec.conf`) to forward Sysmon event logs to Wazuh
7. Simulated six MITRE ATT&CK-mapped techniques and analyzed detection results

## Techniques Simulated

Each technique below was executed manually on the endpoint, then verified against the Wazuh dashboard to determine whether — and how — it was detected.

---

### 1. Registry Persistence (Run Key)

**MITRE ATT&CK:** T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys

**Description:** Adversaries commonly add entries to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` so a payload executes automatically on every user logon — a simple, effective persistence mechanism.

**Command executed:**
```powershell
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "TestPersistence" -Value "C:\Windows\System32\notepad.exe" -PropertyType String
```

**Detection Result:** ⚠️ Not detected by default correlation rules.

**Analysis:** Sysmon locally logged the registry modification (Event ID 13 – RegistryEvent), confirming the endpoint-level sensor worked correctly. However, the event did not surface in Wazuh's Threat Hunting view under a dedicated rule. Wazuh's File Integrity Monitoring (FIM/Syscheck) module — which does actively monitor certain registry paths (e.g., `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services`) — does not include `HKCU\...\Run` in its default watch list, and no correlation rule was pre-built to surface raw Sysmon Event ID 13 data prominently.

**Conclusion:** This is a genuine default-configuration visibility gap, not a tool failure. It demonstrates that even with Sysmon actively capturing the right telemetry, a SIEM still needs deliberately configured FIM paths and correlation rules to surface high-value persistence locations like the Run key.

---

### 2. Scheduled Task Abuse (ONSTART Trigger)

**MITRE ATT&CK:** T1053.005 – Scheduled Task/Job: Scheduled Task

**Description:** Creating a scheduled task that runs at system startup under the SYSTEM account is a common persistence and privilege-retention technique. The task name was deliberately chosen to mimic a legitimate system process (masquerading).

**Command executed:**
```powershell
schtasks /create /tn "SystemUpdateCheck" /tr "C:\Windows\System32\notepad.exe" /sc ONSTART /ru SYSTEM /f
```

**Detection Result:** ❌ Not detected initially → ✅ Detected after remediation.

**Root Cause Analysis:** Windows only writes Scheduled Task creation events (Event ID 4698) to the Security event log when the relevant Advanced Audit Policy subcategory is enabled. This subcategory ("Other Object Access Events") is **disabled by default** on standalone Windows systems, meaning the event was never logged locally in the first place — independent of any SIEM configuration.

**Remediation applied:**
```powershell
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

**Verification:** A second scheduled task (`SystemUpdateCheck2`) was created after enabling the audit policy. It was detected successfully:
- Rule 60228 – "A scheduled task was created" (Level 4)
- Rule 60112 – "Windows Audit Policy changed" (Level 8) — Wazuh also flagged the audit policy change itself as a notable security event

**Conclusion:** This is the strongest example in the project of full-cycle SOC analyst work: simulate → detect gap → root-cause the failure → apply a fix → verify the fix closed the gap.

---

### 3. Fake/Suspicious Service Creation

**MITRE ATT&CK:** T1543.003 – Create or Modify System Process: Windows Service

**Description:** Adversaries frequently create Windows services with names that impersonate legitimate system services, while pointing the actual binary path to malicious code. This masquerading technique blends malicious persistence into what looks like normal system administration activity.

**Command executed:**
```powershell
sc.exe create WindowsUpdateHelper binPath= "C:\Windows\System32\notepad.exe" start= demand
```

**Detection Result:** ✅ Detected immediately, no configuration changes required.

**Analysis:** Unlike Scheduled Tasks, Windows Service creation events are logged to the System event log by default (independent of Advanced Audit Policy settings), which Wazuh reads out of the box. Detected rules:
- Rule 61138 – "New Windows Service Created" (Level 5)
- Rule 92307 – "Evidence of new service creation found" (Level 3)

**Conclusion:** This technique highlighted a useful contrast: default Windows event logging visibility varies significantly by event category. Services are visible by default; Scheduled Tasks are not.

---

### 4. Alternate Data Streams (ADS) — Defense Evasion

**MITRE ATT&CK:** T1564.004 – Hide Artifacts: NTFS File Attributes

**Description:** NTFS allows a file to contain hidden secondary data streams that are invisible through normal file browsing or standard `dir`/Explorer views. Attackers use this to hide payloads inside seemingly benign files.

**Commands executed:**
```powershell
echo "This is a normal file" > C:\Users\Public\report.txt
cmd /c "echo Hidden malicious payload data > C:\Users\Public\report.txt:hidden"
```

**Detection Result:** ❌ Not detected. (Confirmed with dedicated verification: `Get-Item -Path report.txt -Stream *` showed both the `:$DATA` and `:hidden` streams existed locally, but no related event appeared in Wazuh across an extended time window.)

**Analysis:** Neither the default FIM configuration nor Sysmon (as configured) monitor NTFS alternate data streams. This is a known, expected blind spot for most SIEM deployments — ADS abuse is specifically effective *because* it evades stream-unaware monitoring tools.

**Compensating control developed:** Since no automatic detection exists out of the box, a manual/scheduled PowerShell audit script was built to close this gap:
```powershell
Get-ChildItem -Path C:\Users\Public -Recurse | Get-Item -Stream * | Where-Object {$_.Stream -ne ':$DATA'}
```
This script successfully identified the hidden `report.txt:hidden` stream and can be scheduled as a recurring task to provide periodic coverage where real-time SIEM visibility is unavailable.

**Conclusion:** Demonstrates understanding that SIEM tools have inherent blind spots, and that a competent analyst compensates with custom tooling rather than assuming full coverage.

---

### 5. CertUtil Abuse (LOLBIN Simulation)

**MITRE ATT&CK:** T1140 – Deobfuscate/Decode Files or Information

**Description:** `certutil.exe` is a legitimate, Microsoft-signed Windows binary intended for certificate management. Attackers abuse its `-encode`/`-decode` functionality to obfuscate and reconstruct malicious payloads while evading tools that only flag unsigned or unfamiliar binaries — a technique known as a LOLBIN (Living Off The Land Binary).

**Commands executed:**
```powershell
"This is a harmless test payload" | Out-File C:\Users\Public\payload.txt
certutil -encode C:\Users\Public\payload.txt C:\Users\Public\payload_encoded.txt
certutil -decode C:\Users\Public\payload_encoded.txt C:\Users\Public\payload_decoded.txt
```

**Detection Result:** ✅ Detected immediately, with full context.

**Detection details:**
- Rule 92073 – "Powershell executing certutil to decode a file" (Level 6)
- **MITRE mapping (automatic):** T1140, Tactic: Defense Evasion, Technique: Deobfuscate/Decode Files or Information
- Full process lineage captured: `powershell.exe` (parent) → `certutil.exe` (child), including the exact command line, parent user (`WIN10-CLIENT01\Joud`), and process integrity level (High)

**Conclusion:** This was the strongest detection result in the project — Wazuh's Sysmon-based ruleset not only flagged the activity but automatically enriched it with MITRE ATT&CK context and complete process ancestry, exactly the kind of evidence a SOC analyst needs to triage an alert quickly.

---

### 6. Volume Shadow Copy (VSS) Inspection

**MITRE ATT&CK:** T1003.002 – OS Credential Dumping: Security Account Manager (related technique, enabled by VSS abuse)

**Description:** Windows' Volume Shadow Copy Service creates point-in-time snapshots of the file system, originally intended for backup and recovery. Attackers can abuse existing shadow copies to access normally-locked, credential-sensitive files (e.g., the SAM database) without triggering the file locks that protect them during normal operation. This step was investigative only — no credential extraction was attempted.

**Commands executed:**
```powershell
vssadmin list shadows
vssadmin list volumes
```

**Result:** No shadow copies existed on the system at the time of testing.

**Analysis (defensive perspective):** The absence of shadow copies means this endpoint currently has **no backup/recovery point** — in the event of a ransomware attack, there would be no local shadow copy to restore from. This is a meaningful defensive finding, separate from the offensive angle.

**Analysis (offensive perspective):** Without existing shadow copies, this specific VSS-based credential access technique is not currently viable against this host — an attacker would need to wait for or force snapshot creation first.

**Conclusion:** Even without an executable exploit path, contextual reconnaissance-style checks like this one provide real value in an assessment or investigation, informing both attack feasibility and defensive recommendations (e.g., enabling System Protection).

---

## Key Findings & Skills Demonstrated

- **Independent environment build:** Deployed a full SIEM stack (Wazuh Manager, Indexer, Dashboard) and endpoint monitoring (Sysmon) from scratch — no pre-configured lab template
- **Attack simulation across the MITRE ATT&CK matrix:** Covered Persistence (T1547.001, T1053.005, T1543.003), Defense Evasion (T1564.004, T1140), and Credential Access reconnaissance (T1003.002-adjacent)
- **Root-cause analysis of detection gaps:** Diagnosed *why* techniques went undetected (missing FIM paths, disabled audit policies, inherent monitoring blind spots) rather than treating "no alert" as a dead end
- **Remediation and verification cycle:** For the Scheduled Task gap, implemented a fix (`auditpol`) and confirmed it closed the gap with a second test
- **Compensating controls:** Built a custom PowerShell script to detect Alternate Data Streams where no SIEM-native detection existed
- **Evidence-based documentation:** Every finding is backed by dashboard screenshots and raw event data (rule IDs, MITRE mappings, process lineage)

## Tools Used

| Tool | Purpose |
|---|---|
| Wazuh 4.9.2 | SIEM (Manager, Indexer, Dashboard) |
| Sysmon (SwiftOnSecurity config) | Endpoint telemetry |
| VMware Workstation | Virtualization platform |
| Ubuntu Server 26.04 LTS | SIEM host OS |
| Windows 10 Pro | Monitored endpoint OS |
| PowerShell / CMD | Technique simulation and custom detection scripting |

## Possible Future Improvements

- Add a dedicated Wazuh custom rule for Registry Run Key changes (Event ID 13) to close the Technique #1 gap natively
- Schedule the ADS-detection PowerShell script as a recurring Wazuh-integrated task (e.g., via a custom Wazuh command wodle)
- Extend Sysmon configuration to explicitly capture more registry paths of interest
- Build a full Incident Response Playbook tying multiple techniques together into a single simulated intrusion scenario

---
