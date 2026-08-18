# 🗺️ MITRE ATT&CK Mapping & Verification Matrix

This document maps the adversary behaviors observed in this lab to the **MITRE ATT&CK Enterprise Matrix**, grounded strictly in captured Sysmon telemetry.

---

## 📊 Summary Mapping Matrix

| ATT&CK Tactic | Technique ID | Technique Name | Sub-Technique | Observed Emulation Activity | Verified Telemetry Hook |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Initial Access** | `T1189` | Drive-by Compromise | — | Staged executable downloaded from internal Python HTTP server (`:8080`) via Microsoft Edge | Sysmon Event ID 15 (`FileCreateStreamHash`) |
| **Execution** | `T1204` | User Execution | `T1204.002` (Malicious File) | Interactive user detonation of `payload.exe` from `C:\Users\soc-lab\Downloads\` | Sysmon Event ID 1 (`ProcessCreate`) |
| **Discovery** | `T1033` | System Owner/User Discovery | — | Execution of discovery commands (`getuid`, `whoami`) and spawned `cmd.exe` | Sysmon Event ID 1 (`ProcessCreate`) |
| **Discovery** | `T1082` | System Information Discovery | — | Meterpreter `sysinfo` command enumerating OS build and architecture | Meterpreter Session Logs |
| **Command & Control** | `T1095` | Non-Application Layer Protocol | — | Direct raw reverse TCP socket established from endpoint to Kali listener on port `4444` | Sysmon Event ID 3 (`NetworkConnect`) |

---

## 🔍 Verified Technical Breakdown

### 1. Initial Access: Drive-by Compromise (`T1189`)
* **Observed Red Team Behavior:** Target host requested `GET /payload.exe` from `192.168.20.**:8080`.
* **Captured Endpoint Telemetry:** Sysmon Event ID 15 captured `msedge.exe` saving `C:\Users\soc-lab\Downloads\payload.exe:Zone.Identifier` with HostUrl `[http://192.168.20.**:8080/payload.exe](http://192.168.20.**:8080/payload.exe)`.
* **Splunk Query:**
  ```splunk
  index=main sourcetype="*Sysmon*" "<EventID>15</EventID>"
  | rex field=_raw "Image'>(?<ProcessImage>[^<]+)"
  | rex field=_raw "TargetFilename'>(?<TargetFile>[^<]+)"
  | rex field=_raw "HostUrl'>(?<DownloadSource>[^<]+)"
  | rex field=_raw "User'>(?<ExecutingUser>[^<]+)"
  | table _time, ExecutingUser, ProcessImage, TargetFile, DownloadSource
  | sort - _time
