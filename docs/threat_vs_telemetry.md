# ⚔️ Threat Emulation vs. Detection Telemetry

This document matches the actions executed on Kali Linux against the verified Sysmon telemetry captured in Splunk.

---

## 📊 Correlation Matrix

| Attack Phase | Adversary Action (Red Team) | Sysmon Event ID & Sensor Hook | Key Captured Artifacts | Evidence File |
| :--- | :--- | :--- | :--- | :--- |
| **1. Payload Delivery** | Staged payload hosted on Python HTTP (`:8080`) and downloaded via Edge | **Event ID 15**<br>*(FileCreateStreamHash)* | `HostUrl: http://192.168.20.**:8080/payload.exe`<br>`TargetFilename: payload.exe:Zone.Identifier`<br>`Image: msedge.exe` | [Delivery Proof](../screenshots/04_payload_download_victim_machine.jpg) |
| **2. Process Execution** | User executed `payload.exe` from Downloads folder | **Event ID 1**<br>*(Process Creation)* | `Image: C:\Users\soc-lab\Downloads\payload.exe`<br>`User: DESKTOP-*****\soc-lab` | [Execution Proof](../screenshots/07_splunk_sysmon_eventid_1_process_creation.jpg) |
| **3. C2 Network Socket** | Outbound reverse TCP shell connected to Kali listener (`:4444`) | **Event ID 3**<br>*(Network Connection)* | `SourceIp: 192.168.20.10`<br>`DestinationIp: 192.168.20.11`<br>`DestinationPort: 4444` | [Network C2 Proof](../screenshots/08_splunk_sysmon_eventid_3_network_connection.jpg) |
| **4. Discovery & Recon** | Spawning interactive shell and running discovery commands | **Event ID 1**<br>*(Process Creation)* | `ParentImage: ...\payload.exe`<br>`Image: C:\Windows\System32\cmd.exe` | [Session Proof](../screenshots/06_meterpreter_session_established.jpg) |

---

## 🔍 Detailed Verification

### 1. Ingress & Mark-of-the-Web (Event ID 15)
* **Adversary Activity:** Binary delivered over HTTP port 8080.
* **Sysmon Telemetry:** Captured NTFS `:Zone.Identifier` stream generation.
* **Splunk Query:**
  ```splunk
  index=main sourcetype="*Sysmon*" "<EventID>15</EventID>"
  | rex field=_raw "Image'>(?<ProcessImage>[^<]+)"
  | rex field=_raw "TargetFilename'>(?<TargetFile>[^<]+)"
  | rex field=_raw "HostUrl'>(?<DownloadSource>[^<]+)"
  | rex field=_raw "User'>(?<ExecutingUser>[^<]+)"
  | table _time, ExecutingUser, ProcessImage, TargetFile, DownloadSource
  | sort - _time
