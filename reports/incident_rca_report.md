# 📑 Incident Root Cause Analysis (RCA) Report

## Incident Summary
* **Incident ID:** `INC-20260817-01`
* **Severity:** High
* **Status:** Resolved / Remediated
* **Affected Endpoint:** `DESKTOP-******`
* **Compromised User:** `DESKTOP-******\soc-lab`
* **Attacker IP:** `192.168.20.**`
* **Victim IP:** `192.168.20.**`

---

## Executive Summary
A security incident occurred on host `DESKTOP-*****` involving unauthorized standalone binary execution and an outbound reverse TCP C2 connection. An executable named `payload.exe` was downloaded from `http://192.168.20.11:8080` via Microsoft Edge into the user's `Downloads` folder. The binary was executed interactively, establishing a reverse TCP socket to `192.168.20.11:4444`. The attacker subsequently spawned `cmd.exe` to run discovery commands before the process terminated.

---

## Chronological Forensic Timeline (Sysmon Evidence)

| Timestamp | Source | Event ID | Activity Observed | Evidence Reference |
| :--- | :--- | :--- | :--- | :--- |
| `13:20:38` | Sysmon | ID 15 | `msedge.exe` wrote `payload.exe:Zone.Identifier` from `http://192.168.20.**:8080` | `10_splunk_sysmon_eventid_15_regex_zone_identifier.jpg` |
| `13:23:38` | Sysmon | ID 1 | `payload.exe` spawned under user `DESKTOP-*****\soc-lab` | `07_splunk_sysmon_eventid_1_process_creation.jpg` |
| `13:23:40` | Sysmon | ID 3 | `payload.exe` connected to `192.168.20.**:4444` | `08_splunk_sysmon_eventid_3_network_connection.jpg` |
| `13:31:47` | Sysmon | ID 1 | `payload.exe` spawned child process `cmd.exe` | `07_splunk_sysmon_eventid_1_process_creation.jpg` |
| `13:38:59` | Sysmon | ID 1 | `payload.exe` triggered `WerFault.exe` upon exit | `07_splunk_sysmon_eventid_1_process_creation.jpg` |

---

## Root Cause Analysis
1. **Unrestricted Network Egress:** Host firewall configurations allowed uninspected outbound TCP connections over high-risk non-standard port `4444`.
2. **Execution from User-Writable Paths:** The endpoint allowed unprivileged execution of unsigned `.exe` files directly from `C:\Users\soc-lab\Downloads\`.
3. **Lack of Ingress Boundary Filtering:** The endpoint was permitted to make unauthenticated direct-IP HTTP connections to download standalone binaries.

---

## Corrective & Preventative Engineering Mitigations
* **Application Control (AppLocker / WDAC):** Enforce execution restrictions blocking unsigned `.exe` binaries inside `%USERPROFILE%\Downloads\` and `%TEMP%`.
* **Stateful Egress Firewall Rules:** Restrict outbound workstation traffic strictly to standard web proxy ports (`80/443`); block outbound raw TCP traffic on unassigned high ports.
* **SIEM Correlation Alerts:** Configure real-time Splunk alerts triggering when Sysmon Event ID 15 (download stream) is followed by Sysmon Event ID 3 (non-standard port egress) within 60 seconds.
