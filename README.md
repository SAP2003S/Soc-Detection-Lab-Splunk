# ⚡ Red-to-Blue: End-to-End SOC Detection Engineering Lab

### *Adversary C2 Emulation • Windows Sysmon Telemetry • Splunk SPL Hunting Pipeline*

<div align="center">

[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-orange.svg?style=for-the-badge&logo=target)](https://attack.mitre.org/)
[![SIEM](https://img.shields.io/badge/SIEM-Splunk%20Enterprise-black.svg?style=for-the-badge&logo=splunk)](https://www.splunk.com/)
[![Sensor](https://img.shields.io/badge/Sensor-Microsoft%20Sysmon-blue.svg?style=for-the-badge&logo=windows)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
[![C2](https://img.shields.io/badge/C2%20Framework-Metasploit-red.svg?style=for-the-badge&logo=metasploit)](https://www.metasploit.com/)

<p align="center">
  <b>A strictly verified detection engineering project mapping a staged Meterpreter C2 reverse shell to endpoint telemetry, SPL correlation logic, and Root Cause Analysis (RCA).</b>
</p>

[Lab Architecture](./docs/architecture.md) • [MITRE Mapping](./docs/mitre_attack_mapping.md) • [Threat vs. Telemetry](./docs/threat_vs_telemetry.md) • [Incident RCA Report](./reports/incident_rca_report.md) • [Splunk Queries](./splunk-queries/)

</div>

---

## 📑 Table of Contents
- [🎯 Executive Summary](#executive-summary)
- [🏗️ Lab Topology & Ingestion Pipeline](#lab-topology-ingestion-pipeline)
- [🗺️ MITRE ATT&CK Alignment](#mitre-attack-alignment)
- [⚔️ Interactive Attack Lifecycle & Telemetry Evidence](#attack-lifecycle-telemetry-evidence)
  - [1. Network Reachability & Interface Configuration](#phase-1-network)
  - [2. Reverse TCP Binary Compilation](#phase-2-payload)
  - [3. Multi/Handler Listener Initialization](#phase-3-listener)
  - [4. Delivery Web Server Access Telemetry](#phase-4-delivery)
  - [5. Target Execution from User Space](#phase-5-execution)
  - [6. Established Meterpreter Session & Reconnaissance](#phase-6-session)
  - [7. Process Creation & Lineage Hunting (Event ID 1)](#phase-7-process)
  - [8. Outbound Non-Standard C2 Socket Hunting (Event ID 3)](#phase-8-network)
  - [9. XML Key-Value Stream Parsing (Event ID 15)](#phase-9-xmlkv)
  - [10. Custom Regex Ingress & MOTW Extraction (Event ID 15)](#phase-10-rex)
- [🔍 Production Splunk SPL Queries](#production-splunk-spl-queries)
  - [Rule 1: Browser Ingress & Zone Identifier Hunting (Event ID 15)](#query-rule-1)
  - [Rule 2: Malicious Process Lineage Extraction (Event ID 1)](#query-rule-2)
  - [Rule 3: Non-Standard Outbound C2 Socket Hunting (Event ID 3)](#query-rule-3)
- [📑 Incident Root Cause Analysis (RCA)](#incident-rca)
- [📁 Repository Directory Tree](#repository-directory-tree)

---

<div id="executive-summary"></div>

## 🎯 Executive Summary

This project showcases a verified detection engineering workflow designed to capture, parse, and alert on an adversary establishing an interactive reverse TCP shell.

```text
  [ Adversary Emulation ] ──> [ Sysmon v15+ Ingestion ] ──> [ Splunk Universal Forwarder ] ──> [ SPL Rule Engineering ]
    • Staged x64 Payload        • Process Creation (ID 1)     • Real-Time TCP :9997 Stream      • Regex Field Parsing
    • Python HTTP Staging       • Network Sockets (ID 3)      • Host-Only Virtual Segment       • Non-Standard Port Hunting
    • Meterpreter C2 :4444      • File Ingress Stream (ID 15)                                   • Incident RCA Matrix
