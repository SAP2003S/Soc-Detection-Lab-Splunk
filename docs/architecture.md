# 🏗️ Lab Architecture & Network Topology

This document details the virtualized lab infrastructure, IP assignments, network segmentation, and telemetry pipeline configured for this threat emulation and detection exercise.

---

## 🗺️ High-Level Topology

```text
┌──────────────────────────────────────┐            ┌──────────────────────────────────────┐
│        ATTACKER (Kali Linux)         │            │      TARGET (Windows 10 Workstation) │
│        IP: 192.168.20.**             │            │      IP: 192.168.20.**              │
├──────────────────────────────────────┤            ├──────────────────────────────────────┤
│  • msfvenom Payload Generator        │ <========> │  • Host: DESKTOP-******             │
│  • Python HTTP Server (:8080)        │  TCP :4444 │  • User: DESKTOP-******\soc-lab     │
│  • Metasploit Handler (:4444)        │            │  • Microsoft Sysmon v15+ (Sensor)    │
└──────────────────────────────────────┘            │  • Splunk Universal Forwarder (UF)   │
                                                    └──────────────────┬───────────────────┘
                                                                       │
                                                               TCP :9997 (Encrypted Stream)
                                                                       ▼
                                                    ┌──────────────────────────────────────┐
                                                    │         SIEM / INDEXER HOST          │
                                                    │         Splunk Enterprise            │
                                                    ├──────────────────────────────────────┤
                                                    │  • Windows Host Ingestion (:9997)    │
                                                    │  • Web Search Head (Port :8000)      │
                                                    │  • Custom SPL Field Extraction       │
                                                    └──────────────────────────────────────┘
