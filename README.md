# Active Directory Reconnaissance Detection with Splunk and Sysmon

## Overview

This project demonstrates the detection, investigation, and containment of reconnaissance activity within an Active Directory environment using Sysmon, Splunk Enterprise, Kali Linux, and MikroTik firewall controls.

A simulated attacker system running Kali Linux performed reconnaissance against an Active Directory Domain Controller. Sysmon captured network connection telemetry which was forwarded to Splunk for analysis. Detection queries were developed to identify attacker activity, and MikroTik firewall controls were implemented to mitigate the threat.

This project simulates a real-world Security Operations Center (SOC) workflow by covering the complete lifecycle of:

* Reconnaissance
* Detection
* Investigation
* Containment
* Validation

---

# Lab Architecture

## Blue Team Network (10.20.20.0/24)

### Active Directory Domain Controller

* Hostname: ADDC01
* IP Address: 10.20.20.10
* Services:

  * DNS
  * LDAP
  * Kerberos
  * SMB
  * WinRM

### Splunk Server

* Ubuntu Server
* Splunk Enterprise
* Syslog Collection
* Log Analysis

---

## Red Team Network (10.30.30.0/24)

### Kali Linux Attacker

* IP Address: 10.30.30.5
* Tools:

  * Nmap
  * Linux Networking Utilities

---

## Monitoring Stack

### Sysmon

Collected endpoint telemetry including:

* Process Creation
* Network Connections
* File Activity
* Service Creation
* Registry Activity

### Splunk Enterprise

Used for:

* Log Aggregation
* Threat Hunting
* Event Correlation
* Detection Development

---

# Objectives

The goals of this project were:

1. Simulate reconnaissance activity against Active Directory.
2. Capture network connection telemetry using Sysmon.
3. Forward Sysmon logs into Splunk.
4. Develop custom SPL searches.
5. Identify attacker IP addresses and targeted services.
6. Implement firewall controls to mitigate reconnaissance activity.
7. Validate mitigation effectiveness.

---

# Attack Simulation

Reconnaissance was performed from the Kali Linux host against the Domain Controller.

### Command Executed

```bash
nmap -sC -sV 10.20.20.10
```

### Purpose

The scan was designed to identify:

* Open Ports
* Running Services
* Service Versions
* Active Directory Services

### Services Discovered

| Port | Service  |
| ---- | -------- |
| 53   | DNS      |
| 88   | Kerberos |
| 135  | RPC      |
| 389  | LDAP     |
| 445  | SMB      |
| 5985 | WinRM    |

---

# Detection Engineering

## Sysmon Event ID 3

Sysmon Event ID 3 was used to monitor network connections.

Captured fields included:

* Source IP
* Destination IP
* Source Port
* Destination Port
* Process Information

Example:

Source IP:

```text
10.30.30.5
```

Destination IP:

```text
10.20.20.10
```

Destination Port:

```text
5985
```

---

# Splunk Investigation

## Verify Sysmon Log Ingestion

```spl
index=endpoint
| stats count by sourcetype
```

Confirmed Sysmon Operational logs were successfully indexed.

---

## Verify Host Logging

```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count by host
```

Confirmed Active Directory server telemetry was being collected.

---

## Extract Source and Destination Fields

```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='SourceIp'>(?<SourceIp>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationIp'>(?<DestinationIp>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationPort'>(?<DestinationPort>[^<]+)</Data>"
```

---

## Identify Reconnaissance Traffic

```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='SourceIp'>(?<SourceIp>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationIp'>(?<DestinationIp>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationPort'>(?<DestinationPort>[^<]+)</Data>"
| search SourceIp="10.30.30.5" DestinationIp="10.20.20.10"
| table _time host SourceIp DestinationIp DestinationPort
```

---

## Destination Port Analysis

```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='SourceIp'>(?<SourceIp>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationIp'>(?<DestinationIp>[^<]+)</Data>"
| rex field=_raw "<Data Name='DestinationPort'>(?<DestinationPort>[^<]+)</Data>"
| search SourceIp="10.30.30.5" DestinationIp="10.20.20.10"
| stats count by DestinationPort
| sort -count
```

Results showed repeated activity against:

```text
5985
```

which corresponds to WinRM.

---

# Containment

Reconnaissance activity was mitigated using MikroTik firewall controls.

Firewall Rule:

```text
chain=forward
action=drop
src-address=10.30.30.5
dst-address=10.20.20.10
```

Purpose:

Prevent reconnaissance traffic originating from the Kali attacker host.

---

# Validation

After implementing firewall controls, validation testing was performed.

## ICMP Test

```bash
ping 10.20.20.10
```

Result:

```text
100% packet loss
```

---

## Nmap Validation Scan

```bash
nmap -Pn -sC -sV 10.20.20.10
```

Result:

```text
All 1000 scanned ports are filtered
```

This confirmed the firewall controls successfully reduced attacker visibility into the target system.

---

# MITRE ATT&CK Mapping

| Technique ID | Technique                 |
| ------------ | ------------------------- |
| T1046        | Network Service Discovery |
| T1018        | Remote System Discovery   |
| T1595        | Active Scanning           |

The reconnaissance activity generated by Nmap aligns closely with these ATT&CK techniques.

---

# Screenshots

## 01 – Sysmon Event ID 3 Detection

<img width="1280" height="647" alt="01 - Sysmon Event ID 3 Detection " src="https://github.com/user-attachments/assets/ea30b717-0a8c-4048-a906-72e9e6cf66aa" />


*Figure: Sysmon Event Viewer showing Event ID 3*

---

## 02 – Nmap Reconnaissance Scan

<img width="1919" height="1200" alt="02 – Nmap Reconnaissance Scan" src="https://github.com/user-attachments/assets/e79f3a16-185e-40d1-bdf1-fb81cf2122b9" />


*Figure: Kali Linux Nmap scan results*

---

## 03 – Splunk Log Ingestion Validation

<img width="1280" height="661" alt="03 - Splunk Log Ingestion Validation " src="https://github.com/user-attachments/assets/908fcdb5-bd53-4b6b-889e-4c6638d34176" />


*Figure: stats count by sourcetype*

---

## 04 – Host Telemetry Verification

<img width="1280" height="665" alt="04 - Host Telementry Verification " src="https://github.com/user-attachments/assets/452a36bd-3c83-40d6-a5cc-fc79f379bdb5" />


*Figure: stats count by host*

---

## 05 – Field Extraction

<img width="1280" height="678" alt="05 – Detection Query" src="https://github.com/user-attachments/assets/5e47369e-a9d2-40dc-a062-a6cc4c99c2a8" />


* Source IP
* Destination IP
* Destination Port

---

## 06 – Destination Port Analytics

<img width="1280" height="720" alt="06 - Detection Analytics" src="https://github.com/user-attachments/assets/60e937bf-fbe0-478a-8153-e1f8058dfaad" />


*Figure: stats count by DestinationPort*

---

## 07 – MikroTik Firewall Rule

<img width="720" height="400" alt="07 – MikroTik Firewall Rule" src="https://github.com/user-attachments/assets/46443d8a-0849-452a-8c5f-0920bb0f2c16" />


*Figure: Mikrotik router Reconnaissance blocking rule 2* 

---

## 08 – Mitigation Validation

<img width="1919" height="1200" alt="09 – Mitigation Validation" src="https://github.com/user-attachments/assets/5cf041cd-1c71-413e-8d4d-91c5f115ea39" />


*Figure: Nmap scan after mitigation*

---

## 09 - Destination Port Analysis - Mitigation Vlaidation 

<img width="1280" height="720" alt="08 -  Destination Port Analysis_ Mitigation Validation" src="https://github.com/user-attachments/assets/84d6f860-0fcd-4300-8d2e-490c5faca941" />

*Figure: splunk log after mitigation*

---

# Skills Demonstrated

* Security Operations (SOC)
* Threat Hunting
* Splunk Enterprise
* Sysmon
* Active Directory Security Monitoring
* Detection Engineering
* Log Analysis
* Incident Response
* Firewall Administration
* Network Security Monitoring
* MITRE ATT&CK Mapping
* Nmap Reconnaissance Detection

---

# Future Improvements

Planned enhancements include:

* Splunk Dashboards
* Automated Splunk Alerts
* Security Onion Integration
* Snort IDS Deployment
* Active Directory Attack Simulations
* MITRE ATT&CK Dashboarding
* Detection-as-Code Development

---

# Author

Subryan Karpen

Cybersecurity Student | SOC Analyst Aspirant | Homelab Builder

Focused on building practical blue-team skills through hands-on cybersecurity projects involving Active Directory, SIEM, threat hunting, and network defense.
