# Case Study 003 — Network Anomaly: C2 Beaconing Detection

**Platform:** LetsDefend  
**Date:** December 2024  
**Severity:** High  
**Verdict:** True Positive  
**Analyst:** Jay Solanki  

---

## Summary
A SIEM alert flagged unusual outbound traffic from an internal host repeatedly 
connecting to a single external IP at regular intervals. PCAP analysis confirmed 
classic C2 beaconing behaviour. Destination IP flagged malicious on VirusTotal 
and associated with known C2 infrastructure.

---

## Alert Details
| Field | Value |
|-------|-------|
| Alert Source | SIEM — Network Traffic Monitoring |
| Severity | High |
| Category | Network Anomaly / C2 Communication |
| Verdict | True Positive |

---

## Investigation Steps

### 1. Initial Triage
| Field | Value |
|-------|-------|
| Source IP | 192.168.1.105 (WORKSTATION-07) |
| Destination IP | 91.195.240.117 |
| Destination Port | 4444 / TCP |
| Protocol | TCP |
| Alert Trigger | Repeated outbound connections to single external IP |

### 2. Traffic Volume & Frequency Analysis
| Field | Finding |
|-------|---------|
| Total Connections | 147 over 24 hours |
| Average Interval | Every 9 minutes 47 seconds |
| Interval Variance | Less than 3 seconds — automated, not human |
| Data Per Beacon | 256–512 bytes average |
| Total Data Sent | 38.2 MB outbound |
| Business Hours | Beaconing continued through night |

### 3. IP Reputation — VirusTotal
- Flagged malicious by 19/94 VirusTotal vendors
- Hosted on Serverius — known bulletproof hosting provider
- Associated with Cobalt Strike, AsyncRAT, njRAT
- Open ports: 4444, 8080, 443

### 4. Port Analysis
- Port 4444 has no legitimate standard service
- Commonly used by Metasploit reverse shells and Meterpreter
- Outbound port 4444 should have been blocked — firewall policy gap identified

### 5. PCAP Analysis
- TCP SYN packets at exact 9m 47s intervals — automated beaconing timer confirmed
- Payload encrypted — C2 instructions hidden from inspection
- Consistent packet size: 287 bytes average — heartbeat traffic
- C2 server actively responding — three-way handshake completing successfully
- Larger response packets (2–4KB) from C2 — task/instruction delivery

### 6. C2 Beaconing Confirmation
- Regular interval connections — every 9m 47s, less than 3s variance
- Single external destination — all 147 connections to same IP
- Non-standard port — port 4444, associated with reverse shells
- Malicious IP — 19/94 VirusTotal vendors
- Small consistent packet sizes — 287 bytes heartbeat
- 24/7 activity — no business hours pattern
- Encrypted payload — obfuscating C2 instructions

---

## IOCs
| IOC Type | Value |
|----------|-------|
| C2 IP | 91.195.240.117 |
| C2 Port | 4444 / TCP |
| Infected Host | 192.168.1.105 (WORKSTATION-07) |
| Beacon Interval | 587 seconds |
| Avg Packet Size | 287 bytes |
| ASN | Serverius — AS49981 |
| Associated Malware | Cobalt Strike / AsyncRAT (suspected) |

---

## MITRE ATT&CK Mapping
| Technique | Description |
|-----------|-------------|
| T1071.001 | Application Layer Protocol — C2 over web protocols |
| T1095 | Non-Application Layer Protocol — Raw TCP port 4444 |
| T1571 | Non-Standard Port — evading standard monitoring |
| T1573 | Encrypted Channel — hiding C2 instructions |
| T1041 | Exfiltration Over C2 Channel |
| T1059 | Command and Scripting Interpreter — shell command delivery |

---

## Verdict & Actions
- WORKSTATION-07 immediately isolated from network
- C2 IP blocked at firewall for all internal hosts
- Port 4444 outbound blocked — firewall policy gap closed
- Incident escalated to Tier 2 for endpoint forensics
- All other hosts checked for same C2 IP connections
- IOCs added to SIEM detection rules

---

## Lessons Learned
- Flag any host making 10+ connections to same external IP within 1 hour
- Port 4444 outbound should be blocked at perimeter firewall
- Low time variance in connection intervals = automated beaconing
- Bulletproof hosting ASNs should be on threat intel watchlist
- Encrypted traffic on non-standard ports = elevated alert priority
