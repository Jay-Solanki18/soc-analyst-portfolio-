# Case Study 002 — Brute Force Attack Detection (Home SIEM Lab)

**Platform:** Wazuh SIEM (Personal Home Lab)  
**Date:** March 2026  
**Severity:** Medium  
**Verdict:** True Positive  
**Analyst:** Jay Solanki  

---

## Lab Environment
| Component | Details |
|-----------|---------|
| SIEM | Wazuh v4.7.5 |
| Server OS | Ubuntu 24.04 LTS (VirtualBox VM) |
| Server IP | 192.168.1.9 |
| Endpoint | Windows 11 Home (Onxyveil) |
| Agent IP | 192.168.1.6 |

---

## Summary
A simulated brute force attack was executed against a monitored Windows 11 
endpoint. Wazuh SIEM detected and alerted on repeated authentication failures 
within seconds, mapping activity to MITRE ATT&CK techniques T1078 and T1531.

---

## Attack Simulation
```powershell
