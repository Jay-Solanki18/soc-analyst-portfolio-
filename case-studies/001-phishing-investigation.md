# Case Study 001 — Phishing Email Investigation

**Platform:** LetsDefend  
**Date:** December 2024  
**Severity:** High  
**Verdict:** True Positive  
**Analyst:** Jay Solanki  

---

## Summary
A SIEM alert was triggered by an inbound email flagged by the email security 
gateway. Investigation confirmed a targeted phishing attempt designed to steal 
user credentials using a spoofed domain, malicious URL, and macro-enabled attachment.

---

## Alert Details
| Field | Value |
|-------|-------|
| Alert Source | SIEM — Email Security Gateway |
| Severity | High |
| Category | Phishing / Social Engineering |

---

## Investigation Steps

### 1. Email Header Analysis
- Display name spoofed as Microsoft Support
- Actual sender: support@micros0ft-helpdesk.com (lookalike domain)
- SPF, DKIM, DMARC — all FAILED
- Reply-To pointed to attacker-controlled ProtonMail

### 2. Sender IP — VirusTotal
- IP flagged malicious by 14/94 vendors
- Origin: Russia — mismatch with claimed US origin
- ASN: Tor exit node (anonymisation infrastructure)
- AbuseIPDB confidence: 97% malicious

### 3. URL Analysis
- URL used character substitution: micros0ft (0 instead of o)
- Flagged malicious on VirusTotal and URLScan.io
- Destination: fake Microsoft login credential capture page
- Domain age: 3 days old, no SSL certificate

### 4. Attachment Analysis
- Filename: Account_Verification_Form.docx
- Contains auto-executing VBA macro
- Macro downloads secondary payload from C2 server
- VirusTotal: flagged by 22/70 vendors

---

## IOCs
| Type | Value |
|------|-------|
| Malicious IP | 185.220.101.47 |
| Phishing Domain | micros0ft-helpdesk[.]com |
| Phishing URL | hxxp://micros0ft-account-verify[.]ru/login |
| C2 URL | hxxp://185.220.101.47/payload.exe |
| Attachment Hash | a1b2c3d4e5f6789012345678abcdef01 |

---

## MITRE ATT&CK Mapping
| Technique | Description |
|-----------|-------------|
| T1566.001 | Phishing — Spearphishing Attachment |
| T1566.002 | Phishing — Spearphishing Link |
| T1036 | Masquerading — Lookalike domain |
| T1204.002 | User Execution — Malicious macro |
| T1105 | Ingress Tool Transfer — C2 payload |
| T1056.003 | Input Capture — Fake login page |

---

## Verdict & Actions
- Email quarantined from all mailboxes
- Sender domain blocked at email gateway
- IP blocked at firewall
- URL added to web proxy blocklist
- Attachment hash added to endpoint blocklist
- User notified, incident escalated to Tier 2

---

## Lessons Learned
- Homoglyph detection rules needed for lookalike domains
- SPF/DKIM/DMARC failures should auto-escalate alert priority
- Newly registered domains under 30 days warrant auto-quarantine
