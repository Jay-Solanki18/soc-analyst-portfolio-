# Splunk SPL Queries — Network Anomaly Detection

**Author:** Jay Solanki | SOC Analyst Portfolio  
**Use Case:** Detecting network-based threats and anomalous traffic patterns

---

## 1. Port Scan Detection
Detects a single source IP hitting many destination ports — classic port scan.
```spl
index=network
| stats dc(dest_port) as unique_ports by src_ip
| where unique_ports > 20
| eval alert="Possible port scan detected"
| sort - unique_ports
```

---

## 2. Large Data Exfiltration Detection
Flags unusually large outbound data transfers.
```spl
index=network
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip
| eval mb=round(total_bytes/1024/1024, 2)
| where mb > 500
| eval alert="WARNING — Large outbound transfer: " + mb + " MB"
| sort - mb
```

---

## 3. Suspicious Outbound Traffic on Non-Standard Ports
```spl
index=network direction=outbound
| where dest_port != 80 AND dest_port != 443 
  AND dest_port != 53 AND dest_port != 25
| stats count by src_ip, dest_ip, dest_port
| where count > 10
| sort - count
```

---

## 4. Internal Reconnaissance — Lateral Movement Detection
Detects one internal host connecting to many other internal hosts.
```spl
index=network
| where src_ip LIKE "192.168.%" AND dest_ip LIKE "192.168.%"
| stats dc(dest_ip) as hosts_contacted by src_ip
| where hosts_contacted > 15
| eval alert="Possible lateral movement — internal reconnaissance"
| sort - hosts_contacted
```

---

## 5. DNS Tunnelling Detection
Detects abnormally high DNS query volume from single host — tunnelling indicator.
```spl
index=dns
| bucket _time span=1m
| stats count by _time, src_ip
| where count > 100
| eval alert="Possible DNS tunnelling — high query volume"
| sort - count
```

---

## 6. Tor Exit Node Communication
Detects connections to known Tor exit node IP ranges.
```spl
index=network
| lookup tor_exit_nodes.csv ip as dest_ip OUTPUT is_tor
| where is_tor="true"
| stats count by src_ip, dest_ip, dest_port
| eval alert="CRITICAL — Connection to Tor exit node detected"
| sort - count
```

---

## 7. Beaconing Detection — Regular Interval Connections
Detects C2 beaconing by identifying connections at suspiciously regular intervals.
```spl
index=network
| bucket _time span=1m
| stats count by _time, src_ip, dest_ip
| eventstats stdev(count) as deviation by src_ip, dest_ip
| where deviation < 2
| eval alert="Possible C2 beacon — regular interval traffic pattern"
| sort - deviation
```

---

## 8. Newly Seen External IP Communication
Flags connections to IPs your network has never communicated with before.
```spl
index=network earliest=-1d latest=now
| stats count by dest_ip
| where count=1
| eval alert="First time connection to this external IP — verify if legitimate"
| sort - count
```
