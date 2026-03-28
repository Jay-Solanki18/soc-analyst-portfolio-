# Splunk SPL Queries — Authentication & Brute Force Detection

**Author:** Jay Solanki | SOC Analyst Portfolio  
**Use Case:** Detecting authentication attacks in a SOC environment

---

## 1. Failed Login Detection
Detect any failed login attempts on Windows endpoints.
```spl
index=windows EventCode=4625
| stats count by Account_Name, src_ip, host
| where count > 3
| sort - count
```

---

## 2. Brute Force Detection
Flag accounts with more than 5 failed logins within 5 minutes.
```spl
index=windows EventCode=4625
| bucket _time span=5m
| stats count by _time, Account_Name, src_ip
| where count > 5
| sort - count
```

---

## 3. Successful Login After Multiple Failures (Credential Compromise)
Detects a successful login following repeated failures — 
high confidence indicator of successful brute force.
```spl
index=windows (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as failures,
        count(eval(EventCode=4624)) as successes by Account_Name, src_ip
| where failures > 5 AND successes > 0
| eval risk="HIGH - Possible credential compromise"
| table Account_Name, src_ip, failures, successes, risk
```

---

## 4. Account Lockout Detection
```spl
index=windows EventCode=4740
| stats count by TargetUserName, src_ip, host
| sort - count
```

---

## 5. Off-Hours Login Detection
Flag logins outside business hours (before 8am or after 8pm).
```spl
index=windows EventCode=4624
| eval hour=strftime(_time, "%H")
| where hour < 8 OR hour > 20
| stats count by Account_Name, src_ip, host, hour
| sort - count
```

---

## 6. New User Account Created
```spl
index=windows EventCode=4720
| stats count by Account_Name, src_ip, host
| eval alert="New user account created — verify if authorised"
| table _time, Account_Name, src_ip, host, alert
```

---

## 7. User Added to Admin Group
```spl
index=windows EventCode=4732
| search Group_Name="Administrators"
| stats count by Account_Name, Group_Name, host
| eval alert="CRITICAL — User added to Administrators group"
| table _time, Account_Name, Group_Name, host, alert
```
