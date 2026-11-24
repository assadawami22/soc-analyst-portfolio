# LetsDefend SOC127 — SQL Injection Detected

**Date analyzed:** 2026-11-24
**Category:** Web Attack / SQL Injection
**Tools used:** LetsDefend (Log Management, Email Security, Endpoint Security), VirusTotal
**Result:** True Positive

## Summary
TODO

## Investigation

### 1. Alert details

| Field | Value |
|---|---|
| Event ID | 235 |
| Rule | SOC127 - SQL Injection Detected |
| Source IP | `118.194.247[.]28` (external) |
| Source reputation | 8/92 security vendors flagged this IP as malicious (VirusTotal) |
| Destination | `172.16.20.12` — WebServer1000 |
| Time | 2024-03-07T12:51:45+03:00 |
| Device Action | Allowed |

### 2. Traffic analysis
- 42 requests from `118.194.247[.]28` to `172.16.20.12` in 3 minutes on 2024-03-07.
- Sample request:

```
118.194.247.28 - - [07/Mar/2024:12:53:47 +0000] "GET /index.php?id=1%20ORDER%20BY%208991--%20eXLc HTTP/1.1" 200 865 "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"
```

- Method: GET · Status: 200 · Size: 865
- TODO: decoded payload + what `ORDER BY` means

### 3. Is it malicious? — YES
- 42 requests in 3 minutes.
- The requests include SQL injection code.
- The source IP has a bad reputation.

### 4. Planned test? — NO
- Searched email: nothing related to the attacker's IP.

### 5. Direction
Internet → Company Network

### 6. Was it successful?
- The source IP sent more than 20 requests with different SQL injection payloads,
  and all of them returned status 200 with the same size (865).
- Endpoint: no processes, commands, files or network activity at the time of the attack.
- TODO: why identical sizes don't prove failure

### 7. Firewall logs
- After the proxy logs, about 20 more entries appeared with type `Firewall` and no payload.
- Fields: type, source_address, source_port, destination_address, destination_port, time.
  Example: `118.194.247[.]28:37298 → 172.16.20.12:50843` at 2024-03-07 11:56:44.
- No action field.
- My first assumption: the traffic was blocked, because the last requests were firewall entries.
- TODO: what it really was

## IOCs

| Type | Value |
|---|---|
| Source IP | `118.194.247[.]28` |
| TODO | |

## MITRE ATT&CK
TODO

## Verdict & Actions
- **Classification:** True Positive
- **Escalation:** TODO
- **Analyst note:**

```
What:      Source IP 118.194.247.28 to WebServer1000, 42 requests via sqlmap in 3 minutes.
Malicious: YES, the payloads contain SQL injection code and the source IP 118.194.247.28
           has a bad reputation checked via VirusTotal - 8/92 security vendors flagged
           this IP address as malicious.
Success:   NO, all response sizes are 865 for all payloads and the payloads are different.
Test:      No planned test found in email.
Actions:   Block the IP, ask the web team to verify the parameter is safe.
```

- TODO: update the note with the final verdict

## Lessons Learned
TODO
