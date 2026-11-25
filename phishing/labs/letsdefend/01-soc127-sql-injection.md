# LetsDefend SOC127 — SQL Injection Detected

*Simulated alert on LetsDefend, based on a real attack technique.*

**Date analyzed:** 2026-11-24
**Category:** Web Attack / SQL Injection
**Tools used:** LetsDefend (Log Management, Email Security, Endpoint Security), VirusTotal
**Result:** True Positive — Escalated to Tier 2

## Summary

SQL injection attack on WebServer1000 from external IP 118.194.247[.]28, which first
performed a port scan and then sent 42 automated requests (sqlmap) in 3 minutes. The
attacker was testing whether he could access the database by injecting SQL commands
into the "id" URL parameter. The server processed the requests (HTTP 200), and success
could not be ruled out.

**Verdict:** True Positive — escalated to Tier 2.

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
- Decoded payload: `id=1 ORDER BY 8991-- eXLc`
  - `ORDER BY <number>` tests how many columns the database table has: the first step
    before `UNION SELECT` to extract data.
  - `--` comments out the rest of the SQL query.

### 3. Is it malicious? — YES

- 42 requests in 3 minutes.
- The requests include SQL injection code.
- The source IP has a bad reputation.

### 4. Planned test? — NO

- Searched email: nothing related to the attacker's IP.

### 5. Direction

Internet → Company Network

### 6. Was it successful?

- The server processed all injected requests (HTTP 200), so the SQL commands reached
  the application. We do not know what the database returned.
- The identical response sizes suggest no data was shown on the page, but sqlmap often
  uses blind SQL injection, which can succeed without changing the response size.
- **Conclusion:** the attack is treated as **potentially successful**, and was escalated.

### 7. Firewall logs

- About 20 entries appeared with type `Firewall` and no payload.
- Fields: type, source_address, source_port, destination_address, destination_port, time.
  Example: `118.194.247[.]28:37298 → 172.16.20.12:50843` at 2024-03-07 11:56:44.
- No action field.
- My first assumption: the traffic was blocked, because the last requests were firewall
  entries. But with no action field, a block could not be confirmed.
- **Conclusion:** the attacker performed a **port scan** (`T1595` Active Scanning): one IP
  connecting to many different destination ports, with no web content.
- The firewall timestamps (11:56) appear earlier than the web logs (12:53), suggesting the
  scan came before the SQL injection. The order is unconfirmed because the firewall log
  shows no timezone.

## IOCs

| Type | Value |
|---|---|
| Source IP | `118.194.247[.]28` |
| User-Agent (supporting) | `sqlmap/1.7.2` |

## Affected Assets

| Type | Value |
|---|---|
| Hostname | `WebServer1000` |
| IP | `172.16.20.12` |

## MITRE ATT&CK

| Tactic | Technique | ID |
|---|---|---|
| Reconnaissance | Active Scanning: Vulnerability Scanning | T1595.002 |
| Initial Access | Exploit Public-Facing Application | T1190 |

**Software used:** sqlmap (S0225)

## Verdict & Actions

- **Classification:** True Positive
- **Escalation:** Escalated to Tier 2 — success could not be ruled out.
- **Analyst note:**

```
What:      SQL injection from 118.194.247[.]28 to WebServer1000, 42 requests via sqlmap
           in 3 minutes.
Malicious: YES. The payloads contain SQL injection code, and the source IP has a bad
           reputation on VirusTotal (8/92 vendors flagged it as malicious).
Success:   POTENTIALLY. Although all responses were 865 bytes for different payloads,
           the server processed the injected requests (HTTP 200). sqlmap often uses blind
           SQL injection, which can succeed without changing the response size.
Test:      No planned test found in email.
Actions:   Block the source IP. Ask the web team to verify the "id" parameter is safe.
           Escalated to Tier 2 to review database logs and search for the same IP on
           other hosts.
```

## Lessons Learned

- **Absence of proof is not proof of absence.** I first concluded the attack failed because
  all responses had the same size. But blind SQL injection (common with sqlmap) can succeed
  without changing the response size. When failure can't be proven, escalate.
- **A firewall log is not a block.** I assumed the traffic was blocked because firewall
  entries appeared after the proxy logs in the log view. There was no action field. The
  entries were actually a port scan: one IP hitting many different ports.
- **IOCs belong to the attacker.** The attacker's IP is an IOC. Our own server and its IP are
  affected assets, not IOCs.
- **Take structured notes during the investigation.** Writing each step (what I checked, what
  I found) as I go made the final note and this write-up faster and more accurate.
- **Trust the payload, not the label.** The User-Agent said "sqlmap", but it can be faked.
  The real proof was the decoded payload: "ORDER BY 8991--" (testing the number of columns).
- **Check timezones before linking logs.** The alert, web logs and firewall logs used
  different time formats, which made the order of events unclear.
