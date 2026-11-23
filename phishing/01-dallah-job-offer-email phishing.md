# Recruitment Phishing Impersonating Dallah Driving School

**Date received:** 2026-11-08
**Date analyzed:** 2026-11-16
**Category:** Phishing / Credential & Personal Data Harvesting
**Tools used:** Gmail "Show original", manual header analysis, email body decoding

## Summary

A fake job offer email was received impersonating Dallah Driving School (Saudi Arabia).
The email passed the three authentication checks, but the sender domain, link destination
and hosting infrastructure had no relation to the impersonated organization. The attacker
played on job seekers' emotions to make them submit their personal data on a fake page.


**Verdict:** True Positive — Recruitment Phishing

## Analysis

### 1. Context
- The recipient never applied for a job at this organization.
- Unsolicited "your application has been approved" message with no interview.

### 2. Header Analysis

| Field | Value | Observation |
|---|---|---|
| From | `Joseph Clark <joseph@glidelogicio[.]co>` | Personal English name on an unrelated domain claiming to be a Saudi school's HR |
| To | *(missing)* | Recipient was in BCC — mass mailing |
| Return-Path | `joseph@glidelogicio[.]co` | Matches sender |
| Origin server | `outbound.protection.outlook.com` `[2a01:111:f403:dc08::]` | Legitimate Microsoft 365 server — attacker abused a trusted cloud service |
| Tenant region | `INDPRD01` / `southindia` | Hosted in India, not Saudi Arabia |
| Message-ID | `...@...PROD.OUTLOOK.COM` | Normal for Microsoft 365 — not a red flag |

### 3. Authentication Results

| Check | Result |
|---|---|
| SPF | pass |
| DKIM | pass |
| DMARC | pass (p=REJECT) |

All checks passed because the attacker registered their own domain and configured it
correctly. Authentication verifies the sender's **identity**, not their **intent**.

### 4. Body & Link Analysis
- Professional, well-written Arabic text (likely AI-assisted) — good language is no longer a sign of legitimacy.
- Generic greeting: "Dear Sir/Madam" — no recipient name.
- Emotional lure: congratulations on job approval, creating urgency to respond.
- Link text: "Official Recruitment Platform"
  - Actual destination: `hxxps://cairnpartnerio[.]com/ddschool` — a second unrelated domain.
  - Hidden in HTML: URL shortener `zrrtkq.s[.]gy` — used to hide the final destination.
- Logo hosted on a Gmail signature server (`googleusercontent.com/mail-sig`), not on the organization's website.
- Request: "verify your personal and job information" — data harvesting.

### 5. Threat Intelligence Results

| Domain | Role | VirusTotal | Created | Age at delivery |
|---|---|---|---|---|
| `glidelogicio[.]co` | Sender domain | 0/92 | 2026-08-20 | ~80 days |
| `cairnpartnerio[.]com` | Phishing landing page | 0/92 | 2026-10-15 | 24 days |
| `zrrtkq.s[.]gy` | URL shortener | Legitimate service — destination pending | — | — |

**Campaign timeline:**
- 2026-08-20 — Sender domain registered
- 2026-10-15 — Phishing page domain registered
- 2026-10-19 — Phishing URL first submitted to VirusTotal
- 2026-11-08 — Email received

  **urlscan.io results:**

Redirect chain:
`hxxps://cairnpartnerio[.]com/ddschool` → HTTP 302 → `hxxps://ddcschoolasd.bolt[.]host/`

| Domain | Role |
|---|---|
| `ddcschoolasd.bolt[.]host` | Phishing landing page (fake employment data form) |
| `tbekwctgnxucijexaqwh.supabase[.]co` | Attacker's backend — likely stores victim data |
| `bolt[.]new` | AI website builder used to create the page |
| `cloudfront[.]net` / Google Fonts | Platform resources — benign |

- Landing page hosted behind Cloudflare (`104.26.13.118`). This is a shared CDN IP and
  should **not** be blocked; block domains instead.
- Valid TLS certificate — HTTPS does not indicate legitimacy.
- Landing page first seen ~18h before the scan, newer than the email itself, suggesting
  the redirector is used to rotate landing pages after delivery.

**Attack chain:** every stage abused a legitimate platform
(Microsoft 365 → redirector → Bolt hosting → Supabase backend).

**Key findings:**
- Both domains had **zero detections**, despite clear phishing indicators. A 0/92 score
  means "not yet reported", not "safe".
- The sender domain was older than the landing domain — consistent with **domain aging**
  (to build sender reputation) and **disposable landing infrastructure**.
## IOCs

| Type | Value |
|---|---|
| Sender domain | `glidelogicio[.]co` |
| Sender email | `joseph@glidelogicio[.]co` |
| Phishing URL | `hxxps://cairnpartnerio[.]com/ddschool` |
| URL shortener | `zrrtkq.s[.]gy` |
| Phishing page | `ddcschoolasd.bolt[.]host` |
| Data backend | `tbekwctgnxucijexaqwh.supabase[.]co` |

## MITRE ATT&CK

| Technique | ID |
|---|---|
| Phishing for Information: Spearphishing Link | T1598.003 |
| Phishing: Spearphishing Link | T1566.002 |
| Impersonation | T1656 |
| Acquire Infrastructure: Domains | T1583.001 |
| Establish Accounts: Email Accounts | T1585.002 |

## Verdict & Recommendations

**Verdict:** True Positive — Recruitment phishing impersonating Dallah Driving School.

**Recommendations:**
1. Do not click the link or reply.
2. Report as phishing in the email client.
3. Block the sender domain and URL domains.
4. If any data was submitted: change passwords and enable MFA.
5. Verify job offers only through the organization's official website or phone number.

## Lessons Learned

- SPF, DKIM and DMARC can all **pass** on a phishing email — they prove the email came from that domain, not that the domain is trustworthy.
- Attackers abuse legitimate cloud services (Microsoft 365) to bypass filters.
- A missing `To:` field indicates BCC mass mailing.
- Platform knowledge matters: a Message-ID mismatch is normal for Microsoft 365.
- Job seekers are high-value targets because they expect recruitment emails.
