# SOC Tier 1 Playbook: SSH Brute-Force Detection and Triage

**Playbook ID:** SOC-PB-SSH-001  
**Version:** 1.0  
**Owner:** Andrii Hurskykh  
**Context:** Enterprise SOC Monitoring Lab / Splunk Enterprise  
**Trigger:** `SOC - SSH Brute Force Alert` — five or more failed password attempts from the same source IP to the same host within 300 seconds  
**Default alert priority (lab):** Medium

> This is a training playbook. In production, follow the organization's authorization, incident-response policy, evidence-retention requirements and escalation matrix. Do not block addresses or alter accounts without approval.

## 1. Objective

Identify repeated SSH authentication failures, determine whether they plausibly represent unauthorized access attempts, check for follow-on successful logins, and hand off actionable findings to the appropriate responder.

## 2. Inputs Required

- Alert execution time and matching event time range
- Hostname, source IP, target username(s), failed-attempt counts
- Raw Linux authentication events and available successful-login events
- Asset criticality, business owner and approved IP / VPN allowlists
- Related alerts and prior incident history, if available

## 3. Triage Workflow

### Step 1 — Validate the alert

1. Open **Splunk > Search & Reporting > Alerts** and locate the alert or dashboard entry.
2. Confirm the search actually ran and inspect the returned events. Do not equate multiple matching rows with separate attacks.
3. Record when the events occurred versus when the alert fired. Check for duplicate scheduled alerts.

Example — failed SSH attempts:

```spl
index=linux sourcetype=linux_secure "Failed password"
| rex field=_raw "Failed password for (?:invalid user )?(?<target_user>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| stats count AS failures earliest(_time) AS first_seen latest(_time) AS last_seen values(target_user) AS target_users by host src_ip
| convert ctime(first_seen) ctime(last_seen)
| sort -failures
```

**Decision:** If no authentic matching records are found, investigate parsing, time range, scheduler behavior or a false-positive alert before escalating.

### Step 2 — Establish scope and context

- Identify source IP, destination host and accounts targeted.
- Check whether the address belongs to a known admin workstation, VPN, scanner, localhost or test infrastructure.
- Compare failed attempts across hosts and users to identify spraying or distributed patterns.
- Determine whether attempts occurred during authorized maintenance or a penetration test.
- Preserve relevant original events and search parameters as evidence.

### Step 3 — Check for successful SSH logins

```spl
index=linux sourcetype=linux_secure "Accepted password"
| rex field=_raw "Accepted password for (?<target_user>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| table _time host target_user src_ip _raw
| sort -_time
```

Correlate the same `src_ip`, `host` and `target_user` with failures in the preceding minutes. Successful authentication following repeated failures is **higher priority for investigation**, but is not by itself proof of unauthorized access.

### Step 4 — Check related activity

Search for privileged commands and authentication errors around the observed window:

```spl
index=linux sourcetype=linux_secure ("sudo" OR "authentication failure" OR "session opened")
| table _time host _raw
| sort -_time
```

Where available, review endpoint telemetry, interactive sessions, privileged actions and change records. If those data sources are unavailable, state that limitation in the case notes.

### Step 5 — Assess severity and choose disposition

| Observations | Suggested SOC Tier 1 handling |
|---|---|
| Known authorized test / administrator error, no concerning follow-on activity | Document and close under the applicable policy |
| Repeated failures from unrecognized source; no confirmed success | Investigate context and escalate if policy threshold or asset criticality requires |
| Failures followed by unusual successful login | Escalate promptly to Tier 2 / incident response for validation and containment decision |
| Multiple targeted accounts, privileged account, critical host or suspicious post-login activity | Prioritize escalation according to the organization's incident-severity matrix |

The configured **Medium** Splunk alert severity is an initial signal, not a fixed incident-severity determination.

### Step 6 — Escalate and recommend containment

Provide: timestamp and time zone, hostname, source IP, targeted accounts, count / window, raw-event references, success-login findings, scope, confidence, and recommended next actions.

**Potential containment actions for authorized responders:** rate limiting, firewall or VPN controls, SSH hardening, password reset where justified, account/session review and increased monitoring. Obtain required approvals and avoid disrupting legitimate access.

### Step 7 — Close or hand off

- Record a disposition: benign authorized activity, false positive, suspicious/unconfirmed, or confirmed incident.
- Document what was verified and what remains unknown.
- Attach sanitized Splunk results, scheduler and audit evidence where appropriate.
- Record owner, next action and follow-up status.
- Recommend rule tuning for repeat alerts or known-good sources.

## 4. Required Case Notes Template

```text
Case ID:
Detection / alert name:
Analyst:
Event time range and time zone:
Alert fired at:
Host / asset owner:
Source IP(s):
Target username(s):
Failed attempts / window:
Successful logins identified? (Yes/No/Unknown):
Other suspicious activity:
Business / test context:
Evidence references:
Assessment and confidence:
Escalation / approval:
Disposition:
Next action / owner:
```

## 5. Lab Validation Reference

On **13 November 2026**, a controlled six-failure SSH sequence in the Ubuntu lab reached counts of **5** and **6**. The Splunk scheduler reported **two matching results** at **11:25:00**, an `alert_fired` record appeared in `_audit`, and the dashboard reflected the alert. This demonstrated detection and alert visibility only; no production containment was performed.

See: [`../incident-reports/SSH_Brute_Force_Incident_Report.md`](../incident-reports/SSH_Brute_Force_Incident_Report.md)

---

*This playbook is educational and should be adapted before use in an operational SOC.*
