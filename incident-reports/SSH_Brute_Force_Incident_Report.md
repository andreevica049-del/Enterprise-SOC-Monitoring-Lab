# SOC Incident Report: SSH Brute-Force Detection (Lab Simulation)

**Incident ID:** LAB-SOC-2026-11-13-001  
**Date:** 13 November 2026  
**Analyst:** Andrii Hurskykh  
**Environment:** Isolated Enterprise SOC Monitoring Lab (VirtualBox / Ubuntu / Splunk Enterprise)  
**Classification:** Controlled security test — **not a production incident**  
**Detection priority:** Medium (configured Splunk alert severity)  
**Status:** Detection workflow validated; no actual compromise established

## 1. Executive Summary

A controlled sequence of six failed SSH password-authentication attempts was generated against the Ubuntu lab endpoint. Linux authentication logs were forwarded by Splunk Universal Forwarder to Splunk Enterprise, where a scheduled detection searched for at least five failures from the same source IP to the same host within a five-minute rolling window.

The test reached the detection threshold. The scheduled **SOC - SSH Brute Force Alert** ran at **11:25:00** on 13 November 2026 and reported **two matching search results**. A corresponding `alert_fired` audit record was observed at approximately **11:25:00.896**; the alert also appeared on the SOC monitoring dashboard. These timestamps are as displayed in the lab's Splunk interface; the time-zone configuration was not independently documented.

**Outcome:** The lab's log ingestion, detection logic, alert scheduling, audit trail and dashboard visibility were demonstrated. The test did **not** establish successful unauthorized access, credential compromise, persistence or data loss.

## 2. Lab Scope and Data Sources

| Component | Role |
|---|---|
| Ubuntu VM (`ubuntu-ssh-lab`) | SSH authentication event source |
| `/var/log/auth.log` | Linux authentication log |
| Splunk Universal Forwarder | Log collection and forwarding |
| Splunk Enterprise | Search, correlation and scheduled alerting |
| `index=linux`, `sourcetype=linux_secure` | Indexed Linux authentication data |
| `Enterprise SOC - Linux Security Monitoring` | Dashboard for analyst review |

The validation used localhost SSH attempts (`127.0.0.1`) in a controlled training environment. No external attacker IP, victim organization or production system is claimed.

## 3. Detection Logic

**Alert name:** `SOC - SSH Brute Force Alert`  
**Schedule:** `*/5 * * * *` (every five minutes)  
**Scheduled search range:** Last 10 minutes (configured for the alert)  
**Trigger condition:** Number of results greater than zero  
**Threshold:** At least five failed SSH password attempts within 300 seconds, grouped by `host` and `src_ip`.

```spl
index=linux sourcetype=linux_secure "Failed password"
| rex field=_raw "Failed password for (?:invalid user )?(?<target_user>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| sort 0 _time
| streamstats time_window=300s count AS failed_attempts by host src_ip
| where failed_attempts >= 5
| table _time host src_ip target_user failed_attempts
| sort -_time
```

The SPL emits **one row for each event at or above the threshold**; it does not aggregate these rows into a single incident. Consequently, two results can represent the fifth and sixth attempts within the same simulated sequence, rather than two distinct attacks.

## 4. Evidence and Timeline

| Date/time (Splunk display) | Observed activity | Evidence interpretation |
|---|---|---|
| 13 Nov 2026, 10:29:04 | `SOC_STAGE7_TEST_001` appeared in Splunk from `/var/log/auth.log` | Verified end-to-end forwarding and indexing |
| 13 Nov 2026, ~11:19–11:21 | Repeated failed SSH password attempts generated | Controlled test activity |
| 13 Nov 2026, 11:21:17 | Search displayed `failed_attempts=5` | Detection threshold reached |
| 13 Nov 2026, 11:21:33 | Search displayed `failed_attempts=6` | Additional failed attempt in the window |
| 13 Nov 2026, 11:20:00 | Scheduled search `status=success`, `result_count=0` | No matching results at this earlier execution |
| 13 Nov 2026, 11:25:00 | Scheduled search `status=success`, `result_count=2` | Detection executed and found matching rows |
| 13 Nov 2026, ~11:25:00.896 | `_audit` contained `action=alert_fired` | Alert firing recorded |
| 13 Nov 2026, after refresh | Detection alert and recent SSH failures displayed on dashboard | Analyst visibility confirmed |

**Evidence inspected during the exercise:** Splunk Search results, scheduler records in `_internal`, audit events in `_audit`, and the dashboard's alert and recent-events panels. Supporting screenshots should be added under the repository's `screenshots/` directory, with any identifiers or sensitive data reviewed before publication.

## 5. Analyst Assessment

- **Observed:** A short burst of password failures from a common SSH source to the same Ubuntu host; Splunk detected it based on the configured threshold.
- **Plausible security meaning:** Such a pattern may indicate password guessing or brute-force activity in an uncontrolled environment.
- **Confidence for this exercise:** High that the *configured rule fired as designed*; no claim of malicious real-world intent because the activity was deliberately generated.
- **Impact:** No verified unauthorized access or business impact. Successful login after the failures was not demonstrated by this specific test.
- **Limitations:** The extraction regular expression matches IPv4 addresses only. The alert can fire multiple matching rows for a single burst; authorized-user mistakes can also trigger it. A 10-minute scheduled search overlapping a 5-minute rolling threshold may repeat notifications unless suppression is configured. Source-IP and account identity should be verified before operational containment.

## 6. Response Actions (Simulated / Proposed)

1. Reviewed the failed-login search results and confirmed source host, source IP, account name, timing and count.
2. Checked the scheduled-search execution using `index=_internal sourcetype=scheduler` and the alert audit trail using `index=_audit action=alert_fired`.
3. Reviewed the dashboard's detection alerts and recent security events panels.
4. For a real environment, the next steps would be to search for successful logins after the failures, validate whether the source is trusted, review affected account activity, and escalate confirmed suspicious behavior.

**Actions not performed or not established:** No production IP blocking, account lockout, endpoint isolation, password reset, incident escalation or forensic acquisition is claimed.

## 7. Conclusion

**Validation result: PASS.** A six-attempt controlled sequence produced threshold hits (`5` and `6`), a scheduled search with two matching rows, an auditable fired alert, and visible dashboard entries. The exercise demonstrates a working entry-level SOC detection workflow, not compromise of a production system.

## 8. Follow-up Improvements

- Confirm a stable source-IP field for both IPv4 and IPv6, and validate regex parsing against real log formats.
- Add allowlists, exception handling and rate-based tuning to reduce false positives.
- Correlate failures with subsequent successful logins and account activity.
- Document alert throttling / suppression and case deduplication.
- Capture sanitized screenshots showing the scheduled search, audit record, dashboard and search results.

---

*Portfolio note: all activity described above is part of an authorized, isolated lab simulation.*
