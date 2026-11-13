# End-to-End SOC Validation Report

**Project:** Enterprise SOC — Linux Security Monitoring (Splunk Enterprise)
**Test date:** 13 November 2026
**Environment:** Isolated, owner-controlled VirtualBox laboratory
**Scenario:** SSH brute-force detection and alerting
**Validation status:** **PASS for the tested SSH brute-force workflow**

## 1. Executive summary

This report documents a controlled, end-to-end validation of the Linux security monitoring workflow. Six deliberately unsuccessful SSH password attempts were generated against the local laboratory SSH service. Linux authentication events were collected from the Ubuntu endpoint, forwarded to Splunk Enterprise, matched by a scheduled SPL detection, recorded as a fired alert, and displayed in the SOC dashboard.

The test is a **lab simulation**, not evidence of a real intrusion or a production SOC deployment. Other alert rules and dashboards were configured and previously tested, but were not all revalidated end-to-end during this test.

## 2. Environment and scope

- **Log source:** Ubuntu virtual machine `ubuntu-ssh-lab` (SSH service and `/var/log/auth.log`)
- **Forwarding:** Splunk Universal Forwarder
- **SIEM:** Splunk Enterprise 10.6.1 (lab server)
- **Index / sourcetype:** `index=linux`, `sourcetype=linux_secure`
- **Detection:** `SOC - SSH Brute Force Alert`, scheduled every 5 minutes
- **Detection criteria:** At least 5 SSH password failures from a single host/source IP within a rolling 300-second window
- **Alert window / action:** Search last 10 minutes; number of results > 0; Add to Triggered Alerts; Medium severity
- **Dashboard:** `Enterprise SOC - Linux Security Monitoring`, six panels
- **Test source:** `127.0.0.1` (loopback, not a remote threat actor)
- **Test account:** `labuser`

## 3. Validation results

| ID | Validation check | Observation | Result |
|---|---|---|---|
| 7.1 | Fresh event ingestion | Marker `SOC_STAGE7_TEST_001` indexed from `/var/log/auth.log` on 13 Nov | PASS |
| 7.2 | SSH failure generation | Six unsuccessful SSH password attempts observed | PASS |
| 7.3 | SPL detection threshold | Rolling-window results reached `failed_attempts=5` and `6` at 11:21:17 and 11:21:33 | PASS |
| 7.4 | Scheduled detection | Scheduler `status=success`, `result_count=2` at 11:25:00 | PASS |
| 7.4b | Fired alert audit | `index=_audit action=alert_fired` records `SOC - SSH Brute Force Alert` at 11:25:00 | PASS |
| 7.5 | Dashboard presentation | New alert and corresponding failed SSH events visible in dashboard panels | PASS |

**Timestamp note:** Times above are taken from the Splunk UI screenshots and reflect the UI's configured timezone. The screenshots do not independently prove synchronized clocks across all hosts.

## 4. Detection implementation

Saved rule: `SOC - SSH Brute Force Alert`

```spl
index=linux sourcetype=linux_secure "Failed password"
| rex field=_raw "Failed password for (?:invalid user )?(?<target_user>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| sort 0 _time
| streamstats time_window=300s count AS failed_attempts by host src_ip
| where failed_attempts >= 5
| table _time host src_ip target_user failed_attempts
| sort -_time
```

The retained scheduled search evaluates a rolling five-minute window within its ten-minute scheduled search range. `result_count=2` means two matching result rows, **not two independent security incidents**. Scheduled-search execution, alert registration, and analyst interpretation are distinct checks.

## 5. Evidence files

| File | Purpose |
|---|---|
| `evidence/01_forwarder_ingestion.png` | Test marker searchable in Splunk |
| `evidence/02_detection_threshold.png` | New SSH failures reaching detection threshold |
| `evidence/03_scheduler_result_count_2.png` | Scheduled search returns two results |
| `evidence/04_alert_fired_audit.png` | Audit log records the alert firing |
| `evidence/05_dashboard_new_alert_and_events.png` | Dashboard surfaces current alert and source events |
| `evidence/06_dashboard_history_page_2.png` | Additional dashboard records |
| `enterprise_soc_dashboard.xml` | Splunk Classic Dashboard source (six panels, dark theme) |

## 6. Limitations and follow-up

1. Only a **single, controlled SSH brute-force scenario** was validated end-to-end on 13 November; do not generalize this PASS to every detection rule.
2. `127.0.0.1` is a loopback test address. Real network attacks, attacker attribution and geolocation were **not** tested.
3. The dashboard primarily uses historical `All time` queries. A global time picker, automatic refresh, and operational retention policy remain future enhancements.
4. The experiment shows alerting, not automatic blocking, containment or response orchestration.
5. No quantitative ingestion latency, detection-latency benchmark, false-positive rate or stress test was measured.
6. Verify that scheduler logs and source-event timestamps remain synchronized, and review saved searches for suppression or duplication in production-like conditions.

## 7. Conclusion

**PASS — Tested workflow:** Ubuntu authentication log → Universal Forwarder → Splunk indexing → scheduled SSH brute-force SPL detection → fired alert audit → SOC dashboard. The project demonstrates practical SIEM ingestion, SPL correlation, alerting validation and evidence-based SOC analysis in a self-managed laboratory.

**Next project stage:** Stage 8 — GitHub Portfolio Documentation (README, architecture diagram, sanitized configurations, SPL rules, screenshots, incident reports and playbooks).
