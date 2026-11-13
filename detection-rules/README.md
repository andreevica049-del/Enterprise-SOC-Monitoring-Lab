# Splunk SOC Detection Rules

Four SPL searches developed for the **Enterprise SOC – Linux Security Monitoring Lab**. These are laboratory detections, not production-ready correlation searches.

| File | Detection | Criteria | Alert severity |
| --- | --- | --- | --- |
| [`ssh_brute_force.spl`](ssh_brute_force.spl) | SSH brute-force activity | At least 5 failed SSH logins from the same `host` and `src_ip` within a rolling 300-second window | Medium |
| [`suspicious_ssh_login.spl`](suspicious_ssh_login.spl) | Successful SSH login after failures | Successful login associated with at least 5 failed attempts in a 300-second window for the same `host`, `src_ip`, and `target_user`; additionally restricts matches to the last 10 minutes | High |
| [`unusual_ssh_source_ip.spl`](unusual_ssh_source_ip.spl) | SSH login from an untrusted IP | Successful password login where `src_ip` is not `127.0.0.1` | Medium |
| [`failed_sudo_authentication.spl`](failed_sudo_authentication.spl) | Repeated failed sudo authentication | At least 2 `pam_unix(sudo:auth)` failures for the same `host` and `sudo_user` in a rolling 300-second window | Medium |

## Environment

- Data: `index=linux sourcetype=linux_secure` from Ubuntu authentication logs, forwarded by Splunk Universal Forwarder.
- Alert configuration (schedules, time ranges, trigger actions, throttle, and severity) lives in Splunk saved-alert settings and **is not encoded in these `.spl` files**.
- The SSH brute-force alert was validated end-to-end on November 13, 2026: a six-failure test was observed by Splunk, the scheduled search returned two result rows at 11:25, and an `alert_fired` record was recorded in `index=_audit`.
- Other rules were exercised in earlier lab tests, but were not all revalidated end-to-end in the same November 13 test.

## Important limitations

1. These searches are lab-specific and rely on OpenSSH / sudo log text patterns. Different distributions, event formats, or SSH configurations may require adjustments.
2. `127.0.0.1` is the only trusted IP in the unusual-source rule; a real deployment needs a maintained allowlist or asset-aware baseline.
3. Events returned by `streamstats` at or above a threshold can represent successive matches in one burst; they should not be interpreted as distinct incidents without deduplication.
4. The sudo search uses the `ruser` field extracted from log text. Confirm that this field identifies the intended user in your environment before deploying the rule.
5. Consider scheduled-search lookback, ingestion lag, and false positives before moving any rule to production.

## How to use

Open **Splunk Enterprise → Search & Reporting**, paste a `.spl` query, select a suitable time range, and run it. To create an alert, save the search as a scheduled alert and configure trigger condition and action separately. For reproducibility, document the alert settings in the portfolio's validation materials.
