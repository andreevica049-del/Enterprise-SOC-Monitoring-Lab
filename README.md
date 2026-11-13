# Enterprise SOC Monitoring Lab — Splunk & Linux

A hands-on Security Operations Center (SOC) lab demonstrating Linux authentication log collection, Splunk-based threat detection, scheduled alerting, security dashboards, and end-to-end validation of an SSH brute-force detection scenario.

> **Scope:** An isolated, authorized training environment. The activity described here is simulated; no production systems or third-party assets were tested.

## Project overview

The lab collects Linux authentication events from an Ubuntu endpoint using **Splunk Universal Forwarder**, indexes them in **Splunk Enterprise**, and analyzes the data with SPL detection queries. A six-panel monitoring dashboard provides visibility into authentication activity and recorded detection alerts.

**Technology stack:** Splunk Enterprise 10.6.1, Splunk Universal Forwarder, Ubuntu Linux, OpenSSH, SPL, Oracle VirtualBox.

## Architecture

```text
Ubuntu SSH Lab (ubuntu-ssh-lab)
    └─ /var/log/auth.log
         └─ Splunk Universal Forwarder
              └─ Splunk Enterprise (index=linux, sourcetype=linux_secure)
                   ├─ Scheduled SPL detection rules
                   ├─ Triggered alerts / audit trail (index=_audit)
                   └─ Enterprise SOC - Linux Security Monitoring dashboard
```

The lab uses private network addresses, including `192.168.56.10` for the Splunk web interface in the observed setup. Loopback SSH tests originate from `127.0.0.1`.

## Detection use cases

| Rule | Focus |
| --- | --- |
| SOC - SSH Brute Force Alert | Repeated failed SSH logins from the same source IP |
| SOC - Suspicious SSH Login Alert | Suspicious SSH authentication sequences |
| SOC - Failed Sudo Authentication Alert | Repeated sudo authentication failures |
| SOC - Unusual SSH Source IP Alert | Successful SSH logins from sources outside the configured trusted IP list |

The exact production readiness of each rule is not claimed; detection rules were tested in a controlled lab.

## SOC dashboard

The **Enterprise SOC - Linux Security Monitoring** Classic XML dashboard includes:

1. SSH Authentication Overview — successful vs. failed SSH logins
2. Failed SSH Logins Over Time — five-minute trend
3. Top SSH Source IP Addresses — top authentication sources
4. Sudo Authentication Failures — failed sudo authentication trend
5. SOC Detection Alerts — alert history from `index=_audit`
6. Recent Security Events — recent Linux authentication and sudo events

Dashboard source: [`dashboards/`](dashboards/). Screenshots: [`screenshots/`](screenshots/).

## End-to-end validation — November 13, 2026

A controlled SSH test verified the path from source logs to a triggered alert and dashboard display.

| Validation check | Observed result |
| --- | --- |
| Log transport | Test message `SOC_STAGE7_TEST_001` found in `index=linux` from `/var/log/auth.log` |
| SSH failed-login generation | Six failed logins for `labuser` from `127.0.0.1` within a five-minute rolling window |
| Detection SPL | `streamstats time_window=300s` reached counts of five and six |
| Scheduled search | At 11:25:00, scheduler status `success`, `result_count=2` |
| Alert registration | `SOC - SSH Brute Force Alert` recorded in `index=_audit` at 11:25:00 |
| Dashboard | New alert and failed-login events displayed in the relevant dashboard panels |

**Interpretation:** This validates one complete SSH brute-force detection scenario, not every possible threat pattern or all rule variants. Two scheduler result rows do not imply two independent incidents.

Full evidence and methodology: [`validation/`](validation/).

## Repository structure

```text
Enterprise-SOC-Monitoring-Lab/
├── README.md
├── architecture/
├── dashboards/
├── detection-rules/
├── incident-reports/
├── screenshots/
├── soc-playbooks/
└── validation/
```



## Reproduction notes

1. Set up an isolated Ubuntu SSH endpoint and Splunk Enterprise instance.
2. Configure Universal Forwarder to collect Linux authentication logs into `index=linux` using `sourcetype=linux_secure`.
3. Validate ingestion with a unique `logger` message and an SPL search.
4. Add and tune the detection rules, scheduled actions, and dashboard using the sanitized files in this repository.
5. Generate a small number of **authorized lab-only** failed SSH logins and correlate events, scheduler results, alerts, and dashboard updates.

Actual deployment details (passwords, tokens, certificates, secrets, private configuration) must not be published.

## Limitations and future work

- Testing used a small isolated environment rather than a production network.
- The demonstrated brute-force scenario used loopback (`127.0.0.1`) and a single Ubuntu endpoint.
- Dashboard panels currently query historical `All time` data; add a shared time picker and refresh policy for operational use.
- Validate ingestion delays, alert suppression, false positives, and each rule separately before any production adaptation.
- Add event enrichment, response playbooks, and version-controlled detection tests.

## Author

Andrii Hurskykh — cybersecurity / SOC analyst portfolio project.
