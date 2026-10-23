# Cloud Security Log Analysis

**SQL detections over cloud identity and audit logs, scored against planted incidents with known
timestamps, plus a research report on how managed cloud databases (DBaaS) get exposed.**

Most cloud database breaches do not start with a broken provider. They start with a customer
setting: a database left reachable from the internet, a role granted too widely, an account
taken over by password guessing. All of these leave a trace in the logs. This project asks
whether plain SQL can find them, and how to tell when it can't.

```
451 sign-ins, 4 IAM changes, 4 DB config changes loaded

[critical] 2026-09-10 02:31:00  compromise_then_privilege_change   m.rossi            GrantRole DBAdmin on m.rossi, 16 minutes after a suspected brute-forced sign-in
[critical] 2026-09-10 02:40:00  db_made_public                     prod-customers-db  m.rossi set publicly_accessible=true on prod-customers-db
[critical] 2026-09-11 14:22:00  spray_then_success                 f.haddad           Successful sign-in from 203.0.113.250, which began spraying passwords across accounts at 2026-09-11 14:00:00
[    high] 2026-09-10 02:14:30  brute_force_then_success           m.rossi            8 failed sign-ins in the 10 minutes before a success from 198.51.100.77 (NL)
[    high] 2026-09-10 02:31:00  offhours_privileged_grant          m.rossi            m.rossi granted DBAdmin to m.rossi outside business hours
[    high] 2026-09-11 14:00:00  password_spray                     203.0.113.250      12 failed sign-ins across 12 accounts within 30 minutes
[    high] 2026-09-14 11:00:00  db_encryption_disabled             analytics-db       j.nguyen set storage_encrypted=false on analytics-db
[  medium] 2026-09-10 02:14:30  new_country_signin                 m.rossi            First successful sign-in from NL (home AU) via 198.51.100.77
[  medium] 2026-09-11 14:22:00  new_country_signin                 f.haddad           First successful sign-in from US (home AU) via 203.0.113.250

Missed: 0   Unexpected: 0
```

**All 9 expected alerts across the 3 planted incidents fired, with 0 alerts on benign activity.
12 of 12 tests pass.** The first attack chain is visible in order: 30 minutes from the first
failed password to the customer database being made public.

---

## What it does

1. **Generates 14 days of synthetic logs** for a 20-person organisation: identity-provider
   sign-ins, IAM changes and managed-database configuration changes
   ([`src/generate_logs.py`](src/generate_logs.py)). All IPs come from the RFC 5737
   documentation ranges.
2. **Plants three incidents** with known timestamps:
   - **A brute-force attack chain:** password guessing → sign-in from a new country → the
     attacker grants itself `DBAdmin` at 2:31 am → the production customer database is made
     public.
   - **A password spray that works:** one IP tries 12 accounts once each, and one password is
     right.
   - **Encryption at rest switched off** on an analytics database.
3. **Detects them with SQL only.** There are three [triggers](sql/triggers.sql) that alert the
   moment a row is inserted, and five [batch queries](sql/detections/) for rules that need a
   time window or history.
4. **Scores the result.** Every planted incident must alert, and nothing benign may. Each rule
   has a benign look-alike in the data that it has to ignore.

## Two findings

**A successful password spray is invisible to per-account rules.** The account that falls sees
one failed sign-in, not five, so the brute-force rule stays silent. A separate spray rule sees
the attack but can't say whether it worked. Only joining the two on the source IP
([`05_spray_then_success.sql`](sql/detections/05_spray_then_success.sql)) shows the compromise.
This is the technique behind Microsoft's January 2024 Midnight Blizzard intrusion.

**Not alerting is harder than alerting.** Each rule has a look-alike it must ignore:

| Rule | Must ignore |
|---|---|
| Brute force then success | Someone who mistypes their password twice |
| New country sign-in | A colleague who regularly works from New Zealand |
| Off-hours privileged grant | The same `DBAdmin` grant made at 2 pm on a Tuesday |
| Database made public | Turning public access **off** |

The traveller case needed a **seven-day learning period**. Without it, the rule alerts on every
traveller's first trip *in the dataset*. That measures where the log starts, not anything the
user did. Details and the remaining limitations are in
[`docs/01-detections.md`](docs/01-detections.md).

## Research report

[**Securing Database-as-a-Service: shared responsibility, exposure and detection**](docs/04-research-report.md).
The report reviews why cloud database breaches are mostly customer-side failures, using the 2019
Capital One, 2024 Snowflake-customer and 2024 Midnight Blizzard incidents as case studies. It
critically evaluates the controls available and uses this lab to show what log-based detection
can and cannot catch.

**▶ Watch the presentation:** [youtu.be/CF2NkH50zOU](https://youtu.be/CF2NkH50zOU). A 7-slide
recorded walkthrough of the research and the detection lab.

**Slides:** [`docs/presentation.pptx`](docs/presentation.pptx), with the spoken script in each
slide's speaker notes.

## Quick start

Requires Python 3.10+ and nothing else. SQLite ships with Python.

```bash
python -m src.loglab
```

```bash
python -m unittest discover -s tests -v
```

Running `loglab` builds `data/loglab.db`, prints the alerts, and writes
[`results/alerts.csv`](results/alerts.csv) and [`results/summary.md`](results/summary.md). It
exits non-zero if any planted incident is missed or any benign activity alerts. Open the
database in [DB Browser for SQLite](https://sqlitebrowser.org/) to run the rules by hand.

## Repository layout

```
sql/
  schema.sql            tables, CHECK and FOREIGN KEY constraints
  triggers.sql          real-time, single-event detections
  detections/           windowed and correlated detections (one SELECT per file)
src/
  generate_logs.py      synthetic logs + ground truth
  loglab.py             build, detect, score, report
tests/
  test_detections.py    planted incidents, benign look-alikes, schema constraints
docs/
  01-detections.md               each rule, its ATT&CK mapping, design decisions, limitations
  02-research-report-outline.md  the plan the report was written from
  03-presentation-outline.md     7-slide talk structure
  04-research-report.md          research report: securing Database-as-a-Service
  presentation.pptx              7-slide deck with speaker notes
```

## Skills demonstrated

- SQL for security analysis: self-joins over time windows, correlated subqueries, CTEs, triggers
- Detection engineering: thresholds, baselines, multi-stage correlation, false-positive control
- Mapping detections to MITRE ATT&CK (T1110.001, T1110.003, T1078.004, T1098)
- Cloud security: shared responsibility, IAM, DBaaS exposure and encryption settings
- Testing detection logic against ground truth
- Research and critical review of cloud security incidents and controls

## Roadmap

- [x] Correlate a successful password spray with the account it compromised
- [ ] Run the same rules over a real audit log from a free-tier cloud account
- [ ] Port the detections to KQL (Microsoft Sentinel) and compare
- [x] Record the 7-slide presentation ([watch on YouTube](https://youtu.be/CF2NkH50zOU))
- [ ] Add a small web form for analysts to log incident triage notes, with validated inserts

## Background

This project grew out of *SIT103 Database Fundamentals* at Deakin University. It extends the
unit's SQL, trigger and research work towards cloud security and security data analysis.

## License

MIT. See [LICENSE](LICENSE).
