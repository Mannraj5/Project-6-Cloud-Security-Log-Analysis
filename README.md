# Cloud Security Log Analysis

**SQL detections over cloud identity and audit logs, scored against planted incidents with known
timestamps, plus research into how managed cloud databases (DBaaS) get exposed.**

Most cloud database breaches do not start with a broken provider. They start with a customer
setting: a database left reachable from the internet, a role granted too widely, an account
taken over by password guessing. All of these leave a trace in the logs. This project asks
whether plain SQL can find them, and how to tell when it can't.

```
450 sign-ins, 4 IAM changes, 4 DB config changes loaded

[critical] 2026-09-10 02:31:00  compromise_then_privilege_change   m.rossi            GrantRole DBAdmin on m.rossi, 16 minutes after a suspected brute-forced sign-in
[critical] 2026-09-10 02:40:00  db_made_public                     prod-customers-db  m.rossi set publicly_accessible=true on prod-customers-db
[    high] 2026-09-10 02:14:30  brute_force_then_success           m.rossi            8 failed sign-ins in the 10 minutes before a success from 198.51.100.77 (NL)
[    high] 2026-09-10 02:31:00  offhours_privileged_grant          m.rossi            m.rossi granted DBAdmin to m.rossi outside business hours
[    high] 2026-09-11 14:00:00  password_spray                     203.0.113.250      12 failed sign-ins across 12 accounts within 30 minutes
[    high] 2026-09-14 11:00:00  db_encryption_disabled             analytics-db       j.nguyen set storage_encrypted=false on analytics-db
[  medium] 2026-09-10 02:14:30  new_country_signin                 m.rossi            First successful sign-in from NL (home AU) via 198.51.100.77

Missed: 0   Unexpected: 0
```

**7 of 7 planted incidents detected, 0 alerts on benign activity, 11 of 11 tests passing.**
The full attack chain is visible in order: 30 minutes from the first failed password to the
customer database being made public.

---

## What it does

1. **Generates 14 days of synthetic logs** for a 20-person organisation: identity-provider
   sign-ins, IAM changes and managed-database configuration changes
   ([`src/generate_logs.py`](src/generate_logs.py)). All IPs come from the RFC 5737
   documentation ranges.
2. **Plants three incidents** with known timestamps:
   - **An attack chain:** brute force → sign-in from a new country → the attacker grants itself
     `DBAdmin` at 2:31 am → the production customer database is made public.
   - **A password spray** across 12 accounts from one IP.
   - **Encryption at rest switched off** on an analytics database.
3. **Detects them with SQL only.** There are three [triggers](sql/triggers.sql) that alert the
   moment a row is inserted, and four [batch queries](sql/detections/) for rules that need a time
   window or history.
4. **Scores the result.** Every planted incident must alert, and nothing benign may. Each rule
   has a benign look-alike in the data that it has to ignore.

## The interesting part: the look-alikes

Catching the attack is easy. Not alerting on the people who look like it is harder:

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

## Quick start

Requires Python 3.10+ and nothing else. SQLite ships with Python.

```bash
python -m src.loglab
```

```bash
python -m unittest discover -s tests -v
```

Running `loglab` builds `data/loglab.db`, prints the alerts, and writes
[`results/alerts.csv`](results/) and `results/summary.md`. It exits non-zero if any planted
incident is missed or any benign activity alerts. Open the database in
[DB Browser for SQLite](https://sqlitebrowser.org/) to run the rules by hand.

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
  02-research-report-outline.md  research: securing Database-as-a-Service
  03-presentation-outline.md     7-slide talk structure
```

## Skills demonstrated

- SQL for security analysis: self-joins over time windows, correlated subqueries, CTEs, triggers
- Detection engineering: thresholds, baselines, correlation, false-positive control
- Mapping detections to MITRE ATT&CK (T1110.001, T1110.003, T1078.004, T1098)
- Cloud security concepts: shared responsibility, IAM, DBaaS exposure and encryption settings
- Testing detection logic against ground truth

## Roadmap

- [ ] Run the same rules over a real audit log from a free-tier cloud account
- [ ] Port the detections to KQL (Microsoft Sentinel) and compare
- [ ] Correlate a successful password spray with the account it compromised
- [ ] Add a small web form for analysts to log incident triage notes, with validated inserts

## Background

This project grew out of *SIT103 Database Fundamentals* at Deakin University. It extends the
unit's SQL, trigger and research work towards cloud security and security data analysis.

## License

MIT. See [LICENSE](LICENSE).
