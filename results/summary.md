# Alert summary

| Severity | Time | Detection | Entity | Detail |
|---|---|---|---|---|
| critical | 2026-09-10 02:31:00 | `compromise_then_privilege_change` | `m.rossi` | GrantRole DBAdmin on m.rossi, 16 minutes after a suspected brute-forced sign-in |
| critical | 2026-09-10 02:40:00 | `db_made_public` | `prod-customers-db` | m.rossi set publicly_accessible=true on prod-customers-db |
| critical | 2026-09-11 14:22:00 | `spray_then_success` | `f.haddad` | Successful sign-in from 203.0.113.250, which began spraying passwords across accounts at 2026-09-11 14:00:00 |
| high | 2026-09-10 02:14:30 | `brute_force_then_success` | `m.rossi` | 8 failed sign-ins in the 10 minutes before a success from 198.51.100.77 (NL) |
| high | 2026-09-10 02:31:00 | `offhours_privileged_grant` | `m.rossi` | m.rossi granted DBAdmin to m.rossi outside business hours |
| high | 2026-09-11 14:00:00 | `password_spray` | `203.0.113.250` | 12 failed sign-ins across 12 accounts within 30 minutes |
| high | 2026-09-14 11:00:00 | `db_encryption_disabled` | `analytics-db` | j.nguyen set storage_encrypted=false on analytics-db |
| medium | 2026-09-10 02:14:30 | `new_country_signin` | `m.rossi` | First successful sign-in from NL (home AU) via 198.51.100.77 |
| medium | 2026-09-11 14:22:00 | `new_country_signin` | `f.haddad` | First successful sign-in from US (home AU) via 203.0.113.250 |

Planted incidents missed: **0**  
Alerts on benign activity: **0**
