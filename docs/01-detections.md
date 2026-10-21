# Detections

Eight rules over three log sources. Each one answers a question an analyst would ask, and each
has a benign look-alike in the dataset that it must stay quiet on — a rule is only as good as
the thing it ignores.

| # | Detection | Type | Severity | ATT&CK | Benign look-alike it must ignore |
|---|---|---|---|---|---|
| 1 | `brute_force_then_success` | Batch SQL | high | T1110.001 | Users who mistype their password once or twice |
| 2 | `password_spray` | Batch SQL | high | T1110.003 | Ordinary failures, which come from one user's own IP |
| 3 | `new_country_signin` | Batch SQL | medium | T1078.004 | A colleague who regularly works from New Zealand |
| 4 | `compromise_then_privilege_change` | Batch SQL (correlation) | critical | T1110.001 → T1098 | Admin role changes not preceded by a suspicious sign-in |
| 5 | `spray_then_success` | Batch SQL (correlation) | critical | T1110.003 → T1078.004 | Sprayed accounts whose own users sign in normally afterwards from their usual IP |
| 6 | `offhours_privileged_grant` | Trigger | high | T1098.003 | The same privileged grant made at 2 pm on a Tuesday |
| 7 | `db_made_public` | Trigger | critical | — (misconfiguration) | Turning public access **off** on a staging database |
| 8 | `db_encryption_disabled` | Trigger | high | — (misconfiguration) | Routine changes such as backup retention |

## Why some rules are triggers and some are queries

A trigger sees one row: the one being inserted. That is enough when a single event is the
whole story — a database flipped to public needs no context to be alarming — and it means the
alert exists the instant the log line lands.

Counting failures in a window or comparing against a user's history needs other rows, so those
rules are SELECTs run over the table. In production that is a scheduled query; the SQL is the
same.

## Design decisions worth defending

**The learning period in rule 3.** Without it, every traveller alerts on their first trip *in
the dataset*, which measures where the log starts, not anything the user did. Seven days is
arbitrary; in practice it would be tuned against the false-positive rate.

**Rule 4 recomputes rule 1 rather than reading the alerts table.** Reading alerts would make the
result depend on which file ran first. Recomputing costs a join and removes the ordering bug
entirely.

**`user_id` in `signin_events` is not a foreign key.** Attackers try usernames that do not
exist. Rejecting those rows would throw away the evidence.

**One spray, one alert.** Every failure is tried as the start of a 30-minute window, so a single
spray qualifies many times. Only the earliest window per IP is reported.

## Known limitations

- **Timestamps are local business time.** Real cloud logs are UTC; the off-hours rule would need
  the organisation's time zone, and a multi-region organisation has more than one.
- **The spray correlation keys on one IP.** Rule 5 closed the gap where a successful spray went
  unnoticed: the account that fell sees only one failure, so rule 1 is blind to it. But rule 5
  joins on the source IP, and real sprays such as Midnight Blizzard's in 2024 rotate through
  residential proxies so that no single IP stands out. Catching that needs a different signal,
  such as many accounts failing at a similar rate from many IPs at once.
- **Thresholds are fixed** (5 failures / 10 min, 5 accounts / 30 min). An attacker who knows them
  stays under them. Per-user baselines would be harder to evade.
- **No IP reputation or geolocation lookup.** Country is taken as given in the log.
- **Synthetic data.** It proves the logic, not real-world precision. The next step is the same
  rules over a public dataset or a free-tier cloud account's own audit log.
