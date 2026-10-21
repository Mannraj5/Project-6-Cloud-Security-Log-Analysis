-- Successful sign-in from an IP that was password spraying.
-- Question: did any account sign in successfully from an IP that, in the two
-- hours before, failed against 5 or more different accounts?
-- ATT&CK: T1110.003 Brute Force: Password Spraying, then T1078.004 Valid Accounts: Cloud Accounts
--
-- Rule 02 sees the spray; it cannot say whether it worked. Rule 01 cannot see
-- the compromise either: a spray tries each account once or twice, so the
-- account that falls never reaches 5 failures. Joining on the source IP is
-- what connects the two halves.
WITH spray_windows AS (
    SELECT a.source_ip, a.ts AS window_start
    FROM signin_events AS a
    JOIN signin_events AS b
      ON b.source_ip = a.source_ip
     AND b.result    = 'failure'
     AND b.ts >= a.ts
     AND b.ts <  datetime(a.ts, '+30 minutes')
    WHERE a.result = 'failure'
    GROUP BY a.event_id
    HAVING COUNT(DISTINCT b.user_id) >= 5
)
SELECT 'spray_then_success' AS detection,
       'critical'           AS severity,
       s.ts                 AS ts,
       s.user_id            AS entity,
       printf('Successful sign-in from %s, which began spraying passwords across accounts at %s',
              s.source_ip, MIN(w.window_start)) AS detail
FROM signin_events AS s
JOIN spray_windows AS w
  ON w.source_ip = s.source_ip
 AND s.ts >= w.window_start
 AND s.ts <= datetime(w.window_start, '+2 hours')
WHERE s.result = 'success'
GROUP BY s.event_id
