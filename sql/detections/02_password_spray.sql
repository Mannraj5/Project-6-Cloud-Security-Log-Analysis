-- Password spray.
-- Question: did one source IP fail against 5 or more different accounts
-- within 30 minutes? Brute force hammers one account; a spray tries one or two
-- passwords across many, staying under per-account lockout thresholds.
-- ATT&CK: T1110.003 Brute Force: Password Spraying
--
-- Every failure is tried as the start of a 30-minute window; only the earliest
-- qualifying window per IP is reported, so one spray produces one alert.
WITH windows AS (
    SELECT a.source_ip                AS source_ip,
           a.ts                       AS window_start,
           COUNT(DISTINCT b.user_id)  AS accounts,
           COUNT(*)                   AS attempts
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
SELECT 'password_spray' AS detection,
       'high'           AS severity,
       w.window_start   AS ts,
       w.source_ip      AS entity,
       printf('%d failed sign-ins across %d accounts within 30 minutes',
              w.attempts, w.accounts) AS detail
FROM windows AS w
WHERE w.window_start = (SELECT MIN(w2.window_start)
                        FROM windows AS w2
                        WHERE w2.source_ip = w.source_ip)
