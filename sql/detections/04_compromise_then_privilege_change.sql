-- Suspected compromise followed by a privilege change.
-- Question: did an account change IAM permissions within 60 minutes of a
-- sign-in that looked brute-forced?
-- ATT&CK: T1110.001 then T1098 Account Manipulation
--
-- This is a correlation rule: neither half is critical on its own, the
-- sequence is. It reuses the brute-force logic from 01 rather than reading
-- the alerts table, so it gives the same answer however the rules are ordered.
WITH suspected AS (
    SELECT s.user_id, s.ts
    FROM signin_events AS s
    JOIN signin_events AS f
      ON f.user_id = s.user_id
     AND f.result  = 'failure'
     AND f.ts >= datetime(s.ts, '-10 minutes')
     AND f.ts <  s.ts
    WHERE s.result = 'success'
    GROUP BY s.event_id
    HAVING COUNT(f.event_id) >= 5
)
SELECT 'compromise_then_privilege_change' AS detection,
       'critical'                         AS severity,
       i.ts                               AS ts,
       i.actor                            AS entity,
       printf('%s %s on %s, %d minutes after a suspected brute-forced sign-in',
              i.action, COALESCE(i.role, '-'), i.target,
              CAST((julianday(i.ts) - julianday(c.ts)) * 1440 AS INTEGER)) AS detail
FROM iam_changes AS i
JOIN suspected AS c
  ON c.user_id = i.actor
 AND i.ts >= c.ts
 AND i.ts <= datetime(c.ts, '+60 minutes')
