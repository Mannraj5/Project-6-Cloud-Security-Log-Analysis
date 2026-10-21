-- Brute force followed by a successful sign-in.
-- Question: did any account sign in successfully after 5 or more failures in
-- the 10 minutes before it?
-- ATT&CK: T1110.001 Brute Force: Password Guessing
SELECT 'brute_force_then_success' AS detection,
       'high'                     AS severity,
       s.ts                       AS ts,
       s.user_id                  AS entity,
       printf('%d failed sign-ins in the 10 minutes before a success from %s (%s)',
              COUNT(f.event_id), s.source_ip, s.country) AS detail
FROM signin_events AS s
JOIN signin_events AS f
  ON f.user_id = s.user_id
 AND f.result  = 'failure'
 AND f.ts >= datetime(s.ts, '-10 minutes')
 AND f.ts <  s.ts
WHERE s.result = 'success'
GROUP BY s.event_id
HAVING COUNT(f.event_id) >= 5
