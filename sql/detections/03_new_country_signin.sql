-- First successful sign-in from a new country.
-- Question: did an account sign in successfully from a country it has never
-- signed in from before, other than its home country?
-- ATT&CK: T1078.004 Valid Accounts: Cloud Accounts
--
-- The first 7 days of the log are a learning period and never alert. Without
-- it, every regular traveller fires on their first trip in the dataset — the
-- rule would be measuring the start of the log, not anything the user did.
SELECT 'new_country_signin' AS detection,
       'medium'             AS severity,
       s.ts                 AS ts,
       s.user_id            AS entity,
       printf('First successful sign-in from %s (home %s) via %s',
              s.country, u.home_country, s.source_ip) AS detail
FROM signin_events AS s
JOIN users AS u ON u.user_id = s.user_id
WHERE s.result = 'success'
  AND s.country <> u.home_country
  AND s.ts >= datetime((SELECT MIN(ts) FROM signin_events), '+7 days')
  AND NOT EXISTS (
        SELECT 1
        FROM signin_events AS p
        WHERE p.user_id = s.user_id
          AND p.result  = 'success'
          AND p.country = s.country
          AND p.ts      < s.ts)
