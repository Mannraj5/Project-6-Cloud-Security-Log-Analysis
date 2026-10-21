"""Every planted incident must alert; nothing benign may.

    python -m unittest discover -s tests -v
"""

import sqlite3
import unittest

from src.generate_logs import generate
from src.loglab import alerts, build, score


class DetectionScoring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = generate()
        cls.conn = build(":memory:", cls.data)
        cls.rows = alerts(cls.conn)
        cls.pairs = {(r[0], r[3]) for r in cls.rows}

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()

    def test_no_planted_incident_is_missed(self):
        missed, _ = score(self.rows, self.data["expected_alerts"])
        self.assertEqual(missed, [])

    def test_no_alert_on_benign_activity(self):
        _, unexpected = score(self.rows, self.data["expected_alerts"])
        self.assertEqual(unexpected, [])

    def test_each_incident_alerts_exactly_once(self):
        self.assertEqual(len(self.rows), len(self.data["expected_alerts"]))

    # --- The boundaries: the benign cases that look closest to an attack ------

    def test_traveller_second_trip_is_not_new(self):
        self.assertNotIn(("new_country_signin", "k.patel"), self.pairs)

    def test_business_hours_privileged_grant_is_quiet(self):
        self.assertNotIn(("offhours_privileged_grant", "it.admin"), self.pairs)

    def test_turning_public_access_off_is_quiet(self):
        self.assertNotIn(("db_made_public", "staging-db"), self.pairs)

    def test_sprayed_users_do_not_look_brute_forced(self):
        brute = {e for d, e in self.pairs if d == "brute_force_then_success"}
        self.assertEqual(brute, {"m.rossi"})

    # --- Triggers fire at insert time, not after the batch rules -------------

    def test_trigger_alerts_the_moment_the_row_lands(self):
        conn = build(":memory:", {**self.data, "db_config_changes": []})
        conn.execute("DELETE FROM alerts")
        conn.execute("INSERT INTO db_config_changes "
                     "(ts, actor, db_instance, setting, old_value, new_value) "
                     "VALUES ('2026-09-15 12:00:00', 'it.admin', 'test-db', "
                     "'publicly_accessible', 'false', 'true')")
        row = conn.execute("SELECT detection, entity FROM alerts").fetchone()
        self.assertEqual(row, ("db_made_public", "test-db"))
        conn.close()

    def test_weekend_grant_in_business_hours_alerts(self):
        conn = build(":memory:", {**self.data, "iam_changes": []})
        conn.execute("DELETE FROM alerts")
        conn.execute("INSERT INTO iam_changes (ts, actor, target, action, role) "
                     "VALUES ('2026-09-12 10:00:00', 'it.admin', 'q.lee', 'GrantRole', 'Owner')")
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 1)
        conn.close()

    # --- The schema rejects bad data rather than storing it ------------------

    def test_schema_rejects_unknown_result(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("INSERT INTO signin_events (ts, user_id, source_ip, country, result) "
                              "VALUES ('2026-09-15 09:00:00', 'a.chen', '192.0.2.10', 'AU', 'maybe')")

    def test_schema_rejects_change_by_unknown_actor(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute("INSERT INTO iam_changes (ts, actor, target, action, role) "
                              "VALUES ('2026-09-15 09:00:00', 'nobody', 'a.chen', 'GrantRole', 'Reader')")


if __name__ == "__main__":
    unittest.main()
