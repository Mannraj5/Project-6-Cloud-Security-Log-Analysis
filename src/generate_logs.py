"""Synthetic cloud identity and audit logs with planted incidents.

Fourteen days of ordinary activity for a 20-person organisation, plus a small
number of planted incidents whose exact timestamps are known. Because the
ground truth is known, the detections can be scored: every planted incident
must alert, and nothing benign may.

All IP addresses come from the RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24), so none of them belong to a real host.

Run directly to write the logs as CSV into data/:
    python -m src.generate_logs
"""

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

SEED = 103
START = datetime(2026, 9, 1)          # a Tuesday
DAYS = 14
FMT = "%Y-%m-%d %H:%M:%S"

USERS = [
    # user_id,      department,   is_admin, home_country
    ("a.chen",       "finance",     0, "AU"),
    ("b.okafor",     "finance",     0, "AU"),
    ("c.silva",      "sales",       0, "AU"),
    ("d.murphy",     "sales",       0, "AU"),
    ("e.kowalski",   "sales",       0, "AU"),
    ("f.haddad",     "marketing",   0, "AU"),
    ("g.tanaka",     "marketing",   0, "AU"),
    ("h.brown",      "hr",          0, "AU"),
    ("i.singh",      "hr",          0, "AU"),
    ("j.nguyen",     "engineering", 0, "AU"),
    ("k.patel",      "engineering", 0, "AU"),   # regular traveller to NZ
    ("l.garcia",     "engineering", 0, "AU"),
    ("m.rossi",      "engineering", 0, "AU"),   # account compromised in incident 1
    ("n.ali",        "engineering", 0, "AU"),
    ("o.smith",      "support",     0, "AU"),
    ("p.wilson",     "support",     0, "AU"),
    ("q.lee",        "support",     0, "AU"),
    ("r.jones",      "operations",  0, "AU"),
    ("s.martin",     "operations",  0, "AU"),
    ("it.admin",     "it",          1, "AU"),
]

TRAVELLER_NZ_IP = "192.0.2.200"
BRUTE_FORCE_IP = "198.51.100.77"
SPRAY_IP = "203.0.113.250"


def _ts(dt):
    return dt.strftime(FMT)


def _home_ip(index):
    return f"192.0.2.{10 + index}"


def generate(seed=SEED):
    """Return {'users': [...], 'signin_events': [...], 'iam_changes': [...],
    'db_config_changes': [...], 'expected_alerts': [...]} as lists of tuples."""
    rng = random.Random(seed)
    signins, iam, config = [], [], []

    # --- Ordinary activity -------------------------------------------------
    for day in range(DAYS):
        date = START + timedelta(days=day)
        if date.weekday() >= 5:            # no routine work at weekends
            continue
        for index, (user, _dept, _admin, country) in enumerate(USERS):
            ip = _home_ip(index)
            for session in range(rng.randint(1, 3)):
                at = date + timedelta(hours=rng.randint(8, 17), minutes=rng.randint(0, 59),
                                      seconds=rng.randint(0, 59))
                # Typos happen: one or two failures, first session of the day only,
                # so a user never accumulates enough to look like an attack.
                if session == 0 and rng.random() < 0.10:
                    for back in range(rng.randint(1, 2), 0, -1):
                        signins.append((_ts(at - timedelta(seconds=40 * back)),
                                        user, ip, country, "failure"))
                signins.append((_ts(at), user, ip, country, "success"))

    # The traveller signs in from New Zealand inside the learning period and
    # again later. The second trip must NOT alert: the country is no longer new.
    signins.append(("2026-09-02 10:15:00", "k.patel", TRAVELLER_NZ_IP, "NZ", "success"))
    signins.append(("2026-09-11 09:05:00", "k.patel", TRAVELLER_NZ_IP, "NZ", "success"))

    # Routine admin work during business hours, including a privileged grant —
    # the off-hours rule must stay quiet for it.
    iam.append(("2026-09-03 10:20:00", "it.admin", "c.silva", "GrantRole", "Reader"))
    iam.append(("2026-09-08 14:00:00", "it.admin", "n.ali", "GrantRole", "DBAdmin"))
    iam.append(("2026-09-09 11:30:00", "it.admin", "q.lee", "RevokeRole", "Reader"))
    config.append(("2026-09-04 15:00:00", "it.admin", "prod-customers-db",
                   "backup_retention_days", "7", "14"))
    # Hardening, not exposure: switching public access OFF must not alert.
    config.append(("2026-09-07 09:40:00", "it.admin", "staging-db",
                   "publicly_accessible", "true", "false"))

    # --- Incident 1: brute force -> new country -> privilege -> exposure -----
    # 8 failures 30 s apart against one account, then a success.
    t0 = datetime(2026, 9, 10, 2, 10, 0)
    for i in range(8):
        signins.append((_ts(t0 + timedelta(seconds=30 * i)),
                        "m.rossi", BRUTE_FORCE_IP, "NL", "failure"))
    signins.append(("2026-09-10 02:14:30", "m.rossi", BRUTE_FORCE_IP, "NL", "success"))
    iam.append(("2026-09-10 02:31:00", "m.rossi", "m.rossi", "GrantRole", "DBAdmin"))
    config.append(("2026-09-10 02:40:00", "m.rossi", "prod-customers-db",
                   "publicly_accessible", "false", "true"))

    # --- Incident 2: password spray — one failure each across 12 accounts ----
    # then the guessed password works for one of them. That account sees only
    # one failure, so per-account rules stay quiet; only correlating on the
    # spraying IP catches it.
    sprayed = [u[0] for u in USERS[:12]]
    s0 = datetime(2026, 9, 11, 14, 0, 0)
    for i, user in enumerate(sprayed):
        signins.append((_ts(s0 + timedelta(seconds=90 * i)), user, SPRAY_IP, "US", "failure"))
    signins.append(("2026-09-11 14:22:00", "f.haddad", SPRAY_IP, "US", "success"))

    # --- Incident 3: encryption at rest disabled during business hours -------
    config.append(("2026-09-14 11:00:00", "j.nguyen", "analytics-db",
                   "storage_encrypted", "true", "false"))

    signins.sort(key=lambda row: row[0])

    expected = [
        ("brute_force_then_success",          "m.rossi"),
        ("new_country_signin",                "m.rossi"),
        ("offhours_privileged_grant",         "m.rossi"),
        ("compromise_then_privilege_change",  "m.rossi"),
        ("db_made_public",                    "prod-customers-db"),
        ("password_spray",                    SPRAY_IP),
        ("spray_then_success",                "f.haddad"),
        ("new_country_signin",                "f.haddad"),
        ("db_encryption_disabled",            "analytics-db"),
    ]

    return {
        "users": list(USERS),
        "signin_events": signins,
        "iam_changes": iam,
        "db_config_changes": config,
        "expected_alerts": expected,
    }


HEADERS = {
    "users": ["user_id", "department", "is_admin", "home_country"],
    "signin_events": ["ts", "user_id", "source_ip", "country", "result"],
    "iam_changes": ["ts", "actor", "target", "action", "role"],
    "db_config_changes": ["ts", "actor", "db_instance", "setting", "old_value", "new_value"],
}


def write_csv(data, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for table, header in HEADERS.items():
        with open(out_dir / f"{table}.csv", "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(header)
            writer.writerows(data[table])


if __name__ == "__main__":
    root = Path(__file__).resolve().parent.parent
    data = generate()
    write_csv(data, root / "data")
    print(f"Wrote {len(data['signin_events'])} sign-ins, {len(data['iam_changes'])} IAM changes, "
          f"{len(data['db_config_changes'])} DB config changes to {root / 'data'}")
