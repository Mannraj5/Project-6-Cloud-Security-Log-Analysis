"""Build the log database, run every detection, and report the alerts.

    python -m src.loglab            # build data/loglab.db, write results/

The pipeline is deliberately boring: schema, triggers, load, then each SQL
file in sql/detections/ is run as a plain SELECT and its rows are stored in
the alerts table. The detection logic lives entirely in SQL, so an analyst
can open the database and run any rule by hand.
"""

import csv
import sqlite3
from pathlib import Path

from src.generate_logs import generate

ROOT = Path(__file__).resolve().parent.parent
SQL_DIR = ROOT / "sql"
DETECTIONS_DIR = SQL_DIR / "detections"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def build(db_path=":memory:", data=None):
    """Create the database, load the logs, run all detections.
    Returns an open sqlite3 connection."""
    data = data if data is not None else generate()
    if db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        Path(db_path).unlink(missing_ok=True)

    conn = sqlite3.connect(db_path)
    conn.executescript((SQL_DIR / "schema.sql").read_text(encoding="utf-8"))
    conn.executescript((SQL_DIR / "triggers.sql").read_text(encoding="utf-8"))

    # Triggers fire during these inserts.
    conn.executemany("INSERT INTO users VALUES (?, ?, ?, ?)", data["users"])
    conn.executemany("INSERT INTO signin_events (ts, user_id, source_ip, country, result) "
                     "VALUES (?, ?, ?, ?, ?)", data["signin_events"])
    conn.executemany("INSERT INTO iam_changes (ts, actor, target, action, role) "
                     "VALUES (?, ?, ?, ?, ?)", data["iam_changes"])
    conn.executemany("INSERT INTO db_config_changes "
                     "(ts, actor, db_instance, setting, old_value, new_value) "
                     "VALUES (?, ?, ?, ?, ?, ?)", data["db_config_changes"])

    for rule in sorted(DETECTIONS_DIR.glob("*.sql")):
        rows = conn.execute(rule.read_text(encoding="utf-8")).fetchall()
        conn.executemany("INSERT OR IGNORE INTO alerts (detection, severity, ts, entity, detail) "
                         "VALUES (?, ?, ?, ?, ?)", rows)
    conn.commit()
    return conn


def alerts(conn):
    rows = conn.execute("SELECT detection, severity, ts, entity, detail FROM alerts").fetchall()
    return sorted(rows, key=lambda r: (SEVERITY_ORDER[r[1]], r[2]))


def score(found, expected):
    """Compare (detection, entity) pairs. Returns (missed, unexpected)."""
    found_pairs = {(r[0], r[3]) for r in found}
    expected_pairs = set(expected)
    return sorted(expected_pairs - found_pairs), sorted(found_pairs - expected_pairs)


def write_results(rows, missed, unexpected, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "alerts.csv", "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["detection", "severity", "ts", "entity", "detail"])
        writer.writerows(rows)

    lines = ["# Alert summary", "",
             "| Severity | Time | Detection | Entity | Detail |",
             "|---|---|---|---|---|"]
    lines += [f"| {r[1]} | {r[2]} | `{r[0]}` | `{r[3]}` | {r[4]} |" for r in rows]
    lines += ["", f"Planted incidents missed: **{len(missed)}**  ",
              f"Alerts on benign activity: **{len(unexpected)}**"]
    for label, items in (("Missed", missed), ("Unexpected", unexpected)):
        lines += [f"- {label}: `{d}` on `{e}`" for d, e in items]
    (out_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    data = generate()
    conn = build(ROOT / "data" / "loglab.db", data)
    rows = alerts(conn)
    missed, unexpected = score(rows, data["expected_alerts"])
    write_results(rows, missed, unexpected, ROOT / "results")

    print(f"{len(data['signin_events'])} sign-ins, {len(data['iam_changes'])} IAM changes, "
          f"{len(data['db_config_changes'])} DB config changes loaded\n")
    for detection, severity, ts, entity, detail in rows:
        print(f"[{severity:>8}] {ts}  {detection:<34} {entity:<20} {detail}")
    print(f"\nMissed: {len(missed)}   Unexpected: {len(unexpected)}")
    print(f"Wrote {ROOT / 'results' / 'alerts.csv'} and summary.md")
    conn.close()
    return 0 if not missed and not unexpected else 1


if __name__ == "__main__":
    raise SystemExit(main())
