-- Cloud Security Log Analysis — schema
-- Target: SQLite 3.35+ (ships with Python 3.10+).
--
-- Timestamps are TEXT in 'YYYY-MM-DD HH:MM:SS', in the organisation's local
-- business time zone. That format sorts and compares correctly as a string and
-- is what SQLite's datetime() returns, so window arithmetic needs no casting.

PRAGMA foreign_keys = ON;

CREATE TABLE users (
    user_id       TEXT PRIMARY KEY,
    department    TEXT NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
    home_country  TEXT NOT NULL CHECK (length(home_country) = 2)
);

-- Identity provider sign-in log (shape modelled on Entra ID / Okta exports).
-- user_id is deliberately NOT a foreign key: attackers try usernames that do
-- not exist, and those attempts are evidence, not bad data.
CREATE TABLE signin_events (
    event_id   INTEGER PRIMARY KEY,
    ts         TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    source_ip  TEXT NOT NULL,
    country    TEXT NOT NULL CHECK (length(country) = 2),
    result     TEXT NOT NULL CHECK (result IN ('success', 'failure'))
);
CREATE INDEX ix_signin_user_ts ON signin_events (user_id, ts);
CREATE INDEX ix_signin_ip_ts   ON signin_events (source_ip, ts);

-- Cloud control-plane audit log: identity and access management changes.
CREATE TABLE iam_changes (
    change_id  INTEGER PRIMARY KEY,
    ts         TEXT NOT NULL,
    actor      TEXT NOT NULL REFERENCES users (user_id),
    target     TEXT NOT NULL,
    action     TEXT NOT NULL CHECK (action IN ('GrantRole', 'RevokeRole',
                                               'CreateAccessKey', 'DeleteAccessKey')),
    role       TEXT
);

-- Cloud control-plane audit log: managed database (DBaaS) configuration changes.
CREATE TABLE db_config_changes (
    change_id    INTEGER PRIMARY KEY,
    ts           TEXT NOT NULL,
    actor        TEXT NOT NULL REFERENCES users (user_id),
    db_instance  TEXT NOT NULL,
    setting      TEXT NOT NULL,
    old_value    TEXT,
    new_value    TEXT NOT NULL
);

CREATE TABLE alerts (
    alert_id   INTEGER PRIMARY KEY,
    detection  TEXT NOT NULL,
    severity   TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    ts         TEXT NOT NULL,
    entity     TEXT NOT NULL,
    detail     TEXT NOT NULL,
    UNIQUE (detection, ts, entity)
);
