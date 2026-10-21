-- Real-time detections.
--
-- These fire inside the INSERT that records the event, so the alert exists
-- the moment the log line lands. They suit single-event rules: one row is
-- enough to know something is wrong. Rules that need a window of history
-- (counting failures, comparing against a baseline) live in sql/detections/.

-- A managed database was made reachable from the internet.
CREATE TRIGGER trg_db_made_public
AFTER INSERT ON db_config_changes
WHEN NEW.setting = 'publicly_accessible' AND NEW.new_value = 'true'
BEGIN
    INSERT OR IGNORE INTO alerts (detection, severity, ts, entity, detail)
    VALUES ('db_made_public', 'critical', NEW.ts, NEW.db_instance,
            printf('%s set publicly_accessible=true on %s', NEW.actor, NEW.db_instance));
END;

-- Encryption at rest was switched off on a managed database.
CREATE TRIGGER trg_db_encryption_disabled
AFTER INSERT ON db_config_changes
WHEN NEW.setting = 'storage_encrypted' AND NEW.new_value = 'false'
BEGIN
    INSERT OR IGNORE INTO alerts (detection, severity, ts, entity, detail)
    VALUES ('db_encryption_disabled', 'high', NEW.ts, NEW.db_instance,
            printf('%s set storage_encrypted=false on %s', NEW.actor, NEW.db_instance));
END;

-- A privileged role was granted outside business hours (08:00-17:59, Mon-Fri).
-- strftime('%w') is 0 for Sunday and 6 for Saturday.
CREATE TRIGGER trg_offhours_privileged_grant
AFTER INSERT ON iam_changes
WHEN NEW.action = 'GrantRole'
 AND NEW.role IN ('Owner', 'Administrator', 'DBAdmin')
 AND (CAST(strftime('%H', NEW.ts) AS INTEGER) NOT BETWEEN 8 AND 17
      OR strftime('%w', NEW.ts) IN ('0', '6'))
BEGIN
    INSERT OR IGNORE INTO alerts (detection, severity, ts, entity, detail)
    VALUES ('offhours_privileged_grant', 'high', NEW.ts, NEW.actor,
            printf('%s granted %s to %s outside business hours', NEW.actor, NEW.role, NEW.target));
END;
