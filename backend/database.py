import os
import json
import sqlite3
import logging
from typing import Dict, List, Optional
from datetime import datetime, timezone, timedelta
from contextlib import contextmanager
from pathlib import Path

logger = logging.getLogger('threatiq')

DB_PATH = os.getenv('DB_PATH', os.path.join(os.path.dirname(__file__), 'threatiq.db'))


# ══════════════════════════════════════════════════════════════
# DATABASE CLASS
# ══════════════════════════════════════════════════════════════

class Database:

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()
        logger.info(f"Database initialized at {self.db_path}")

    # ── Context Manager ────────────────────────────────────────

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA synchronous=NORMAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ── Schema ─────────────────────────────────────────────────

    def _init_db(self):
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    email           TEXT    UNIQUE NOT NULL,
                    username        TEXT    UNIQUE,
                    password        TEXT    NOT NULL,
                    role            TEXT    NOT NULL DEFAULT 'analyst',
                    is_active       INTEGER NOT NULL DEFAULT 1,
                    created_at      TEXT    NOT NULL,
                    last_login      TEXT,
                    login_count     INTEGER NOT NULL DEFAULT 0,
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    locked_until    TEXT
                );

                CREATE TABLE IF NOT EXISTS analyses (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id         INTEGER NOT NULL,
                    input_data      TEXT    NOT NULL,
                    input_type      TEXT    NOT NULL,
                    result          TEXT    NOT NULL,
                    threat_level    TEXT,
                    confidence      INTEGER,
                    ttp_count       INTEGER,
                    ioc_count       INTEGER,
                    processing_ms   INTEGER,
                    created_at      TEXT    NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS iocs (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id      INTEGER NOT NULL,
                    ioc_type         TEXT    NOT NULL,
                    ioc_value        TEXT    NOT NULL,
                    risk_level       TEXT,
                    confidence_boost INTEGER DEFAULT 0,
                    validation_data  TEXT,
                    created_at       TEXT    NOT NULL,
                    FOREIGN KEY (analysis_id) REFERENCES analyses(id)
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id     INTEGER,
                    action      TEXT    NOT NULL,
                    detail      TEXT,
                    ip_address  TEXT,
                    created_at  TEXT    NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_analyses_user
                    ON analyses(user_id);
                CREATE INDEX IF NOT EXISTS idx_analyses_created
                    ON analyses(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_analyses_threat
                    ON analyses(threat_level);
                CREATE INDEX IF NOT EXISTS idx_iocs_analysis
                    ON iocs(analysis_id);
                CREATE INDEX IF NOT EXISTS idx_iocs_value
                    ON iocs(ioc_value);
                CREATE INDEX IF NOT EXISTS idx_audit_user
                    ON audit_log(user_id);
                CREATE INDEX IF NOT EXISTS idx_users_username
                    ON users(username);
            """)

            # Migration: add username column if upgrading from old schema
            try:
                conn.execute("ALTER TABLE users ADD COLUMN username TEXT UNIQUE")
            except sqlite3.OperationalError:
                pass   # column already exists — expected on fresh installs

    # ══════════════════════════════════════════════════════════
    # USER METHODS
    # ══════════════════════════════════════════════════════════

    def create_user(self, email: str, hashed_password: str,
                    role: str = 'analyst', username: str = None) -> int:
        """Create a new user. FIX: accepts optional username parameter."""
        now = datetime.now(timezone.utc).isoformat()
        derived_username = username or email.split('@')[0]
        with self._conn() as conn:
            cursor = conn.execute(
                """INSERT INTO users (email, username, password, role, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (email.lower().strip(), derived_username, hashed_password, role, now)
            )
            user_id = cursor.lastrowid
            self._audit(conn, user_id, 'user_created', f"email={email} username={derived_username}")
            return user_id

    def get_user(self, email: str) -> Optional[Dict]:
        """Lookup by email only (kept for backwards compatibility)."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE email = ? AND is_active = 1",
                (email.lower().strip(),)
            ).fetchone()
            return dict(row) if row else None

    def get_user_by_identifier(self, identifier: str) -> Optional[Dict]:
        """
        FIX: lookup by email OR username.
        auth.py login/register use this instead of get_user().
        """
        identifier = identifier.strip()
        with self._conn() as conn:
            row = conn.execute(
                """SELECT * FROM users
                   WHERE (email = ? OR username = ?) AND is_active = 1""",
                (identifier.lower(), identifier)
            ).fetchone()
            return dict(row) if row else None

    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        with self._conn() as conn:
            row = conn.execute(
                """SELECT id, email, username, role, created_at,
                          last_login, login_count
                   FROM users WHERE id = ?""",
                (user_id,)
            ).fetchone()
            return dict(row) if row else None

    def update_password(self, user_id: int, hashed_password: str):
        """FIX: public method so auth.py doesn't have to access db._conn() directly."""
        with self._conn() as conn:
            conn.execute(
                "UPDATE users SET password = ? WHERE id = ?",
                (hashed_password, user_id)
            )
            self._audit(conn, user_id, 'password_changed')

    def update_login_success(self, user_id: int):
        now = datetime.now(timezone.utc).isoformat()
        with self._conn() as conn:
            conn.execute(
                """UPDATE users
                   SET last_login = ?, login_count = login_count + 1,
                       failed_attempts = 0, locked_until = NULL
                   WHERE id = ?""",
                (now, user_id)
            )
            self._audit(conn, user_id, 'login_success')

    def update_login_failure(self, identifier: str) -> int:
        """
        FIX: accepts email OR username as identifier (matches auth.py usage).
        Returns updated failed_attempts count.
        """
        identifier = identifier.strip()
        with self._conn() as conn:
            conn.execute(
                """UPDATE users
                   SET failed_attempts = failed_attempts + 1
                   WHERE email = ? OR username = ?""",
                (identifier.lower(), identifier)
            )
            row = conn.execute(
                """SELECT id, failed_attempts FROM users
                   WHERE email = ? OR username = ?""",
                (identifier.lower(), identifier)
            ).fetchone()
            if not row:
                return 0
            attempts = row['failed_attempts']
            if attempts >= 5:
                locked_until = (
                    datetime.now(timezone.utc) + timedelta(minutes=15)
                ).isoformat()
                conn.execute(
                    "UPDATE users SET locked_until = ? WHERE id = ?",
                    (locked_until, row['id'])
                )
                self._audit(conn, row['id'], 'account_locked',
                            f"attempts={attempts}")
            return attempts

    def is_account_locked(self, identifier: str) -> bool:
        """
        FIX: accepts email OR username as identifier (matches auth.py usage).
        Auto-unlocks if lock period has expired.
        """
        identifier = identifier.strip()
        with self._conn() as conn:
            row = conn.execute(
                """SELECT id, locked_until FROM users
                   WHERE email = ? OR username = ?""",
                (identifier.lower(), identifier)
            ).fetchone()
            if not row or not row['locked_until']:
                return False
            locked_until = datetime.fromisoformat(row['locked_until'])
            if datetime.now(timezone.utc) < locked_until:
                return True
            # Lock expired — clear it
            conn.execute(
                "UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE id = ?",
                (row['id'],)
            )
            return False

    # ══════════════════════════════════════════════════════════
    # ANALYSIS METHODS
    # ══════════════════════════════════════════════════════════

    def _ensure_user_exists(self, conn, user_id: int):
        """Create a placeholder user if user_id doesn't exist (prevents FOREIGN KEY errors)."""
        row = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                """INSERT OR IGNORE INTO users
                   (id, email, username, password, role, is_active, created_at)
                   VALUES (?, ?, ?, ?, 'analyst', 1, ?)""",
                (user_id,
                 f'user{user_id}@threatiq.local',
                 f'user{user_id}',
                 'placeholder',
                 now)
            )
            logger.warning(f"Auto-created placeholder for missing user_id={user_id}")

    def save_analysis(self, user_id: int, input_data: str,
                      input_type: str, result: Dict) -> int:
        now           = datetime.now(timezone.utc).isoformat()
        threat_level  = result.get('threat_level', 'UNKNOWN')
        confidence    = result.get('overall_confidence', 0)
        ttp_count     = len(result.get('ttps', []))
        ioc_count     = result.get('ioc_summary', {}).get('total_iocs', 0)
        processing_ms = result.get('analysis_metadata', {}).get('processing_time_ms', 0)

        with self._conn() as conn:
            self._ensure_user_exists(conn, user_id)
            cursor = conn.execute(
                """INSERT INTO analyses
                   (user_id, input_data, input_type, result, threat_level,
                    confidence, ttp_count, ioc_count, processing_ms, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (user_id, input_data, input_type, json.dumps(result),
                 threat_level, confidence, ttp_count, ioc_count,
                 processing_ms, now)
            )
            analysis_id = cursor.lastrowid

            # Save individual IOCs
            ioc_validation = result.get('ioc_validation', {})
            for key, ioc_entry in ioc_validation.items():
                conn.execute(
                    """INSERT INTO iocs
                       (analysis_id, ioc_type, ioc_value, risk_level,
                        confidence_boost, validation_data, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        analysis_id,
                        ioc_entry.get('ioc_type', 'unknown'),
                        ioc_entry.get('ioc_value', ''),
                        ioc_entry.get('risk_level', 'unknown'),
                        ioc_entry.get('confidence_boost', 0),
                        json.dumps(ioc_entry.get('sources', {})),
                        now
                    )
                )

            self._audit(conn, user_id, 'analysis_created',
                        f"id={analysis_id} level={threat_level} confidence={confidence}%")

            logger.info(f"Analysis saved | id={analysis_id} | user={user_id}")
            return analysis_id

    def get_analysis(self, analysis_id: int, user_id: int) -> Optional[Dict]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM analyses WHERE id = ? AND user_id = ?",
                (analysis_id, user_id)
            ).fetchone()
            if not row:
                return None
            data = dict(row)
            data['result'] = json.loads(data['result'])
            return data

    def get_history(self, user_id: int, limit: int = 20,
                    offset: int = 0) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT id, input_type, threat_level, confidence,
                          ttp_count, ioc_count, processing_ms, created_at,
                          SUBSTR(input_data, 1, 120) AS input_data
                   FROM analyses
                   WHERE user_id = ?
                   ORDER BY created_at DESC
                   LIMIT ? OFFSET ?""",
                (user_id, min(limit, 100), offset)
            ).fetchall()
            return [dict(row) for row in rows]

    def get_stats(self, user_id: int) -> Dict:
        with self._conn() as conn:
            row = conn.execute(
                """SELECT
                       COUNT(*)  AS total_analyses,
                       AVG(confidence)  AS avg_confidence,
                       MAX(confidence)  AS max_confidence,
                       SUM(ttp_count)   AS total_ttps,
                       SUM(ioc_count)   AS total_iocs,
                       SUM(CASE WHEN threat_level = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_count,
                       SUM(CASE WHEN threat_level = 'HIGH'     THEN 1 ELSE 0 END) AS high_count,
                       SUM(CASE WHEN threat_level = 'MEDIUM'   THEN 1 ELSE 0 END) AS medium_count,
                       SUM(CASE WHEN threat_level = 'LOW'      THEN 1 ELSE 0 END) AS low_count
                   FROM analyses
                   WHERE user_id = ?""",
                (user_id,)
            ).fetchone()
            return dict(row) if row else {}

    def search_ioc(self, ioc_value: str) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT i.*, a.threat_level, a.created_at AS analysis_date
                   FROM iocs i
                   JOIN analyses a ON i.analysis_id = a.id
                   WHERE i.ioc_value LIKE ?
                   ORDER BY i.created_at DESC
                   LIMIT 50""",
                (f'%{ioc_value}%',)
            ).fetchall()
            return [dict(row) for row in rows]

    # ══════════════════════════════════════════════════════════
    # AUDIT LOG
    # ══════════════════════════════════════════════════════════

    def _audit(self, conn: sqlite3.Connection, user_id: Optional[int],
               action: str, detail: str = '', ip: str = ''):
        conn.execute(
            """INSERT INTO audit_log (user_id, action, detail, ip_address, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (user_id, action, detail, ip,
             datetime.now(timezone.utc).isoformat())
        )

    def get_audit_log(self, user_id: int, limit: int = 50) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM audit_log
                   WHERE user_id = ?
                   ORDER BY created_at DESC
                   LIMIT ?""",
                (user_id, limit)
            ).fetchall()
            return [dict(row) for row in rows]

    # ══════════════════════════════════════════════════════════
    # MAINTENANCE
    # ══════════════════════════════════════════════════════════

    def delete_old_analyses(self, days: int = 90) -> int:
        """Delete analyses older than N days. Returns count deleted."""
        # FIX: was ignoring days param — cutoff was always today midnight
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._conn() as conn:
            cursor = conn.execute(
                "DELETE FROM analyses WHERE created_at < ?",
                (cutoff,)
            )
            deleted = cursor.rowcount
            logger.info(f"Deleted {deleted} old analyses (>{days}d)")
            return deleted
