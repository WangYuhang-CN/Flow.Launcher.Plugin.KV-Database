from __future__ import annotations

import datetime
import inspect
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import secure_crypto
from secure_crypto import CryptoError, RecoveryKeyError

PLUGIN_DIR = Path(__file__).resolve().parent
DB_DIR = PLUGIN_DIR / "db"
DB_PATH = DB_DIR / "kv.sqlite3"
LOG_FILE_PATH = PLUGIN_DIR / "plugin.log"
SCHEMA_VERSION = 2
WRAP_DPAPI_USER = "dpapi_user"
WRAP_RECOVERY_KEY = "recovery_key"
VALUE_AAD_PREFIX = b"kvdb-entry:"
RECOVERY_AAD = b"kvdb-data-key:recovery:v1"

__version__ = "0.1.0"
__author__ = "Wang.Yuhang"
__description__ = "Flow Launcher plugin for KV Database"
__license__ = "MIT"

LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
CURRENT_LOG_LEVEL = "INFO"
_log_lock = threading.Lock()


def log(message: str, level: str = "INFO") -> None:
    if level not in LOG_LEVELS:
        level = "INFO"
    if LOG_LEVELS.index(level) < LOG_LEVELS.index(CURRENT_LOG_LEVEL):
        return

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    frame = inspect.stack()[1]
    caller_info = f"{Path(frame.filename).name}:{frame.lineno}"
    log_entry = f"[{now}] [{level}] [{caller_info}] {message}"

    with _log_lock:
        with LOG_FILE_PATH.open("a", encoding="utf-8") as f:
            f.write(log_entry + "\n")


@dataclass(frozen=True)
class KVEntry:
    key: str
    value: str
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class SecurityStatus:
    encrypted: bool
    dpapi_configured: bool
    dpapi_unlockable: bool
    recovery_configured: bool
    entry_count: int


class KVStoreLockedError(Exception):
    """Raised when encrypted values cannot be unlocked on this Windows user."""


class KVStoreRecoveryError(Exception):
    """Raised when recovery key setup or unlock fails."""


class KVStore:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = Path(db_path)
        self._data_key: bytes | None = None
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 10000")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._create_key_wrappings_table(conn)
            columns = self._table_columns(conn, "kv_entries")
            if not columns:
                self._create_secure_entries_table(conn)
            elif "encrypted_value" not in columns:
                self._migrate_plaintext_entries(conn)
            else:
                self._create_secure_indexes(conn)

            if self._entry_count(conn) == 0:
                self._ensure_empty_database_key(conn)
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def get(self, key: str) -> KVEntry | None:
        key = key.strip()
        if not key:
            return None

        data_key = self._require_data_key()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT key, encrypted_value, value_nonce, created_at, updated_at
                FROM kv_entries
                WHERE key = ?
                """,
                (key,),
            ).fetchone()
        return self._row_to_entry(row, data_key)

    def search(self, keyword: str, limit: int = 8) -> list[KVEntry]:
        keyword = keyword.strip()
        if not keyword:
            return self.recent(limit)

        escaped = self._escape_like(keyword)
        prefix_pattern = f"{escaped}%"
        contains_pattern = f"%{escaped}%"

        data_key = self._require_data_key()
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT key, encrypted_value, value_nonce, created_at, updated_at
                FROM kv_entries
                WHERE key LIKE ? ESCAPE '\\'
                ORDER BY
                    CASE
                        WHEN key = ? THEN 0
                        WHEN key LIKE ? ESCAPE '\\' THEN 1
                        ELSE 2
                    END,
                    updated_at DESC,
                    key ASC
                LIMIT ?
                """,
                (contains_pattern, keyword, prefix_pattern, limit),
            ).fetchall()
        return [self._row_to_entry(row, data_key) for row in rows]

    def recent(self, limit: int = 8) -> list[KVEntry]:
        data_key = self._require_data_key()
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT key, encrypted_value, value_nonce, created_at, updated_at
                FROM kv_entries
                ORDER BY updated_at DESC, key ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [self._row_to_entry(row, data_key) for row in rows]

    def upsert(self, key: str, value: str) -> KVEntry:
        key = key.strip()
        value = value.strip()
        if not key:
            raise ValueError("Key cannot be empty.")
        if not value:
            raise ValueError("Value cannot be empty.")

        now = self._now()
        data_key = self._require_data_key()
        value_nonce, encrypted_value = self._encrypt_value(data_key, key, value)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO kv_entries (key, encrypted_value, value_nonce, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    encrypted_value = excluded.encrypted_value,
                    value_nonce = excluded.value_nonce,
                    updated_at = excluded.updated_at
                """,
                (key, encrypted_value, value_nonce, now, now),
            )
        log(f"Saved key: {key}", "INFO")
        return self.get(key)

    def delete(self, key: str) -> bool:
        key = key.strip()
        if not key:
            return False

        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM kv_entries WHERE key = ?", (key,))
        deleted = cursor.rowcount > 0
        if deleted:
            log(f"Deleted key: {key}", "INFO")
        return deleted

    def security_status(self) -> SecurityStatus:
        with self._connect() as conn:
            columns = self._table_columns(conn, "kv_entries")
            dpapi_configured = self._has_wrapping(conn, WRAP_DPAPI_USER)
            recovery_configured = self._has_wrapping(conn, WRAP_RECOVERY_KEY)
            dpapi_unlockable = False
            if dpapi_configured:
                try:
                    self._get_data_key_from_dpapi(conn)
                    dpapi_unlockable = True
                except CryptoError:
                    dpapi_unlockable = False

            return SecurityStatus(
                encrypted="encrypted_value" in columns,
                dpapi_configured=dpapi_configured,
                dpapi_unlockable=dpapi_unlockable,
                recovery_configured=recovery_configured,
                entry_count=self._entry_count(conn),
            )

    def create_or_rotate_recovery_key(self) -> str:
        data_key = self._require_data_key()
        recovery_key = secure_crypto.generate_recovery_key()
        salt = secure_crypto.random_bytes(16)
        wrapping_key = secure_crypto.derive_recovery_key(recovery_key, salt)
        nonce, encrypted_data_key = secure_crypto.aes_gcm_encrypt(
            wrapping_key,
            data_key,
            aad=RECOVERY_AAD,
        )

        with self._connect() as conn:
            self._upsert_wrapping(
                conn,
                WRAP_RECOVERY_KEY,
                "pbkdf2-sha256",
                salt,
                nonce,
                encrypted_data_key,
            )
        log("Recovery key wrapping created or rotated.", "INFO")
        return recovery_key

    def unlock_with_recovery_key(self, recovery_key: str) -> bool:
        try:
            with self._connect() as conn:
                wrapping = self._get_wrapping(conn, WRAP_RECOVERY_KEY)
                if wrapping is None:
                    raise KVStoreRecoveryError("No recovery key is configured.")

                wrapping_key = secure_crypto.derive_recovery_key(recovery_key, wrapping["salt"])
                data_key = secure_crypto.aes_gcm_decrypt(
                    wrapping_key,
                    wrapping["nonce"],
                    wrapping["encrypted_data_key"],
                    aad=RECOVERY_AAD,
                )
                if len(data_key) != secure_crypto.AES_KEY_BYTES:
                    raise KVStoreRecoveryError("Recovery key decrypted an invalid data key.")

                self._data_key = data_key
                self._upsert_dpapi_wrapping(conn, data_key)
            log("Database unlocked and rebound to current Windows user.", "INFO")
            return True
        except (CryptoError, RecoveryKeyError) as exc:
            raise KVStoreRecoveryError("Recovery key unlock failed.") from exc

    def has_recovery_key(self) -> bool:
        with self._connect() as conn:
            return self._has_wrapping(conn, WRAP_RECOVERY_KEY)

    def _row_to_entry(self, row: sqlite3.Row | None, data_key: bytes) -> KVEntry | None:
        if row is None:
            return None
        value = self._decrypt_value(
            data_key,
            row["key"],
            row["value_nonce"],
            row["encrypted_value"],
        )
        return KVEntry(
            key=row["key"],
            value=value,
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def _require_data_key(self) -> bytes:
        if self._data_key is not None:
            return self._data_key
        with self._connect() as conn:
            return self._get_or_create_data_key(conn)

    def _get_or_create_data_key(self, conn: sqlite3.Connection) -> bytes:
        if self._data_key is not None:
            return self._data_key
        if self._has_wrapping(conn, WRAP_DPAPI_USER):
            try:
                return self._get_data_key_from_dpapi(conn)
            except CryptoError as exc:
                if self._entry_count(conn) == 0:
                    return self._reset_empty_database_key(conn)
                raise KVStoreLockedError("Database is locked for this Windows user.") from exc
        if not self._has_any_wrapping(conn):
            return self._create_data_key(conn)
        if self._entry_count(conn) == 0:
            return self._reset_empty_database_key(conn)
        raise KVStoreLockedError("Database is locked for this Windows user.")

    def _ensure_empty_database_key(self, conn: sqlite3.Connection) -> None:
        if not self._has_any_wrapping(conn):
            self._create_data_key(conn)
            return

        if not self._has_wrapping(conn, WRAP_DPAPI_USER):
            self._reset_empty_database_key(conn)
            return

        try:
            self._get_data_key_from_dpapi(conn)
        except CryptoError:
            self._reset_empty_database_key(conn)

    def _reset_empty_database_key(self, conn: sqlite3.Connection) -> bytes:
        if self._entry_count(conn) != 0:
            raise KVStoreLockedError("Database is locked for this Windows user.")

        self._data_key = None
        conn.execute("DELETE FROM key_wrappings")
        data_key = self._create_data_key(conn)
        log("Reset stale encryption key wrapping for empty database.", "WARNING")
        return data_key

    def _get_data_key_from_dpapi(self, conn: sqlite3.Connection) -> bytes:
        wrapping = self._get_wrapping(conn, WRAP_DPAPI_USER)
        if wrapping is None:
            raise CryptoError("DPAPI wrapping is missing.")
        data_key = secure_crypto.dpapi_unprotect(wrapping["encrypted_data_key"])
        if len(data_key) != secure_crypto.AES_KEY_BYTES:
            raise CryptoError("DPAPI decrypted an invalid data key.")
        self._data_key = data_key
        return data_key

    def _create_data_key(self, conn: sqlite3.Connection) -> bytes:
        data_key = secure_crypto.random_bytes(secure_crypto.AES_KEY_BYTES)
        self._data_key = data_key
        self._upsert_dpapi_wrapping(conn, data_key)
        return data_key

    def _upsert_dpapi_wrapping(self, conn: sqlite3.Connection, data_key: bytes) -> None:
        self._upsert_wrapping(
            conn,
            WRAP_DPAPI_USER,
            "none",
            None,
            None,
            secure_crypto.dpapi_protect(data_key),
        )

    def _upsert_wrapping(
        self,
        conn: sqlite3.Connection,
        wrapping_type: str,
        kdf: str,
        salt: bytes | None,
        nonce: bytes | None,
        encrypted_data_key: bytes,
    ) -> None:
        now = self._now()
        conn.execute(
            """
            INSERT INTO key_wrappings
                (type, kdf, salt, nonce, encrypted_data_key, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(type) DO UPDATE SET
                kdf = excluded.kdf,
                salt = excluded.salt,
                nonce = excluded.nonce,
                encrypted_data_key = excluded.encrypted_data_key,
                updated_at = excluded.updated_at
            """,
            (wrapping_type, kdf, salt, nonce, encrypted_data_key, now, now),
        )

    def _create_key_wrappings_table(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS key_wrappings (
                type TEXT PRIMARY KEY,
                kdf TEXT NOT NULL,
                salt BLOB,
                nonce BLOB,
                encrypted_data_key BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

    def _create_secure_entries_table(
        self,
        conn: sqlite3.Connection,
        table_name: str = "kv_entries",
        create_index: bool = True,
    ) -> None:
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {table_name} (
                key TEXT PRIMARY KEY,
                encrypted_value BLOB NOT NULL,
                value_nonce BLOB NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        if create_index:
            self._create_secure_indexes(conn, table_name)

    def _create_secure_indexes(
        self,
        conn: sqlite3.Connection,
        table_name: str = "kv_entries",
    ) -> None:
        if table_name == "kv_entries":
            conn.execute("DROP INDEX IF EXISTS idx_kv_entries_secure_updated_at")
        conn.execute(
            f"CREATE INDEX IF NOT EXISTS idx_{table_name}_updated_at "
            f"ON {table_name}(updated_at DESC)"
        )

    def _migrate_plaintext_entries(self, conn: sqlite3.Connection) -> None:
        columns = self._table_columns(conn, "kv_entries")
        if "value" not in columns:
            raise RuntimeError("Cannot migrate kv_entries without a value column.")

        data_key = self._get_or_create_data_key(conn)
        rows = conn.execute(
            """
            SELECT key, value, created_at, updated_at
            FROM kv_entries
            """
        ).fetchall()

        self._create_secure_entries_table(conn, "kv_entries_secure", create_index=False)
        for row in rows:
            nonce, encrypted_value = self._encrypt_value(data_key, row["key"], row["value"])
            conn.execute(
                """
                INSERT INTO kv_entries_secure
                    (key, encrypted_value, value_nonce, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (row["key"], encrypted_value, nonce, row["created_at"], row["updated_at"]),
            )

        conn.execute("DROP TABLE kv_entries")
        conn.execute("ALTER TABLE kv_entries_secure RENAME TO kv_entries")
        self._create_secure_indexes(conn)
        log(f"Migrated {len(rows)} plaintext entries to encrypted storage.", "INFO")

    def _encrypt_value(self, data_key: bytes, key: str, value: str) -> tuple[bytes, bytes]:
        return secure_crypto.aes_gcm_encrypt(
            data_key,
            value.encode("utf-8"),
            aad=self._value_aad(key),
        )

    def _decrypt_value(
        self,
        data_key: bytes,
        key: str,
        nonce: bytes,
        encrypted_value: bytes,
    ) -> str:
        plaintext = secure_crypto.aes_gcm_decrypt(
            data_key,
            nonce,
            encrypted_value,
            aad=self._value_aad(key),
        )
        return plaintext.decode("utf-8")

    @staticmethod
    def _value_aad(key: str) -> bytes:
        return VALUE_AAD_PREFIX + key.encode("utf-8")

    @staticmethod
    def _table_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
        rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        return {row["name"] for row in rows}

    @staticmethod
    def _get_wrapping(conn: sqlite3.Connection, wrapping_type: str) -> sqlite3.Row | None:
        return conn.execute(
            """
            SELECT type, kdf, salt, nonce, encrypted_data_key, created_at, updated_at
            FROM key_wrappings
            WHERE type = ?
            """,
            (wrapping_type,),
        ).fetchone()

    @staticmethod
    def _has_wrapping(conn: sqlite3.Connection, wrapping_type: str) -> bool:
        row = conn.execute(
            "SELECT 1 FROM key_wrappings WHERE type = ?",
            (wrapping_type,),
        ).fetchone()
        return row is not None

    @staticmethod
    def _has_any_wrapping(conn: sqlite3.Connection) -> bool:
        row = conn.execute("SELECT 1 FROM key_wrappings LIMIT 1").fetchone()
        return row is not None

    @staticmethod
    def _entry_count(conn: sqlite3.Connection) -> int:
        row = conn.execute("SELECT COUNT(*) AS count FROM kv_entries").fetchone()
        return int(row["count"])

    @staticmethod
    def _escape_like(value: str) -> str:
        return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    @staticmethod
    def _now() -> str:
        return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
