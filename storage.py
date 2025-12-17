import sqlite3
import time
import uuid
from pathlib import Path
from typing import Optional


def init_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mailboxes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                address TEXT UNIQUE NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                active INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mailbox_id INTEGER NOT NULL,
                received_at INTEGER NOT NULL,
                peer_ip TEXT,
                helo TEXT,
                mail_from TEXT,
                raw BLOB NOT NULL,
                analysis_json TEXT,
                analyzed_at INTEGER,
                FOREIGN KEY(mailbox_id) REFERENCES mailboxes(id)
            )
            """
        )


def _row_to_dict(cursor, row):
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}


def create_mailbox(db_path: Path, domain: str, ttl_seconds: int) -> dict:
    token = uuid.uuid4().hex
    local_part = token[:10]
    address = f"{local_part}@{domain}"
    now = int(time.time())
    expires_at = now + ttl_seconds
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO mailboxes (token, address, created_at, expires_at, active) VALUES (?, ?, ?, ?, 1)",
            (token, address, now, expires_at),
        )
    return {
        "token": token,
        "address": address,
        "created_at": now,
        "expires_at": expires_at,
    }


def purge_expired(db_path: Path) -> None:
    now = int(time.time())
    with sqlite3.connect(db_path) as conn:
        conn.execute("DELETE FROM messages WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE expires_at < ?)", (now,))
        conn.execute("DELETE FROM mailboxes WHERE expires_at < ?", (now,))


def get_mailbox_by_token(db_path: Path, token: str) -> Optional[dict]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = _row_to_dict
        row = conn.execute("SELECT * FROM mailboxes WHERE token = ?", (token,)).fetchone()
    return row


def get_mailbox_by_address(db_path: Path, address: str) -> Optional[dict]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = _row_to_dict
        row = conn.execute("SELECT * FROM mailboxes WHERE address = ? AND active = 1", (address,)).fetchone()
    return row


def save_message(
    db_path: Path,
    mailbox_id: int,
    raw_bytes: bytes,
    peer_ip: str,
    helo: str,
    mail_from: str,
) -> int:
    now = int(time.time())
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO messages (mailbox_id, received_at, peer_ip, helo, mail_from, raw)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (mailbox_id, now, peer_ip, helo, mail_from, raw_bytes),
        )
        conn.execute("UPDATE mailboxes SET active = 0 WHERE id = ?", (mailbox_id,))
        message_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    return int(message_id)


def get_latest_message(db_path: Path, mailbox_id: int) -> Optional[dict]:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = _row_to_dict
        row = conn.execute(
            "SELECT * FROM messages WHERE mailbox_id = ? ORDER BY received_at DESC LIMIT 1",
            (mailbox_id,),
        ).fetchone()
    return row


def update_message_analysis(db_path: Path, message_id: int, analysis_json: str) -> None:
    now = int(time.time())
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE messages SET analysis_json = ?, analyzed_at = ? WHERE id = ?",
            (analysis_json, now, message_id),
        )
