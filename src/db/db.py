"""Simple MySQL/MariaDB helper using PyMySQL.

Usage:
  from db.db import get_conn, init_schema, create_user, get_user_by_email

Configure via environment variables or .env:
  DB_HOST, DB_USER, DB_PASS, DB_NAME
"""

import os
import pymysql


def get_conn():
    host = os.environ.get("DB_HOST", "localhost")
    user = os.environ.get("DB_USER", "chatuser")
    password = os.environ.get("DB_PASS", "StrongPassword123!")
    db = os.environ.get("DB_NAME", "securechat")
    print("Connecting to DB:", host, user, db)
    try:
        return pymysql.connect(
            host=host,
            user=user,
            password=password,
            database=db,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
        )
    except Exception as e:
        print("DB CONNECT ERROR:", repr(e))
        raise


def init_schema(conn=None):
    close_after = False
    if conn is None:
        conn = get_conn()
        close_after = True
    try:
        with conn.cursor() as cur:
            cur.execute(
                """CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(255),
                    username VARCHAR(255) UNIQUE,
                    salt VARBINARY(16),
                    pwd_hash CHAR(64),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                ) CHARACTER SET utf8mb4;"""
            )
            conn.commit()
            print("users table ensured.")
    finally:
        if close_after:
            conn.close()


def create_user(email: str, username: str, salt: bytes, pwd_hash: str) -> bool:
    """Insert a new user. Returns True on success, False on duplicate username."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
                    (email, username, salt, pwd_hash),
                )
                conn.commit()
                return True
            except pymysql.err.IntegrityError:
                # username already exists (UNIQUE)
                conn.rollback()
                return False
    finally:
        conn.close()


def get_user_by_email(email: str):
    """Fetch user row by email. Returns dict or None."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            row = cur.fetchone()
            return row
    finally:
        conn.close()
