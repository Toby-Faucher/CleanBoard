from contextlib import contextmanager
from pathlib import Path

import duckdb
from config import settings


class DatabaseConnection:
    def __init__(self):
        self.db_path = settings.database_path
        self._ensure_db_directory()
        self._init_database()

    def _ensure_db_directory(self):
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)

    def _init_database(self):
        with duckdb.connect(self.db_path) as conn:
            self._create_tables(conn)

    def _create_tables(self, conn):
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                hashed_password VARCHAR(255) NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                is_admin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        """)

    @contextmanager
    def get_connection(self):
        conn = duckdb.connect(self.db_path)
        try:
            yield conn
        finally:
            conn.close()


db = DatabaseConnection()


def get_db_connection():
    return db.get_connection()

