from typing import Optional

from database import get_db_connection

from .schemas import UserCreate, UserOut
from .utils import hash_password, verify_password


class UserModel:
    @staticmethod
    def create_user(user: UserCreate) -> UserOut:
        hashed_password = hash_password(user.password)

        with get_db_connection() as conn:
            result = conn.execute(
                """
                INSERT INTO users (username, email, hashed_password)
                VALUES (?, ?, ?)
                RETURNING id, username, email, is_active, is_admin
            """,
                [user.username, user.email, hashed_password],
            ).fetchone()

            return UserOut(
                id=result[0],
                username=result[1],
                email=result[2],
                is_active=result[3],
                is_admin=result[4],
            )

    @staticmethod
    def get_user_by_username(username: str) -> Optional[dict]:
        with get_db_connection() as conn:
            result = conn.execute(
                """
                SELECT id, username, email, hashed_password, is_active, is_admin, created_at
                FROM users 
                WHERE username = ?
            """,
                [username],
            ).fetchone()

            if result:
                return {
                    "id": result[0],
                    "username": result[1],
                    "email": result[2],
                    "hashed_password": result[3],
                    "is_active": result[4],
                    "is_admin": result[5],
                    "created_at": result[6],
                }
            return None

    @staticmethod
    def get_user_by_email(email: str) -> Optional[dict]:
        with get_db_connection() as conn:
            result = conn.execute(
                """
                SELECT id, username, email, hashed_password, is_active, is_admin, created_at
                FROM users 
                WHERE email = ?
            """,
                [email],
            ).fetchone()

            if result:
                return {
                    "id": result[0],
                    "username": result[1],
                    "email": result[2],
                    "hashed_password": result[3],
                    "is_active": result[4],
                    "is_admin": result[5],
                    "created_at": result[6],
                }
            return None

    @staticmethod
    def get_user_by_id(user_id: int) -> Optional[UserOut]:
        with get_db_connection() as conn:
            result = conn.execute(
                """
                SELECT id, username, email, is_active, is_admin
                FROM users 
                WHERE id = ?
            """,
                [user_id],
            ).fetchone()

            if result:
                return UserOut(
                    id=result[0],
                    username=result[1],
                    email=result[2],
                    is_active=result[3],
                    is_admin=result[4],
                )
            return None

    @staticmethod
    def authenticate_user(username: str, password: str) -> Optional[dict]:
        user = UserModel.get_user_by_username(username)
        if user and verify_password(password, user["hashed_password"]):
            return user
        return None

    @staticmethod
    def update_user(user_id: int, **kwargs) -> Optional[UserOut]:
        if not kwargs:
            return UserModel.get_user_by_id(user_id)

        set_clause = ", ".join([f"{k} = ?" for k in kwargs.keys()])
        values = list(kwargs.values()) + [user_id]

        with get_db_connection() as conn:
            conn.execute(
                f"""
                UPDATE users 
                SET {set_clause}, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """,
                values,
            )

            return UserModel.get_user_by_id(user_id)

    @staticmethod
    def delete_user(user_id: int) -> bool:
        with get_db_connection() as conn:
            result = conn.execute(
                """
                DELETE FROM users WHERE id = ?
            """,
                [user_id],
            )

            return result.rowcount > 0

    @staticmethod
    def list_users(limit: int = 100, offset: int = 0) -> list[UserOut]:
        with get_db_connection() as conn:
            results = conn.execute(
                """
                SELECT id, username, email, is_active, is_admin
                FROM users 
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            """,
                [limit, offset],
            ).fetchall()

            return [
                UserOut(
                    id=row[0],
                    username=row[1],
                    email=row[2],
                    is_active=row[3],
                    is_admin=row[4],
                )
                for row in results
            ]

