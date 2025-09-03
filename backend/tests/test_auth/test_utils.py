"""Tests for authentication utility functions."""

from datetime import datetime, timedelta
from unittest.mock import patch

import pytest
from bcrypt import checkpw
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from jose import jwt
from src.auth.utils import (
    ALGORITHM,
    SECRET_KEY,
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
    verify_token,
)


class TestHashPassword:
    """Test class for the hash_password function."""

    def test_returns_string(self):
        """Test that hash_password returns a string."""
        password = "test_pass"
        result = hash_password(password)
        assert isinstance(result, str)

    def test_produces_different_hashes_for_same_password(self):
        """Test that same password produces different hashes due to random salt."""
        password = "test_pass"
        result = hash_password(password)
        result2 = hash_password(password)
        assert result != result2

    def test_handles_empty_string(self):
        """Test hashing empty string."""
        password = ""
        result = hash_password(password)
        assert result is not None
        assert len(result) > 0

    def test_produces_verifiable_hash(self):
        """Test that hashed password can be verified with bcrypt.checkpw."""
        password = "test_password"
        result = hash_password(password)

        # Convert result back to bytes for verification
        result_bytes = result.encode("utf-8")

        assert checkpw(password.encode("utf-8"), result_bytes)

    def test_handles_special_characters(self):
        """Test hashing password with special characters."""
        password = "p@ssw0rd!#$%^&*()"
        result = hash_password(password)
        assert result is not None

        # Verify it can be checked
        result_bytes = result.encode("utf-8")
        assert checkpw(password.encode("utf-8"), result_bytes)

    def test_handles_long_password(self):
        """Test hashing very long password."""
        password = "ILoveTests!" * 100
        result = hash_password(password)
        assert result is not None

        # Verify it can be checked
        result_bytes = result.encode("utf-8")
        assert checkpw(password.encode("utf-8"), result_bytes)

    def test_handles_unicode_characters(self):
        """Test hashing password with unicode characters."""
        password = "пароль测试🔐"  # wtf claude
        result = hash_password(password)
        assert result is not None

        # Verify it can be checked
        result_bytes = result.encode("utf-8")
        assert checkpw(password.encode("utf-8"), result_bytes)


class TestVerifyPassword:
    """Test class for the verify_password function."""

    def test_correct_password_verification(self):
        """Test that correct password is verified successfully."""
        password = "test_password"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True

    def test_incorrect_password_verification(self):
        """Test that incorrect password fails verification."""
        password = "test_password"
        wrong_password = "wrong_password"
        hashed = hash_password(password)
        assert verify_password(wrong_password, hashed) is False

    def test_empty_password_verification(self):
        """Test verification with empty password."""
        empty_password = ""
        hashed = hash_password(empty_password)
        assert verify_password(empty_password, hashed) is True
        assert verify_password("not_empty", hashed) is False

    def test_special_characters_verification(self):
        """Test verification with special characters."""
        password = "p@ssw0rd!#$%^&*()"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True
        assert verify_password("p@ssw0rd!#$%^&*()x", hashed) is False

    def test_unicode_characters_verification(self):
        """Test verification with unicode characters."""
        password = "пароль测试🔐"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True
        assert verify_password("пароль测试🔑", hashed) is False

    def test_case_sensitive_verification(self):
        """Test that password verification is case sensitive."""
        password = "TestPassword"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True
        assert verify_password("testpassword", hashed) is False
        assert verify_password("TESTPASSWORD", hashed) is False


class TestCreateAccessToken:
    """Test class for the create_access_token function."""

    def test_creates_valid_jwt_token(self):
        """Test that create_access_token produces a valid JWT."""
        data = {"sub": "testuser"}
        token = create_access_token(data)

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        assert payload["sub"] == "testuser"
        assert "exp" in payload

    def test_uses_custom_expiration_delta(self):
        """Test that custom expiration delta is respected."""
        data = {"sub": "testuser"}
        custom_delta = timedelta(minutes=30)

        now = datetime.utcnow()
        token = create_access_token(data, custom_delta)

        payload = jwt.decode(
            token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False}
        )

        exp_time = datetime.utcfromtimestamp(payload["exp"])
        actual_delta = exp_time - now

        # Should be approximately 30 minutes (allow some tolerance for test execution time)
        assert abs(actual_delta.total_seconds() - custom_delta.total_seconds()) < 5

    def test_uses_default_expiration_when_none_provided(self):
        """Test that default 15 minute expiration is used when no delta provided."""
        data = {"sub": "testuser"}

        now = datetime.utcnow()
        token = create_access_token(data)

        payload = jwt.decode(
            token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False}
        )

        exp_time = datetime.utcfromtimestamp(payload["exp"])
        actual_delta = exp_time - now

        # Should be approximately 15 minutes (allow some tolerance for test execution time)
        expected_delta = timedelta(minutes=15)
        assert abs(actual_delta.total_seconds() - expected_delta.total_seconds()) < 5

    def test_preserves_original_data(self):
        """Test that original data dict is not modified."""
        original_data = {"sub": "testuser", "role": "admin"}
        data_copy = original_data.copy()

        create_access_token(original_data)

        assert original_data == data_copy
        assert "exp" not in original_data

    def test_includes_all_provided_data(self):
        """Test that all provided data is included in the token."""
        data = {
            "sub": "testuser",
            "role": "admin",
            "permissions": ["read", "write"],
            "user_id": 123,
        }

        token = create_access_token(data)
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        assert payload["sub"] == "testuser"
        assert payload["role"] == "admin"
        assert payload["permissions"] == ["read", "write"]
        assert payload["user_id"] == 123
        assert "exp" in payload

    def test_handles_empty_data_dict(self):
        """Test that empty data dict is handled correctly."""
        data = {}
        token = create_access_token(data)
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # Should only contain the expiration
        assert "exp" in payload
        assert len(payload) == 1


class TestVerifyToken:
    """Test class for the verify_token function."""

    def test_verifies_valid_token(self):
        """Test that valid token is verified correctly."""
        data = {"sub": "testuser", "role": "admin"}
        token = create_access_token(data)

        payload = verify_token(token)
        assert payload is not None
        assert payload["sub"] == "testuser"
        assert payload["role"] == "admin"

    def test_returns_none_for_invalid_token(self):
        """Test that invalid token returns None."""
        invalid_token = "invalid.jwt.token"
        payload = verify_token(invalid_token)
        assert payload is None

    def test_returns_none_for_expired_token(self):
        """Test that expired token returns None."""
        data = {"sub": "testuser"}

        # Create token with past expiration
        with patch("src.auth.utils.datetime") as mock_datetime:
            past_time = datetime(2020, 1, 1, 12, 0, 0)  # Use old date
            mock_datetime.utcnow.return_value = past_time

            token = create_access_token(data, timedelta(minutes=15))

        payload = verify_token(token)
        assert payload is None

    def test_returns_none_for_token_without_sub(self):
        """Test that token without 'sub' claim returns None."""
        data = {"role": "admin", "user_id": 123}
        token = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

        payload = verify_token(token)
        assert payload is None

    def test_returns_none_for_token_with_none_sub(self):
        """Test that token with None 'sub' claim returns None."""
        data = {"sub": None, "role": "admin"}
        token = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

        payload = verify_token(token)
        assert payload is None

    def test_returns_none_for_malformed_token(self):
        """Test that malformed token returns None."""
        malformed_tokens = [
            "",
            "not.a.jwt",
            "header.payload",  # Missing signature
            "a.b.c.d.e",  # Too many parts
        ]

        for token in malformed_tokens:
            payload = verify_token(token)
            assert payload is None

    def test_returns_none_for_token_with_wrong_secret(self):
        """Test that token signed with wrong secret returns None."""
        data = {"sub": "testuser"}
        wrong_secret_token = jwt.encode(data, "wrong_secret", algorithm=ALGORITHM)

        payload = verify_token(wrong_secret_token)
        assert payload is None

    def test_returns_none_for_token_with_wrong_algorithm(self):
        """Test that token with wrong algorithm returns None."""
        data = {"sub": "testuser"}
        wrong_algo_token = jwt.encode(data, SECRET_KEY, algorithm="HS512")

        payload = verify_token(wrong_algo_token)
        assert payload is None


class TestGetCurrentUser:
    """Test class for the get_current_user function."""

    @pytest.mark.asyncio
    async def test_returns_token_data_for_valid_token(self):
        """Test that valid token returns correct TokenData."""
        data = {"sub": "testuser"}
        token = create_access_token(data)
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

        result = await get_current_user(credentials)
        assert result.username == "testuser"

    @pytest.mark.asyncio
    async def test_raises_exception_for_invalid_token(self):
        """Test that invalid token raises HTTPException."""
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer", credentials="invalid.jwt.token"
        )

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(credentials)

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Could not validate credentials"
        assert exc_info.value.headers == {"WWW-Authenticate": "Bearer"}

    @pytest.mark.asyncio
    async def test_raises_exception_for_token_without_sub(self):
        """Test that token without 'sub' raises HTTPException."""
        data = {"role": "admin", "user_id": 123}
        token = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(credentials)

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Could not validate credentials"

    @pytest.mark.asyncio
    async def test_raises_exception_for_token_with_none_sub(self):
        """Test that token with None 'sub' raises HTTPException."""
        data = {"sub": None, "role": "admin"}
        token = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(credentials)

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Could not validate credentials"

    @pytest.mark.asyncio
    async def test_raises_exception_for_expired_token(self):
        """Test that expired token raises HTTPException."""
        data = {"sub": "testuser"}

        # Create token with past expiration
        with patch("src.auth.utils.datetime") as mock_datetime:
            past_time = datetime(2020, 1, 1, 12, 0, 0)  # Use old date
            mock_datetime.utcnow.return_value = past_time

            token = create_access_token(data, timedelta(minutes=15))

        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(credentials)

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Could not validate credentials"

    @pytest.mark.asyncio
    async def test_raises_exception_for_malformed_token(self):
        """Test that malformed token raises HTTPException."""
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer", credentials="not.a.jwt"
        )

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(credentials)

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Could not validate credentials"

    @pytest.mark.asyncio
    async def test_raises_exception_for_token_with_wrong_secret(self):
        """Test that token signed with wrong secret raises HTTPException."""
        data = {"sub": "testuser"}
        wrong_secret_token = jwt.encode(data, "wrong_secret", algorithm=ALGORITHM)
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer", credentials=wrong_secret_token
        )

        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(credentials)

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == "Could not validate credentials"
