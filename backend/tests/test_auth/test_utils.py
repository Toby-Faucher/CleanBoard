"""Tests for authentication utility functions."""

from bcrypt import checkpw

from backend.src.auth.utils import hash_password


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

