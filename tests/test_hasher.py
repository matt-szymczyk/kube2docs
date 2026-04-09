"""Tests for explorer.security.hasher."""

import hashlib

from kube2docs.security.hasher import (
    hash_bytes,
    hash_value,
    is_sensitive_key,
    redact_if_sensitive,
    redact_secrets,
)


class TestHashValue:
    def test_returns_64_char_hex(self):
        result = hash_value("hello")
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_matches_stdlib_sha256(self):
        expected = hashlib.sha256(b"test-secret").hexdigest()
        assert hash_value("test-secret") == expected

    def test_deterministic(self):
        assert hash_value("same") == hash_value("same")

    def test_different_inputs_different_hashes(self):
        assert hash_value("a") != hash_value("b")

    def test_empty_string(self):
        result = hash_value("")
        assert len(result) == 64
        assert result == hashlib.sha256(b"").hexdigest()

    def test_unicode(self):
        result = hash_value("пароль")
        expected = hashlib.sha256("пароль".encode()).hexdigest()
        assert result == expected


class TestHashBytes:
    def test_returns_64_char_hex(self):
        assert len(hash_bytes(b"data")) == 64

    def test_matches_stdlib(self):
        data = b"\x00\x01\x02\xff"
        assert hash_bytes(data) == hashlib.sha256(data).hexdigest()

    def test_empty_bytes(self):
        assert hash_bytes(b"") == hashlib.sha256(b"").hexdigest()


class TestIsSensitiveKey:
    def test_password_variants(self):
        assert is_sensitive_key("PASSWORD")
        assert is_sensitive_key("db_password")
        assert is_sensitive_key("MYSQL_ROOT_PASSWORD")
        assert is_sensitive_key("passwd")

    def test_api_key_variants(self):
        assert is_sensitive_key("API_KEY")
        assert is_sensitive_key("api-key")
        assert is_sensitive_key("apikey")
        assert is_sensitive_key("STRIPE_API_KEY")

    def test_token(self):
        assert is_sensitive_key("AUTH_TOKEN")
        assert is_sensitive_key("access_token")
        assert is_sensitive_key("TOKEN")

    def test_secret(self):
        assert is_sensitive_key("CLIENT_SECRET")
        assert is_sensitive_key("SECRET_KEY")

    def test_connection_strings(self):
        assert is_sensitive_key("DATABASE_URL")
        assert is_sensitive_key("CONNECTION_STRING")
        assert is_sensitive_key("DSN")

    def test_credentials(self):
        assert is_sensitive_key("AWS_CREDENTIALS")
        assert is_sensitive_key("credential_file")

    def test_private_key(self):
        assert is_sensitive_key("PRIVATE_KEY")
        assert is_sensitive_key("private-key")
        assert is_sensitive_key("TLS_PRIVATE_KEY")

    def test_access_key(self):
        assert is_sensitive_key("ACCESS_KEY")
        assert is_sensitive_key("AWS_ACCESS_KEY_ID")

    def test_non_sensitive(self):
        assert not is_sensitive_key("LOG_LEVEL")
        assert not is_sensitive_key("PORT")
        assert not is_sensitive_key("HOSTNAME")
        assert not is_sensitive_key("REPLICAS")
        assert not is_sensitive_key("NODE_ENV")
        assert not is_sensitive_key("TIMEOUT")


class TestRedactIfSensitive:
    def test_sensitive_key_returns_hash(self):
        result = redact_if_sensitive("DB_PASSWORD", "supersecret")
        assert result == hash_value("supersecret")
        assert result != "supersecret"

    def test_non_sensitive_key_returns_original(self):
        assert redact_if_sensitive("LOG_LEVEL", "debug") == "debug"

    def test_sensitive_empty_value(self):
        result = redact_if_sensitive("API_KEY", "")
        assert result == hash_value("")


class TestRedactSecrets:
    """Tests for the combined key=value + content-pattern secret redaction."""

    def test_key_value_password_redacted(self):
        content = "password: my-super-secret\nusername: admin"
        result = redact_secrets(content)
        assert "my-super-secret" not in result
        assert "REDACTED:sha256:" in result
        assert "admin" in result  # non-sensitive preserved

    def test_key_value_api_key_redacted(self):
        content = "api_key=abc123xyz\nport=8080"
        result = redact_secrets(content)
        assert "abc123xyz" not in result
        assert "port=8080" in result

    def test_preserves_non_sensitive_content(self):
        content = "host: localhost\nport: 5432\nmax_connections: 100"
        result = redact_secrets(content)
        assert result == content  # unchanged

    def test_jwt_redacted(self):
        # JWT without sensitive key name — matched by content pattern
        content = (
            "body contains eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c token"
        )
        result = redact_secrets(content)
        assert "eyJhbGciOiJIUzI1NiJ9" not in result
        assert "[REDACTED:JWT:" in result

    def test_jwt_in_authorization_header_redacted(self):
        # JWT in Authorization header — caught by layer 1 key match
        content = "Authorization: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = redact_secrets(content)
        assert "eyJhbGciOiJIUzI1NiJ9" not in result
        assert "REDACTED" in result

    def test_aws_access_key_redacted(self):
        content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        result = redact_secrets(content)
        assert "AKIAIOSFODNN7EXAMPLE" not in result

    def test_github_token_redacted(self):
        content = "token: ghp_abcdefghijklmnopqrstuvwxyz0123456789"
        result = redact_secrets(content)
        assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in result

    def test_uri_credential_redacted(self):
        content = "DATABASE_URL=postgresql://appuser:secretpass@db.example.com:5432/appdb"
        result = redact_secrets(content)
        assert "secretpass" not in result
        # The scheme is preserved
        assert "postgresql://" in result or "REDACTED" in result

    def test_private_key_redacted(self):
        content = (
            "Header\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEA...\n"
            "lotsofkeymaterialhere==\n"
            "-----END RSA PRIVATE KEY-----\n"
            "Footer"
        )
        result = redact_secrets(content)
        assert "MIIEpAIBAAKCAQEA" not in result
        assert "lotsofkeymaterialhere" not in result
        assert "[REDACTED:PRIVATE_KEY:" in result
        assert "Header" in result
        assert "Footer" in result

    def test_bearer_token_redacted(self):
        content = "Authorization: Bearer abc123xyzlongtokenstring456def789"
        result = redact_secrets(content)
        assert "abc123xyzlongtokenstring456def789" not in result

    def test_empty_value_not_redacted(self):
        content = 'password=\nsecret: ""'
        result = redact_secrets(content)
        # Empty values should stay empty (no false positives on empty)
        assert result == content

    def test_stripe_key_redacted(self):
        content = "STRIPE_SECRET=sk_test_FAKE0000000000000000000000"
        result = redact_secrets(content)
        assert "sk_test_FAKE0000000000000000000000" not in result
