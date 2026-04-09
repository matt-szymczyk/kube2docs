"""SHA-256 hashing for sensitive values."""

import hashlib
import re

# Patterns that suggest a key name holds a sensitive value (case-insensitive).
_SENSITIVE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"passwd", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"api[_-]?key", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"auth", re.IGNORECASE),
    re.compile(r"credential", re.IGNORECASE),
    re.compile(r"private[_-]?key", re.IGNORECASE),
    re.compile(r"access[_-]?key", re.IGNORECASE),
    re.compile(r"connection[_-]?string", re.IGNORECASE),
    re.compile(r"dsn", re.IGNORECASE),
    re.compile(r"database[_-]?url", re.IGNORECASE),
    re.compile(r"client[_-]?secret", re.IGNORECASE),
    re.compile(r"signing[_-]?key", re.IGNORECASE),
    re.compile(r"encryption[_-]?key", re.IGNORECASE),
    re.compile(r"salt", re.IGNORECASE),
]

# Content-based secret patterns (match sensitive-looking values regardless of key name).
# Each entry: (pattern, label_for_redaction)
_SECRET_CONTENT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Private keys (PEM blocks) — match the whole block
    (
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
            r".*?"
            r"-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
            re.DOTALL,
        ),
        "PRIVATE_KEY",
    ),
    # Certificates (keep these somewhat — they're public, but they're noisy)
    (
        re.compile(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL),
        "CERTIFICATE",
    ),
    # AWS access key IDs
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS_ACCESS_KEY"),
    (re.compile(r"\bASIA[0-9A-Z]{16}\b"), "AWS_SESSION_KEY"),
    # GitHub personal access tokens
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "GITHUB_TOKEN"),
    # GitLab tokens
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "GITLAB_TOKEN"),
    # Slack tokens
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "SLACK_TOKEN"),
    # Stripe keys
    (re.compile(r"\b(sk|pk|rk)_(live|test)_[A-Za-z0-9]{24,}\b"), "STRIPE_KEY"),
    # JWTs (three dot-separated base64url segments, first starts with eyJ)
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), "JWT"),
    # URI credentials: scheme://user:password@host
    (re.compile(r"([a-z][a-z0-9+.-]*://)[^:/\s]+:([^@\s]+)@"), "URI_CREDENTIAL"),
    # Bearer tokens in headers
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}\b"), "BEARER_TOKEN"),
    # Generic long base64 secrets following = or : (at least 32 chars)
    # Only match when clearly a value assignment, not just any hex blob
    (
        re.compile(r"(?i)(?:api[_-]?key|token|secret|password)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-+/=]{32,})"),
        "SECRET_VALUE",
    ),
]


def hash_value(value: str) -> str:
    """Return the SHA-256 hex digest of a string value."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_bytes(data: bytes) -> str:
    """Return the SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def is_sensitive_key(key: str) -> bool:
    """Check whether a config key name looks like it holds a sensitive value."""
    return any(p.search(key) for p in _SENSITIVE_PATTERNS)


def redact_if_sensitive(key: str, value: str) -> str:
    """Return the SHA-256 hash if the key looks sensitive, otherwise the original value."""
    if is_sensitive_key(key):
        return hash_value(value)
    return value


def redact_secrets(content: str) -> str:
    """Redact known secret patterns from arbitrary text content.

    Applied to any content before it leaves the local process (e.g. sent to
    an LLM provider). Two-layer approach:

    1. Line-based key=value redaction for sensitive-looking keys (passwords,
       tokens, etc.) — handles structured config files.
    2. Content-pattern matching for known secret formats (JWTs, AWS keys,
       private keys, URI credentials, etc.) — catches raw tokens that have
       no associated key name.

    Redacted values are replaced with a hashed placeholder so the LLM can
    still see that *something* was there and tell values apart, but cannot
    recover the plaintext.
    """
    # Layer 1: structured key=value redaction
    lines = []
    for line in content.splitlines():
        m = re.match(r"^(\s*([A-Za-z_][\w.-]*)\s*[=:]\s*)(.*)", line)
        if m and is_sensitive_key(m.group(2)):
            value = m.group(3).strip()
            if value and value not in ('""', "''", "null", "None"):
                # Strip surrounding quotes for hashing
                stripped = value.strip("\"'")
                lines.append(f"{m.group(1)}[REDACTED:sha256:{hash_value(stripped)[:16]}]")
            else:
                lines.append(line)
        else:
            lines.append(line)
    result = "\n".join(lines)

    # Layer 2: content-pattern replacement
    for pattern, label in _SECRET_CONTENT_PATTERNS:

        def _replace(match: re.Match[str], lbl: str = label) -> str:
            matched = match.group(0)
            return f"[REDACTED:{lbl}:sha256:{hash_value(matched)[:16]}]"

        result = pattern.sub(_replace, result)

    return result
