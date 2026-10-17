# An empty value stops load_dotenv() from filling the key from the real .env.
# To run the live Groq tests, export GROQ_API_KEY in the shell before running pytest.
import os
# setdefault keeps any value already set in the shell; under pytest, the test
# environment lets the startup guards load without production secrets.
os.environ.setdefault("GROQ_ENV", "test")
# A per-run test key; never a real key. Setting it before app.core.config is
# imported keeps the real .env.eternal key out of the test process
# (load_dotenv doesn't override), and the suite runs without that file.
from cryptography.fernet import Fernet
os.environ.setdefault("FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
# Per-run test credential; never a real password.
import secrets
os.environ.setdefault("AUDIT_LOG_ADMIN_PASSWORD", secrets.token_urlsafe(32))
os.environ.setdefault("GROQ_API_KEY", "")
