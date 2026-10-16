# An empty value stops load_dotenv() from filling the key from the real .env.
# To run the live Groq tests, export GROQ_API_KEY in the shell before running pytest.
import os
# setdefault keeps any value already set in the shell; under pytest, the test
# environment lets the startup guards load without production secrets.
os.environ.setdefault("GROQ_ENV", "test")
os.environ.setdefault("GROQ_API_KEY", "")
