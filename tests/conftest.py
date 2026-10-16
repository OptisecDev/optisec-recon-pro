# An empty value stops load_dotenv() from filling the key from the real .env.
# To run the live Groq tests, export GROQ_API_KEY in the shell before running pytest.
import os
os.environ.setdefault("GROQ_API_KEY", "")
