# DHMIS Backend

FastAPI control-plane and tenant services for DHMIS.

## Installation

Requirements: Python 3.12+, PostgreSQL, and Redis for queue-backed workers.

```bash
cd Backend
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.lock.txt
cp .env.example .env
```

Set the development database, JWT, bootstrap, and provider values in .env. Run the schema migrations before starting the API:

```bash
alembic upgrade head
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Run the backend checks with pytest. Keep .env, .venv/, Python caches, and local test caches out of version control.
