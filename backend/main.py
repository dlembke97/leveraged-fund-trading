# backend/main.py
from fastapi import FastAPI
import os

app = FastAPI(title="Leveraged Fund Trading API")

# Reading sensitive info from environment variables (set via fly.io secrets)
SECRET_KEY = os.getenv("SECRET_KEY", "default_secret")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///:memory:")

@app.get("/")
async def root():
    return {"message": "Welcome to the Leveraged Fund Trading API"}

@app.get("/trade")
async def trade_info():
    # Replace this with your actual trading logic.
    return {
        "trade": "example",
        "status": "executed",
        "secret_used": SECRET_KEY,
        "db": DATABASE_URL
    }
