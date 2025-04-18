# services/admin.py

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from db.database import SessionLocal, User
from services.common_scripts import setup_logger
import os

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")

router = APIRouter()
logger = setup_logger(__name__)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_admin_user(token: str = Depends(...)):
    """
    Replace this stub with your real auth logic.
    For example, read an API key header or verify a JWT.
    """
    if token != ADMIN_TOKEN:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authorized")
    return {"username": "admin"}

@router.get("/users", summary="List all registered users")
def list_users(
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin_user),
):
    users = db.query(User).all()
    result = []
    for u in users:
        result.append({
            "user_id": u.user_id,
            "username": u.username,
            "email": u.email,
            "sender_email": u.sender_email,
            "receiver_email": u.receiver_email,
        })
    logger.info(f"Admin fetched {len(result)} users")
    return result
