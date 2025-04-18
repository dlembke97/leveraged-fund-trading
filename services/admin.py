# services/admin.py
import os
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from db.database import SessionLocal, User
from services.common_scripts import setup_logger

router = APIRouter()
logger = setup_logger(__name__)

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")
bearer_scheme = HTTPBearer()    # ← our security scheme

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_admin_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)
):
    token = credentials.credentials
    if token != ADMIN_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authorized",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"username": "admin"}

@router.get("/users", summary="List all registered users")
def list_users(
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin_user),
):
    users = db.query(User).all()
    result = [
        {
            "user_id": u.user_id,
            "username": u.username,
            "email": u.email,
            "sender_email": u.sender_email,
            "receiver_email": u.receiver_email,
        }
        for u in users
    ]
    logger.info(f"Admin fetched {len(result)} users")
    return result
