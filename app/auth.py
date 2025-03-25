from fastapi import HTTPException
from passlib.context import CryptContext
from pydantic import BaseModel

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Example user database
fake_users_db = {
    "user1": {
        "username": "user1",
        "password": "$2b$12$k1K8bsnUt6Fls0CwzmnBAeH/XXH7Kqz.2nxFZGgm9YFfLRtGpoV6q"  # "password123"
    },
}

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

class User(BaseModel):
    username: str

class UserInDB(User):
    password: str

def get_user(username: str):
    if username in fake_users_db:
        return UserInDB(**fake_users_db[username])

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user or not verify_password(password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return user
