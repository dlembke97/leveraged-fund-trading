# database.py
import os
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Use a SQLite database by default for simplicity
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./users.db")

# Create the engine. For SQLite, we need to set check_same_thread=False
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Define a User model
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, unique=True, index=True)  # Unique user identifier (e.g., a UUID)
    username = Column(String, unique=True, index=True)
    alpaca_api_key = Column(String)
    alpaca_api_secret = Column(String)
    email = Column(String)
    sender_email = Column(String)
    sender_email_password = Column(String)
    receiver_email = Column(String)

def init_db():
    Base.metadata.create_all(bind=engine)
