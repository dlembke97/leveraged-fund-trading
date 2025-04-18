# app.py
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel
import uuid

from sqlalchemy.orm import Session
from db.database import SessionLocal, init_db, User
from services.trading_engine import TradingEngine, engines
from services.admin import router as admin_router
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()
# Mount the admin router
app.include_router(admin_router, prefix="/admin", tags=["admin"])
# Run database initialization on startup
@app.on_event("startup")
def startup_event():
    init_db()

# Dependency to create a new session per request
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Pydantic model for user registration input
class UserRegister(BaseModel):
    username: str
    alpaca_api_key: str
    alpaca_api_secret: str
    email: str
    sender_email: str
    sender_email_password: str
    receiver_email: str

# Updated /register endpoint: Persist user information in the database
@app.post("/register")
def register(user: UserRegister, db: Session = Depends(get_db)):
    # Check for an existing user with the same username
    existing = db.query(User).filter(User.username == user.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Generate a unique user_id (UUID)
    user_id = str(uuid.uuid4())
    
    new_user = User(
        user_id=user_id,
        username=user.username,
        alpaca_api_key=user.alpaca_api_key,
        alpaca_api_secret=user.alpaca_api_secret,
        email=user.email,
        sender_email=user.sender_email,
        sender_email_password=user.sender_email_password,
        receiver_email=user.receiver_email
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"user_id": new_user.user_id}

# Pydantic model for bot control endpoints
class BotControl(BaseModel):
    user_id: str

# Updated /start_bot endpoint: Retrieve user from the database and apply a default trading_config
@app.post("/start_bot")
def start_bot(bot: BotControl, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    # Look up the user in the persistent database
    user_obj = db.query(User).filter(User.user_id == bot.user_id).first()
    if not user_obj:
        raise HTTPException(status_code=404, detail="User not found")
    
    if bot.user_id in engines:
        raise HTTPException(status_code=400, detail="Bot already running for this user")
    
    # Define a default trading configuration for now.
    # In the future, you'll likely store this in the database or allow the user to update it.
    trading_config = {
        "FNGA": {
            "buy_triggers": [300, 250, 200],
            "sell_triggers": [650, 700, 750],
            "last_buy_price": None,
            "last_sell_price": None,
            "triggered_buy_levels": set(),
            "triggered_sell_levels": set(),
        },
        "TQQQ": {
            "buy_triggers": [45, 40, 35],
            "sell_triggers": [85, 90, 95],
            "last_buy_price": None,
            "last_sell_price": None,
            "triggered_buy_levels": set(),
            "triggered_sell_levels": set(),
        }
    }
    
    # Create the trading engine using the user's credentials from the database.
    engine = TradingEngine(
        user_id=bot.user_id,
        alpaca_api_key=user_obj.alpaca_api_key,
        alpaca_api_secret=user_obj.alpaca_api_secret,
        trading_config=trading_config,
        email_config={
            "sender_email": user_obj.sender_email,
            "sender_email_password": user_obj.sender_email_password,
            "receiver_email": user_obj.receiver_email
        }
    )
    engines[bot.user_id] = engine
    background_tasks.add_task(engine.run)
    return {"detail": "Trading bot started."}

# /stop_bot remains similar: Stops the background trading task.
@app.post("/stop_bot")
def stop_bot(bot: BotControl):
    if bot.user_id not in engines:
        raise HTTPException(status_code=404, detail="Bot not running for this user")
    engine = engines.pop(bot.user_id)
    engine.stop()
    return {"detail": "Trading bot stopped."}
