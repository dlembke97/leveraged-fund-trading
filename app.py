# app.py
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
import uuid
from services.trading_engine import TradingEngine, engines

app = FastAPI()

# In-memory user store (replace with a proper database in production)
users = {}

class UserRegister(BaseModel):
    username: str
    alpaca_api_key: str
    alpaca_api_secret: str
    email: str
    sender_email: str
    sender_email_password: str
    receiver_email: str

@app.post("/register")
def register(user: UserRegister):
    user_id = str(uuid.uuid4())
    # Default trading configuration per user
    users[user_id] = {
        "username": user.username,
        "alpaca_api_key": user.alpaca_api_key,
        "alpaca_api_secret": user.alpaca_api_secret,
        "email": user.email,
        "sender_email": user.sender_email,
        "sender_email_password": user.sender_email_password,
        "receiver_email": user.receiver_email,
        "trading_config": {
            "FNGA": {
                "buy_triggers": [300, 250, 200],
                "sell_triggers": [650, 700, 750],
                "last_buy_price": None,
                "last_sell_price": None,
                "triggered_buy_levels": set(),
                "triggered_sell_levels": set(),
            },
            "TQQQ": {
                "buy_triggers": [50, 40, 30],
                "sell_triggers": [85, 90, 95],
                "last_buy_price": None,
                "last_sell_price": None,
                "triggered_buy_levels": set(),
                "triggered_sell_levels": set(),
            }
        }
    }
    return {"user_id": user_id}

class BotControl(BaseModel):
    user_id: str

@app.post("/start_bot")
def start_bot(bot: BotControl, background_tasks: BackgroundTasks):
    if bot.user_id not in users:
        raise HTTPException(status_code=404, detail="User not found")
    if bot.user_id in engines:
        raise HTTPException(status_code=400, detail="Bot already running for this user")
    
    user_config = users[bot.user_id]
    engine = TradingEngine(
        user_id=bot.user_id,
        alpaca_api_key=user_config["alpaca_api_key"],
        alpaca_api_secret=user_config["alpaca_api_secret"],
        trading_config=user_config["trading_config"],
        email_config={
            "sender_email": user_config["sender_email"],
            "sender_email_password": user_config["sender_email_password"],
            "receiver_email": user_config["receiver_email"]
        }
    )
    engines[bot.user_id] = engine
    background_tasks.add_task(engine.run)
    return {"detail": "Trading bot started."}

@app.post("/stop_bot")
def stop_bot(bot: BotControl):
    if bot.user_id not in engines:
        raise HTTPException(status_code=404, detail="Bot not running for this user")
    engine = engines.pop(bot.user_id)
    engine.stop()
    return {"detail": "Trading bot stopped."}
