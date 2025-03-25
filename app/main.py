from fastapi import FastAPI, Depends
from auth import authenticate_user
from alpaca_api import initialize_api

app = FastAPI()

@app.post("/token")
def login(username: str, password: str):
    user = authenticate_user(username, password)
    return {"access_token": user.username, "token_type": "bearer"}

@app.get("/restricted")
def restricted_area(token: str = Depends(oauth2_scheme)):
    # You can implement trading logic or other features here
    return {"message": "This is a restricted area for authorized users."}
