from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta
from pydantic import BaseModel
from typing import Union
from typing_extensions import Annotated
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm 
from jose import JWTError, jwt
from passlib.context import CryptContext

app = FastAPI()
SECRET_KEY ='b6774eaae3a0adff73bba261ee1ba2fead5dbc0bbf1b6a81b575ff5b34d28dc0'
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES  = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com" ,
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW" ,
        "disabled": False,
    }
}
class Token(BaseModel):
    access_token: str
    token_type: str
class TokenData(BaseModel):
    username: Union[str, None] = None

class User (BaseModel):
    username :str 
    email:Union[str, None] = None
    full_name: Union[str, None] = None
    disabled: Union[bool, None] = None

class UserInDB(User):
    hashed_password: str

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)
def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def fake_decode_token(token):
    return User(
        username=token + "fakedecoded", email="john@example.com", full_name="John Doe"
    )

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    user = fake_decode_token(token)
    return user


rate_limit_count ={}


def rate_limit_exceeded(user: str, limit: int = 5, interval: int = 60):
    current_time  = datetime.utcnow()
    if user not in rate_limit_count :
        rate_limit_count[user]={"count":1,"last_access_time": current_time}
    else:
        last_access_time = rate_limit_count[user]["last_access_time"]
        if current_time - last_access_time > timedelta(seconds=interval):
            rate_limit_count[user] = {"count": 1, "last_access_time": current_time}
        else:
            rate_limit_count[user]["count"] += 1
            if rate_limit_count[user]["count"] > limit:
                return True
    return False

def check_rate_limit(user: str = Depends(oauth2_scheme)):
    if rate_limit_exceeded(user):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": 60},
        )
    return user




@app.get("/", dependencies=[Depends(check_rate_limit)])
async def root():
    return {"ping":"pong","message": "This route is limited by rate"}

@app.get("/users/me")
async def read_users_me(current_user: Annotated[User, Depends(get_current_user)]):
    return current_user


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)