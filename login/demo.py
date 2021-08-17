from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, status, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

from login import LoginServer, Token, MongoUser

import os


# region MongoDB

mongo_url = os.environ.get("MONGO_CONN_URL", "localhost")
mongo_port = int(os.environ.get("MONGO_CONN_PORT", "27017"))

# to get a SECRET_KEY string, run:
# openssl rand -hex 32
secret_key = os.environ.get("JWT_SIGNATURE")

server = LoginServer(mongo_url, mongo_port, "test", secret_key, token_expire=30)

# endregion MongoDB

# region SiteDomainDB

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "email": "johndoe@example.com",
        "full_name": "John Doe",
        "disabled": False,
    }
}


class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


# endregion SiteDomainDB

# region FastAPI

app = FastAPI()

TOKEN_PATH = "token"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=TOKEN_PATH)


def get_current_user(token: str = Depends(oauth2_scheme)) -> MongoUser:
    return server.get_current_user(token)


def get_current_active_user(login_user: MongoUser = Depends(get_current_user)):
    user_dict = fake_users_db.get(login_user.user_id)

    if user_dict is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    user_data = User(**user_dict)

    if user_data is None or user_data.disabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    return user_data


@app.post(f"/{TOKEN_PATH}", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = server.authenticate_user(form_data.username, form_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = server.create_access_token({"sub": user.user_id})

    return Token(access_token=access_token, token_type="bearer")


class NewUser(BaseModel):
    username: str
    password: str


@app.post("/login/new", status_code=status.HTTP_201_CREATED)
def new_user(response: Response, created_user: bool = Depends(server.create_user)):
    if not created_user:
        response.status_code = status.HTTP_400_BAD_REQUEST


@app.delete("/login/delete", status_code=status.HTTP_202_ACCEPTED)
def delete_user(response: Response, current_user: MongoUser = Depends(get_current_user)):
    if not server.delete_user(current_user.user_id):
        response.status_code = status.HTTP_400_BAD_REQUEST


@app.get("/users/me/", response_model=User)
def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@app.get("/users/me/items/")
def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{"item_id": "Foo", "owner": current_user.username}]

# endregion FastAPI
