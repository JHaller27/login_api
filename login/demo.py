from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, status, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

from login import LoginServer, Token

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


def get_current_active_user(token: str = Depends(oauth2_scheme)):
    login_user = server.get_current_user(token)
    user_dict = fake_users_db.get(login_user.user_id)

    user_data = User(**user_dict)

    if user_data is None or user_data.disabled:
        return None

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


@app.post("/login/new", status_code=status.HTTP_201_CREATED)
def new_user(response: Response, form_data: OAuth2PasswordRequestForm = Depends()):
    success = server.create_user(form_data.username, form_data.password)

    if not success:
        response.status_code = status.HTTP_400_BAD_REQUEST


@app.get("/users/me/", response_model=User)
def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@app.get("/users/me/items/")
def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{"item_id": "Foo", "owner": current_user.username}]

# endregion FastAPI
