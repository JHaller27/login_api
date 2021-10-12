from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

from login import LoginServer, Token, TokenHandler

import os


# to get a SECRET_KEY string, run:
# openssl rand -hex 32
secret_key = os.environ.get("JWT_SIGNATURE")
token_handler = TokenHandler(secret_key, 30)

# region MongoDB

mongo_url = os.environ.get("MONGO_CONN_URL", "localhost")
mongo_port = int(os.environ.get("MONGO_CONN_PORT", "27017"))

server = LoginServer(mongo_url, mongo_port, "test", token_handler)

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

TOKEN_PATH = "token/"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=TOKEN_PATH)


def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    if user := server.get_current_user(token):
        return user

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_active_user(user_id: str = Depends(get_current_user)) -> User:
    user_dict = fake_users_db.get(user_id)

    if user_dict is None:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="User exists in credentials database, but not in domain database")

    user_data = User(**user_dict)

    if user_data is None or user_data.disabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    return user_data


@app.post(f"/{TOKEN_PATH}", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    is_authenticated = server.authenticate_user(form_data.username, form_data.password)

    if not is_authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = token_handler.create_access_token(form_data.username)

    return access_token


@app.post("/login/new/", status_code=status.HTTP_201_CREATED)
def new_user(created_user: str = Depends(server.create_user)):
    if created_user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)

    new_user_obj = User(
        username=created_user,
        email=f"{created_user}@fakemail.com",
        full_name=created_user.title(),
        disabled=False
    )

    fake_users_db[created_user] = new_user_obj.dict()


@app.delete("/login/delete/", status_code=status.HTTP_202_ACCEPTED)
def delete_user(user_id: str = Depends(get_current_user)):
    fake_users_db.pop(user_id)

    if not server.delete_user(user_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)


@app.get("/users/me/", response_model=User)
def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@app.get("/users/me/items/")
def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{"item_id": "Foo", "owner": current_user.username}]

# endregion FastAPI
