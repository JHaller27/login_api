from pymongo import MongoClient
from pymongo.collection import Collection

from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta

from fastapi import HTTPException, status

from jose import JWTError, jwt
from passlib.context import CryptContext


class ServerConfig(BaseModel):
    url: str
    port: int
    db_name: str
    collection_name: str
    algorithm: str

    # Time in minutes
    # TODO: Use Pydantic magic to magic this return a timedelta
    # TODO: Docs example defaults to 15 - is this what we want?
    token_expire: int

    # to get a SECRET_KEY string, run:
    # openssl rand -hex 32
    secret_key: str


class MongoUser(BaseModel):
    user_id: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class LoginServer:
    _client: MongoClient
    _collection: Optional[Collection]
    _crypt_context: CryptContext

    def __init__(self, mongo_url: str, mongo_port: int, db_name: str, secret_key: str,
                 collection_name: str = "login", /,
                 algorithm: str = "HS256", token_expire: int = 30):
        self._config = ServerConfig(
            url=mongo_url,
            port=mongo_port,
            db_name=db_name,
            collection_name=collection_name,
            secret_key=secret_key,
            algorithm=algorithm,
            token_expire=token_expire,
        )

        self._crypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

        self._client = MongoClient(self._config.url, self._config.port)
        self.connect()

    def connect(self) -> None:
        db = self._client[self._config.db_name]
        coll = db[self._config.collection_name]

        self._collection = coll

    def disconnect(self) -> None:
        self._collection = None
        self._client.close()

    def get_user(self, user_id: str) -> Optional[MongoUser]:
        if user_dict := self._collection.find_one({"user_id": user_id}):
            return MongoUser(**user_dict)

    def authenticate_user(self, user_id: str, password: str) -> Optional[MongoUser]:
        user = self.get_user(user_id)

        if not user:
            return None

        if not self.verify_password(password, user.password):
            return None

        return user

    def create_access_token(self, data: dict) -> str:
        to_encode = data.copy()

        expires_delta = timedelta(minutes=self._config.token_expire)

        expire = datetime.utcnow() + expires_delta
        to_encode.update({"exp": expire})

        encoded_jwt = jwt.encode(to_encode, self._config.secret_key, algorithm=self._config.algorithm)

        return encoded_jwt

    def get_current_user(self, token: str) -> MongoUser:
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

        try:
            payload = jwt.decode(token, self._config.secret_key, algorithms=[self._config.algorithm])
            username: str = payload.get("sub")
            if username is None:
                raise credentials_exception
            token_data = TokenData(username=username)
        except JWTError:
            raise credentials_exception

        user = self.get_user(token_data.username)
        if user is None:
            raise credentials_exception

        return user

    def verify_password(self, plain_password, hashed_password) -> bool:
        return self._crypt_context.verify(plain_password, hashed_password)

    def get_password_hash(self, password):
        return self._crypt_context.hash(password)

    def create_user(self, user_id: str, password: str) -> bool:
        """
        Create a new user. Return true if user successfully added, false if user could not be added.
        """
        if self.get_user(user_id) is not None:
            return False

        new_user = MongoUser(user_id=user_id, password=password)
        self._collection.insert_one(new_user.dict())

        return True
