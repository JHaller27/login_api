from pymongo import MongoClient
from pymongo.collection import Collection

from pydantic import BaseModel
from typing import Optional

from passlib.context import CryptContext

from .tokens import TokenHandler


class ServerConfig(BaseModel):
    url: str
    port: int
    db_name: str
    collection_name: str


class MongoUser(BaseModel):
    user_id: str
    password: str


class LoginServer:
    _client: MongoClient
    _collection: Optional[Collection]
    _crypt_context: CryptContext
    _token_handler: TokenHandler

    def __init__(self, mongo_url: str, mongo_port: int, db_name: str, token_handler: TokenHandler,
                 collection_name: str = "login"):
        self._config = ServerConfig(
            url=mongo_url,
            port=mongo_port,
            db_name=db_name,
            collection_name=collection_name,
        )

        self._token_handler = token_handler

        self._crypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

        self._client = MongoClient(self._config.url, self._config.port)
        self.connect()

    def _get_user(self, user_id: str) -> Optional[MongoUser]:
        if user_dict := self._collection.find_one({"user_id": user_id}):
            return MongoUser(**user_dict)

    def _verify_password(self, plaintext_password, hashed_password) -> bool:
        return self._crypt_context.verify(plaintext_password, hashed_password)

    def _get_password_hash(self, password):
        return self._crypt_context.hash(password)

    def connect(self) -> None:
        db = self._client[self._config.db_name]
        coll = db[self._config.collection_name]

        self._collection = coll

    def disconnect(self) -> None:
        self._collection = None
        self._client.close()

    def authenticate_user(self, user_id: str, plaintext_password: str) -> bool:
        user = self._get_user(user_id)

        if not user:
            return False

        if not self._verify_password(plaintext_password, user.password):
            return False

        return True

    # Create
    def create_user(self, user_id: str, plaintext_password: str) -> Optional[str]:
        """
        Create a new user. Return the user id if user successfully added, None if user could not be added.
        """
        if self._get_user(user_id) is not None:
            return None

        hashed_pass = self._get_password_hash(plaintext_password)

        new_user = MongoUser(user_id=user_id, password=hashed_pass)
        self._collection.insert_one(new_user.dict())

        return user_id

    # Read
    def get_current_user(self, token: str) -> Optional[str]:
        username = self._token_handler.get_subject(token)
        if username is None:
            return None

        user = self._get_user(username)
        if user is None:
            return None

        return user.user_id

    # Update
    def update_user(self, token: str, plaintext_password: str) -> bool:
        # TODO Implement update user
        return False

    # Delete
    def delete_user(self, user_id: str) -> bool:
        self._collection.delete_one({"user_id": user_id})
        return True
