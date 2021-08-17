from datetime import datetime, timedelta

from typing import Optional
from pydantic import BaseModel

from jose import JWTError, jwt


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenHandlerConfig(BaseModel):
    algorithm: str

    # Time in minutes
    # TODO: Use Pydantic magic to magic this return a timedelta
    # TODO: Docs example defaults to 15 - is this what we want?
    token_expire: int

    # to get a SECRET_KEY string, run:
    # openssl rand -hex 32
    secret_key: str


class TokenHandler:
    _config: TokenHandlerConfig

    def __init__(self, secret_key: str, token_expire: int = 30, algorithm: str = "HS256"):
        self._config = TokenHandlerConfig(algorithm=algorithm, token_expire=token_expire, secret_key=secret_key)

    def create_access_token(self, subject: str, **kwargs) -> Token:
        data = {"sub": subject, **kwargs}
        to_encode = data.copy()

        expires_delta = timedelta(minutes=self._config.token_expire)

        expire = datetime.utcnow() + expires_delta
        # noinspection PyTypeChecker
        to_encode.update({"exp": expire})

        encoded_jwt = jwt.encode(to_encode, self._config.secret_key, algorithm=self._config.algorithm)

        return Token(access_token=encoded_jwt, token_type="bearer")

    def _decode(self, token: str) -> Optional[dict]:
        try:
            payload = jwt.decode(token, self._config.secret_key, algorithms=[self._config.algorithm])
            return payload

        except JWTError as jwterr:
            return None

    def get_subject(self, token: str) -> Optional[str]:
        payload = self._decode(token)

        if payload is None:
            return None

        return payload.get("sub")
