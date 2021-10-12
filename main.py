from pymongo import MongoClient
from fastapi import FastAPI
from pydantic import BaseModel
import os


#region MongoDB

mongo_host = os.environ.get("MONGO_CONN_URL", "localhost")
mongo_port = int(os.environ.get("MONGO_CONN_PORT", "27017"))

client = MongoClient(mongo_host, mongo_port)


class MongoUser(BaseModel):
    username: str
    password: str

#endregion MongoDB

#region JWTSigning

# to get a new SECRET_KEY string, run:
# openssl rand -hex 32
SECRET_KEY = os.environ.get("JWT_SIGNATURE")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

#endregion JWTSigning


app = FastAPI(title="Login DB")

