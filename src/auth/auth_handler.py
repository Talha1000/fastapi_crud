import time
from typing import Dict
from datetime import datetime, timedelta

import jwt

JWT_SECRET = "secret"
JWT_ALGORITHM = "HS256"


def create_access_token(data: dict):
    to_encode = data.copy()
    expires = datetime.utcnow() + timedelta(days=2)
    to_encode.update({"expires": expires.timestamp()})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)


def token_response(access_token: str):
    return {
        "access_token": access_token
    }


def signJWT(id: int) -> Dict[str, str]:
    payload = {
        "id": id,
        "expires": time.time() + 600
    }
    access_token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return token_response(access_token)


def decodeJWT(access_token: str) -> dict:
    try:
        decoded_token = jwt.decode(
            access_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return decoded_token if decoded_token["expires"] >= time.time() else None
    except jwt.ExpiredSignatureError:
        return {}
    except jwt.InvalidTokenError:
        return {}
