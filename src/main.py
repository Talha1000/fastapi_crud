from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from passlib.hash import bcrypt
import uvicorn
import time
from datetime import datetime, timedelta
import jwt
import models.models as models
import schemas.schema as schemas
from database.db import SessionLocal, engine

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

models.Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain_password, hashed_password):
    return bcrypt.verify(plain_password, hashed_password)


def get_current_user(access_token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"}
    )

    decoded_token = decodeJWT(access_token)
    if decoded_token is None:
        raise credentials_exception

    print("Decoded Token:", decoded_token)

    return decoded_token


def create_access_token(data: dict):
    to_encode = data.copy()
    expires = datetime.utcnow() + timedelta(days=2)
    to_encode.update({"expires": expires.timestamp()})
    return jwt.encode(to_encode, "secret", algorithm="HS256")


def decodeJWT(access_token: str) -> dict:
    try:
        decoded_token = jwt.decode(
            access_token, "secret", algorithms=["HS256"])
        return decoded_token if decoded_token["expires"] >= time.time() else None
    except jwt.ExpiredSignatureError:
        return {}
    except jwt.InvalidTokenError:
        return {}


@app.post("/user-login/")
def login(login_request: schemas.LoginRequest, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(
        models.User.email == login_request.email).first()
    if not db_user or not verify_password(login_request.password, db_user.password):
        return {"message": "Login failed", "authenticated": False}
    access_token = create_access_token(data={"sub": db_user.email})
    print("Generated Token:", access_token)
    return {"message": "Login successful", "authenticated": True, "access_token": access_token, "token_type": "bearer"}


@app.get("/protected-route")
async def protected_route(current_user: dict = Depends(get_current_user)):
    return {"message": "This is secure data!", "user_id": current_user.get("id")}


@app.post("/create-users/", response_model=dict)
def create_user(user: schemas.UserIn, db: Session = Depends(get_db)):
    hashed_password = bcrypt.hash(user.password)

    db_user = models.User(name=user.name, phone=user.phone,
                          email=user.email, password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    access_token = create_access_token(data={"sub": db_user.email})
    return {"message": "User created successfully", "access_token": access_token, "token_type": "bearer"}


@app.get("/read-all-users", response_model=dict)
def read_all_users(db: Session = Depends(get_db), access_token: str = Depends(decodeJWT)):
    if not access_token:
        raise HTTPException(status_code=401, detail="Invalid token")

    db_users = db.query(models.User).all()
    decoded_users = [{"id": user.id, "name": user.name, "phone": user.phone,
                      "email": user.email, "password": user.password} for user in db_users]
    return {"users": decoded_users}


@app.get("/read-profile/{id}")
def read_profile(id: int, db: Session = Depends(get_db), access_token: str = Depends(decodeJWT)):
    if not access_token and access_token["id"] != id:
        raise HTTPException(
            status_code=403, detail="Not authorized to access this profile")

    db_user = db.query(models.User).filter(
        models.User.id == id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    return {"id": db_user.id, "name": db_user.name, "phone": db_user.phone,
            "email": db_user.email, "password": db_user.password}


@app.put("/users-update/{id}")
def update_user(id: int, user: schemas.UserUpdate, db: Session = Depends(get_db), access_token: str = Depends(decodeJWT)):
    if not access_token and access_token["id"] != id:
        raise HTTPException(
            status_code=403, detail="Not authorized to update this user")

    db_user = db.query(models.User).filter(models.User.id == id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db_user_data = user.__dict__
    for field, value in db_user_data.items():
        setattr(db_user, field, value)

    db.commit()
    db.refresh(db_user)
    return {"message": "User updated successfully"}


@app.delete("/users-delete/{id}", response_model=dict)
def delete_user(id: int, db: Session = Depends(get_db), access_token: str = Depends(decodeJWT)):
    if not access_token and access_token["id"] != id:
        raise HTTPException(
            status_code=403, detail="Not authorized to delete this user")

    db_user = db.query(models.User).filter(models.User.id == id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(db_user)
    db.commit()
    return {"message": "User deleted successfully"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000,
                reload=True, log_level="info")
