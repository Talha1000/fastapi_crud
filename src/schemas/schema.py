from pydantic import BaseModel


class UserBase(BaseModel):
    name: str
    phone: str
    email: str
    password: str


class LoginRequest(BaseModel):
    email: str
    password: str


class UserIn(UserBase):
    pass


class UserUpdate(UserBase):
    pass


class UserOut(UserBase):
    id: int

    class Config:
        from_attributes = True
