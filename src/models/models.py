from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer,
                primary_key=True, index=True, autoincrement=True)
    name = Column(String(255), index=True)
    phone = Column(String(255))
    email = Column(String(255), unique=True, index=True)
    password = Column(String(255))
