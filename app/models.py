from sqlalchemy import Column, Integer, String, Text, TIMESTAMP
from .database import Base
from sqlalchemy.sql import func


class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String)
    event_type = Column(String)
    severity = Column(String)
    message = Column(Text)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    type = Column(String)
    source_ip = Column(String)
    severity = Column(String)
    details = Column(Text)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    role = Column(String, default="viewer")
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
