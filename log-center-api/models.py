from sqlalchemy import Column, String, DateTime, create_engine, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from datetime import datetime
from enum import Enum
from dotenv import load_dotenv
from sqlalchemy.engine.url import make_url
import os

load_dotenv()

DATABASE_URL = os.getenv("LOG_CENTER_DATABASE_URL", "sqlite:///./logs.db")



url = make_url(DATABASE_URL)
connect_args = {"check_same_thread": False} if url.drivername.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class APIKey(Base):
    __tablename__ = "api_keys"
    key = Column(String, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.now)
    owner_email = Column(String, ForeignKey("key_holders.email"))
    deactivated_at = Column(DateTime, nullable=True)
    active = Column(Boolean, default=True)
    
    def deactivate_key(self):
        self.active = False
        self.deactivated_at = datetime.now()

class LogEntry(Base):
    __tablename__ = "logs"
    id = Column(String, primary_key=True, index=True)
    level = Column(String, index=True)
    message = Column(String)
    process_name = Column(String, index=True)
    timestamp = Column(DateTime, default=datetime.now)
    
class KeyHolder(Base):
    __tablename__ = "key_holders"
    email = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=True)
    keys = relationship("APIKey", back_populates="api_key")
    created_at = Column(DateTime, default=datetime.now)
    active = Column(Boolean, default=True)
    deactivated_at = Column(DateTime, nullable=True)
    
    def __init__(self, email: str, name: str = None):
        self.email = email
        self.name = name
        self.created_at = datetime.now()
        self.active = True
        self.deactivated_at = None
    
    def deactivate_user(self):
        self.active = False
        self.deactivated_at = datetime.now()
