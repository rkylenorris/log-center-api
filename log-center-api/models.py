from sqlalchemy import Column, String, DateTime, create_engine, Boolean, ForeignKey
from sqlalchemy import Enum as SQLAEnum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship, with_polymorphic
from datetime import datetime
from enum import Enum
from dotenv import load_dotenv
from sqlalchemy.engine.url import make_url
import os
import secrets

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
        
        
class KeyType(str, Enum):
    USER = "USER"
    PROCESS = "PROCESS"


class Environment(str, Enum):
    DEVELOPMENT = "DEVELOPMENT"
    PRODUCTION = "PRODUCTION"
    TESTING = "TESTING"
    

class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


def admin_api_key_exists(key: str, db: Session) -> bool:
    """
    Check if an API key exists in the database.
    
    :param key: The API key to check.
    :param db: The database session.
    :return: True if the key exists, False otherwise.
    """
    return db.query(AdminApiKey).filter(AdminApiKey.key == key, AdminApiKey.active == True).count() > 0

def api_key_exists(key: str, db: Session) -> bool:
    """
    Check if an API key exists in the database.
    
    :param key: The API key to check.
    :param db: The database session.
    :return: True if the key exists, False otherwise.
    """
    return db.query(AbstractAPIKey).filter(AbstractAPIKey.key == key, AbstractAPIKey.active == True).count() > 0

class AdminApiKey(Base):
    __tablename__ = "admin_api_keys"
    key = Column(String, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.now)
    active = Column(Boolean, default=True)
    deactivated_at = Column(DateTime, nullable=True)
    admin_key_holder_email = Column(String, ForeignKey("admin_key_holders.email"))
    
    def __init__(self, admin_key_holder_email: str):
        new_key = secrets.token_hex(32)
        while admin_api_key_exists(new_key, SessionLocal()):
            new_key = secrets.token_hex(32)
        self.key = new_key
        self.admin_key_holder_email = admin_key_holder_email
        self.created_at = datetime.now()
        self.active = True
        self.deactivated_at = None
    
    def deactivate_key(self):
        self.active = False
        self.deactivated_at = datetime.now()


class AbstractAPIKey(Base):
    __abstract__ = True
    key = Column(String, primary_key=True, index=True, unique=True)
    created_at = Column(DateTime, default=datetime.now)
    key_owner_email = Column(String, ForeignKey("key_holders.email"))
    deactivated_at = Column(DateTime, nullable=True)
    active = Column(Boolean, default=True)
    type = Column(SQLAEnum(KeyType), default=KeyType.USER)
    
    def __init__(self, key_owner_email: str, type: KeyType):
        
        new_key = secrets.token_hex(32)
        while api_key_exists(new_key, SessionLocal()):
            new_key = secrets.token_hex(32)
        
        self.key = new_key
        self.key_owner_email = key_owner_email
        self.created_at = datetime.now()
        self.active = True
        self.deactivated_at = None
        self.type = type
    
    __mapper_args__ = {
        'polymorphic_on': type,
        'polymorphic_identity': 'base'
    }
    
    def deactivate_key(self):
        self.active = False
        self.deactivated_at = datetime.now()


class UserAPIKey(AbstractAPIKey):
    __tablename__ = "user_api_keys"
    __mapper_args__ = {
        'polymorphic_identity': 'USER'
    }
    
    def __init__(self, key_owner_email: str, type: KeyType = KeyType.USER):
        super().__init__(key_owner_email, type)
        

class ProcessAPIKey(AbstractAPIKey):
    __tablename__ = "process_api_keys"
    process_name = Column(String, index=True)
    environment = Column(SQLAEnum(Environment), default=Environment.DEVELOPMENT, index=True)

    __mapper_args__ = {
        'polymorphic_identity': 'PROCESS'
    }
    
    def __init__(self, key_owner_email: str, process_name: str, environment: Environment, type: KeyType = KeyType.PROCESS):
        super().__init__(key_owner_email, type)
        self.process_name = process_name
        self.environment = environment
        
APIKeyPoly = with_polymorphic(AbstractAPIKey, [UserAPIKey, ProcessAPIKey])

class LogEntry(Base):
    __tablename__ = "logs"
    id = Column(String, primary_key=True, index=True)
    level = Column(SQLAEnum(LogLevel), index=True)
    message = Column(String)
    process_name = Column(String, index=True)
    timestamp = Column(DateTime, default=datetime.now)
    module = Column(String, nullable=True)
    function = Column(String, nullable=True)
    line_number = Column(String, nullable=True)


class AdminKeyHolder(Base):
    __tablename__ = "admin_key_holders"
    email = Column(String, primary_key=True, index=True)
    name = Column(String)
    admin_keys = relationship("AdminApiKey", backref="admin_key_holder", cascade="all, delete-orphan")
    created_at = Column(DateTime, default=datetime.now)
    active = Column(Boolean, default=True)
    deactivated_at = Column(DateTime, nullable=True)
    
    def __init__(self, email: str, name: str):
        self.email = email
        self.name = name
        self.created_at = datetime.now()
        self.active = True
        self.deactivated_at = None
    
    def deactivate_user(self):
        self.active = False
        self.deactivated_at = datetime.now()
    
    @property
    def all_keys(self):
        return self.admin_keys


class KeyHolder(Base):
    __tablename__ = "key_holders"
    email = Column(String, primary_key=True, index=True)
    name = Column(String)
    user_keys = relationship("UserAPIKey", backref="key_holder", cascade="all, delete-orphan")
    process_keys = relationship("ProcessAPIKey", backref="key_holder", cascade="all, delete-orphan")
    created_at = Column(DateTime, default=datetime.now)
    active = Column(Boolean, default=True)
    deactivated_at = Column(DateTime, nullable=True)
    
    def __init__(self, email: str, name: str):
        self.email = email
        self.name = name
        self.created_at = datetime.now()
        self.active = True
        self.deactivated_at = None
    
    def deactivate_user(self):
        self.active = False
        self.deactivated_at = datetime.now()
    
    @property
    def all_keys(self):
        return self.user_keys + self.process_keys

