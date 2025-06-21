from datetime import datetime
from enum import Enum

from sqlalchemy import Boolean, Column, DateTime
from sqlalchemy import Enum as SQLAEnum
from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import with_polymorphic

from .db import Base


class Environment(str, Enum):
    DEVELOPMENT = "DEVELOPMENT"
    PRODUCTION = "PRODUCTION"
    TESTING = "TESTING"


class KeyType(str, Enum):
    USER = "USER"
    PROCESS = "PROCESS"
    ADMIN = "ADMIN"


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(String, nullable=True)
    created = Column(DateTime, default=datetime.now)
    updated = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    read_only = Column(Boolean, default=False)
    read_write = Column(Boolean, default=True)
    delete = Column(Boolean, default=False)
    is_admin = Column(Boolean, default=False)

    def __repr__(self):
        return f"<Auth_Roles(name={self.name})>"
    

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(Integer, ForeignKey("auth_roles.id", ondelete="SET NULL"))
    active = Column(Boolean, default=True)
    created = Column(DateTime, default=datetime.now)
    updated = Column(DateTime, default=datetime.now, onupdate=datetime.now)

    def __repr__(self):
        return f"<Auth_User(username={self.username}, role={self.role})>"


class AbstractAPIKey(Base):
    __abstract__ = True
    
    key = Column(String, primary_key=True, index=True, unique=True)
    owner_id = Column(Integer, ForeignKey("auth_users.id"))
    created = Column(DateTime, default=datetime.now)
    active = Column(Boolean, default=True)
    deactivated = Column(DateTime, nullable=True)
    type = Column(SQLAEnum(KeyType), default=KeyType.USER)
    
    def __init__(self, key: str, owner_id: int, type: KeyType):
        self.key = key
        self.owner_id = owner_id
        self.created = datetime.now()
        self.active = True
        self.deactivated = None
        self.type = type
    
    __mapper_args__ = {
        'polymorphic_on': type,
        'polymorphic_identity': 'base'
    }

    def deactivate_key(self):
        self.active = False
        self.deactivated = datetime.now()
        

class UserAPIKey(AbstractAPIKey):
    __tablename__ = "user_api_keys"
    
    __mapper_args__ = {
        'polymorphic_identity': KeyType.USER
    }
    
    def __init__(self, key: str, owner_id: int, type: KeyType = KeyType.USER):
        super().__init__(key, owner_id, type)


class ProcessAPIKey(AbstractAPIKey):
    __tablename__ = "process_api_keys"
    process_id = Column(Integer, ForeignKey("processes.id", ondelete="SET NULL"))
    environment = Column(SQLAEnum(Environment), default=Environment.DEVELOPMENT)
    
    __mapper_args__ = {
        'polymorphic_identity': KeyType.PROCESS
    }
    
    def __init__(self, key: str, owner_id: int, type: KeyType = KeyType.PROCESS):
        super().__init__(key, owner_id, type)


class AdminAPIKey(AbstractAPIKey):
    __tablename__ = "admin_api_keys"
    
    __mapper_args__ = {
        'polymorphic_identity': KeyType.ADMIN
    }
    
    def __init__(self, key: str, owner_id: int, type: KeyType = KeyType.ADMIN):
        super().__init__(key, owner_id, type)

APIKeyPoly = with_polymorphic(AbstractAPIKey, [UserAPIKey, ProcessAPIKey, AdminAPIKey])

