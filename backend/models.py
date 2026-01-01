from pydantic import BaseModel, EmailStr, field_validator, Field, model_validator
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import re
from urllib.parse import urlparse
from sqlalchemy import  Column, Integer, String, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


# User Models
class UserCreate(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    
    class Config:
        from_attributes = True


# Token Models
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


# Board Models
class BoardCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError('Board name cannot be empty')
        return v.strip()


class BoardResponse(BaseModel):
    id: int
    user_id: int
    name: str
    pins: List['PinResponse'] = []
    
    class Config:
        from_attributes = True


# Pin Models
class PinCreate(BaseModel):
    board_id: int
    ioc_value: str = Field(..., min_length=1, max_length=500)
    ioc_type: str = Field(..., pattern="^(ip|domain|hash|keyword)$")  # "ip", "domain", "hash", "keyword"
    
    @model_validator(mode='before')
    @classmethod
    def extract_domain_from_url(cls, data: Any) -> Any:
        if isinstance(data, dict):
            ioc_type = data.get('ioc_type')
            ioc_value = data.get('ioc_value')
            
            if ioc_type == 'domain' and ioc_value:
                # Strip leading/trailing whitespace and slashes
                ioc_value = ioc_value.strip().strip('/')
                data['ioc_value'] = ioc_value # Update data with stripped value

                if '://' in ioc_value:
                    # If it looks like a URL, extract the domain
                    parsed_url = urlparse(ioc_value)
                    if parsed_url.netloc:
                        data['ioc_value'] = parsed_url.netloc
        return data

    @field_validator('ioc_value')
    @classmethod
    def validate_ioc_value(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError('IOC value cannot be empty')
        return v
    
    @field_validator('ioc_type')
    @classmethod
    def validate_ioc_type(cls, v: str) -> str:
        if v not in ['ip', 'domain', 'hash', 'keyword']:
            raise ValueError('ioc_type must be one of: ip, domain, hash, keyword')
        return v
    
    @model_validator(mode='after')
    def validate_ioc_format(self):
        # Validate IOC value format based on type
        if self.ioc_type == 'ip':
            # IPv4 or IPv6 pattern
            ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$'
            if not (re.match(ipv4_pattern, self.ioc_value) or re.match(ipv6_pattern, self.ioc_value)):
                raise ValueError('Invalid IP address format')
        elif self.ioc_type == 'domain':
            # Domain pattern (simplified)
            domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
            if not re.match(domain_pattern, self.ioc_value):
                raise ValueError('Invalid domain format')
        elif self.ioc_type == 'hash':
            # MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex)
            hash_pattern = r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'
            if not re.match(hash_pattern, self.ioc_value):
                raise ValueError('Invalid hash format (must be MD5, SHA1, or SHA256)')
        # keyword type doesn't need format validation
        return self


class PinResponse(BaseModel):
    id: int
    board_id: int
    ioc_value: str
    ioc_type: str
    active: bool
    
    class Config:
        from_attributes = True


# Snapshot Models
class SnapshotCreate(BaseModel):
    pin_id: int
    full_report_json: Dict[str, Any]


class SnapshotResponse(BaseModel):
    id: int
    pin_id: int
    timestamp: datetime
    full_report_json: Dict[str, Any]
    
    class Config:
        from_attributes = True


# Alert Models
class AlertCreate(BaseModel):
    pin_id: int
    delta_data: Dict[str, Any]


class AlertResponse(BaseModel):
    id: int
    pin_id: int
    timestamp: datetime
    delta_data: Dict[str, Any]
    pin: PinResponse
    
    class Config:
        from_attributes = True


# Update forward references
BoardResponse.model_rebuild()
AlertResponse.model_rebuild()



# SQLAlchemy ORM Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    
    boards = relationship("Board", back_populates="user", cascade="all, delete-orphan")


class Board(Base):
    __tablename__ = "boards"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    
    user = relationship("User", back_populates="boards")
    pins = relationship("Pin", back_populates="board", cascade="all, delete-orphan")


class Pin(Base):
    __tablename__ = "pins"
    
    id = Column(Integer, primary_key=True, index=True)
    board_id = Column(Integer, ForeignKey("boards.id"), nullable=False)
    ioc_value = Column(String, nullable=False)
    ioc_type = Column(String, nullable=False)  # "ip", "domain", "hash", "keyword"
    active = Column(Boolean, default=True)
    
    board = relationship("Board", back_populates="pins")
    snapshots = relationship("Snapshot", back_populates="pin", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="pin", cascade="all, delete-orphan")


class Snapshot(Base):
    __tablename__ = "snapshots"
    
    id = Column(Integer, primary_key=True, index=True)
    pin_id = Column(Integer, ForeignKey("pins.id"), nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    full_report_json = Column(JSON, nullable=False)
    
    pin = relationship("Pin", back_populates="snapshots")


class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    pin_id = Column(Integer, ForeignKey("pins.id"), nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    delta_data = Column(JSON, nullable=False)
    
    pin = relationship("Pin", back_populates="alerts")