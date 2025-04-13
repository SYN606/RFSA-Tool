from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from datetime import datetime

# Database configuration
DB_DIR = "analysis"
DB_FILE = "db.sqlite3"
DB_PATH = os.path.join(DB_DIR, DB_FILE)

# SQLAlchemy base and engine
Base = declarative_base()
engine = create_engine(f"sqlite:///{DB_PATH}")
SessionLocal = sessionmaker(bind=engine)


# === Firmware CVE Signature Model ===
class FirmwareSignature(Base):
    __tablename__ = "firmware_signatures"

    id = Column(Integer, primary_key=True)
    vendor = Column(String(100), nullable=False)
    model = Column(String(100), nullable=True)
    version = Column(String(100), nullable=False)
    cve_id = Column(String(50), nullable=True)
    description = Column(Text)


# === Metadata Table for Storing Last Sync, Version etc. ===
class Metadata(Base):
    __tablename__ = "metadata"

    id = Column(Integer, primary_key=True)
    key = Column(String(100), unique=True, nullable=False)
    value = Column(String(255), nullable=True)
    last_modified = Column(DateTime, default=datetime.utcnow)


# === Initialize DB (Creates Tables) ===
def init_db():
    # Ensure the directory exists
    os.makedirs(DB_DIR, exist_ok=True)
    Base.metadata.create_all(engine)
