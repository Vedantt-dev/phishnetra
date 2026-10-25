"""SQLite persistence for scan history and user feedback."""
import json
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import DB_URL

engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
Base = declarative_base()


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=utcnow, index=True)
    url = Column(Text, nullable=False)
    domain = Column(String(255), index=True)
    stage = Column(String(16), default="url")        # url (pre-navigation) | dom (post-load)
    source = Column(String(32), default="api")
    risk = Column(Float)
    verdict = Column(String(16), index=True)
    trust = Column(String(16))
    impersonated_brand = Column(String(64), nullable=True, index=True)
    layers_json = Column(Text)
    reasons_json = Column(Text)
    latency_ms = Column(Float)
    overridden = Column(Boolean, default=False)

    @property
    def layers(self):
        return json.loads(self.layers_json or "[]")

    @property
    def reasons(self):
        return json.loads(self.reasons_json or "[]")


class Feedback(Base):
    __tablename__ = "feedback"
    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=utcnow)
    url = Column(Text)
    label = Column(String(16))     # phishing | legitimate
    scan_id = Column(Integer, nullable=True)
    comment = Column(Text, nullable=True)


def init_db():
    Base.metadata.create_all(engine)
