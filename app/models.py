from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Boolean
from sqlalchemy.sql import func
from .db import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    encrypted_tokens = Column(Text, nullable=True)
    last_history_id = Column(String, nullable=True)
    last_scan_date = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ScanProgress(Base):
    __tablename__ = "scan_progress"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False, unique=True)
    current_message = Column(Integer, default=0, server_default="0")
    estimated_total = Column(Integer, default=0, server_default="0")
    is_scanning = Column(Boolean, default=False, server_default="0")
    started_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True),
                        server_default=func.now(), onupdate=func.now())
    new_subscriptions_found = Column(Integer, default=0, server_default="0")
    total_messages_scanned = Column(Integer, default=0, server_default="0")


class SubscriptionGroup(Base):
    __tablename__ = "subscription_groups"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    sender_domain = Column(String, index=True)
    sender_name = Column(String)
    frequency_score = Column(Integer, default=0, server_default="0")
    confidence_score = Column(Integer, default=0, server_default="0")
    example_subjects = Column(JSON)
    unsubscribed = Column(Integer, default=0,
                          server_default="0", nullable=False)
    unsubscribe_failed = Column(Integer, default=0,
                                server_default="0", nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class SubscriptionMessage(Base):
    __tablename__ = "subscription_messages"
    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, index=True, nullable=False)
    gmail_thread_id = Column(String, index=True)
    unsubscribe_methods = Column(JSON)
    detected_headers = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
