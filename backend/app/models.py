# backend/app/models.py

from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from typing import List, Dict, Any
import uuid

Base = declarative_base()


class ScanJob(Base):
    """
    Model representing a scan job.
    """
    __tablename__ = "scan_jobs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target = Column(String, nullable=False)
    profile = Column(String, nullable=False)
    status = Column(String, default="pending")  # pending, running, completed, failed
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    completed_at = Column(DateTime, nullable=True)
    tool = Column(String, nullable=False)  # nmap, nuclei, nikto
    output_file = Column(String, nullable=True)
    error_message = Column(Text, nullable=True)


class Report(Base):
    """
    Model representing a normalized scan report.
    """
    __tablename__ = "reports"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target = Column(String, nullable=False)
    scan_timestamp = Column(DateTime, default=func.now())
    raw_files = Column(JSON, nullable=True)  # Store paths to raw output files
    normalized_data = Column(JSON, nullable=True)  # Store normalized scan data
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())


class Vulnerability(Base):
    """
    Model representing a normalized vulnerability.
    """
    __tablename__ = "vulnerabilities"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    report_id = Column(String, ForeignKey("reports.id"), nullable=False)
    cve = Column(String, nullable=True)
    cvss = Column(String, nullable=True)
    severity = Column(String, nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    affected_components = Column(JSON, nullable=True)
    evidence = Column(JSON, nullable=True)
    exploit_refs = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=func.now())


class AttackGraphNode(Base):
    """
    Model representing a node in the attack graph.
    """
    __tablename__ = "attack_graph_nodes"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    report_id = Column(String, ForeignKey("reports.id"), nullable=False)
    node_id = Column(String, nullable=False)  # ID used in the graph
    node_type = Column(String, nullable=False)  # host, service, vuln
    label = Column(String, nullable=False)
    details = Column(JSON, nullable=True)  # Additional details about the node
    created_at = Column(DateTime, default=func.now())


class AttackGraphEdge(Base):
    """
    Model representing an edge in the attack graph.
    """
    __tablename__ = "attack_graph_edges"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    report_id = Column(String, ForeignKey("reports.id"), nullable=False)
    from_node = Column(String, nullable=False)  # node_id of source node
    to_node = Column(String, nullable=False)  # node_id of target node
    description = Column(String, nullable=False)
    score = Column(String, nullable=True)  # Exploitability score
    created_at = Column(DateTime, default=func.now())


class ThreatIntel(Base):
    """
    Model representing threat intelligence data.
    """
    __tablename__ = "threat_intel"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    cve = Column(String, nullable=False, unique=True)
    description = Column(Text, nullable=True)
    cvss_score = Column(String, nullable=True)
    exploit_refs = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())


class ChatSession(Base):
    """
    Model representing a chat session.
    """
    __tablename__ = "chat_sessions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    report_id = Column(String, ForeignKey("reports.id"), nullable=False)
    user_id = Column(String, nullable=False)
    created_at = Column(DateTime, default=func.now())


class ChatMessage(Base):
    """
    Model representing a chat message.
    """
    __tablename__ = "chat_messages"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String, ForeignKey("chat_sessions.id"), nullable=False)
    query = Column(Text, nullable=False)
    response = Column(Text, nullable=False)
    citations = Column(JSON, nullable=True)
    confidence = Column(String, nullable=True)
    created_at = Column(DateTime, default=func.now())


class AuditLog(Base):
    """
    Model representing an audit log entry.
    """
    __tablename__ = "audit_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, nullable=False)
    action = Column(String, nullable=False)
    target = Column(String, nullable=False)
    timestamp = Column(DateTime, default=func.now())
    details = Column(JSON, nullable=True)


class User(Base):
    """
    Model representing a user.
    """
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="user")
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    is_active = Column(Boolean, default=True)
