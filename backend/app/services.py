# backend/app/services.py

from sqlalchemy.orm import Session
from . import models
from typing import List, Dict, Any
import uuid
from datetime import datetime


def create_scan_job(db: Session, target: str, profile: str, tool: str) -> models.ScanJob:
    """
    Create a new scan job in the database.
    """
    try:
        scan_job = models.ScanJob(
            target=target,
            profile=profile,
            tool=tool,
            status="pending"
        )
        db.add(scan_job)
        db.commit()
        db.refresh(scan_job)
        return scan_job
    except Exception as e:
        db.rollback()
        raise e


def update_scan_job_status(db: Session, job_id: str, status: str, output_file: str = None, error_message: str = None):
    """
    Update the status of a scan job.
    """
    try:
        scan_job = db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()
        if scan_job:
            scan_job.status = status
            if output_file:
                scan_job.output_file = output_file
            if error_message:
                scan_job.error_message = error_message
            if status in ["completed", "failed"]:
                scan_job.completed_at = datetime.now()
            db.commit()
            db.refresh(scan_job)
        return scan_job
    except Exception as e:
        db.rollback()
        raise e


def get_scan_job(db: Session, job_id: str) -> models.ScanJob:
    """
    Retrieve a scan job by ID.
    """
    try:
        return db.query(models.ScanJob).filter(models.ScanJob.id == job_id).first()
    except Exception as e:
        raise e


def create_report(db: Session, target: str, raw_files: List[str], normalized_data: Dict[str, Any]) -> models.Report:
    """
    Create a new report in the database.
    """
    try:
        report = models.Report(
            target=target,
            raw_files=raw_files,
            normalized_data=normalized_data
        )
        db.add(report)
        db.commit()
        db.refresh(report)
        return report
    except Exception as e:
        db.rollback()
        raise e


def get_report(db: Session, report_id: str) -> models.Report:
    """
    Retrieve a report by ID.
    """
    try:
        return db.query(models.Report).filter(models.Report.id == report_id).first()
    except Exception as e:
        raise e


def get_reports_list(db: Session) -> List[models.Report]:
    """
    Retrieve all reports.
    """
    try:
        return db.query(models.Report).all()
    except Exception as e:
        raise e


def create_vulnerabilities(db: Session, report_id: str, vulnerabilities: List[Dict[str, Any]]) -> List[models.Vulnerability]:
    """
    Create vulnerability entries for a report.
    """
    try:
        created_vulns = []
        for vuln_data in vulnerabilities:
            vuln = models.Vulnerability(
                report_id=report_id,
                cve=vuln_data.get("cve"),
                cvss=vuln_data.get("cvss"),
                severity=vuln_data.get("severity"),
                title=vuln_data.get("title"),
                description=vuln_data.get("description"),
                affected_components=vuln_data.get("affected_components"),
                evidence=vuln_data.get("evidence"),
                exploit_refs=vuln_data.get("exploit_refs")
            )
            db.add(vuln)
            created_vulns.append(vuln)
        
        db.commit()
        
        # Refresh all created vulnerabilities
        for vuln in created_vulns:
            db.refresh(vuln)
            
        return created_vulns
    except Exception as e:
        db.rollback()
        raise e


def create_attack_graph(db: Session, report_id: str, nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]):
    """
    Create attack graph nodes and edges for a report.
    """
    try:
        # Create nodes
        for node_data in nodes:
            node = models.AttackGraphNode(
                report_id=report_id,
                node_id=node_data["id"],
                node_type=node_data["type"],
                label=node_data["label"],
                details=node_data.get("details")
            )
            db.add(node)
        
        # Create edges
        for edge_data in edges:
            edge = models.AttackGraphEdge(
                report_id=report_id,
                from_node=edge_data["from"],
                to_node=edge_data["to"],
                description=edge_data["desc"],
                score=edge_data.get("score")
            )
            db.add(edge)
        
        db.commit()
    except Exception as e:
        db.rollback()
        raise e


def get_attack_graph(db: Session, report_id: str):
    """
    Retrieve attack graph for a report.
    """
    try:
        nodes = db.query(models.AttackGraphNode).filter(models.AttackGraphNode.report_id == report_id).all()
        edges = db.query(models.AttackGraphEdge).filter(models.AttackGraphEdge.report_id == report_id).all()
        
        return {
            "nodes": [{"id": node.node_id, "type": node.node_type, "label": node.label, "details": node.details} for node in nodes],
            "edges": [{"from": edge.from_node, "to": edge.to_node, "desc": edge.description, "score": edge.score} for edge in edges]
        }
    except Exception as e:
        raise e


def create_threat_intel(db: Session, cve: str, description: str, cvss_score: str, exploit_refs: List[Dict[str, Any]]):
    """
    Create or update threat intelligence data.
    """
    try:
        intel = db.query(models.ThreatIntel).filter(models.ThreatIntel.cve == cve).first()
        if intel:
            # Update existing entry
            intel.description = description
            intel.cvss_score = cvss_score
            intel.exploit_refs = exploit_refs
            intel.updated_at = datetime.now()
        else:
            # Create new entry
            intel = models.ThreatIntel(
                cve=cve,
                description=description,
                cvss_score=cvss_score,
                exploit_refs=exploit_refs
            )
            db.add(intel)
        
        db.commit()
        db.refresh(intel)
        return intel
    except Exception as e:
        db.rollback()
        raise e


def get_threat_intel(db: Session, cve: str) -> models.ThreatIntel:
    """
    Retrieve threat intelligence data for a CVE.
    """
    try:
        return db.query(models.ThreatIntel).filter(models.ThreatIntel.cve == cve).first()
    except Exception as e:
        raise e


def create_chat_session(db: Session, report_id: str, user_id: str) -> models.ChatSession:
    """
    Create a new chat session.
    """
    try:
        session = models.ChatSession(
            report_id=report_id,
            user_id=user_id
        )
        db.add(session)
        db.commit()
        db.refresh(session)
        return session
    except Exception as e:
        db.rollback()
        raise e


def create_chat_message(db: Session, session_id: str, query: str, response: str, citations: List[Dict[str, Any]], confidence: float):
    """
    Create a new chat message.
    """
    try:
        message = models.ChatMessage(
            session_id=session_id,
            query=query,
            response=response,
            citations=citations,
            confidence=str(confidence)
        )
        db.add(message)
        db.commit()
        db.refresh(message)
        return message
    except Exception as e:
        db.rollback()
        raise e


def create_audit_log(db: Session, user_id: str, action: str, target: str, details: Dict[str, Any] = None):
    """
    Create a new audit log entry.
    """
    try:
        log = models.AuditLog(
            user_id=user_id,
            action=action,
            target=target,
            details=details
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        return log
    except Exception as e:
        db.rollback()
        raise e