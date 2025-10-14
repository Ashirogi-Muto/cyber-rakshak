# backend/app/main_complete.py

from fastapi import FastAPI, status, HTTPException, Body, Depends, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any
import uuid
import json
import time
from .worker import run_nmap_scan, run_nuclei_scan, run_nikto_scan
from . import database, models, services
from .upload import normalize_uploaded_report
from .auth import get_current_active_user, get_current_admin_user, authenticate_user, create_access_token
from .security import limiter, get_scan_limit, verify_scan_authorization, validate_target, create_audit_log_entry
from .intel import enrich_vulnerabilities
from .attack_path import generate_attack_graph, score_attack_paths, identify_critical_paths
from .chat import get_chat_assistant
from .init_db import init_db
from sqlalchemy.orm import Session
from datetime import timedelta
from slowapi.errors import RateLimitExceeded

# Initialize the database with default users
init_db()

# Create all tables in the database
models.Base.metadata.create_all(bind=database.engine)

# Create the FastAPI app instance
app = FastAPI(
    title="Centralized Vulnerability Detection & Intelligent Query Interface",
    description="API for orchestrating vulnerability scans, managing reports, and querying results.",
    version="0.1.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this to specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add rate limiting middleware
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Dependency to get a database session
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Initialize chat assistant
chat_assistant = get_chat_assistant()

# --- Authentication Endpoints ---

@app.post("/api/auth/token", tags=["Authentication"])
async def login_for_access_token(form_data: Dict[str, str] = Body(...), db: Session = Depends(get_db)):
    """Authenticate user and return access token."""
    username = form_data.get("username")
    password = form_data.get("password")
    
    if not username or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username and password required"
        )
    
    user = authenticate_user(db, username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer", "role": user.role}

# --- API Endpoints ---

@app.get("/", tags=["Health Check"])
async def read_root():
    """A simple health check endpoint."""
    return {"status": "ok", "message": "Welcome to the Vulnerability Detection API!"}

@app.post("/api/scan/start", status_code=status.HTTP_202_ACCEPTED, tags=["Scanning"])
async def start_scan(
    scan_request: Dict[str, Any] = Body(...), 
    db: Session = Depends(get_db),
    user: User = Depends(get_current_active_user)
):
    """
    Accepts a scan request and queues it for background processing via Celery.
    - target: The target to scan (e.g., 'scanme.nmap.org').
    - profile: The scan profile ('safe', 'normal', 'deep').
    - tools: List of tools to use (nmap, nuclei, nikto).
    """
    target = scan_request.get("target")
    profile = scan_request.get("profile", "safe")
    tools = scan_request.get("tools", ["nmap"])

    if not target:
        raise HTTPException(status_code=400, detail="'target' is required.")
    
    # Validate target
    if not validate_target(target):
        raise HTTPException(status_code=400, detail="Invalid target")
    
    # Verify authorization
    if not verify_scan_authorization(target, profile, user):
        raise HTTPException(status_code=403, detail="Not authorized to scan this target with this profile")
    
    # Apply rate limiting
    rate_limit = get_scan_limit(profile, user)
    
    job_ids = []
    
    # Create audit log entry
    create_audit_log_entry(user.username, "start_scan", target, {
        "profile": profile,
        "tools": tools
    })
    
    # Create scan jobs in the database and send tasks to the Celery workers
    if "nmap" in tools:
        # Create database entry
        scan_job = services.create_scan_job(db, target, profile, "nmap")
        # Send the task to the Celery worker
        task = run_nmap_scan.delay(target=target, profile=profile)
        job_ids.append({"tool": "nmap", "job_id": task.id, "db_id": scan_job.id})
    
    if "nuclei" in tools:
        # Create database entry
        scan_job = services.create_scan_job(db, target, profile, "nuclei")
        # Send the task to the Celery worker
        task = run_nuclei_scan.delay(target=target, profile=profile)
        job_ids.append({"tool": "nuclei", "job_id": task.id, "db_id": scan_job.id})
    
    if "nikto" in tools:
        # Create database entry
        scan_job = services.create_scan_job(db, target, profile, "nikto")
        # Send the task to the Celery worker
        task = run_nikto_scan.delay(target=target, profile=profile)
        job_ids.append({"tool": "nikto", "job_id": task.id, "db_id": scan_job.id})

    return {"message": "Scans accepted and queued.", "jobs": job_ids}

@app.get("/api/scan/status/{job_id}", tags=["Scanning"])
async def get_scan_status(
    job_id: str, 
    db: Session = Depends(get_db),
    user: User = Depends(get_current_active_user)
):
    """Retrieves the status of a background scan job."""
    scan_job = services.get_scan_job(db, job_id)
    if not scan_job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    
    # Create audit log entry
    create_audit_log_entry(user.username, "get_scan_status", scan_job.target)
    
    return {
        "job_id": scan_job.id,
        "status": scan_job.status,
        "tool": scan_job.tool,
        "target": scan_job.target,
        "profile": scan_job.profile,
        "created_at": scan_job.created_at,
        "completed_at": scan_job.completed_at
    }

@app.get("/api/reports", tags=["Reports"])
async def get_reports_list(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_active_user)
):
    """Returns a list of all available reports."""
    reports = services.get_reports_list(db)
    report_list = []
    for report in reports:
        # Count vulnerabilities by severity
        vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        # In a full implementation, we would query the vulnerabilities table
        # For now, we'll use placeholder data
        report_list.append({
            "report_id": report.id,
            "target": report.target,
            "scan_timestamp": report.scan_timestamp,
            "severity_counts": vuln_counts
        })
    
    # Create audit log entry
    create_audit_log_entry(user.username, "get_reports_list", "all_reports")
    
    return report_list

@app.get("/api/report/{report_id}", tags=["Reports"])
async def get_report_details(
    report_id: str, 
    db: Session = Depends(get_db),
    user: User = Depends(get_current_active_user)
):
    """Returns the full normalized JSON for a specific report."""
    report = services.get_report(db, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Create audit log entry
    create_audit_log_entry(user.username, "get_report_details", report.target)
    
    # Return the normalized report data
    return {
        "report_id": report.id,
        "target": report.target,
        "scan_timestamp": report.scan_timestamp,
        "scans": report.normalized_data.get("scans", []),
        "vulnerabilities": report.normalized_data.get("vulnerabilities", []),
        "attack_graph": report.normalized_data.get("attack_graph", {}),
        "enrichment": report.normalized_data.get("enrichment", {})
    }

@app.post("/api/report/upload", tags=["Reports"])
async def upload_report(
    file: UploadFile = File(...),
    report_data: str = Body(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_admin_user)  # Only admins can upload reports
):
    """Uploads and processes scanner raw outputs (xml/json) to normalize."""
    try:
        # Parse the report data JSON
        data = json.loads(report_data)
        target = data.get("target", "unknown")
        file_type = data.get("file_type", "openvas")  # openvas, nessus
        
        # Read the uploaded file content
        content = await file.read()
        file_content = content.decode('utf-8')
        
        # Normalize the uploaded report
        normalized_data = normalize_uploaded_report(file_content, file_type)
        
        # Update target if provided in the request
        if target != "unknown":
            normalized_data["target"] = target
        
        # Create a new report in the database
        report = services.create_report(
            db, 
            normalized_data["target"], 
            [f"uploaded_{file_type}_report"], 
            normalized_data
        )
        
        # Create vulnerabilities if provided
        vulnerabilities = normalized_data.get("vulnerabilities", [])
        if vulnerabilities:
            services.create_vulnerabilities(db, report.id, vulnerabilities)
        
        # Create attack graph if provided
        attack_graph = normalized_data.get("attack_graph", {})
        if attack_graph:
            nodes = attack_graph.get("nodes", [])
            edges = attack_graph.get("edges", [])
            if nodes and edges:
                services.create_attack_graph(db, report.id, nodes, edges)
        
        # Create audit log entry
        create_audit_log_entry(user.username, "upload_report", normalized_data["target"], {
            "file_type": file_type,
            "report_id": report.id
        })
        
        return {"message": "Report uploaded successfully", "report_id": report.id}
        
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON in report_data")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing upload: {str(e)}")

@app.get("/api/attackpath/{report_id}", tags=["Attack Path"])
async def get_attack_path(
    report_id: str, 
    db: Session = Depends(get_db),
    user: User = Depends(get_current_active_user)
):
    """Returns the attack graph JSON for a specific report."""
    # Check if report exists
    report = services.get_report(db, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Create audit log entry
    create_audit_log_entry(user.username, "get_attack_path", report.target)
    
    # Get attack graph from database
    attack_graph = services.get_attack_graph(db, report_id)
    return attack_graph

@app.post("/api/chat/query", tags=["Chat"])
async def chat_query(
    query_data: Dict[str, Any] = Body(...), 
    db: Session = Depends(get_db),
    user: User = Depends(get_current_active_user)
):
    """Processes a natural language query about reports/attack paths."""
    report_id = query_data.get("report_id")
    query = query_data.get("query")
    mode = query_data.get("mode", "text")
    
    if not report_id or not query:
        raise HTTPException(status_code=400, detail="'report_id' and 'query' are required")
    
    # Check if report exists
    report = services.get_report(db, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    # Create audit log entry
    create_audit_log_entry(user.username, "chat_query", report.target, {
        "query": query
    })
    
    # Create a chat session if it doesn't exist
    session = services.create_chat_session(db, report_id, user.username)
    
    # Add report data to chat assistant
    chat_assistant.add_report_chunks(report.normalized_data)
    
    # Process the query and generate a response
    response = chat_assistant.process_query(query)
    
    # Save the chat message
    services.create_chat_message(
        db, 
        session.id, 
        query, 
        response["answer"], 
        response["citations"], 
        response["confidence"]
    )
    
    return response

@app.get("/api/intel/cve/{cve}", tags=["Threat Intel"])
async def get_cve_intel(
    cve: str, 
    db: Session = Depends(get_db),
    user: User = Depends(get_current_active_user)
):
    """Returns NVD/ExploitDB enrichment entry for a specific CVE."""
    # Create audit log entry
    create_audit_log_entry(user.username, "get_cve_intel", cve)
    
    intel = services.get_threat_intel(db, cve)
    if not intel:
        raise HTTPException(status_code=404, detail="Threat intelligence not found for this CVE")
    
    return {
        "cve": intel.cve,
        "description": intel.description,
        "cvss": intel.cvss_score,
        "exploit_refs": intel.exploit_refs,
        "updated_at": intel.updated_at
    }