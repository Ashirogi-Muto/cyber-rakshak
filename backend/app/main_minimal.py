# backend/app/main_minimal.py

from fastapi import FastAPI, status, HTTPException, Body, Depends
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, List, Any
from . import database, models
from .auth import authenticate_user, create_access_token, get_current_user
from sqlalchemy.orm import Session
from datetime import timedelta
import uuid

# Create the FastAPI app instance
app = FastAPI(
    title="Cybersecurity Dashboard API",
    description="API for the Cybersecurity Dashboard with authentication and reporting",
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

# Dependency to get a database session
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Initialize the database
models.Base.metadata.create_all(bind=database.engine)

@app.post("/api/auth/token")
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

@app.get("/")
async def read_root():
    """A simple health check endpoint."""
    return {"status": "ok", "message": "Cybersecurity Dashboard API is running!"}

# Report endpoints
@app.get("/api/reports")
async def get_reports_list(db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """Get list of all reports."""
    try:
        # Return a placeholder list of reports
        return [
            {
                "report_id": "rpt-2025-10-13-0001",
                "target": "example.com",
                "scan_timestamp": "2025-10-13T09:12:00Z",
                "severity_counts": {
                    "critical": 1,
                    "high": 3,
                    "medium": 5,
                    "low": 12
                }
            },
            {
                "report_id": "rpt-2025-10-12-0002",
                "target": "test.org",
                "scan_timestamp": "2025-10-12T14:30:00Z",
                "severity_counts": {
                    "critical": 0,
                    "high": 2,
                    "medium": 4,
                    "low": 8
                }
            }
        ]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch reports: {str(e)}"
        )

@app.get("/api/report/{report_id}")
async def get_report_details(report_id: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """Get details of a specific report."""
    try:
        # Return placeholder report details
        if report_id == "rpt-2025-10-13-0001":
            return {
                "report_id": report_id,
                "target": "example.com",
                "vulnerabilities": [
                    {
                        "cve": "CVE-2021-44228",
                        "severity": "Critical",
                        "title": "Apache Log4Shell",
                        "description": "A critical vulnerability in Apache Log4j",
                        "cvss": 10.0
                    },
                    {
                        "cve": "CVE-2021-34527",
                        "severity": "High",
                        "title": "PrintNightmare",
                        "description": "Windows Print Spooler Remote Code Execution Vulnerability",
                        "cvss": 8.8
                    }
                ]
            }
        elif report_id == "rpt-2025-10-12-0002":
            return {
                "report_id": report_id,
                "target": "test.org",
                "vulnerabilities": [
                    {
                        "cve": "CVE-2021-34527",
                        "severity": "High",
                        "title": "PrintNightmare",
                        "description": "Windows Print Spooler Remote Code Execution Vulnerability",
                        "cvss": 8.8
                    },
                    {
                        "severity": "Medium",
                        "title": "Weak SSL Configuration",
                        "description": "SSL/TLS configuration uses weak ciphers"
                    }
                ]
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report not found"
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch report details: {str(e)}"
        )

@app.post("/api/report/upload")
async def upload_report(report_data: Dict[str, Any] = Body(...), db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """Upload a new report."""
    try:
        # Placeholder for report upload functionality
        report_id = "rpt-" + str(uuid.uuid4())[:8]
        return {
            "message": "Report uploaded successfully",
            "report_id": report_id
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload report: {str(e)}"
        )

# Scan endpoints
@app.post("/api/scan/start")
async def start_scan(scan_request: Dict[str, Any] = Body(...), db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """Start a new scan."""
    try:
        # Placeholder for scan functionality
        target = scan_request.get("target", "example.com")
        tools = scan_request.get("tools", [])
        
        # Create mock results based on requested tools
        results = []
        for tool in tools:
            if tool == "nmap":
                result = {
                    "ports": [
                        {"port": 22, "service": "ssh", "state": "open"},
                        {"port": 80, "service": "http", "state": "open"},
                        {"port": 443, "service": "https", "state": "open"}
                    ]
                }
            elif tool == "nessus":
                result = {
                    "vulnerabilities": [
                        {"severity": "High", "title": "OpenSSL Vulnerability"},
                        {"severity": "Medium", "title": "Weak Cipher Suite"}
                    ]
                }
            elif tool == "openvas":
                result = {
                    "vulnerabilities": [
                        {"severity": "Medium", "title": "Outdated Software"},
                        {"severity": "Low", "title": "Information Disclosure"}
                    ]
                }
            elif tool == "nikto":
                result = {
                    "vulnerabilities": [
                        {"severity": "High", "title": "Server Misconfiguration"},
                        {"severity": "Medium", "title": "Outdated Components"}
                    ]
                }
            elif tool == "nuclei":
                result = {
                    "vulnerabilities": [
                        {"severity": "Critical", "title": "Remote Code Execution"},
                        {"severity": "High", "title": "SQL Injection"}
                    ]
                }
            else:
                result = {"message": f"Scan completed for {tool}"}
            
            results.append({
                "tool": tool,
                "result": result
            })
        
        return {
            "message": f"Scan started for {target}",
            "results": results
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start scan: {str(e)}"
        )

@app.get("/api/scan/status/{job_id}")
async def get_scan_status(job_id: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """Get the status of a scan job."""
    try:
        # Placeholder for scan status
        return {
            "job_id": job_id,
            "status": "completed",
            "progress": "100%"
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get scan status: {str(e)}"
        )

# Attack path endpoints
@app.get("/api/attackpath/{report_id}")
async def get_attack_path(report_id: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """Get the attack path for a report."""
    try:
        # Placeholder for attack path
        return {
            "nodes": [
                {"id": "h1", "type": "host", "label": "10.0.0.5"},
                {"id": "v1", "type": "vuln", "label": "CVE-2021-44228"}
            ],
            "edges": [
                {"from": "h1", "to": "v1", "desc": "vulnerable service"}
            ]
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get attack path: {str(e)}"
        )

# Chat endpoints
@app.post("/api/chat/query")
async def chat_query(query_data: Dict[str, Any] = Body(...), db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """Process a chat query."""
    try:
        query = query_data.get("query", "")
        # Placeholder for chat functionality
        return {
            "answer": f"This is a sample answer to your query: {query}",
            "citations": [
                {"id": "chunk-17", "source": "report", "text_snippet": "Sample text...", "ref": "report:vuln-0001"}
            ],
            "confidence": 0.87
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process chat query: {str(e)}"
        )

# Threat intel endpoints
@app.get("/api/intel/cve/{cve}")
async def get_cve_intel(cve: str, db: Session = Depends(get_db), user: models.User = Depends(get_current_user)):
    """Get threat intelligence for a CVE."""
    try:
        # Placeholder for CVE intelligence
        return {
            "cve": cve,
            "description": "Sample CVE description",
            "cvss": 9.8,
            "exploit_refs": ["https://example.com/exploit"],
            "updated_at": "2025-10-14T00:00:00Z"
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get CVE intelligence: {str(e)}"
        )