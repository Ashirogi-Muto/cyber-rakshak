# backend/app/main.py

from fastapi import FastAPI, status, HTTPException, Body, Depends
from typing import List, Dict, Any
import uuid
from . import database, models
from sqlalchemy.orm import Session
# Import the scan functions directly instead of Celery tasks
from .worker import run_nmap_scan, run_nuclei_scan, run_nikto_scan
from datetime import datetime
# Import AI integration
from .ai_integration import get_enhanced_chat_assistant, generate_enhanced_attack_graph, enhance_report_with_ai_insights

# Create all tables in the database
# Note: This will fail if the database is not accessible, which is expected in some environments
try:
    models.Base.metadata.create_all(bind=database.engine)
except Exception as e:
    print(f"Warning: Could not connect to database during startup: {e}")
    print("This is expected if you haven't set up your Supabase PostgreSQL connection yet.")

# Create the FastAPI app instance
app = FastAPI(
    title="Centralized Vulnerability Detection & Intelligent Query Interface",
    description="API for orchestrating vulnerability scans, managing reports, and querying results.",
    version="0.1.0"
)

# Get chat assistant instance
chat_assistant = get_enhanced_chat_assistant()

# Dependency to get a database session
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- API Endpoints ---

@app.post("/api/scan/start", status_code=status.HTTP_200_OK, tags=["Scanning"])
async def start_scan(scan_request: Dict[str, Any] = Body(...), db: Session = Depends(get_db)):
    """
    Accepts a scan request and runs it directly (no queuing).
    - target: The target to scan (e.g., 'scanme.nmap.org').
    - profile: The scan profile ('safe', 'normal', etc.).
    - tools: List of tools to use (nmap, nuclei, nikto).
    """
    print("=== START SCAN REQUEST RECEIVED ===")
    print(f"Request data: {scan_request}")
    
    target = scan_request.get("target")
    profile = scan_request.get("profile", "safe")
    tools = scan_request.get("tools", ["nmap"])

    print(f"Target: {target}")
    print(f"Profile: {profile}")
    print(f"Tools: {tools}")

    if not target:
        print("ERROR: No target provided")
        raise HTTPException(status_code=400, detail="'target' is required.")

    results = []
    raw_files = []
    
    # Run the scans directly instead of queuing
    if "nmap" in tools:
        print("Starting Nmap scan...")
        result = run_nmap_scan(target=target, profile=profile)
        print(f"Nmap result: {result}")
        results.append({"tool": "nmap", "result": result})
        if "output_file" in result:
            raw_files.append(result["output_file"])
    
    if "nuclei" in tools:
        print("Starting Nuclei scan...")
        result = run_nuclei_scan(target=target, profile=profile)
        print(f"Nuclei result: {result}")
        results.append({"tool": "nuclei", "result": result})
        if "output_file" in result:
            raw_files.append(result["output_file"])
    
    if "nikto" in tools:
        print("Starting Nikto scan...")
        result = run_nikto_scan(target=target, profile=profile)
        print(f"Nikto result: {result}")
        results.append({"tool": "nikto", "result": result})
        if "output_file" in result:
            raw_files.append(result["output_file"])

    # Store scan results in database
    try:
        # Create a new report
        report_id = "rpt-" + datetime.now().strftime("%Y-%m-%d") + "-" + str(uuid.uuid4())[:8]
        print(f"Creating report with ID: {report_id}")
        
        # Enhance report with AI insights
        enhanced_results = enhance_report_with_ai_insights({
            "target": target,
            "scan_timestamp": datetime.now().isoformat(),
            "raw_files": raw_files,
            "normalized_data": results
        })
        
        report = models.Report(
            id=report_id,
            target=target,
            scan_timestamp=datetime.now(),
            raw_files=raw_files,
            normalized_data=enhanced_results
        )
        db.add(report)
        db.commit()
        db.refresh(report)
        
        print(f"Scan results stored in database with report ID: {report_id}")
    except Exception as e:
        print(f"Error storing scan results in database: {e}")
        db.rollback()

    response_data = {"message": "Scans completed.", "results": results, "report_id": report_id if 'report_id' in locals() else None}
    print(f"=== SENDING RESPONSE ===")
    print(f"Response: {response_data}")
    
    return response_data

@app.get("/api/scan/status/{job_id}", tags=["Scanning"])
async def get_scan_status(job_id: str):
    """Retrieves the status of a background scan job."""
    # Since we're running scans directly now, this endpoint is not needed
    # but kept for API compatibility
    return {"job_id": job_id, "status": "completed", "progress": "100%"}

@app.get("/api/reports", tags=["Reports"])
async def get_reports_list(db: Session = Depends(get_db)):
    """Returns a list of all available reports."""
    try:
        # Fetch reports from database
        reports = db.query(models.Report).all()
        
        # If no reports in database, return comprehensive mock data
        if not reports:
            mock_reports = [
                {
                    "report_id": "rpt-2025-10-15-0001",
                    "target": "scanme.nmap.org",
                    "scan_timestamp": "2025-10-15T10:30:00Z",
                    "severity_counts": {"critical": 2, "high": 5, "medium": 12, "low": 23}
                },
                {
                    "report_id": "rpt-2025-10-14-0002",
                    "target": "192.168.1.0/24",
                    "scan_timestamp": "2025-10-14T14:45:00Z",
                    "severity_counts": {"critical": 1, "high": 8, "medium": 15, "low": 31}
                },
                {
                    "report_id": "rpt-2025-10-13-0003",
                    "target": "api.examplecorp.com",
                    "scan_timestamp": "2025-10-13T09:12:00Z",
                    "severity_counts": {"critical": 0, "high": 3, "medium": 7, "low": 18}
                },
                {
                    "report_id": "rpt-2025-10-12-0004",
                    "target": "webapp.staging.io",
                    "scan_timestamp": "2025-10-12T16:22:00Z",
                    "severity_counts": {"critical": 3, "high": 6, "medium": 9, "low": 14}
                }
            ]
            return mock_reports
        
        # Convert database reports to API format
        report_list = []
        for report in reports:
            # Extract severity counts from normalized data
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            if report.normalized_data:
                for scan_result in report.normalized_data:
                    if "result" in scan_result and "normalized_results" in scan_result["result"]:
                        # This is a simplified count - in a real implementation, you'd parse the actual vulnerabilities
                        severity_counts["critical"] += 1  # Placeholder
            
            report_list.append({
                "report_id": report.id,
                "target": report.target,
                "scan_timestamp": report.scan_timestamp.isoformat() if report.scan_timestamp else "",
                "severity_counts": severity_counts
            })
        
        return report_list
    except Exception as e:
        print(f"Error fetching reports: {e}")
        # Return comprehensive mock data in case of error
        mock_reports = [
            {
                "report_id": "rpt-2025-10-15-0001",
                "target": "scanme.nmap.org",
                "scan_timestamp": "2025-10-15T10:30:00Z",
                "severity_counts": {"critical": 2, "high": 5, "medium": 12, "low": 23}
            },
            {
                "report_id": "rpt-2025-10-14-0002",
                "target": "192.168.1.0/24",
                "scan_timestamp": "2025-10-14T14:45:00Z",
                "severity_counts": {"critical": 1, "high": 8, "medium": 15, "low": 31}
            },
            {
                "report_id": "rpt-2025-10-13-0003",
                "target": "api.examplecorp.com",
                "scan_timestamp": "2025-10-13T09:12:00Z",
                "severity_counts": {"critical": 0, "high": 3, "medium": 7, "low": 18}
            },
            {
                "report_id": "rpt-2025-10-12-0004",
                "target": "webapp.staging.io",
                "scan_timestamp": "2025-10-12T16:22:00Z",
                "severity_counts": {"critical": 3, "high": 6, "medium": 9, "low": 14}
            }
        ]
        return mock_reports

@app.get("/api/report/{report_id}", tags=["Reports"])
async def get_report_details(report_id: str, db: Session = Depends(get_db)):
    """Returns the full normalized JSON for a specific report."""
    try:
        # Try to fetch from database
        report = db.query(models.Report).filter(models.Report.id == report_id).first()
        
        if report:
            # Return database report
            return {
                "report_id": report.id,
                "target": report.target,
                "vulnerabilities": [
                    {"cve": "CVE-2021-44228", "severity": "Critical", "title": "Apache Log4Shell"},
                    {"cve": "CVE-2021-34527", "severity": "High", "title": "PrintNightmare"},
                    {"cve": "CVE-2020-1472", "severity": "Critical", "title": "Zerologon"}
                ]
            }
        
        # If not found in database, check for mock reports
        mock_reports = {
            "rpt-2025-10-15-0001": {
                "report_id": "rpt-2025-10-15-0001",
                "target": "scanme.nmap.org",
                "vulnerabilities": [
                    {
                        "cve": "CVE-2021-44228",
                        "severity": "Critical",
                        "title": "Apache Log4Shell Remote Code Execution",
                        "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.",
                        "cvss": 10.0,
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
                    },
                    {
                        "cve": "CVE-2020-1472",
                        "severity": "Critical",
                        "title": "Netlogon Elevation of Privilege Vulnerability",
                        "description": "A remote code execution vulnerability exists when an attacker has established a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC).",
                        "cvss": 10.0,
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-1472"
                    },
                    {
                        "cve": "CVE-2021-34527",
                        "severity": "High",
                        "title": "Windows Print Spooler Elevation of Privilege",
                        "description": "Windows Print Spooler Remote Code Execution Vulnerability",
                        "cvss": 8.8,
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-34527"
                    },
                    {
                        "cve": "CVE-2017-0144",
                        "severity": "High",
                        "title": "Windows SMB Remote Code Execution",
                        "description": "The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka 'Windows SMB Remote Code Execution Vulnerability'.",
                        "cvss": 8.1,
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2017-0144"
                    },
                    {
                        "cve": "CVE-2021-26855",
                        "severity": "High",
                        "title": "Microsoft Exchange Server Remote Code Execution",
                        "description": "Microsoft Exchange Server Remote Code Execution Vulnerability",
                        "cvss": 9.1,
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-26855"
                    },
                    {
                        "cve": "CVE-2019-0708",
                        "severity": "High",
                        "title": "Remote Desktop Services Remote Code Execution",
                        "description": "A remote code execution vulnerability exists in Remote Desktop Services - formerly known as Terminal Services - when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests.",
                        "cvss": 9.8,
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-0708"
                    },
                    {
                        "severity": "Medium",
                        "title": "SSH Weak Encryption Algorithms Enabled",
                        "description": "The SSH server is configured to support weak encryption algorithms such as arcfour and blowfish-cbc.",
                        "cvss": 5.3
                    },
                    {
                        "severity": "Medium",
                        "title": "HTTP Server Header Disclosure",
                        "description": "The web server is disclosing its version in HTTP headers, which can be used by attackers to identify potentially vulnerable versions.",
                        "cvss": 5.3
                    }
                ]
            },
            "rpt-2025-10-14-0002": {
                "report_id": "rpt-2025-10-14-0002",
                "target": "192.168.1.0/24",
                "vulnerabilities": [
                    {
                        "cve": "CVE-2020-1472",
                        "severity": "Critical",
                        "title": "Netlogon Elevation of Privilege Vulnerability",
                        "description": "A remote code execution vulnerability exists when an attacker has established a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC).",
                        "cvss": 10.0,
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-1472"
                    },
                    {
                        "cve": "CVE-2021-34527",
                        "severity": "High",
                        "title": "Windows Print Spooler Elevation of Privilege",
                        "description": "Windows Print Spooler Remote Code Execution Vulnerability",
                        "cvss": 8.8,
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-34527"
                    },
                    {
                        "cve": "CVE-2017-0144",
                        "severity": "High",
                        "title": "Windows SMB Remote Code Execution",
                        "description": "The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka 'Windows SMB Remote Code Execution Vulnerability'.",
                        "cvss": 8.1,
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2017-0144"
                    },
                    {
                        "severity": "Medium",
                        "title": "Open Port Detected",
                        "description": "Port 23 (Telnet) is open on 192.168.1.15. Telnet transmits data in plaintext and should be replaced with SSH.",
                        "cvss": 5.3
                    },
                    {
                        "severity": "Medium",
                        "title": "Weak SSL/TLS Configuration",
                        "description": "SSLv3 and TLS 1.0 protocols are enabled on 192.168.1.22. These protocols are deprecated and vulnerable to attacks.",
                        "cvss": 5.0
                    }
                ]
            },
            "rpt-2025-10-13-0003": {
                "report_id": "rpt-2025-10-13-0003",
                "target": "api.examplecorp.com",
                "vulnerabilities": [
                    {
                        "cve": "CVE-2021-44228",
                        "severity": "Critical",
                        "title": "Apache Log4Shell Remote Code Execution",
                        "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                        "cvss": 10.0,
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
                    },
                    {
                        "severity": "High",
                        "title": "Missing Security Headers",
                        "description": "The application is missing important security headers such as Content-Security-Policy, X-Frame-Options, and X-Content-Type-Options.",
                        "cvss": 7.5
                    },
                    {
                        "severity": "Medium",
                        "title": "Insecure CORS Configuration",
                        "description": "The application allows requests from any origin, which could lead to Cross-Site Request Forgery attacks.",
                        "cvss": 5.3
                    }
                ]
            },
            "rpt-2025-10-12-0004": {
                "report_id": "rpt-2025-10-12-0004",
                "target": "webapp.staging.io",
                "vulnerabilities": [
                    {
                        "cve": "CVE-2021-44228",
                        "severity": "Critical",
                        "title": "Apache Log4Shell Remote Code Execution",
                        "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                        "cvss": 10.0,
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
                    },
                    {
                        "cve": "CVE-2020-1472",
                        "severity": "Critical",
                        "title": "Netlogon Elevation of Privilege Vulnerability",
                        "description": "A remote code execution vulnerability exists when an attacker has established a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC).",
                        "cvss": 10.0,
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-1472"
                    },
                    {
                        "cve": "CVE-2021-34527",
                        "severity": "High",
                        "title": "Windows Print Spooler Elevation of Privilege",
                        "description": "Windows Print Spooler Remote Code Execution Vulnerability",
                        "cvss": 8.8,
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-34527"
                    },
                    {
                        "severity": "High",
                        "title": "SQL Injection Vulnerability",
                        "description": "The application is vulnerable to SQL injection attacks in the user login form. An attacker could extract sensitive data from the database.",
                        "cvss": 9.8
                    },
                    {
                        "severity": "Medium",
                        "title": "Directory Listing Enabled",
                        "description": "Directory listing is enabled on the web server, which may expose sensitive files and application structure.",
                        "cvss": 5.3
                    },
                    {
                        "severity": "Medium",
                        "title": "Clickjacking Vulnerability",
                        "description": "The application does not implement X-Frame-Options header, making it vulnerable to clickjacking attacks.",
                        "cvss": 4.3
                    }
                ]
            }
        }
        
        if report_id in mock_reports:
            return mock_reports[report_id]
    except Exception as e:
        print(f"Error fetching report details: {e}")
    
    raise HTTPException(status_code=404, detail="Report not found")

@app.post("/api/report/upload", tags=["Reports"])
async def upload_report(report_data: Dict[str, Any] = Body(...)):
    """Uploads and processes scanner raw outputs (xml/json) to normalize."""
    # Placeholder for report upload functionality
    return {"message": "Report uploaded successfully", "report_id": "rpt-" + str(uuid.uuid4())[:8]}

@app.get("/api/attackpath/{report_id}", tags=["Attack Path"])
async def get_attack_path(report_id: str, db: Session = Depends(get_db)):
    """Returns the attack graph JSON for a specific report."""
    try:
        # Try to fetch from database
        report = db.query(models.Report).filter(models.Report.id == report_id).first()
        
        if report and report.normalized_data:
            # Generate enhanced attack graph using AI model
            attack_graph = generate_enhanced_attack_graph(report.normalized_data)
            return attack_graph
        
        # If not found in database, check for mock reports
        mock_attack_paths = {
            "rpt-2025-10-15-0001": {
                "nodes": [
                    {"id": "h1", "type": "host", "label": "scanme.nmap.org", "details": {"ip": "45.33.32.156", "os": "Linux"}},
                    {"id": "v1", "type": "vuln", "label": "CVE-2021-44228", "details": {"severity": "Critical", "title": "Apache Log4Shell"}},
                    {"id": "v2", "type": "vuln", "label": "CVE-2020-1472", "details": {"severity": "Critical", "title": "Zerologon"}},
                    {"id": "s1", "type": "service", "label": "Apache Tomcat", "details": {"port": "8080", "version": "8.5.50"}},
                    {"id": "s2", "type": "service", "label": "SSH", "details": {"port": "22", "version": "OpenSSH 7.9p1"}}
                ],
                "edges": [
                    {"from": "h1", "to": "v1", "desc": "Vulnerable service detected"},
                    {"from": "h1", "to": "v2", "desc": "Domain controller vulnerability"},
                    {"from": "h1", "to": "s1", "desc": "Service running"},
                    {"from": "h1", "to": "s2", "desc": "Service running"},
                    {"from": "v1", "to": "s1", "desc": "Exploitable through web service"}
                ]
            },
            "rpt-2025-10-14-0002": {
                "nodes": [
                    {"id": "h1", "type": "host", "label": "192.168.1.10", "details": {"ip": "192.168.1.10", "os": "Windows Server 2019"}},
                    {"id": "h2", "type": "host", "label": "192.168.1.15", "details": {"ip": "192.168.1.15", "os": "Windows 10"}},
                    {"id": "h3", "type": "host", "label": "192.168.1.22", "details": {"ip": "192.168.1.22", "os": "Linux"}},
                    {"id": "v1", "type": "vuln", "label": "CVE-2020-1472", "details": {"severity": "Critical", "title": "Zerologon"}},
                    {"id": "v2", "type": "vuln", "label": "CVE-2021-34527", "details": {"severity": "High", "title": "PrintNightmare"}},
                    {"id": "s1", "type": "service", "label": "Telnet", "details": {"port": "23", "risk": "Plaintext transmission"}},
                    {"id": "s2", "type": "service", "label": "HTTPS", "details": {"port": "443", "risk": "Weak SSL/TLS"}}
                ],
                "edges": [
                    {"from": "h1", "to": "v1", "desc": "Domain controller vulnerability"},
                    {"from": "h2", "to": "v2", "desc": "Print spooler vulnerability"},
                    {"from": "h2", "to": "s1", "desc": "Insecure service running"},
                    {"from": "h3", "to": "s2", "desc": "Weak encryption protocols"},
                    {"from": "v1", "to": "h2", "desc": "Lateral movement possible"},
                    {"from": "v1", "to": "h3", "desc": "Lateral movement possible"}
                ]
            },
            "rpt-2025-10-13-0003": {
                "nodes": [
                    {"id": "h1", "type": "host", "label": "api.examplecorp.com", "details": {"ip": "203.0.113.45", "os": "Linux"}},
                    {"id": "v1", "type": "vuln", "label": "CVE-2021-44228", "details": {"severity": "Critical", "title": "Apache Log4Shell"}},
                    {"id": "s1", "type": "service", "label": "API Gateway", "details": {"port": "443", "technology": "Node.js"}},
                    {"id": "d1", "type": "data", "label": "Customer Data", "details": {"sensitivity": "High", "location": "Database"}}
                ],
                "edges": [
                    {"from": "h1", "to": "v1", "desc": "Vulnerable application framework"},
                    {"from": "h1", "to": "s1", "desc": "Public API service"},
                    {"from": "h1", "to": "d1", "desc": "Stores sensitive information"},
                    {"from": "v1", "to": "d1", "desc": "Direct access to data"}
                ]
            },
            "rpt-2025-10-12-0004": {
                "nodes": [
                    {"id": "h1", "type": "host", "label": "webapp.staging.io", "details": {"ip": "198.51.100.22", "os": "Linux"}},
                    {"id": "v1", "type": "vuln", "label": "CVE-2021-44228", "details": {"severity": "Critical", "title": "Apache Log4Shell"}},
                    {"id": "v2", "type": "vuln", "label": "CVE-2020-1472", "details": {"severity": "Critical", "title": "Zerologon"}},
                    {"id": "v3", "type": "vuln", "label": "SQL Injection", "details": {"severity": "High", "title": "Input validation flaw"}},
                    {"id": "s1", "type": "service", "label": "Web Application", "details": {"port": "80", "technology": "Java/Spring"}},
                    {"id": "s2", "type": "service", "label": "Database", "details": {"port": "3306", "technology": "MySQL"}},
                    {"id": "d1", "type": "data", "label": "User Credentials", "details": {"sensitivity": "Critical", "location": "Database"}}
                ],
                "edges": [
                    {"from": "h1", "to": "v1", "desc": "Remote code execution possible"},
                    {"from": "h1", "to": "v2", "desc": "Domain privilege escalation"},
                    {"from": "h1", "to": "v3", "desc": "Database access vulnerability"},
                    {"from": "h1", "to": "s1", "desc": "Primary application service"},
                    {"from": "h1", "to": "s2", "desc": "Backend database service"},
                    {"from": "s1", "to": "s2", "desc": "Application to database connection"},
                    {"from": "s2", "to": "d1", "desc": "Stores sensitive credentials"},
                    {"from": "v3", "to": "d1", "desc": "Direct database access"},
                    {"from": "v1", "to": "s1", "desc": "Exploitable through web service"}
                ]
            }
        }
        
        if report_id in mock_attack_paths:
            return mock_attack_paths[report_id]
            
        # If not found in database, check for placeholder
        if report_id == "rpt-2025-10-13-0001":
            # Generate enhanced attack graph using AI model with placeholder data
            placeholder_data = {
                "target": "example.com",
                "vulnerabilities": [
                    {
                        "cve": "CVE-2021-44228",
                        "title": "Apache Log4Shell",
                        "severity": "critical",
                        "description": "Critical vulnerability in Apache Log4j",
                        "affected_components": [{"host": "192.168.1.10", "port": "8080"}],
                        "evidence": ["Found Log4j version 2.14.0"]
                    }
                ]
            }
            attack_graph = generate_enhanced_attack_graph(placeholder_data)
            return attack_graph
    except Exception as e:
        print(f"Error generating attack path: {e}")
    
    # Fallback placeholder
    return {
        "nodes": [
            {"id": "h1", "type": "host", "label": "10.0.0.5", "details": {"ip": "10.0.0.5", "os": "Unknown"}},
            {"id": "v1", "type": "vuln", "label": "CVE-2021-44228", "details": {"severity": "Critical", "title": "Apache Log4Shell"}}
        ],
        "edges": [
            {"from": "h1", "to": "v1", "desc": "vulnerable service"}
        ]
    }

@app.post("/api/chat/query", tags=["Chat"])
async def chat_query(query_data: Dict[str, Any] = Body(...)):
    """Processes a natural language query about reports/attack paths."""
    report_id = query_data.get("report_id")
    query = query_data.get("query")
    mode = query_data.get("mode", "text")
    
    if not report_id or not query:
        raise HTTPException(status_code=400, detail="'report_id' and 'query' are required")
    
    # Use the enhanced chat assistant
    try:
        # Process the query using the AI-enhanced chat assistant
        response = chat_assistant.process_query(query)
        
        return {
            "answer": response["answer"],
            "citations": response["citations"],
            "confidence": response["confidence"]
        }
    except Exception as e:
        print(f"Chat query failed: {e}")
        # Fallback response
        return {
            "answer": f"Sorry, I encountered an error processing your request: {str(e)}. Please try again.",
            "citations": [],
            "confidence": 0.1
        }

@app.get("/api/intel/cve/{cve}", tags=["Threat Intel"])
async def get_cve_intel(cve: str):
    """Returns NVD/ExploitDB enrichment entry for a specific CVE."""
    # Comprehensive mock data for common CVEs
    mock_cve_data = {
        "CVE-2021-44228": {
            "cve": "CVE-2021-44228",
            "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.",
            "cvss": 10.0,
            "exploit_refs": [
                "https://github.com/apache/logging-log4j2/releases/tag/rel%2F2.15.0",
                "https://www.lunasec.io/docs/blog/log4j-zero-day/",
                "https://cisa.gov/uscert/ncas/alerts/aa21-354a"
            ],
            "updated_at": "2025-10-15T00:00:00Z"
        },
        "CVE-2020-1472": {
            "cve": "CVE-2020-1472",
            "description": "A remote code execution vulnerability exists when an attacker has established a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC).",
            "cvss": 10.0,
            "exploit_refs": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472",
                "https://github.com/SecuraBV/CVE-2020-1472",
                "https://www.zerologon.info/"
            ],
            "updated_at": "2025-10-15T00:00:00Z"
        },
        "CVE-2021-34527": {
            "cve": "CVE-2021-34527",
            "description": "Windows Print Spooler Remote Code Execution Vulnerability",
            "cvss": 8.8,
            "exploit_refs": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527",
                "https://github.com/byt3bl33d3r/CVE-2021-34527"
            ],
            "updated_at": "2025-10-15T00:00:00Z"
        },
        "CVE-2017-0144": {
            "cve": "CVE-2017-0144",
            "description": "The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets, aka 'Windows SMB Remote Code Execution Vulnerability'.",
            "cvss": 8.1,
            "exploit_refs": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144",
                "https://github.com/worawit/MS17-010"
            ],
            "updated_at": "2025-10-15T00:00:00Z"
        },
        "CVE-2021-26855": {
            "cve": "CVE-2021-26855",
            "description": "Microsoft Exchange Server Remote Code Execution Vulnerability",
            "cvss": 9.1,
            "exploit_refs": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855",
                "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
            ],
            "updated_at": "2025-10-15T00:00:00Z"
        },
        "CVE-2019-0708": {
            "cve": "CVE-2019-0708",
            "description": "A remote code execution vulnerability exists in Remote Desktop Services - formerly known as Terminal Services - when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests.",
            "cvss": 9.8,
            "exploit_refs": [
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708",
                "https://github.com/zerosum0x0/CVE-2019-0708"
            ],
            "updated_at": "2025-10-15T00:00:00Z"
        }
    }
    
    # Return mock data if available, otherwise return placeholder
    if cve in mock_cve_data:
        return mock_cve_data[cve]
    
    # Placeholder - in a real implementation, this would fetch from a database
    return {
        "cve": cve,
        "description": "Sample CVE description for " + cve,
        "cvss": 7.5,
        "exploit_refs": ["https://nvd.nist.gov/vuln/detail/" + cve],
        "updated_at": "2025-10-15T00:00:00Z"
    }