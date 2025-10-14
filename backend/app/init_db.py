# backend/app/init_db.py

import sys
import os
from datetime import datetime, timezone
import json

# Add the parent directory to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.orm import Session
from app import models, database
from app.auth import get_password_hash
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def create_mock_normalized_data(target):
    """Create mock normalized data for reports."""
    mock_data = []
    
    # Nmap mock data
    mock_data.append({
        "tool": "nmap",
        "raw_file": f"./scan_outputs/nmap_mock.xml",
        "parsed": [
            {
                "ip": target,
                "hostnames": [f"{target.split('.')[0]}.example.com"],
                "ports": [
                    {"port": "22", "protocol": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH", "version": "7.9p1"},
                    {"port": "80", "protocol": "tcp", "state": "open", "service": "http", "product": "nginx", "version": "1.14.2"},
                    {"port": "443", "protocol": "tcp", "state": "open", "service": "https", "product": "", "version": ""},
                    {"port": "3389", "protocol": "tcp", "state": "open", "service": "ms-wbt-server", "product": "Microsoft Terminal Services", "version": ""},
                    {"port": "8080", "protocol": "tcp", "state": "open", "service": "http-proxy", "product": "Apache Tomcat", "version": "8.5.50"}
                ]
            }
        ]
    })
    
    # Nuclei mock data
    mock_data.append({
        "tool": "nuclei",
        "raw_file": f"./scan_outputs/nuclei_mock.json",
        "parsed": [
            {
                "template_id": "apache-struts-rce-cve-2017-5638",
                "host": target,
                "matched_at": f"http://{target}:8080",
                "info": {
                    "name": "Apache Struts RCE (CVE-2017-5638)",
                    "author": ["pdteam"],
                    "tags": "cve,rce,apache,struts",
                    "description": "Apache Struts versions 2.3.5 - 2.3.31 and 2.5 - 2.5.10 are vulnerable to a remote code execution attack.",
                    "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2017-5638"],
                    "severity": "critical",
                    "classification": {
                        "cve_id": "CVE-2017-5638",
                        "cwe_id": "CWE-20",
                        "cvss_metrics": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "cvss_score": 9.8
                    }
                }
            },
            {
                "template_id": "tomcat-cve-2017-12615",
                "host": target,
                "matched_at": f"http://{target}:8080",
                "info": {
                    "name": "Apache Tomcat RCE (CVE-2017-12615)",
                    "author": ["pdteam"],
                    "tags": "cve,rce,apache,tomcat",
                    "description": "Apache Tomcat versions 7.0.0 to 7.0.79 are vulnerable to a remote code execution attack.",
                    "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2017-12615"],
                    "severity": "high",
                    "classification": {
                        "cve_id": "CVE-2017-12615",
                        "cwe_id": "CWE-434",
                        "cvss_metrics": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "cvss_score": 9.8
                    }
                }
            }
        ]
    })
    
    # Nikto mock data
    mock_data.append({
        "tool": "nikto",
        "raw_file": f"./scan_outputs/nikto_mock.xml",
        "parsed": [
            {
                "id": "000000001",
                "description": "The anti-clickjacking X-Frame-Options header is not present.",
                "uri": "/",
                "namelink": f"http://{target}/",
                "severity": "1"
            },
            {
                "id": "000000002",
                "description": "The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS",
                "uri": "/",
                "namelink": f"http://{target}/",
                "severity": "1"
            }
        ]
    })
    
    return mock_data

def init_db():
    """Initialize the database with default users and mock reports."""
    # Create all tables
    models.Base.metadata.create_all(bind=database.engine)
    
    # Get a database session
    db = database.SessionLocal()
    
    try:
        # Check if admin user already exists
        admin_user = db.query(models.User).filter(models.User.username == "admin").first()
        if not admin_user:
            # Create admin user with demo credentials
            admin_user = models.User(
                username="admin",
                email="admin@cyberrakshak.ai",
                hashed_password=get_password_hash("demo123"),
                role="admin"
            )
            db.add(admin_user)
            print(f"Created admin user: admin with password demo123")
        
        # Check if regular user already exists
        regular_user = db.query(models.User).filter(models.User.username == "user").first()
        if not regular_user:
            # Create regular user with demo credentials
            regular_user = models.User(
                username="user",
                email="user@cyberrakshak.ai",
                hashed_password=get_password_hash("user123"),
                role="user"
            )
            db.add(regular_user)
            print(f"Created regular user: user with password user123")
        
        # Create mock reports if none exist
        existing_reports = db.query(models.Report).count()
        if existing_reports == 0:
            mock_targets = [
                ("scanme.nmap.org", "rpt-2025-10-15-0001"),
                ("192.168.1.0/24", "rpt-2025-10-14-0002"),
                ("api.examplecorp.com", "rpt-2025-10-13-0003"),
                ("webapp.staging.io", "rpt-2025-10-12-0004")
            ]
            
            for target, report_id in mock_targets:
                mock_report = models.Report(
                    id=report_id,
                    target=target,
                    scan_timestamp=datetime.now(timezone.utc),
                    raw_files=[f"./scan_outputs/nmap_mock.xml", f"./scan_outputs/nuclei_mock.json", f"./scan_outputs/nikto_mock.xml"],
                    normalized_data=create_mock_normalized_data(target)
                )
                db.add(mock_report)
                print(f"Created mock report: {report_id} for target {target}")
        
        # Commit the changes
        db.commit()
        print("Database initialized successfully!")
        
    except Exception as e:
        print(f"Error initializing database: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    init_db()