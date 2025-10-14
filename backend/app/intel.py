# backend/app/intel.py

import requests
import json
from typing import Dict, List, Any, Optional
from . import services
from sqlalchemy.orm import Session


def fetch_nvd_cve_data(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Fetch CVE data from NVD API.
    
    Args:
        cve_id: The CVE identifier (e.g., CVE-2021-44228)
        
    Returns:
        Dictionary containing CVE information or None if not found
    """
    try:
        # NVD API endpoint
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        
        # Make the request
        response = requests.get(url)
        response.raise_for_status()
        
        # Parse the JSON response
        data = response.json()
        
        # Extract relevant information
        if "vulnerabilities" in data and len(data["vulnerabilities"]) > 0:
            cve_data = data["vulnerabilities"][0]["cve"]
            
            # Extract description
            description = ""
            if "descriptions" in cve_data:
                for desc in cve_data["descriptions"]:
                    if desc["lang"] == "en":
                        description = desc["value"]
                        break
            
            # Extract CVSS score
            cvss_score = ""
            if "metrics" in cve_data:
                # Try to get CVSS v3 score first
                if "cvssMetricV31" in cve_data["metrics"]:
                    cvss_score = str(cve_data["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"])
                elif "cvssMetricV30" in cve_data["metrics"]:
                    cvss_score = str(cve_data["metrics"]["cvssMetricV30"][0]["cvssData"]["baseScore"])
                elif "cvssMetricV2" in cve_data["metrics"]:
                    cvss_score = str(cve_data["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"])
            
            # Extract references
            references = []
            if "references" in cve_data:
                for ref in cve_data["references"]:
                    references.append({
                        "url": ref.get("url", ""),
                        "source": ref.get("source", ""),
                        "tags": ref.get("tags", [])
                    })
            
            return {
                "cve_id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "references": references
            }
        
        return None
    
    except Exception as e:
        print(f"Error fetching NVD data for {cve_id}: {str(e)}")
        return None


def fetch_exploitdb_data(cve_id: str) -> List[Dict[str, Any]]:
    """
    Fetch ExploitDB references for a CVE.
    Note: This is a simplified implementation. In a real-world scenario,
    you would use the ExploitDB API or local copy of their database.
    
    Args:
        cve_id: The CVE identifier
        
    Returns:
        List of exploit references
    """
    # This is a placeholder implementation
    # In a real implementation, you would query the ExploitDB database
    # or use their API to find exploits for the CVE
    
    # For demonstration purposes, we'll return a mock result
    return [
        {
            "source": "ExploitDB",
            "id": "XXXX",
            "url": f"https://www.exploit-db.com/exploits/XXXX",
            "description": f"Exploit for {cve_id}"
        }
    ]


def correlate_threat_intel(db: Session, cve_id: str) -> Dict[str, Any]:
    """
    Correlate threat intelligence for a CVE from multiple sources.
    
    Args:
        db: Database session
        cve_id: The CVE identifier
        
    Returns:
        Dictionary containing correlated threat intelligence
    """
    # Fetch data from NVD
    nvd_data = fetch_nvd_cve_data(cve_id)
    
    # Fetch data from ExploitDB
    exploitdb_data = fetch_exploitdb_data(cve_id)
    
    # Combine the data
    intel_data = {
        "cve": cve_id,
        "description": "",
        "cvss_score": "",
        "references": [],
        "exploit_refs": exploitdb_data
    }
    
    if nvd_data:
        intel_data["description"] = nvd_data.get("description", "")
        intel_data["cvss_score"] = nvd_data.get("cvss_score", "")
        intel_data["references"] = nvd_data.get("references", [])
    
    # Save to database
    services.create_threat_intel(
        db,
        cve_id,
        intel_data["description"],
        intel_data["cvss_score"],
        intel_data["exploit_refs"]
    )
    
    return intel_data


def enrich_vulnerabilities(db: Session, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Enrich a list of vulnerabilities with threat intelligence data.
    
    Args:
        db: Database session
        vulnerabilities: List of vulnerability dictionaries
        
    Returns:
        List of enriched vulnerability dictionaries
    """
    enriched_vulns = []
    
    for vuln in vulnerabilities:
        # Copy the original vulnerability data
        enriched_vuln = vuln.copy()
        
        # If the vulnerability has a CVE, enrich it with threat intel
        cve = vuln.get("cve")
        if cve and cve.startswith("CVE-"):
            intel = correlate_threat_intel(db, cve)
            enriched_vuln["enrichment"] = intel
        
        enriched_vulns.append(enriched_vuln)
    
    return enriched_vulns