# backend/app/upload.py

import xml.etree.ElementTree as ET
import json
from typing import Dict, List, Any, Tuple
import xmltodict


def parse_openvas_xml(file_content: str) -> Dict[str, Any]:
    """
    Parse OpenVAS XML report and return normalized results.
    
    Args:
        file_content: Content of the OpenVAS XML report file
        
    Returns:
        Dictionary containing normalized scan results
    """
    try:
        # Parse XML content
        data = xmltodict.parse(file_content)
        
        # Extract report data
        report_data = data.get("report", {})
        report_element = report_data.get("report", {}) if isinstance(report_data, dict) else {}
        
        # Extract vulnerabilities
        vulnerabilities = []
        results = report_element.get("results", {}).get("result", [])
        
        # Handle both single item and list cases
        if isinstance(results, list):
            result_items = results
        else:
            result_items = [results] if results else []
            
        for item in result_items:
            vuln = {
                "vuln_id": item.get("id", ""),
                "name": item.get("name", ""),
                "description": item.get("description", ""),
                "severity": item.get("severity", ""),
                "host": item.get("host", {}).get("#text", "") if isinstance(item.get("host"), dict) else item.get("host", ""),
                "port": item.get("port", ""),
                "threat": item.get("threat", ""),
                "nvt": {
                    "oid": item.get("nvt", {}).get("@oid", ""),
                    "name": item.get("nvt", {}).get("name", ""),
                    "cvss_base": item.get("nvt", {}).get("cvss_base", ""),
                    "cve": item.get("nvt", {}).get("cve", ""),
                }
            }
            vulnerabilities.append(vuln)
        
        return {
            "tool": "openvas",
            "parsed": vulnerabilities
        }
        
    except Exception as e:
        print(f"Error parsing OpenVAS XML: {str(e)}")
        return {
            "tool": "openvas",
            "error": str(e),
            "parsed": []
        }


def parse_nessus_xml(file_content: str) -> Dict[str, Any]:
    """
    Parse Nessus XML report and return normalized results.
    
    Args:
        file_content: Content of the Nessus XML report file
        
    Returns:
        Dictionary containing normalized scan results
    """
    try:
        # Parse XML content
        root = ET.fromstring(file_content)
        
        # Extract vulnerabilities
        vulnerabilities = []
        for report_elem in root.findall(".//Report"):
            for host_elem in report_elem.findall(".//ReportHost"):
                host_ip = host_elem.get("name", "")
                
                for item_elem in host_elem.findall(".//ReportItem"):
                    vuln = {
                        "vuln_id": f"{host_ip}:{item_elem.get('portno', '')}:{item_elem.get('pluginID', '')}",
                        "plugin_id": item_elem.get("pluginID", ""),
                        "plugin_name": item_elem.get("pluginName", ""),
                        "plugin_family": item_elem.get("pluginFamily", ""),
                        "severity": item_elem.get("severity", ""),
                        "risk_factor": item_elem.get("risk_factor", ""),
                        "cvss_base_score": item_elem.get("cvss_base_score", ""),
                        "cvss_vector": item_elem.get("cvss_vector", ""),
                        "description": item_elem.get("description", ""),
                        "solution": item_elem.get("solution", ""),
                        "host": host_ip,
                        "port": item_elem.get("port", ""),
                        "protocol": item_elem.get("protocol", ""),
                        "service": item_elem.get("svc_name", "")
                    }
                    vulnerabilities.append(vuln)
        
        return {
            "tool": "nessus",
            "parsed": vulnerabilities
        }
        
    except Exception as e:
        print(f"Error parsing Nessus XML: {str(e)}")
        return {
            "tool": "nessus",
            "error": str(e),
            "parsed": []
        }


def parse_uploaded_file(file_content: str, file_type: str) -> Dict[str, Any]:
    """
    Parse an uploaded scan report file based on its type.
    
    Args:
        file_content: Content of the uploaded file
        file_type: Type of the file (openvas, nessus, nmap, nuclei, nikto)
        
    Returns:
        Dictionary containing normalized scan results
    """
    if file_type.lower() == "openvas":
        return parse_openvas_xml(file_content)
    elif file_type.lower() == "nessus":
        return parse_nessus_xml(file_content)
    else:
        raise ValueError(f"Unsupported file type: {file_type}")


def normalize_uploaded_report(file_content: str, file_type: str) -> Dict[str, Any]:
    """
    Normalize an uploaded scan report into the canonical format.
    
    Args:
        file_content: Content of the uploaded file
        file_type: Type of the file (openvas, nessus)
        
    Returns:
        Dictionary containing normalized report in canonical format
    """
    # Parse the uploaded file
    parsed_data = parse_uploaded_file(file_content, file_type)
    
    # Convert to canonical format
    normalized_report = {
        "report_id": f"rpt-uploaded-{int(time.time())}",
        "target": "unknown",  # Will be determined from the data
        "scan_timestamp": "unknown",
        "scans": [{
            "tool": parsed_data["tool"],
            "raw_file": f"uploaded_{file_type}_report",
            "parsed": parsed_data["parsed"]
        }],
        "vulnerabilities": [],
        "attack_graph": {
            "nodes": [],
            "edges": []
        },
        "enrichment": {}
    }
    
    # Process vulnerabilities based on the tool type
    if file_type.lower() == "openvas":
        for vuln in parsed_data["parsed"]:
            normalized_vuln = {
                "vuln_id": vuln.get("vuln_id", ""),
                "cve": vuln.get("nvt", {}).get("cve", ""),
                "cvss": vuln.get("nvt", {}).get("cvss_base", vuln.get("severity", "")),
                "severity": vuln.get("threat", "").title(),
                "title": vuln.get("name", ""),
                "description": vuln.get("description", ""),
                "affected_components": [{
                    "host": vuln.get("host", ""),
                    "port": vuln.get("port", ""),
                    "service": "",
                    "product": "",
                    "version": ""
                }],
                "evidence": [],
                "exploit_refs": []
            }
            normalized_report["vulnerabilities"].append(normalized_vuln)
            
            # Update target if not set
            if normalized_report["target"] == "unknown" and vuln.get("host"):
                normalized_report["target"] = vuln.get("host")
                
    elif file_type.lower() == "nessus":
        for vuln in parsed_data["parsed"]:
            normalized_vuln = {
                "vuln_id": vuln.get("vuln_id", ""),
                "cve": "",  # Nessus may include CVE in description or plugin output
                "cvss": vuln.get("cvss_base_score", vuln.get("severity", "")),
                "severity": vuln.get("risk_factor", "").title(),
                "title": vuln.get("plugin_name", ""),
                "description": vuln.get("description", ""),
                "affected_components": [{
                    "host": vuln.get("host", ""),
                    "port": vuln.get("port", ""),
                    "service": vuln.get("service", ""),
                    "product": "",
                    "version": ""
                }],
                "evidence": [],
                "exploit_refs": []
            }
            normalized_report["vulnerabilities"].append(normalized_vuln)
            
            # Update target if not set
            if normalized_report["target"] == "unknown" and vuln.get("host"):
                normalized_report["target"] = vuln.get("host")
    
    return normalized_report


# Add time import at the top of the file when implementing fully
import time