# parsers/nuclei_parser.py

import json
from typing import List
import sys
import os

# This is a common trick to allow this script to import modules
# from the parent directory (where schemas.py is located).
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

# Now we can import our schemas
from schemas import Vulnerability, StandardizedReport

def parse_nuclei_json(file_path: str) -> StandardizedReport:
    """
    Parses a Nuclei JSON output file and converts it into our StandardizedReport format.
    """
    vulnerabilities: List[Vulnerability] = []
    
    # Support two common formats for Nuclei output:
    # 1) A single JSON array: [ {...}, {...} ]
    # 2) NDJSON / JSON Lines: one JSON object per line
    data = []
    with open(file_path, 'r', encoding='utf-8') as f:
        text = f.read().strip()
        if not text:
            data = []
        else:
            # Try parsing as a single JSON document first (array or object)
            try:
                parsed = json.loads(text)
                # If it's a dict (single object), wrap into list
                if isinstance(parsed, dict):
                    data = [parsed]
                elif isinstance(parsed, list):
                    data = parsed
                else:
                    # Other JSON values are unexpected; fall back to NDJSON
                    data = []
            except json.JSONDecodeError:
                # Fall back to NDJSON parsing: parse per-line
                data = [json.loads(line) for line in text.splitlines() if line.strip()]


    # Assuming the first item gives us the general target info
    target_host = data[0].get("host", "unknown-target") if data else "unknown-target"

    for item in data:
        info = item.get("info", {})
        
        # Skip informational findings if we only want vulnerabilities
        if info.get("severity") == "info":
            continue

        # Extract port and protocol from the 'matched-at' field. This is a simple approach.
        matched_at = item.get("matched-at", "")
        port = 80 # Default port
        protocol = "http" # Default protocol
        if "://" in matched_at:
            protocol_part, rest = matched_at.split("://", 1)
            protocol = protocol_part
            
            host_port = rest.split("/")[0]
            if ":" in host_port:
                try:
                    port = int(host_port.split(":")[1])
                except ValueError:
                    port = 80
        
        # Create a Vulnerability object using our schema
        vuln = Vulnerability(
            cve_id=info.get("cve-id"),
            vulnerability_name=info.get("name", "N/A"),
            description=info.get("description", "No description provided."),
            cvss_v3_score=info.get("cvss-score"), # Nuclei v3 might have this field
            severity=info.get("severity", "unknown"),
            affected_asset_ip=item.get("ip", "N/A"),
            affected_port=port,
            protocol=protocol,
            source_tool="nuclei",
            exploit_available=True if info.get("severity") in ["critical", "high"] else False
        )
        vulnerabilities.append(vuln)
    
    # Create the final report object
    report = StandardizedReport(
        target=target_host,
        vulnerabilities=vulnerabilities
    )
    
    return report

# This block allows us to run this file directly for testing
if __name__ == "__main__":
    sample_file = "sample_nuclei_output.json"
    
    print(f"--- Parsing {sample_file} ---")
    
    try:
        standardized_report = parse_nuclei_json(sample_file)
        
        # .model_dump_json() is a Pydantic helper to print the object neatly
        print(standardized_report.model_dump_json(indent=2))
        
        print("\n--- Parsing Successful ---")
    except FileNotFoundError:
        print(f"Error: Make sure the file '{sample_file}' exists in your main project directory.")
    except Exception as e:
        print(f"An error occurred: {e}")