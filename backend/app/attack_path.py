# backend/app/attack_path.py

from typing import List, Dict, Any, Tuple
from . import services
from sqlalchemy.orm import Session


def generate_attack_graph(normalized_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate an attack graph from normalized scan data using heuristic chaining.
    
    Args:
        normalized_data: Dictionary containing normalized scan data
        
    Returns:
        Dictionary containing nodes and edges for the attack graph
    """
    nodes = []
    edges = []
    node_id_counter = 0
    
    # Maps to keep track of created nodes
    host_nodes = {}  # ip -> node_id
    service_nodes = {}  # (ip, port) -> node_id
    vulnerability_nodes = {}  # vuln_id -> node_id
    
    # Process hosts from Nmap data
    for scan in normalized_data.get("scans", []):
        if scan["tool"] == "nmap":
            for host_data in scan["parsed"]:
                ip = host_data.get("ip", "")
                if ip and ip not in host_nodes:
                    node_id_counter += 1
                    node_id = f"h{node_id_counter}"
                    host_nodes[ip] = node_id
                    nodes.append({
                        "id": node_id,
                        "type": "host",
                        "label": ip,
                        "details": {
                            "ip": ip,
                            "hostnames": host_data.get("hostnames", [])
                        }
                    })
    
    # Process services and create vulnerability nodes
    vulnerabilities = normalized_data.get("vulnerabilities", [])
    for vuln in vulnerabilities:
        # Create vulnerability node
        vuln_id = vuln.get("vuln_id", "")
        if not vuln_id:
            continue
            
        node_id_counter += 1
        node_id = f"v{node_id_counter}"
        vulnerability_nodes[vuln_id] = node_id
        
        nodes.append({
            "id": node_id,
            "type": "vuln",
            "label": vuln.get("title", "Unknown Vulnerability"),
            "details": {
                "cve": vuln.get("cve", ""),
                "severity": vuln.get("severity", ""),
                "cvss": vuln.get("cvss", "")
            }
        })
        
        # Create edges from affected components to vulnerability
        for component in vuln.get("affected_components", []):
            ip = component.get("host", "")
            port = component.get("port", "")
            
            # Create service node if it doesn't exist
            service_key = (ip, port)
            if service_key not in service_nodes:
                # First check if host node exists
                if ip in host_nodes:
                    host_node_id = host_nodes[ip]
                    
                    # Create service node
                    node_id_counter += 1
                    service_node_id = f"s{node_id_counter}"
                    service_nodes[service_key] = service_node_id
                    
                    nodes.append({
                        "id": service_node_id,
                        "type": "service",
                        "label": f"{ip}:{port}",
                        "details": {
                            "ip": ip,
                            "port": port,
                            "service": component.get("service", ""),
                            "product": component.get("product", ""),
                            "version": component.get("version", "")
                        }
                    })
                    
                    # Create edge from host to service
                    edges.append({
                        "from": host_node_id,
                        "to": service_node_id,
                        "desc": "host_service",
                        "score": "1.0"
                    })
                
            # Create edge from service to vulnerability
            if service_key in service_nodes:
                service_node_id = service_nodes[service_key]
                edges.append({
                    "from": service_node_id,
                    "to": node_id,
                    "desc": "service_vuln",
                    "score": vuln.get("cvss", "5.0")
                })
    
    return {
        "nodes": nodes,
        "edges": edges
    }


def score_attack_paths(attack_graph: Dict[str, Any]) -> Dict[str, Any]:
    """
    Score the attack paths in the graph based on exploitability.
    
    Args:
        attack_graph: Dictionary containing nodes and edges
        
    Returns:
        Dictionary containing the scored attack graph
    """
    # In a more advanced implementation, this would:
    # 1. Calculate path complexity
    # 2. Weight edges based on CVSS scores
    # 3. Identify critical paths
    # 4. Prioritize attack vectors
    
    # For now, we'll just return the graph as-is with some basic scoring
    scored_graph = attack_graph.copy()
    
    # Add a score property to each edge based on a simple heuristic
    for edge in scored_graph["edges"]:
        # Default score
        score = 5.0
        
        # Adjust based on edge description
        if edge["desc"] == "service_vuln":
            # Use the CVSS score if available
            try:
                score = float(edge.get("score", 5.0))
            except (ValueError, TypeError):
                score = 5.0
        elif edge["desc"] == "host_service":
            score = 1.0  # Basic connectivity
            
        edge["score"] = str(score)
    
    return scored_graph


def identify_critical_paths(attack_graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Identify critical attack paths in the graph.
    
    Args:
        attack_graph: Dictionary containing nodes and edges
        
    Returns:
        List of critical paths
    """
    # This is a simplified implementation
    # A full implementation would use graph algorithms to find shortest paths,
    # critical nodes, etc.
    
    critical_paths = []
    
    # Find all vulnerability nodes
    vuln_nodes = [node for node in attack_graph["nodes"] if node["type"] == "vuln"]
    
    # For each critical/high severity vulnerability, create a path
    for node in vuln_nodes:
        severity = node["details"].get("severity", "").lower()
        cvss = node["details"].get("cvss", "0.0")
        
        try:
            cvss_score = float(cvss)
        except (ValueError, TypeError):
            cvss_score = 0.0
            
        # Consider critical (CVSS >= 9.0) or high (CVSS >= 7.0) vulnerabilities as critical paths
        if severity == "critical" or severity == "high" or cvss_score >= 7.0:
            critical_paths.append({
                "vulnerability": node["label"],
                "cve": node["details"].get("cve", ""),
                "severity": severity,
                "cvss": cvss,
                "node_id": node["id"]
            })
    
    return critical_paths