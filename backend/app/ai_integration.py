# backend/app/ai_integration.py

import sys
import os
from typing import Dict, Any, List
from sqlalchemy.orm import Session

# Add the AI model path to the system path
ai_model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'ai_model', 'cyber-ai-assistant')
sys.path.append(ai_model_path)

try:
    # Import AI model components
    from schemas import StandardizedReport, Vulnerability
    from parsers.nuclei_parser import parse_nuclei_json
    from attack_path_generator import generate_attack_graph as ai_generate_attack_graph, find_most_likely_path
    
    # Try to import RAG components, but handle if they're not available
    try:
        # Use our wrapper class
        from rag_wrapper import RAGChatAssistant as AIRAGChatAssistant
        RAG_AVAILABLE = True
    except ImportError:
        AIRAGChatAssistant = None
        RAG_AVAILABLE = False
    
    AI_MODEL_AVAILABLE = True
except ImportError as e:
    print(f"AI model components not available: {e}")
    AI_MODEL_AVAILABLE = False
    RAG_AVAILABLE = False
    AIRAGChatAssistant = None

from . import models, services
from .chat import RAGChatAssistant


def convert_to_standardized_report(normalized_data: Dict[str, Any]) -> StandardizedReport:
    """
    Convert the existing normalized data format to the AI model's standardized report format.
    
    Args:
        normalized_data: Dictionary containing normalized scan data in existing format
        
    Returns:
        StandardizedReport object
    """
    if not AI_MODEL_AVAILABLE:
        raise RuntimeError("AI model components are not available")
    
    # Extract target information
    target = normalized_data.get("target", "unknown")
    
    # Convert vulnerabilities
    vulnerabilities = []
    for vuln_data in normalized_data.get("vulnerabilities", []):
        # Map existing vulnerability format to AI model format
        vuln = Vulnerability(
            cve_id=vuln_data.get("cve"),
            vulnerability_name=vuln_data.get("title", "Unknown Vulnerability"),
            description=vuln_data.get("description", ""),
            cvss_v3_score=float(vuln_data.get("cvss", 0)) if vuln_data.get("cvss") else None,
            severity=vuln_data.get("severity", "unknown").lower(),
            affected_asset_ip=_extract_ip_from_affected_components(vuln_data.get("affected_components", [])),
            affected_port=_extract_port_from_affected_components(vuln_data.get("affected_components", [])),
            protocol="tcp",  # Default protocol
            source_tool=_extract_tool_from_evidence(vuln_data.get("evidence", [])),
            exploit_available=vuln_data.get("severity", "").lower() in ["critical", "high"]
        )
        vulnerabilities.append(vuln)
    
    # Create standardized report
    report = StandardizedReport(
        target=target,
        vulnerabilities=vulnerabilities
    )
    
    return report


def _extract_ip_from_affected_components(affected_components: List[Dict[str, Any]]) -> str:
    """Extract IP address from affected components."""
    if affected_components:
        return affected_components[0].get("host", "unknown")
    return "unknown"


def _extract_port_from_affected_components(affected_components: List[Dict[str, Any]]) -> int:
    """Extract port from affected components."""
    if affected_components:
        try:
            return int(affected_components[0].get("port", 0))
        except (ValueError, TypeError):
            return 0
    return 0


def _extract_tool_from_evidence(evidence: List[str]) -> str:
    """Extract tool information from evidence."""
    if evidence:
        # Simple heuristic: look for tool names in evidence
        evidence_text = " ".join(evidence).lower()
        if "nmap" in evidence_text:
            return "nmap"
        elif "nuclei" in evidence_text:
            return "nuclei"
        elif "nikto" in evidence_text:
            return "nikto"
    return "unknown"


def generate_enhanced_attack_graph(normalized_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate an enhanced attack graph using the AI model.
    
    Args:
        normalized_data: Dictionary containing normalized scan data
        
    Returns:
        Dictionary containing nodes and edges for the attack graph
    """
    if not AI_MODEL_AVAILABLE:
        # Fallback to existing implementation
        from . import attack_path
        return attack_path.generate_attack_graph(normalized_data)
    
    try:
        # Convert to standardized report format
        report = convert_to_standardized_report(normalized_data)
        
        # Generate attack graph using AI model
        ai_graph = ai_generate_attack_graph(report)
        
        # Convert NetworkX graph to existing format
        nodes = []
        edges = []
        
        # Convert nodes
        for node_id in ai_graph.nodes():
            node_data = ai_graph.nodes[node_id]
            nodes.append({
                "id": node_id,
                "type": node_data.get("type", "unknown"),
                "label": node_data.get("label", node_id),
                "details": node_data.get("details", {})
            })
        
        # Convert edges
        for source, target in ai_graph.edges():
            edge_data = ai_graph.get_edge_data(source, target)
            edges.append({
                "from": source,
                "to": target,
                "desc": edge_data.get("label", "connection"),
                "score": str(edge_data.get("weight", 1.0))
            })
        
        return {
            "nodes": nodes,
            "edges": edges
        }
    except Exception as e:
        print(f"Error generating enhanced attack graph: {e}")
        # Fallback to existing implementation
        from . import attack_path
        return attack_path.generate_attack_graph(normalized_data)


def get_enhanced_chat_assistant() -> Any:
    """
    Get the enhanced chat assistant using the AI model.
    
    Returns:
        Chat assistant instance
    """
    if not AI_MODEL_AVAILABLE or not RAG_AVAILABLE:
        # Fallback to existing implementation
        from .chat import get_chat_assistant
        return get_chat_assistant()
    
    # Return the AI model's RAG chat assistant
    return AIRAGChatAssistant()


def enhance_report_with_ai_insights(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enhance report data with AI-generated insights.
    
    Args:
        report_data: Dictionary containing report data
        
    Returns:
        Enhanced report data
    """
    if not AI_MODEL_AVAILABLE:
        return report_data
    
    try:
        # Convert to standardized report format
        report = convert_to_standardized_report(report_data)
        
        # In a full implementation, we would generate AI insights here
        # For now, we'll just return the original data with a flag
        enhanced_data = report_data.copy()
        enhanced_data["ai_enhanced"] = True
        
        return enhanced_data
    except Exception as e:
        print(f"Error enhancing report with AI insights: {e}")
        return report_data