# attack_path_generator.py

import networkx as nx
from schemas import StandardizedReport, Vulnerability

# We need to import the parser from Phase 1 to get our input data for this script.
from parsers.nuclei_parser import parse_nuclei_json

# By defining this here, at the top level of the file,
# it becomes a public variable that other scripts can import.
fake_privesc_vuln = Vulnerability(
    cve_id="CVE-2022-0847",
    vulnerability_name="Dirty Pipe",
    description="A privilege escalation vulnerability in the Linux kernel.",
    severity="high",
    affected_asset_ip="192.168.1.10",
    affected_port=0, # Not port-specific
    protocol="local",
    source_tool="manual_add"
)

def generate_attack_graph(report: StandardizedReport) -> nx.DiGraph:
    """
    Takes a StandardizedReport and builds a directed graph of attack paths.
    """
    G = nx.DiGraph()

    # 1. Add the starting point for all attacks
    G.add_node("Attacker", type="source", label="Attacker")

    # 2. Add nodes for all unique assets found in the report
    all_ips = {vuln.affected_asset_ip for vuln in report.vulnerabilities}
    for ip in all_ips:
        G.add_node(ip, type="asset", label=f"Asset\n({ip})")

    # 3. Add edges based on vulnerability severity and type (The "AI" logic)
    for vuln in report.vulnerabilities:
        
        # Rule 1: Initial Access
        # If a vulnerability is 'critical', we assume it can be used for initial access.
        if vuln.severity == "critical":
            G.add_edge(
                "Attacker",
                vuln.affected_asset_ip,
                cve=vuln.cve_id,
                label=f"Exploit {vuln.cve_id}\n(Initial Access)",
                # Lower weight is an "easier" path for the attacker
                weight=1 
            )

        # Rule 2: Privilege Escalation
        # If a vulnerability allows for privilege escalation, it means an attacker
        # is already on the box and can become 'root' or 'administrator'.
        # We will represent this as a new, more powerful state.
        if "privilege escalation" in vuln.description.lower():
            compromised_user_node = f"{vuln.affected_asset_ip} (User)"
            compromised_root_node = f"{vuln.affected_asset_ip} (Root)"

            G.add_node(compromised_user_node, type="state", label="Compromised (User)")
            G.add_node(compromised_root_node, type="state", label="Compromised (Root)")

            # An attacker with initial access gets user-level compromise
            G.add_edge(vuln.affected_asset_ip, compromised_user_node, label="Gain User Shell", weight=0.5)
            # The priv-esc vuln takes them from User to Root
            G.add_edge(
                compromised_user_node,
                compromised_root_node,
                cve=vuln.cve_id,
                label=f"Exploit {vuln.cve_id}\n(Privilege Escalation)",
                weight=1
            )
            
    return G

def find_most_likely_path(graph: nx.DiGraph, source, target):
    """
    Uses Dijkstra's algorithm to find the shortest (easiest) path for an attacker.
    """
    try:
        # 'dijkstra_path' finds the path with the minimum total 'weight'
        path_nodes = nx.dijkstra_path(graph, source=source, target=target, weight='weight')
        
        path_details = []
        for i in range(len(path_nodes) - 1):
            edge_data = graph.get_edge_data(path_nodes[i], path_nodes[i+1])
            path_details.append(edge_data['label'])
            
        return path_details
    except nx.NetworkXNoPath:
        return [f"No path found from '{source}' to '{target}'."]
    except nx.NodeNotFound:
        return [f"A node was not found in the graph. Ensure '{source}' and '{target}' exist."]


# This block allows us to run this file directly for testing
if __name__ == "__main__":
    # === Step 1: Get the standardized report from our parser ===
    sample_file = "sample_nuclei_output.json"
    report = parse_nuclei_json(sample_file)

    # === Step 2: Manually add a fake vulnerability to show a multi-step attack ===
    # Our sample file only has one vuln. To test the pathfinding logic,
    # let's pretend we also found a privilege escalation vulnerability on the same host.
   # IT'S NOW DEFINED AT THE TOP OF THE FILE.
    report.vulnerabilities.append(fake_privesc_vuln)
    
    print("--- Running Attack Path Analysis on Enriched Report ---")
    
    # === Step 3: Generate the graph from the enriched report ===
    attack_graph = generate_attack_graph(report)

    print(f"\nGraph Nodes: {list(attack_graph.nodes(data=True))}")
    print(f"Graph Edges: {list(attack_graph.edges(data=True))}")
    
    # === Step 4: Find the most likely attack path to the 'Root' state ===
    target_node = "192.168.1.10 (Root)" # Our goal is to become root on this machine
    
    print(f"\n--- Finding shortest attack path to '{target_node}' ---")
    path = find_most_likely_path(attack_graph, source="Attacker", target=target_node)
    
    print("\n✅ Most Likely Attack Path:")
    for i, step in enumerate(path, 1):
        print(f"   Step {i}: {step}")