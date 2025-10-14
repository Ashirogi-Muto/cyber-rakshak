# backend/app/parser.py

import xml.etree.ElementTree as ET
import json
import xmltodict
from typing import List, Dict, Any


def parse_nmap_xml(file_path: str) -> List[Dict[str, Any]]:
    """
    Parse Nmap XML output and return normalized results.
    
    Args:
        file_path: Path to the Nmap XML output file
        
    Returns:
        List of dictionaries containing host information
    """
    try:
        with open(file_path, 'r') as file:
            xml_content = file.read()
        
        # Parse XML content
        root = ET.fromstring(xml_content)
        
        hosts = []
        for host_elem in root.findall('host'):
            host_data = {}
            
            # Extract host address
            address_elem = host_elem.find('address')
            if address_elem is not None:
                host_data['ip'] = address_elem.get('addr', '')
            
            # Extract hostnames
            hostnames = []
            hostnames_elem = host_elem.find('hostnames')
            if hostnames_elem is not None:
                for hostname_elem in hostnames_elem.findall('hostname'):
                    hostnames.append(hostname_elem.get('name', ''))
            host_data['hostnames'] = hostnames
            
            # Extract ports information
            ports = []
            ports_elem = host_elem.find('ports')
            if ports_elem is not None:
                for port_elem in ports_elem.findall('port'):
                    port_data = {
                        'port': port_elem.get('portid'),
                        'protocol': port_elem.get('protocol'),
                        'state': '',
                        'service': ''
                    }
                    
                    # Extract port state
                    state_elem = port_elem.find('state')
                    if state_elem is not None:
                        port_data['state'] = state_elem.get('state', '')
                    
                    # Extract service information
                    service_elem = port_elem.find('service')
                    if service_elem is not None:
                        port_data['service'] = service_elem.get('name', '')
                        port_data['product'] = service_elem.get('product', '')
                        port_data['version'] = service_elem.get('version', '')
                    
                    ports.append(port_data)
            
            host_data['ports'] = ports
            hosts.append(host_data)
        
        return hosts
    
    except Exception as e:
        print(f"Error parsing Nmap XML file: {str(e)}")
        return []


def parse_nuclei_json(file_path: str) -> List[Dict[str, Any]]:
    """
    Parse Nuclei JSON output and return normalized results.
    
    Args:
        file_path: Path to the Nuclei JSON output file
        
    Returns:
        List of dictionaries containing vulnerability information
    """
    try:
        with open(file_path, 'r') as file:
            vulnerabilities = []
            for line in file:
                if line.strip():  # Skip empty lines
                    try:
                        vuln_data = json.loads(line)
                        # Normalize the data structure
                        normalized_vuln = {
                            'template_id': vuln_data.get('template-id', ''),
                            'host': vuln_data.get('host', ''),
                            'matched_at': vuln_data.get('matched-at', ''),
                            'info': {
                                'name': vuln_data.get('info', {}).get('name', ''),
                                'author': vuln_data.get('info', {}).get('author', []),
                                'tags': vuln_data.get('info', {}).get('tags', []),
                                'description': vuln_data.get('info', {}).get('description', ''),
                                'reference': vuln_data.get('info', {}).get('reference', []),
                                'severity': vuln_data.get('info', {}).get('severity', '')
                            },
                            'curl_command': vuln_data.get('curl-command', ''),
                            'matcher_name': vuln_data.get('matcher-name', '')
                        }
                        vulnerabilities.append(normalized_vuln)
                    except json.JSONDecodeError:
                        continue
                        
        return vulnerabilities
    
    except Exception as e:
        print(f"Error parsing Nuclei JSON file: {str(e)}")
        return []


def parse_nikto_xml(file_path: str) -> List[Dict[str, Any]]:
    """
    Parse Nikto XML output and return normalized results.
    
    Args:
        file_path: Path to the Nikto XML output file
        
    Returns:
        List of dictionaries containing vulnerability information
    """
    try:
        with open(file_path, 'r') as file:
            # Parse XML content using xmltodict
            data = xmltodict.parse(file.read())
        
        vulnerabilities = []
        
        # Extract vulnerability information
        if 'niktoscan' in data and 'scandetails' in data['niktoscan']:
            scan_details = data['niktoscan']['scandetails']
            
            # Handle both single item and list cases
            if isinstance(scan_details, list):
                items = scan_details
            else:
                items = [scan_details] if scan_details else []
                
            for item in items:
                if 'item' in item:
                    vuln_items = item['item']
                    # Handle both single item and list cases
                    if isinstance(vuln_items, list):
                        vulns = vuln_items
                    else:
                        vulns = [vuln_items] if vuln_items else []
                        
                    for vuln in vulns:
                        normalized_vuln = {
                            'id': vuln.get('@id', ''),
                            'osvdbid': vuln.get('@osvdbid', ''),
                            'osvdblink': vuln.get('@osvdblink', ''),
                            'method': vuln.get('@method', ''),
                            'uri': vuln.get('uri', ''),
                            'namelink': vuln.get('namelink', ''),
                            'description': vuln.get('description', ''),
                        }
                        vulnerabilities.append(normalized_vuln)
        
        return vulnerabilities
    
    except Exception as e:
        print(f"Error parsing Nikto XML file: {str(e)}")
        return []


def normalize_scan_results(tool_name: str, file_path: str) -> Dict[str, Any]:
    """
    Normalize scan results from various tools into a consistent format.
    
    Args:
        tool_name: Name of the scanning tool (nmap, nuclei, nikto)
        file_path: Path to the scan output file
        
    Returns:
        Dictionary containing normalized scan results
    """
    if tool_name.lower() == 'nmap':
        parsed_data = parse_nmap_xml(file_path)
        return {
            'tool': 'nmap',
            'raw_file': file_path,
            'parsed': parsed_data
        }
    elif tool_name.lower() == 'nuclei':
        parsed_data = parse_nuclei_json(file_path)
        return {
            'tool': 'nuclei',
            'raw_file': file_path,
            'parsed': parsed_data
        }
    elif tool_name.lower() == 'nikto':
        parsed_data = parse_nikto_xml(file_path)
        return {
            'tool': 'nikto',
            'raw_file': file_path,
            'parsed': parsed_data
        }
    else:
        raise ValueError(f"Unsupported tool: {tool_name}")