# backend/app/chat.py

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer
from typing import List, Dict, Any, Tuple
import json
import os
import uuid


class RAGChatAssistant:
    """
    RAG-based chat assistant for vulnerability reports.
    """
    
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        """
        Initialize the RAG chat assistant.
        
        Args:
            model_name: Name of the sentence transformer model to use
        """
        # Initialize the sentence transformer model
        self.model = SentenceTransformer(model_name)
        
        # Initialize FAISS index
        self.dimension = self.model.get_sentence_embedding_dimension()
        self.index = faiss.IndexFlatL2(self.dimension)
        
        # Store document chunks with their metadata
        self.chunks = []  # List of {text, metadata}
        
        # Initialize with some default chunks
        self._initialize_default_chunks()
    
    def _initialize_default_chunks(self):
        """
        Initialize with some default chunks for demonstration.
        """
        default_chunks = [
            {
                "text": "Apache Log4Shell (CVE-2021-44228) is a critical vulnerability in Apache Log4j library that allows remote code execution.",
                "metadata": {
                    "source": "cve_description",
                    "cve": "CVE-2021-44228",
                    "type": "vulnerability"
                }
            },
            {
                "text": "To remediate Log4Shell, update Log4j to version 2.15.0 or later, or set the system property log4j2.formatMsgNoLookups to true.",
                "metadata": {
                    "source": "remediation",
                    "cve": "CVE-2021-44228",
                    "type": "remediation"
                }
            }
        ]
        
        for chunk in default_chunks:
            self.add_chunk(chunk["text"], chunk["metadata"])
    
    def add_chunk(self, text: str, metadata: Dict[str, Any] = None):
        """
        Add a text chunk to the vector store.
        
        Args:
            text: The text to add
            metadata: Metadata associated with the text
        """
        # Generate embedding
        embedding = self.model.encode([text])
        
        # Add to FAISS index
        self.index.add(embedding)
        
        # Store chunk with metadata
        chunk_id = str(uuid.uuid4())
        self.chunks.append({
            "id": chunk_id,
            "text": text,
            "metadata": metadata or {}
        })
    
    def add_report_chunks(self, report_data: Dict[str, Any]):
        """
        Add chunks from a vulnerability report to the vector store.
        
        Args:
            report_data: Normalized report data
        """
        # Add report summary
        report_id = report_data.get("report_id", "unknown")
        target = report_data.get("target", "unknown")
        
        summary_text = f"Vulnerability report for {target} (ID: {report_id})"
        self.add_chunk(summary_text, {"source": "report", "type": "summary", "report_id": report_id})
        
        # Add vulnerability chunks
        vulnerabilities = report_data.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            # Add vulnerability description
            vuln_text = f"{vuln.get('title', 'Unknown vulnerability')}: {vuln.get('description', '')}"
            self.add_chunk(vuln_text, {
                "source": "report", 
                "type": "vulnerability", 
                "report_id": report_id,
                "vuln_id": vuln.get("vuln_id", ""),
                "cve": vuln.get("cve", "")
            })
            
            # Add evidence chunks
            evidence_list = vuln.get("evidence", [])
            for i, evidence in enumerate(evidence_list):
                evidence_text = f"Evidence for {vuln.get('title', 'vulnerability')}: {evidence}"
                self.add_chunk(evidence_text, {
                    "source": "report",
                    "type": "evidence",
                    "report_id": report_id,
                    "vuln_id": vuln.get("vuln_id", ""),
                    "evidence_index": i
                })
        
        # Add attack graph information
        attack_graph = report_data.get("attack_graph", {})
        nodes = attack_graph.get("nodes", [])
        edges = attack_graph.get("edges", [])
        
        if nodes or edges:
            graph_text = f"Attack graph for {target} contains {len(nodes)} nodes and {len(edges)} connections."
            self.add_chunk(graph_text, {
                "source": "report",
                "type": "attack_graph",
                "report_id": report_id
            })
    
    def search(self, query: str, k: int = 5) -> List[Tuple[float, Dict[str, Any]]]:
        """
        Search for relevant chunks given a query.
        
        Args:
            query: The query text
            k: Number of results to return
            
        Returns:
            List of (score, chunk) tuples
        """
        # Generate query embedding
        query_embedding = self.model.encode([query])
        
        # Search in FAISS index
        scores, indices = self.index.search(query_embedding, k)
        
        # Retrieve chunks
        results = []
        for i, idx in enumerate(indices[0]):
            if idx < len(self.chunks):  # Check bounds
                score = float(scores[0][i])
                chunk = self.chunks[idx]
                results.append((score, chunk))
        
        return results
    
    def generate_prompt(self, query: str, k: int = 5) -> str:
        """
        Generate a prompt for the LLM based on the query and retrieved chunks.
        
        Args:
            query: The user query
            k: Number of chunks to retrieve
            
        Returns:
            Formatted prompt string
        """
        # Retrieve relevant chunks
        results = self.search(query, k)
        
        # Build context from chunks
        context_parts = []
        citations = []
        
        for i, (score, chunk) in enumerate(results):
            citation_id = f"[{i+1}]"
            context_parts.append(f"{citation_id} {chunk['text']}")
            citations.append({
                "id": citation_id,
                "text": chunk['text'][:100] + "..." if len(chunk['text']) > 100 else chunk['text'],
                "source": chunk['metadata'].get('source', 'unknown')
            })
        
        context = "\n\n".join(context_parts)
        
        # Create the prompt
        prompt = f"""You are a cybersecurity expert assistant. Use the following context to answer the query according to best practices.

Context:
{context}

Query: {query}

Please provide a detailed answer with specific recommendations. Reference the context using citations like {citation_id} where appropriate.

Answer:"""
        
        return prompt, citations
    
    def process_query(self, query: str, k: int = 5) -> Dict[str, Any]:
        """
        Process a user query and generate a response.
        
        Args:
            query: The user query
            k: Number of chunks to retrieve
            
        Returns:
            Dictionary containing the answer, citations, and confidence score
        """
        # Generate prompt
        prompt, citations = self.generate_prompt(query, k)
        
        # In a real implementation, you would call an LLM here
        # For now, we'll generate a mock response
        answer = self._generate_mock_response(query, citations)
        
        # Calculate confidence (mock implementation)
        confidence = min(0.95, len(citations) * 0.2 + 0.1)
        
        return {
            "answer": answer,
            "citations": citations,
            "confidence": confidence,
            "prompt": prompt
        }
    
    def _generate_mock_response(self, query: str, citations: List[Dict[str, Any]]) -> str:
        """
        Generate a mock response for demonstration purposes.
        
        Args:
            query: The user query
            citations: List of citations
            
        Returns:
            Mock response string
        """
        # This is a placeholder implementation
        # In a real implementation, you would call an LLM
        
        if "log4j" in query.lower() or "log4shell" in query.lower():
            return "Apache Log4Shell (CVE-2021-44228) is a critical remote code execution vulnerability. You should immediately update Log4j to version 2.15.0 or later [1]. Evidence of this vulnerability was found in your scan [2]."
        elif "remediate" in query.lower() or "fix" in query.lower():
            return "To remediate critical vulnerabilities, follow these steps: 1) Update affected software to patched versions, 2) Apply vendor-supplied patches, 3) Implement network segmentation, 4) Monitor for exploitation attempts. Specific remediation steps for Log4Shell are available [2]."
        else:
            return f"Based on the vulnerability report, I found relevant information that addresses your query '{query}'. The key findings include critical vulnerabilities that require immediate attention [1] and evidence of potential exploitation [2]."


# Global instance of the RAG chat assistant
chat_assistant = RAGChatAssistant()


def get_chat_assistant() -> RAGChatAssistant:
    """
    Get the global chat assistant instance.
    
    Returns:
        RAGChatAssistant instance
    """
    return chat_assistant