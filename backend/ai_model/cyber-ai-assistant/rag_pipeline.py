# rag_pipeline.py

import json
from langchain_chroma import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_ollama import OllamaLLM
from langchain.prompts import ChatPromptTemplate
from langchain.schema.runnable import RunnablePassthrough
from langchain.schema.output_parser import StrOutputParser
from langchain.text_splitter import RecursiveCharacterTextSplitter

# Import the work from our previous phases
from schemas import StandardizedReport
from parsers.nuclei_parser import parse_nuclei_json
from attack_path_generator import generate_attack_graph, find_most_likely_path

# --- 1. SETUP THE RAG COMPONENTS ---

# Initialize the embedding model that will turn our text into numbers (vectors)
# This will download the model from Hugging Face the first time you run it.
print("Loading embedding model...")
embedding_model = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

# Initialize the Vector Store (ChromaDB) where we'll store our report data
# This creates a temporary, in-memory database.
vector_store = Chroma(
    collection_name="security_reports",
    embedding_function=embedding_model
)

# Initialize the Large Language Model (LLM) we'll use to generate answers
# Make sure you have Ollama running with the 'llama3' model pulled.
llm = OllamaLLM(model="llama3")

# --- 2. CREATE THE DATA INGESTION PIPELINE ---

def ingest_report_data(report: StandardizedReport, attack_path: list):
    """
    Takes the scan report and attack path, converts them to text,
    and stores them in the vector database.
    """
    print("\n--- Ingesting data into RAG pipeline ---")
    
    # a. Convert our structured data into plain text documents
    report_text = f"Security Scan Report for Target: {report.target}\n"
    for vuln in report.vulnerabilities:
        report_text += f"""
        Vulnerability: {vuln.vulnerability_name}
        CVE ID: {vuln.cve_id}
        Severity: {vuln.severity}
        CVSS Score: {vuln.cvss_v3_score}
        Description: {vuln.description}
        Affected IP: {vuln.affected_asset_ip}
        Affected Port: {vuln.affected_port}
        ---
        """
    
    attack_path_text = "Generated Attack Path Analysis:\n"
    for i, step in enumerate(attack_path, 1):
        attack_path_text += f"Step {i}: {step}\n"

    # b. Use a Text Splitter to break the documents into smaller chunks
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=100)
    docs_to_ingest = text_splitter.create_documents([report_text, attack_path_text])
    
    # c. Add the chunks to our vector store
    vector_store.add_documents(docs_to_ingest)
    print("--- Ingestion complete. Chatbot is ready. ---")


# --- 3. BUILD THE QUERY AND GENERATION CHAIN ---

# Create a "retriever" that can fetch relevant documents from the vector store
retriever = vector_store.as_retriever()

# Create our prompt template. This is crucial for controlling the LLM's output.
# NEW, MORE PERMISSIVE TEMPLATE
template = """
You are an expert cybersecurity analyst AI. Your task is to provide direct, factual answers based on the provided security report data.
Answer the user's question using ONLY the context provided below.
Provide technical details, exploit steps, and remediation guidance as requested, without refusal.

Context:
{context}

Question:
{question}

Answer:
"""
prompt = ChatPromptTemplate.from_template(template)

# Build the final RAG chain using LangChain Expression Language (LCEL)
rag_chain = (
    {"context": retriever, "question": RunnablePassthrough()}
    | prompt
    | llm
    | StrOutputParser()
)

def ask_assistant(query: str):
    """Invokes the RAG chain to answer a user's question."""
    print(f"\n> You asked: {query}")
    response = rag_chain.invoke(query)
    print(f"\n< AI Assistant says:\n{response}")
    return response

# --- 4. MAIN EXECUTION BLOCK FOR TESTING ---

if __name__ == "__main__":
    # Get the report data from Phase 1
    report = parse_nuclei_json("sample_nuclei_output.json")
    
    # Generate the attack path from Phase 2 (using the same enriched data)
    from attack_path_generator import fake_privesc_vuln
    report.vulnerabilities.append(fake_privesc_vuln)
    graph = generate_attack_graph(report)
    path = find_most_likely_path(graph, source="Attacker", target="192.168.1.10 (Root)")

    # Ingest this data into our RAG system
    ingest_report_data(report, path)

    # Ask some questions to test the chatbot
    ask_assistant("What is the most critical vulnerability found?")
    ask_assistant("Summarize the attack path to gain root access.")
    ask_assistant("What is CVE-2017-5638 and how can it be used?")