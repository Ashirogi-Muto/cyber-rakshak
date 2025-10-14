# AI Model Integration Guide

This document provides instructions for integrating the AI model with the existing cybersecurity dashboard.

## Overview

The AI model enhances the existing system with:
1. Advanced chat assistant capabilities using Retrieval-Augmented Generation (RAG)
2. Improved attack path analysis using graph theory
3. Standardized vulnerability reporting format
4. Enhanced threat intelligence correlation

## Prerequisites

1. Python 3.8+
2. Ollama (for running local LLMs)
3. Node.js 16+ (for frontend)
4. Supabase PostgreSQL account (or local PostgreSQL instance)

## Setup Instructions

### 1. Install Backend Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Install AI Model Dependencies

All AI dependencies are contained within the AI model directory:

```bash
cd backend/ai_model/cyber-ai-assistant
pip install -r requirements.txt
```

### 3. Install Ollama and LLM

1. Download and install Ollama from https://ollama.com/
2. Pull the Llama3 model:
   ```bash
   ollama pull llama3
   ```

### 4. Update Environment Variables

Ensure your `.env` file contains the necessary configuration:
```
DATABASE_URL=postgresql://[USER]:[PASSWORD]@[HOST]:[PORT]/[DATABASE]
SECRET_KEY=your-secret-key-change-in-production
```

## Integration Details

### Chat Assistant Enhancement

The AI model replaces the placeholder chat implementation with a full RAG pipeline:

1. **Data Ingestion**: Vulnerability reports are converted to text and stored in a vector database
2. **Retrieval**: User queries retrieve relevant information from the vector store
3. **Generation**: An LLM generates contextual responses based on retrieved information

### Attack Path Analysis

The AI model provides enhanced attack path analysis:

1. **Graph Generation**: Creates directed graphs of potential attack paths
2. **Path Finding**: Uses Dijkstra's algorithm to find the most likely attack paths
3. **Visualization**: Generates JSON structures compatible with the frontend

### Report Standardization

The AI model introduces a standardized report format:

1. **Schema Definition**: Pydantic models for consistent data structure
2. **Parser Integration**: Converts various scanner outputs to standardized format
3. **Data Enrichment**: Adds AI-generated insights to reports

## Running the System

### Start the Backend

```bash
cd backend
python -m uvicorn app.main:app --reload --port 8000
```

### Start the Frontend

```bash
cd frontend
npm install
npm run dev
```

### Access the Application

- Backend API: http://localhost:8000
- Frontend Dashboard: http://localhost:3000
- API Documentation: http://localhost:8000/docs

## Troubleshooting

### Common Issues

1. **Module Import Errors**: Ensure the AI model path is correctly added to sys.path in ai_integration.py
2. **Ollama Connection**: Verify Ollama is running and the llama3 model is installed
3. **Database Connection**: Check DATABASE_URL in .env file

### Logs and Debugging

Check the terminal output for error messages. The system will log:
- AI model loading status
- Vector database operations
- LLM interactions
- Data conversion processes

## Future Enhancements

1. **Multi-Model Support**: Add support for different LLMs
2. **Advanced Prompting**: Implement more sophisticated prompt engineering
3. **Custom Embeddings**: Train domain-specific embeddings
4. **Real-time Learning**: Implement feedback loops for continuous improvement