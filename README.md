# Centralized Vulnerability Detection & Intelligent Query Interface (NTRO)

## Project Overview

This project implements a web platform that orchestrates multiple vulnerability scanners, normalizes and enriches findings, and generates attack-paths. The AI components have been temporarily removed for simplified local deployment.

## Features Implemented

### Phase 1: Enumeration GUI & Tool Integration
- ✅ Backend job orchestration for:
  - ✅ Nmap (port/service discovery, versions)
  - ✅ Nuclei (templated checks)
  - ✅ Nikto (web vulnerability scanning)
- ✅ Upload/import capability for scan results
- ✅ Storage of raw outputs and scan metadata

### Phase 2: Normalization & Enrichment
- ✅ Parsing modules for Nmap, Nuclei, and Nikto → Normalized JSON Reports
- ✅ Report storage and retrieval
- ✅ Attack-path generation

## Technology Stack

### Backend
- **FastAPI** - Python web framework for building APIs
- **Supabase PostgreSQL** for persistent database storage
- **Direct execution** for scan tools (replaces Celery/Redis)
- **Nmap, Nuclei, Nikto** for vulnerability scanning

### Frontend
- **React** - JavaScript library for building user interfaces
- **TypeScript** - Typed superset of JavaScript
- **Vite** - Fast build tool and development server

## Project Structure

```
sih234/
├── backend/
│   ├── app/
│   │   ├── main.py          # FastAPI application
│   │   ├── worker.py        # Direct scan execution functions
│   │   ├── parser.py        # Scan output parsers
│   │   ├── models.py        # Database models
│   │   ├── database.py      # Database connection
│   │   ├── auth.py          # Authentication and security
│   │   └── services.py      # Business logic services
│   └── requirements.txt     # Python dependencies
├── frontend/                # React frontend application
│   ├── src/                 # Source code
│   ├── public/              # Static assets
│   ├── package.json         # Node.js dependencies
│   └── vite.config.ts       # Vite configuration
├── .env                     # Environment variables configuration
├── start_local.bat          # Windows startup script
├── start_local.sh           # Linux/macOS startup script
├── test_deployment.py       # Deployment test script
├── DEPLOYMENT.md            # Deployment guide
└── README.md                # This file
```

## Setup and Installation

1. **Prerequisites**
   - Python 3.8+
   - Node.js 16+
   - Nmap, Nuclei, and Nikto installed and available in PATH
   - Supabase PostgreSQL account (or local PostgreSQL instance)
   - npm (Node package manager)

2. **Environment Variables**
   Configure the environment variables in the `.env` file:
   ```
   # Database Configuration
   DATABASE_URL=postgresql://[USER]:[PASSWORD]@[HOST]:[PORT]/[DATABASE]
   
   # Security Configuration
   SECRET_KEY=your-secret-key-change-in-production
   ```

3. **Run locally**
   ```bash
   # On Windows
   start_local.bat
   
   # On Linux/macOS
   ./start_local.sh
   ```

4. **Manual startup (alternative)**
   ```bash
   # Install backend dependencies
   pip install -r backend/requirements.txt
   
   # Install frontend dependencies
   cd frontend
   npm install
   
   # Set environment variables (or use the .env file)
   export DATABASE_URL=postgresql://[USER]:[PASSWORD]@[HOST]:[PORT]/[DATABASE]
   
   # Start the backend
   cd backend
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   
   # In another terminal, start the frontend
   cd frontend
   npm run dev
   ```

5. **Access the Application**
   - Backend API: http://localhost:8000
   - Frontend Dashboard: http://localhost:3000
   - API Documentation: http://localhost:8000/docs

## API Endpoints

- `GET /` - Health check
- `POST /api/scan/start` - Start a new scan (runs directly, no queuing)
- `GET /api/scan/status/{job_id}` - Get scan status (always returns completed)
- `GET /api/reports` - List all reports
- `GET /api/report/{report_id}` - Get report details
- `POST /api/report/upload` - Upload scan results
- `GET /api/attackpath/{report_id}` - Get attack graph

## Example Usage

### Start a scan
```bash
curl -X POST "http://localhost:8000/api/scan/start" \
     -H "Content-Type: application/json" \
     -d '{"target": "scanme.nmap.org", "profile": "safe", "tools": ["nmap"]}'
```

## Security Features

- Scans only authorized targets
- Input validation to prevent command injection
- JWT-based authentication for API access

## Windows Quick Start

1. Edit the `.env` file to configure your Supabase PostgreSQL credentials
2. Double-click `start_local.bat` to start the system
3. Access the API at http://localhost:8000 and frontend at http://localhost:3000
4. Close the command window to stop the system

## Linux/macOS Quick Start

1. Edit the `.env` file to configure your Supabase PostgreSQL credentials
2. Make the script executable: `chmod +x start_local.sh`
3. Run the script: `./start_local.sh`
4. Access the API at http://localhost:8000 and frontend at http://localhost:3000
5. Press Ctrl+C to stop the system

## Future Enhancements

1. **AI Components**: Re-introduce the RAG chat assistant and threat intelligence correlation
2. **Enhanced Frontend**: Add a web-based user interface
3. **Additional Scanners**: Integrate more vulnerability scanning tools
4. **Reporting Features**: Add PDF/CSV export capabilities
5. **Dashboard Analytics**: Add charts and visualizations for vulnerability trends

## Compliance and Safety

- Scans only explicitly authorized targets
- Provides procedural guidance without automatic exploitation
- Maintains auditability with comprehensive logging