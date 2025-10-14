# Deployment Guide

## Prerequisites

1. Python 3.8+ installed
2. Nmap, Nuclei, and Nikto installed and available in PATH
3. Supabase PostgreSQL account (or local PostgreSQL instance)
4. At least 2GB RAM available
5. Internet connection for initial setup

## Quick Start

1. **Clone or download the repository**
   ```
   git clone <repository-url>
   cd sih234
   ```

2. **Configure environment variables**
   Edit the `.env` file to set your configuration:
   ```
   # Database Configuration
   DATABASE_URL=postgresql://[USER]:[PASSWORD]@[HOST]:[PORT]/[DATABASE]
   
   # Security Configuration
   SECRET_KEY=your-secret-key-change-in-production
   ```

3. **Start the services**
   ```
   # On Windows
   start_local.bat
   
   # On Linux/macOS
   ./start_local.sh
   ```

4. **Access the API**
   - API will be available at: http://localhost:8000
   - API documentation: http://localhost:8000/docs

## Services Overview

The deployment includes the following components:

1. **backend** - FastAPI application with direct scan execution
2. **frontend** - React-based dashboard interface
3. **Supabase PostgreSQL database** - Cloud database for storing metadata
4. **Scan tools** - Nmap, Nuclei, and Nikto for vulnerability scanning

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

### Check scan status
```bash
curl "http://localhost:8000/api/scan/status/{job_id}"
```

### Get reports
```bash
curl "http://localhost:8000/api/reports"
```

## Data Persistence

- Supabase PostgreSQL database for storing metadata
- Scan outputs are stored in the `scan_outputs` directory

## Stopping the Services

To stop the services:
- Press Ctrl+C in the terminal where the application is running
- Or close the command window if using the batch script

## Troubleshooting

1. **Missing dependencies**: If you get import errors, make sure to install the Python dependencies with `pip install -r backend/requirements.txt`.

2. **Scan tools not found**: Ensure Nmap, Nuclei, and Nikto are installed and available in your PATH.

3. **Database connection issues**: Verify that your DATABASE_URL environment variable is set correctly with valid Supabase credentials.

4. **Permission issues**: On Linux/macOS, you may need to make the startup script executable with `chmod +x start_local.sh`.

5. **Port conflicts**: If port 8000 is already in use, modify the startup command to use a different port.

## Customization

### Scan Tools
The system currently supports:
- Nmap (network scanning)
- Nuclei (vulnerability scanning)
- Nikto (web server scanning)

### Scan Profiles
- `safe` - Quick, non-intrusive scans
- `normal` - Comprehensive scans with version detection
- `deep` - Thorough scans with extensive checks

## Security Notes

- For production deployment, use secure Supabase credentials and connection strings
- Change the default SECRET_KEY in the .env file
- The system is designed to scan only authorized targets
- All scan outputs are stored locally