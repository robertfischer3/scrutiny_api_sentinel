"""
API Sentinel - Main Application Module

This module defines the main FastAPI application for the API Sentinel service.
It provides the core functionality for monitoring and analyzing API traffic.
"""

import logging
import os
from pathlib import Path
from typing import Dict, List, Optional
import json
from datetime import datetime

# Temporary in-memory storage for scan results
scan_results = {}

import uvicorn
from pydantic import BaseModel

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, BackgroundTasks, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any, Optional
import json

from scrutiny_api_sentinel.scanner import get_scanner, APILogEntry
from scrutiny_api_sentinel.ml.data_utils import generate_synthetic_anomalies, generate_security_threats

# Import local modules
# from scrutiny_api_sentinel.interceptor import APIInterceptor
# from scrutiny_api_sentinel.models import APIRequest, APIResponse
# from scrutiny_api_sentinel.database import get_db
# from scrutiny_api_sentinel.config import Settings

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("api-sentinel")

# Initialize the FastAPI application
app = FastAPI(
    title="API Sentinel",
    description="Monitor and analyze API traffic for security and performance insights",
    version="0.1.0",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Update for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Define API models
class HealthResponse(BaseModel):
    status: str
    version: str

# Background task function
async def run_scanner_task(scan_id: str, source_type: str, config: Dict[str, Any], 
                          file_path: Optional[Path] = None, data: Optional[Dict[str, Any]] = None):
    """Background task to run a scanner and store results."""
    try:
        scanner = get_scanner(source_type, config)
        
        if source_type == "log" and file_path:
            result = await scanner.scan_file(file_path)
        elif source_type == "traffic" and file_path:
            result = await scanner.scan_capture(file_path)
        elif source_type == "webhook" and data:
            result = await scanner.process_webhook(data)
        else:
            logger.error(f"Invalid scan configuration: {source_type}")
            scan_results[scan_id] = {"status": "error", "message": "Invalid scan configuration"}
            return
            
        # Store results
        scan_results[scan_id] = {
            "status": "completed",
            "timestamp": datetime.now().isoformat(),
            "result": result.dict()
        }
        logger.info(f"Scan {scan_id} completed with {result.entries_processed} entries processed")
        
    except Exception as e:
        logger.exception(f"Error in scan {scan_id}: {str(e)}")
        scan_results[scan_id] = {
            "status": "error", 
            "message": str(e),
            "timestamp": datetime.now().isoformat()
        }

# New endpoint for log file scanning
@app.post("/api/scan/logs", status_code=status.HTTP_202_ACCEPTED)
async def scan_log_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    config: Optional[str] = Form(None)
):
    """Upload and scan an API log file for analysis."""
    scan_id = f"scan_{datetime.now().strftime('%Y%m%d%H%M%S')}_{os.urandom(4).hex()}"
    
    # Save uploaded file to a temporary location
    temp_dir = Path(os.getenv("TEMP_DIR", "/tmp/api-sentinel"))
    temp_dir.mkdir(exist_ok=True)
    
    file_path = temp_dir / f"{scan_id}_{file.filename}"
    
    try:
        # Save the uploaded file
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)
            
        # Parse scanner configuration
        scanner_config = json.loads(config) if config else {}
        
        # Start background scan
        scan_results[scan_id] = {"status": "pending", "timestamp": datetime.now().isoformat()}
        background_tasks.add_task(
            run_scanner_task,
            scan_id=scan_id,
            source_type="log",
            config=scanner_config,
            file_path=file_path
        )
        
        return {"scan_id": scan_id, "status": "pending"}
        
    except Exception as e:
        logger.exception(f"Error setting up log scan: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error setting up scan: {str(e)}"
        )


# Endpoint to check scan status
@app.get("/api/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get the status or results of a previously initiated scan."""
    if scan_id not in scan_results:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID {scan_id} not found"
        )
        
    return scan_results[scan_id]

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint to verify the service is running."""
    return HealthResponse(status="healthy", version="0.1.0")


@app.middleware("http")
async def intercept_middleware(request: Request, call_next):
    """Middleware to intercept and analyze API requests and responses."""
    # You can log or analyze the request here
    logger.info(f"Request path: {request.url.path}")
    
    # Continue processing the request
    response = await call_next(request)
    
    # You can log or analyze the response here
    logger.info(f"Response status code: {response.status_code}")
    
    return response



@app.post("/api/intercept", status_code=status.HTTP_200_OK)
async def intercept_request(request: Request):
    """
    Endpoint to receive intercepted API traffic from external sources.
    This could be used with a proxy or agent that forwards traffic.
    """
    body = await request.json()
    # Process the intercepted request (to be implemented)
    logger.info(f"Intercepted request: {body}")
    
    # Here you would use your interceptor component
    # result = await APIInterceptor.process(body)
    
    return {"status": "received"}


@app.get("/api/analytics/summary")
async def get_analytics_summary():
    """Provide a summary of API analytics."""
    # This would be connected to your database/analytics system
    return {
        "total_requests": 0,
        "average_response_time": 0,
        "error_rate": 0,
        "top_endpoints": []
    }


def run():
    """Run the application using uvicorn server."""
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    
    logger.info(f"Starting API Sentinel server on {host}:{port}")
    uvicorn.run(
        "scrutiny_api_sentinel.main:app",
        host=host,
        port=port,
        reload=bool(os.getenv("DEBUG", "False").lower() == "true")
    )


if __name__ == "__main__":
    # This allows running the app directly with python -m
    run()