import logging
import json
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Union, Any
from pathlib import Path

import pandas as pd
from pydantic import BaseModel, Field

logger = logging.getLogger("api-sentinel.scanner")

class APILogEntry(BaseModel):
    """Model representing a single API log entry."""
    timestamp: datetime
    method: str
    path: str
    status_code: int
    request_size: Optional[int] = None
    response_size: Optional[int] = None
    duration_ms: Optional[float] = None
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    response_type: Optional[str] = None
    auth_method: Optional[str] = None
    user_id: Optional[str] = None
    custom_metadata: Optional[Dict[str, Any]] = None

class ScanResult(BaseModel):
    """Results from a scanning operation."""
    scan_id: str
    timestamp: datetime
    source_type: str  # "log", "traffic", "webhook"
    source_name: str
    entries_processed: int
    anomalies_detected: int
    performance_issues: int
    security_concerns: int
    summary: Dict[str, Any]    