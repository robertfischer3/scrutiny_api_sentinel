from .base import Scanner
from .log_scanner import LogScanner
from .traffic_scanner import TrafficCaptureSanner
from .webhook_scanner import WebhookScanner
from .models import APILogEntry, ScanResult
from ..ml.ml_scanner import MLScanner 

def get_scanner(scanner_type: str, config: dict = None) -> Scanner:
    """Factory function to get the appropriate scanner based on the source type."""
    scanners = {
        "log": LogScanner,
        "traffic": TrafficCaptureSanner,
        "webhook": WebhookScanner,
        "ml": MLScanner,  
    }
    
    scanner_class = scanners.get(scanner_type)
    if not scanner_class:
        raise ValueError(f"Unknown scanner type: {scanner_type}")
        
    return scanner_class(config)

__all__ = [
    'Scanner', 'LogScanner', 'TrafficCaptureSanner', 'WebhookScanner', 'MLScanner', 
    'APILogEntry', 'ScanResult', 'get_scanner'
]