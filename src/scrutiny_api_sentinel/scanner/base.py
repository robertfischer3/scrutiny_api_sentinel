"""
Base Scanner Module

This module defines the base Scanner class that all scanner implementations extend.
It provides common functionality for analyzing API traffic data regardless of source.
"""

import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any, Union

from .models import APILogEntry, ScanResult

logger = logging.getLogger("api-sentinel.scanner")

class Scanner:
    """Base scanner class for API traffic analysis."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the scanner with configuration options.
        
        Args:
            config: Dictionary of configuration parameters
        """
        self.config = config or {}
        self.rules = self.load_rules()
        logger.info(f"Initialized {self.__class__.__name__} with config: {self.config}")
        
    def load_rules(self) -> Dict[str, Any]:
        """
        Load analysis rules from configuration.
        
        Returns:
            Dictionary of rules for detection and analysis
        """
        # In a real implementation, this would load from a database or file
        return {
            "performance": {
                "slow_threshold_ms": self.config.get("slow_threshold_ms", 500),
            },
            "security": {
                "suspicious_patterns": [
                    "..%2F",  # Path traversal
                    "SELECT.*FROM",  # SQL injection attempts
                    "<script>",  # XSS attempts
                ],
                "rate_limits": {
                    "default": self.config.get("rate_limit_default", 100),  # requests per minute
                }
            }
        }
    
    async def analyze_entry(self, entry: APILogEntry) -> Dict[str, Any]:
        """
        Analyze a single API log entry for anomalies, performance issues, and security concerns.
        
        Args:
            entry: The API log entry to analyze
            
        Returns:
            Dictionary with analysis results
        """
        results = {
            "anomalies": [],
            "performance": [],
            "security": []
        }
        
        # Performance check
        if entry.duration_ms and entry.duration_ms > self.rules["performance"]["slow_threshold_ms"]:
            results["performance"].append({
                "type": "slow_response",
                "duration_ms": entry.duration_ms,
                "threshold_ms": self.rules["performance"]["slow_threshold_ms"]
            })
            
        # Security checks
        for pattern in self.rules["security"]["suspicious_patterns"]:
            if pattern in entry.path:
                results["security"].append({
                    "type": "suspicious_pattern",
                    "pattern": pattern,
                    "location": "path"
                })
            
            # Check request parameters if they exist
            if entry.request_params:
                for param, value in entry.request_params.items():
                    if isinstance(value, str) and pattern in value:
                        results["security"].append({
                            "type": "suspicious_pattern",
                            "pattern": pattern,
                            "location": f"request_param.{param}"
                        })
        
        # Extend with custom analyzers
        await self._run_custom_analyzers(entry, results)
        
        return results
    
    async def _run_custom_analyzers(self, entry: APILogEntry, results: Dict[str, List[Dict[str, Any]]]):
        """
        Run custom analyzers defined by subclasses.
        
        This method is meant to be overridden by subclasses to add custom analysis logic.
        
        Args:
            entry: The API log entry to analyze
            results: Dictionary to add analysis results to
        """
        pass
    
    async def process_entries(self, entries: List[APILogEntry], source_type: str, source_name: str) -> ScanResult:
        """
        Process multiple log entries and generate a scan result.
        
        Args:
            entries: List of API log entries to analyze
            source_type: The type of source (log, traffic, webhook)
            source_name: Name or identifier of the source
            
        Returns:
            ScanResult object with analysis results
        """
        if not entries:
            logger.warning(f"No entries to process for {source_type}:{source_name}")
            return ScanResult(
                scan_id=f"scan_{datetime.now().strftime('%Y%m%d%H%M%S')}",
                timestamp=datetime.now(),
                source_type=source_type,
                source_name=source_name,
                entries_processed=0,
                anomalies_detected=0,
                performance_issues=0,
                security_concerns=0,
                summary={"error": "No entries to process"}
            )
        
        # Process each entry
        logger.info(f"Processing {len(entries)} entries from {source_type}:{source_name}")
        analysis_tasks = [self.analyze_entry(entry) for entry in entries]
        analysis_results = await asyncio.gather(*analysis_tasks)
        
        # Aggregate results
        anomalies = 0
        performance_issues = 0
        security_concerns = 0
        
        for result in analysis_results:
            if result["anomalies"]:
                anomalies += len(result["anomalies"])
            if result["performance"]:
                performance_issues += len(result["performance"])
            if result["security"]:
                security_concerns += len(result["security"])
                
        # Generate summary statistics
        methods = {}
        paths = {}
        status_codes = {}
        avg_duration = 0
        total_duration = 0
        
        for entry in entries:
            methods[entry.method] = methods.get(entry.method, 0) + 1
            paths[entry.path] = paths.get(entry.path, 0) + 1
            
            if hasattr(entry, 'status_code') and entry.status_code:
                status_codes[entry.status_code] = status_codes.get(entry.status_code, 0) + 1
            
            if entry.duration_ms:
                total_duration += entry.duration_ms
        
        if entries:
            avg_duration = total_duration / len([e for e in entries if e.duration_ms])
            
        summary = {
            "methods": methods,
            "paths": paths,
            "status_codes": status_codes,
            "total_duration_ms": total_duration,
            "avg_duration_ms": avg_duration,
            "detailed_analysis": self._generate_detailed_analysis(entries, analysis_results)
        }
        
        # Generate scan result
        scan_result = ScanResult(
            scan_id=f"scan_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            timestamp=datetime.now(),
            source_type=source_type,
            source_name=source_name,
            entries_processed=len(entries),
            anomalies_detected=anomalies,
            performance_issues=performance_issues,
            security_concerns=security_concerns,
            summary=summary
        )
        
        logger.info(f"Completed analysis: {scan_result.entries_processed} entries, "
                   f"{scan_result.security_concerns} security issues, "
                   f"{scan_result.performance_issues} performance issues")
                   
        return scan_result
    
    def _generate_detailed_analysis(self, entries: List[APILogEntry], 
                                   analysis_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate detailed analysis summary from entries and analysis results.
        
        Args:
            entries: List of API log entries analyzed
            analysis_results: Corresponding analysis results for each entry
            
        Returns:
            Dictionary with detailed analysis information
        """
        # Implement more sophisticated analysis here
        # This is a simple example to get you started
        detailed = {
            "top_slow_endpoints": [],
            "security_issues_by_path": {},
            "error_rates": {}
        }
        
        # Find slowest endpoints
        if entries and any(e.duration_ms for e in entries):
            path_durations = {}
            path_counts = {}
            
            for entry in entries:
                if entry.duration_ms and entry.path:
                    path_durations[entry.path] = path_durations.get(entry.path, 0) + entry.duration_ms
                    path_counts[entry.path] = path_counts.get(entry.path, 0) + 1
            
            # Calculate average durations
            avg_durations = {
                path: path_durations[path] / path_counts[path]
                for path in path_durations
            }
            
            # Get top 5 slowest endpoints
            detailed["top_slow_endpoints"] = [
                {"path": path, "avg_duration_ms": duration}
                for path, duration in sorted(
                    avg_durations.items(), 
                    key=lambda x: x[1], 
                    reverse=True
                )[:5]
            ]
        
        # Collect security issues by path
        for entry, result in zip(entries, analysis_results):
            if result["security"] and entry.path:
                if entry.path not in detailed["security_issues_by_path"]:
                    detailed["security_issues_by_path"][entry.path] = []
                
                detailed["security_issues_by_path"][entry.path].extend(result["security"])
        
        return detailed