class LogScanner(Scanner):
    """Scanner that processes API logs from files."""
    
    async def scan_file(self, file_path: Union[str, Path]) -> ScanResult:
        """Scan a log file and return analysis results."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")
            
        logger.info(f"Scanning log file: {file_path}")
        
        # In a real implementation, this would use proper log parsing
        # Here's a simple example assuming JSON logs, one per line
        entries = []
        
        with open(path, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    # Convert to our model (would need more mapping in reality)
                    entry = APILogEntry(
                        timestamp=datetime.fromisoformat(data.get("time", datetime.now().isoformat())),
                        method=data.get("method", "UNKNOWN"),
                        path=data.get("path", "/"),
                        status_code=data.get("status", 0),
                        duration_ms=data.get("duration_ms"),
                        client_ip=data.get("client_ip"),
                        request_id=data.get("request_id")
                    )
                    entries.append(entry)
                except json.JSONDecodeError:
                    logger.warning(f"Could not parse log line: {line[:100]}...")
                except Exception as e:
                    logger.error(f"Error processing log line: {str(e)}")
        
        return await self.process_entries(entries)
