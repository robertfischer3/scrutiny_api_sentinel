class WebhookScanner(Scanner):
    """Scanner that processes webhook data sent from API services."""
    
    async def process_webhook(self, data: Dict[str, Any]) -> ScanResult:
        """Process webhook data containing API usage information."""
        logger.info(f"Processing webhook data: {len(data)} entries")
        
        # Convert webhook data to APILogEntry objects
        entries = []
        
        for item in data.get("entries", []):
            try:
                entry = APILogEntry(
                    timestamp=datetime.fromisoformat(item.get("timestamp", datetime.now().isoformat())),
                    method=item.get("method", "UNKNOWN"),
                    path=item.get("path", "/"),
                    status_code=item.get("status_code", 0),
                    duration_ms=item.get("duration_ms"),
                    client_ip=item.get("client_ip"),
                    request_id=item.get("request_id"),
                    custom_metadata=item.get("metadata")
                )
                entries.append(entry)
            except Exception as e:
                logger.error(f"Error processing webhook entry: {str(e)}")
        
        return await self.process_entries(entries)