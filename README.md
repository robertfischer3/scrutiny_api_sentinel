# Scrutiny API Sentinel

A comprehensive API monitoring and security tool for analyzing API traffic, detecting anomalies, and providing insights on performance and security issues.

## Overview

Scrutiny API Sentinel is a powerful service designed to monitor, intercept, and analyze API traffic for security vulnerabilities, performance bottlenecks, and potential anomalies. The system can process data from multiple sources including:

- Live API traffic via proxy interception
- API logs from files
- Network traffic captures
- Webhook data from API services

## Features

- **API Traffic Monitoring**: Intercept and analyze API requests and responses in real-time
- **Security Analysis**: Detect suspicious patterns, injection attempts, and other security concerns
- **Performance Insights**: Identify slow endpoints and track response times
- **Anomaly Detection**: Discover unusual patterns or behaviors in API usage
- **Multiple Data Sources**: Process data from logs, network captures, or webhook events
- **REST API**: Expose analytics and monitoring capabilities through a RESTful API

## Installation

### Prerequisites

- Python 3.9 or higher
- Poetry (for dependency management)

### Setup

1. Clone the repository:

```bash
git clone https://github.com/your-username/scrutiny-api-sentinel.git
cd scrutiny-api-sentinel
```

2. Install dependencies with Poetry:

```bash
poetry install
```

3. Set up environment variables (optional):

```bash
cp .env.example .env
# Edit .env file with your configuration
```

## Usage

### Running the Server

Start the API Sentinel server with:

```bash
poetry run api-sentinel
```

Or directly with Python:

```bash
poetry run python -m scrutiny_api_sentinel.main
```

The server will start on port 8000 by default. You can configure the host and port using environment variables:

```bash
HOST=localhost PORT=9000 poetry run api-sentinel
```

### API Endpoints

- `GET /health` - Health check endpoint
- `POST /api/intercept` - Endpoint to receive intercepted API traffic
- `GET /api/analytics/summary` - Get a summary of API analytics

### Scanner Usage

The system includes several scanners for different data sources:

```python
from scrutiny_api_sentinel.scanner import get_scanner

# Create a log scanner
log_scanner = get_scanner("log", config={"slow_threshold_ms": 300})

# Scan a log file
scan_result = await log_scanner.scan_file("path/to/api/logs.json")

# Process webhook data
webhook_scanner = get_scanner("webhook")
result = await webhook_scanner.process_webhook(webhook_data)
```

## Configuration

Configuration can be provided via environment variables or a configuration file:

- `HOST` - Host to bind the server to (default: 0.0.0.0)
- `PORT` - Port to listen on (default: 8000)
- `DEBUG` - Enable debug mode (default: False)

See the `config` module for more configuration options.

## Development

### Running Tests

```bash
poetry run pytest
```

### Code Formatting

```bash
poetry run black .
poetry run isort .
```

### Type Checking

```bash
poetry run mypy src
```

## Project Structure

```
scrutiny-api-sentinel/
├── src/
│   └── scrutiny_api_sentinel/
│       ├── alert/            # Alert generation and notification
│       ├── analysis/         # Data analysis components
│       ├── api/              # API endpoints
│       ├── config/           # Configuration management
│       ├── proxy/            # Proxy for traffic interception
│       │   └── interceptor.py  # API traffic interceptor
│       ├── scanner/          # Scanners for different data sources
│       │   ├── base.py       # Base scanner class
│       │   ├── log_scanner.py  # Log file scanner
│       │   ├── models.py     # Data models for scanner
│       │   ├── traffic_scanner.py  # Network traffic scanner
│       │   ├── utils.py      # Scanner utilities
│       │   └── webhook_scanner.py  # Webhook data scanner
│       ├── storage/          # Data storage components
│       └── main.py           # Main application entry point
├── tests/                    # Test suite
├── pyproject.toml            # Project configuration
└── README.md                 # This file
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- FastAPI for the web framework
- scikit-learn for anomaly detection algorithms
- pandas and numpy for data processing
