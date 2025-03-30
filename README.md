# SpringActuator Scanner

A high-performance, multi-threaded scanner for detecting exposed Spring Boot Actuator endpoints. This tool helps security professionals identify potentially vulnerable management interfaces that could expose sensitive application data or functionality.

![Python 3.7+](https://img.shields.io/badge/Python-3.7+-blue)
![License MIT](https://img.shields.io/badge/License-MIT-green)

## Features

- **Fast Concurrent Scanning**: Utilizes multi-threading to scan endpoints simultaneously
- **Multiple API Structure Detection**: Automatically detects different Spring Boot API patterns
- **Comprehensive Endpoint Coverage**: Includes common actuator endpoints across different Spring Boot versions
- **Custom Wordlist Support**: Add your own endpoints to test beyond the default list
- **Visual Progress Tracking**: Real-time progress bars show scan status
- **Clean Color-Coded Output**: Easy-to-read results highlighting discovered endpoints

## Why This Matters

Spring Boot Actuator endpoints can expose sensitive information about your application, including:

- Environment variables with potential credentials
- Application metrics and health data
- Logging configurations
- Bean definitions
- Thread dumps and heap dumps
- Configuration properties
- Administrative functions

When left exposed, these endpoints can be leveraged by attackers to gain detailed insights into your application or potentially execute code remotely.

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/springactuator-scanner.git
cd springactuator-scanner

# Install required dependencies
pip install -r requirements.txt
```

## Requirements

- Python 3.7+
- requests
- colorama
- tqdm
- concurrent.futures (standard library)

## Usage

Basic scan with default options:

```bash
python3 actuator_scan.py -u https://target-application.com
```

Scan with a custom wordlist:

```bash
python3 actuator_scan.py -u https://target-application.com -w wordlists/spring-paths.txt
```

Adjust thread count for performance:

```bash
python3 actuator_scan.py -u https://target-application.com -t 25
```

Comprehensive scan:

```bash
python3 actuator_scan.py -u https://target-application.com -w wordlists/spring-paths.txt -t 20
```

## Options

| Flag | Description |
|------|-------------|
| `-u, --url` | Target URL to scan (required) |
| `-w, --wordlist` | Path to wordlist for additional endpoints |
| `-t, --threads` | Number of concurrent threads (default: 10) |

## Default Endpoints Checked

The scanner checks for common Spring Boot actuator endpoints, including:

- /actuator/beans - Displays all Spring beans in the application
- /actuator/env - Exposes environment variables
- /actuator/health - Shows application health information
- /actuator/metrics - Exposes metrics data
- /actuator/mappings - Displays mapped URI paths
- /actuator/heapdump - Generates and returns a heap dump
- /actuator/threaddump - Performs a thread dump
- /actuator/logfile - Returns log contents
- /actuator/prometheus - Exposes metrics in Prometheus format
- ...and many more

## Example Output

```
Scanning https://example-spring-app.com for Spring Boot Actuator endpoints...
Checking API endpoints with 10 threads...
Found: https://example-spring-app.com/api/actuator/health
Found: https://example-spring-app.com/api/actuator/info
Found: https://example-spring-app.com/api/actuator/metrics
Found: https://example-spring-app.com/api/actuator/env

Found 4 vulnerable endpoint(s):
- https://example-spring-app.com/api/actuator/health
- https://example-spring-app.com/api/actuator/info
- https://example-spring-app.com/api/actuator/metrics
- https://example-spring-app.com/api/actuator/env
```

## Security Considerations

This tool should only be used for:
- Authorized security testing
- Validating your own applications
- Educational purposes

Unauthorized scanning may violate laws and terms of service.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and legitimate security testing purposes only. The authors are not responsible for any misuse or damage caused by this program. Always ensure you have explicit permission to scan the target systems. 
