# SecAudit - Comprehensive Security Assessment Platform

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-focused-red.svg)](https://github.com/SiteQ8/secaudit)

**SecAudit** is a comprehensive, open-source security assessment platform designed for cybersecurity professionals, penetration testers, and security researchers. It combines multiple security assessment vectors into a unified tool that provides actionable intelligence and detailed reporting.

## Features

### Multi-Vector Security Assessment
- **Web Security Analysis**: HTTP security headers, SSL/TLS configuration, server information
- **Vulnerability Scanning**: Basic vulnerability detection including XSS, SQL injection, information disclosure
- **Threat Intelligence Integration**: Real-time threat intelligence from multiple free sources
- **Risk Assessment**: CVSS-based vulnerability scoring and overall risk calculation

### Advanced Capabilities
- **Comprehensive Reporting**: Executive and technical reports in HTML, JSON, and CSV formats
- **Threat Intelligence Correlation**: Integration with ThreatMiner, URLhaus, and other free feeds
- **Automated Risk Scoring**: CVSS v3.1 calculations with intelligent severity assessment
- **Professional Output**: Color-coded terminal output and detailed logging

### Built for Cybersecurity Community
- **Free and Open Source**: No licensing fees or restrictions
- **Extensible Architecture**: Modular design for easy customization and extension
- **Industry Standards**: Follows OWASP, NIST, and other security frameworks
- **Community Driven**: Designed with input from cybersecurity professionals

## Requirements

- Python 3.8 or higher
- Internet connection (for threat intelligence feeds)
- Target websites/domains for assessment

## Installation

### Quick Install
```bash
# Clone the repository
git clone https://github.com/SiteQ8/secaudit.git
cd secaudit

# Install dependencies
pip install -r requirements.txt

# Make executable (Linux/Mac)
chmod +x secaudit.py
```

### Virtual Environment (Recommended)
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Linux/Mac:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

### Basic Usage
```bash
# Basic security assessment
python secaudit.py example.com

# Specific scan types
python secaudit.py example.com --scans web vuln threat

# Custom output directory
python secaudit.py example.com --output /path/to/reports
```

### Advanced Usage
```bash
# With custom configuration
python secaudit.py example.com --config custom_config.json

# Multiple targets (using shell scripting)
for target in $(cat targets.txt); do
    python secaudit.py $target --output reports/$target/
done
```

## Example Output

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                 SecAudit v1.0                                ║
║                    Comprehensive Security Assessment Platform                 ║
║                          Built for Cybersecurity Community                   ║
╚═══════════════════════════════════════════════════════════════════════════════╝

[INFO] Starting security assessment for: example.com

[SCAN] Running web security analysis...
[SCAN] Running vulnerability assessment...
[SCAN] Enriching with threat intelligence...
[SCAN] Calculating risk assessment...

[SUCCESS] Assessment completed!
[REPORT] Report saved to: reports/secaudit_example_com_20241226_143022_executive.html
```

## Scan Types

### Web Security (`web`)
- HTTP security headers analysis (CSP, HSTS, X-Frame-Options, etc.)
- SSL/TLS configuration assessment
- Server information disclosure checks
- Security configuration validation

### Vulnerability Assessment (`vuln`)
- Information disclosure vulnerabilities
- Sensitive file/directory exposure
- Basic injection vulnerability detection
- HTTP method testing
- Security misconfiguration identification

### Threat Intelligence (`threat`)
- ThreatMiner domain and IP analysis
- URLhaus malicious URL checking
- Real-time reputation scoring
- Indicator correlation and enrichment

### Risk Assessment (`risk`)
- CVSS v3.1 vulnerability scoring
- Overall risk calculation
- Priority-based recommendations
- Executive risk summaries

## Reports

SecAudit generates multiple report formats:

### Executive Summary
- High-level risk overview
- Vulnerability statistics
- Key findings and recommendations
- Business-focused language

### Technical Report
- Detailed vulnerability information
- Technical remediation guidance
- Evidence and proof of concepts
- CVSS scores and analysis

### Data Exports
- **JSON**: Machine-readable results for integration
- **CSV**: Vulnerability data for spreadsheet analysis

## Configuration

Create `secaudit.json` for custom configuration:

```json
{
  "general": {
    "timeout": 30,
    "max_redirects": 5
  },
  "scanning": {
    "max_concurrent_requests": 10,
    "delay_between_requests": 0.1
  },
  "threat_intelligence": {
    "enabled_sources": ["threatminer", "urlhaus"],
    "cache_ttl": 3600
  },
  "reporting": {
    "output_formats": ["html", "json", "csv"],
    "include_executive_summary": true
  }
}
```

## API Integration

SecAudit integrates with several free threat intelligence APIs:

- **ThreatMiner**: Domain and IP intelligence
- **URLhaus**: Malicious URL detection
- **MISP**: Threat intelligence platform integration (planned)

## Security Considerations

- **Ethical Use**: Only scan systems you own or have explicit permission to test
- **Rate Limiting**: Built-in delays to avoid overwhelming target systems  
- **No Damage**: Designed for reconnaissance, not exploitation
- **Privacy**: No data collection or external transmission of scan results

## Logging

SecAudit provides logging:

```
logs/
├── secaudit.log          # Main application logs
├── scanner.log           # Vulnerability scanning logs
└── threat_intel.log      # Threat intelligence logs
```

## Contributing

We welcome contributions from the cybersecurity community!

### How to Contribute
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Areas for Contribution
- Additional vulnerability checks
- New threat intelligence sources
- Report format improvements
- Performance optimizations
- Documentation enhancements

## Documentation

- [Installation Guide](docs/installation.md)
- [User Manual](docs/user-guide.md)
- [API Documentation](docs/api.md)
- [Developer Guide](docs/development.md)

## Testing

```bash
# Run basic tests
python -m pytest tests/

# Run specific test categories
python -m pytest tests/test_web_scanner.py
python -m pytest tests/test_threat_intel.py
```

## Supported Platforms

- **Linux**: Primary development platform
- **macOS**: Full compatibility
- **Windows**: Compatible with Windows 10/11

## Version History

- **v1.0.0**: Initial release with core functionality
- **v1.1.0**: Enhanced threat intelligence integration (planned)
- **v1.2.0**: Advanced vulnerability detection (planned)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **OWASP** for security testing methodologies
- **NIST** for cybersecurity frameworks
- **ThreatMiner** and **URLhaus** for free threat intelligence feeds
- The cybersecurity community for inspiration and feedback

## Support

- **Issues**: [GitHub Issues](https://github.com/SiteQ8/secaudit/issues)
- **Discussions**: [GitHub Discussions](https://github.com/SiteQ8/secaudit/discussions)
- **Email**: site@hotmail.com

## Disclaimer

SecAudit is intended for legal security testing and research purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems. The developers assume no liability for misuse of this tool.

---

**Built by cybersecurity professionals, for the cybersecurity community.**

*SecAudit - Making security assessment accessible, comprehensive, and actionable.*
