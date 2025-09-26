#!/usr/bin/env python3
"""
SecAudit Demo Script
Demonstrates the capabilities of SecAudit with example targets
"""

import asyncio
import sys
import os
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from modules.web_scanner import WebSecurityScanner
from modules.threat_intel import ThreatIntelligenceEngine
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.cvss_calculator import CVSSCalculator
from modules.reporter import SecurityReporter
from utils.config import Config
from utils.logger import SecurityLogger

async def demo_web_security():
    """Demo web security scanning"""
    print("\n=== Web Security Analysis Demo ===")

    config = Config()
    scanner = WebSecurityScanner(config)

    # Safe demo targets (public sites that allow scanning)
    demo_targets = [
        "https://httpbin.org",
        "https://example.com"
    ]

    for target in demo_targets:
        print(f"\nScanning: {target}")
        try:
            result = await scanner.scan(target)

            print(f"Security Score: {result.get('security_score', 0)}/100")
            print(f"Missing Headers: {len(result.get('missing_headers', []))}")
            print(f"Vulnerabilities: {len(result.get('vulnerabilities', []))}")

        except Exception as e:
            print(f"Error scanning {target}: {e}")

async def demo_cvss_calculation():
    """Demo CVSS calculation"""
    print("\n=== CVSS Calculation Demo ===")

    calculator = CVSSCalculator()

    # Example vulnerability
    sample_vulnerability = {
        'type': 'SQL Injection',
        'severity': 'CRITICAL',
        'description': 'SQL injection vulnerability in login form'
    }

    result = calculator.calculate_from_vulnerability(sample_vulnerability)

    print(f"Vulnerability: {sample_vulnerability['type']}")
    print(f"CVSS Score: {result.get('base_score', 0)}")
    print(f"Severity: {result.get('severity', 'Unknown')}")
    print(f"Vector: {result.get('vector_string', 'N/A')}")

async def demo_threat_intelligence():
    """Demo threat intelligence"""
    print("\n=== Threat Intelligence Demo ===")

    config = Config()
    threat_engine = ThreatIntelligenceEngine(config)

    # Example domains (safe to query)
    demo_domains = ["example.com", "google.com"]

    for domain in demo_domains:
        print(f"\nAnalyzing: {domain}")
        try:
            result = await threat_engine.enrich(domain)

            print(f"Reputation: {result.get('reputation', 'Unknown')}")
            print(f"Risk Score: {result.get('risk_score', 0):.1f}/10")
            print(f"Sources Queried: {len(result.get('threat_sources', {}))}")

        except Exception as e:
            print(f"Error analyzing {domain}: {e}")

def demo_reporting():
    """Demo report generation"""
    print("\n=== Report Generation Demo ===")

    # Sample results data
    sample_results = {
        'scan_info': {
            'timestamp': '2024-01-01T12:00:00',
            'version': '1.0.0',
            'target': 'demo.example.com'
        },
        'vulnerabilities': [
            {
                'type': 'Information Disclosure',
                'severity': 'LOW',
                'target': 'https://demo.example.com',
                'description': 'Server header reveals version information',
                'recommendation': 'Configure server to hide version information',
                'timestamp': '2024-01-01T12:00:00'
            }
        ],
        'risk_assessment': {
            'overall_score': 25.5,
            'risk_level': 'MEDIUM',
            'risk_factors': [
                {
                    'category': 'Web Security',
                    'description': 'Missing security headers detected'
                }
            ]
        },
        'recommendations': [
            {
                'category': 'Web Security',
                'priority': 'Medium',
                'title': 'Implement security headers',
                'description': 'Add missing HTTP security headers'
            }
        ]
    }

    config = Config()
    reporter = SecurityReporter(config)

    # Generate demo reports
    import tempfile
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            report_path = asyncio.run(
                reporter.generate_report(sample_results, 'executive', temp_dir)
            )
            print(f"Demo report generated: {report_path}")

            # Show file size
            if report_path and os.path.exists(report_path):
                size = os.path.getsize(report_path)
                print(f"Report size: {size:,} bytes")

        except Exception as e:
            print(f"Error generating demo report: {e}")

async def main():
    """Main demo function"""
    print("SecAudit - Comprehensive Security Assessment Platform")
    print("=" * 60)
    print("Demo Mode - Showcasing SecAudit Capabilities")
    print("=" * 60)

    try:
        # Run demos
        await demo_web_security()
        await demo_cvss_calculation()
        await demo_threat_intelligence()
        demo_reporting()

        print("\n" + "=" * 60)
        print("Demo completed successfully!")
        print("\nTo run a real assessment:")
        print("python secaudit.py <target-domain>")
        print("\nFor help:")
        print("python secaudit.py --help")

    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")
    except Exception as e:
        print(f"\n\nDemo error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
