#!/usr/bin/env python3
"""
SecAudit - Comprehensive Security Assessment Platform
A powerful cybersecurity tool for multi-vector security assessment
Author: Cybersecurity Community
Version: 1.0.0
"""

import sys
import argparse
import json
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any
import colorama
from colorama import Fore, Back, Style

# Import our custom modules
from modules.web_scanner import WebSecurityScanner
from modules.threat_intel import ThreatIntelligenceEngine
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.reporter import SecurityReporter
from modules.cvss_calculator import CVSSCalculator
from utils.logger import SecurityLogger
from utils.config import Config

class SecAudit:
    """
    Main SecAudit class that orchestrates all security assessment modules
    """

    def __init__(self, config_path: Optional[str] = None):
        """Initialize SecAudit with configuration"""
        colorama.init()
        self.config = Config(config_path)
        self.logger = SecurityLogger()
        self.results = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'version': '1.0.0',
                'target': None
            },
            'web_security': {},
            'vulnerabilities': [],
            'threat_intelligence': {},
            'risk_assessment': {},
            'recommendations': []
        }

    def print_banner(self):
        """Display SecAudit banner"""
        banner = f"""{Fore.CYAN}
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                 SecAudit v1.0                                ║
║                    Comprehensive Security Assessment Platform                 ║
║                          Built for Cybersecurity Community                   ║
╚═══════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
        print(banner)

    async def run_assessment(self, target: str, scan_types: List[str] = None):
        """
        Run comprehensive security assessment on target

        Args:
            target: URL or domain to assess
            scan_types: List of scan types to perform
        """
        self.results['scan_info']['target'] = target
        self.print_banner()

        print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Starting security assessment for: {Fore.YELLOW}{target}{Style.RESET_ALL}")

        if not scan_types:
            scan_types = ['web', 'vuln', 'threat', 'risk']

        # Initialize scanners
        web_scanner = WebSecurityScanner(self.config)
        vuln_scanner = VulnerabilityScanner(self.config) 
        threat_engine = ThreatIntelligenceEngine(self.config)
        cvss_calc = CVSSCalculator()

        # Run scans based on selected types
        if 'web' in scan_types:
            print(f"\n{Fore.CYAN}[SCAN]{Style.RESET_ALL} Running web security analysis...")
            self.results['web_security'] = await web_scanner.scan(target)

        if 'vuln' in scan_types:
            print(f"\n{Fore.CYAN}[SCAN]{Style.RESET_ALL} Running vulnerability assessment...")
            self.results['vulnerabilities'] = await vuln_scanner.scan(target)

        if 'threat' in scan_types:
            print(f"\n{Fore.CYAN}[SCAN]{Style.RESET_ALL} Enriching with threat intelligence...")
            self.results['threat_intelligence'] = await threat_engine.enrich(target)

        if 'risk' in scan_types:
            print(f"\n{Fore.CYAN}[SCAN]{Style.RESET_ALL} Calculating risk assessment...")
            self.results['risk_assessment'] = self.calculate_risk_score()

        # Generate recommendations
        self.results['recommendations'] = self.generate_recommendations()

        # Generate and save report
        reporter = SecurityReporter(self.config)
        report_path = await reporter.generate_report(self.results)

        print(f"\n{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Assessment completed!")
        print(f"{Fore.GREEN}[REPORT]{Style.RESET_ALL} Report saved to: {Fore.YELLOW}{report_path}{Style.RESET_ALL}")

        return self.results

    def calculate_risk_score(self) -> Dict[str, Any]:
        """Calculate overall risk score based on findings"""
        total_score = 0.0
        risk_factors = []

        # Web security risk factors
        if self.results.get('web_security'):
            web_score = self.results['web_security'].get('security_score', 0)
            if web_score < 70:
                risk_factors.append({
                    'category': 'Web Security Headers',
                    'score': web_score,
                    'impact': 'Medium',
                    'description': 'Missing or misconfigured security headers'
                })
                total_score += (100 - web_score) * 0.3

        # Vulnerability risk factors  
        if self.results.get('vulnerabilities'):
            high_vulns = len([v for v in self.results['vulnerabilities'] 
                            if v.get('severity') == 'HIGH'])
            critical_vulns = len([v for v in self.results['vulnerabilities'] 
                                if v.get('severity') == 'CRITICAL'])

            if critical_vulns > 0:
                risk_factors.append({
                    'category': 'Critical Vulnerabilities',
                    'count': critical_vulns,
                    'impact': 'Critical',
                    'description': f'{critical_vulns} critical vulnerabilities found'
                })
                total_score += critical_vulns * 25

            if high_vulns > 0:
                risk_factors.append({
                    'category': 'High Vulnerabilities', 
                    'count': high_vulns,
                    'impact': 'High',
                    'description': f'{high_vulns} high severity vulnerabilities found'
                })
                total_score += high_vulns * 15

        # Threat intelligence risk factors
        if self.results.get('threat_intelligence'):
            threat_score = self.results['threat_intelligence'].get('risk_score', 0)
            if threat_score > 5:
                risk_factors.append({
                    'category': 'Threat Intelligence',
                    'score': threat_score,
                    'impact': 'High' if threat_score > 7 else 'Medium',
                    'description': 'Target associated with suspicious activity'
                })
                total_score += threat_score * 10

        # Normalize score to 0-100
        final_score = min(100, max(0, total_score))

        risk_level = 'LOW'
        if final_score >= 70:
            risk_level = 'CRITICAL'
        elif final_score >= 50:
            risk_level = 'HIGH'
        elif final_score >= 30:
            risk_level = 'MEDIUM'

        return {
            'overall_score': round(final_score, 2),
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'calculated_at': datetime.now().isoformat()
        }

    def generate_recommendations(self) -> List[Dict[str, str]]:
        """Generate security recommendations based on findings"""
        recommendations = []

        # Web security recommendations
        if self.results.get('web_security'):
            missing_headers = self.results['web_security'].get('missing_headers', [])
            for header in missing_headers[:5]:  # Top 5 missing headers
                recommendations.append({
                    'category': 'Web Security',
                    'priority': 'High',
                    'title': f'Implement {header} header',
                    'description': f'Add {header} security header to protect against web vulnerabilities',
                    'remediation': 'Configure web server to include security headers in HTTP responses'
                })

        # Vulnerability recommendations
        critical_vulns = [v for v in self.results.get('vulnerabilities', []) 
                         if v.get('severity') == 'CRITICAL']
        for vuln in critical_vulns[:3]:  # Top 3 critical vulnerabilities
            recommendations.append({
                'category': 'Vulnerability Management',
                'priority': 'Critical',
                'title': f'Fix {vuln.get("type", "vulnerability")}',
                'description': vuln.get('description', 'Critical vulnerability found'),
                'remediation': vuln.get('solution', 'Apply security patches and updates')
            })

        # Threat intelligence recommendations
        if self.results.get('threat_intelligence', {}).get('risk_score', 0) > 5:
            recommendations.append({
                'category': 'Threat Intelligence',
                'priority': 'High',
                'title': 'Monitor for suspicious activity',
                'description': 'Target shows indicators of compromise or suspicious activity',
                'remediation': 'Implement enhanced monitoring and threat detection controls'
            })

        return recommendations

async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='SecAudit - Comprehensive Security Assessment Platform')
    parser.add_argument('target', help='Target URL or domain to assess')
    parser.add_argument('--scans', '-s', 
                       choices=['web', 'vuln', 'threat', 'risk'], 
                       nargs='+', 
                       default=['web', 'vuln', 'threat', 'risk'],
                       help='Scan types to perform')
    parser.add_argument('--config', '-c', help='Configuration file path')
    parser.add_argument('--output', '-o', help='Output directory for reports')

    args = parser.parse_args()

    try:
        audit = SecAudit(args.config)
        results = await audit.run_assessment(args.target, args.scans)
        return 0
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[INTERRUPTED]{Style.RESET_ALL} Assessment interrupted by user")
        return 1
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR]{Style.RESET_ALL} Assessment failed: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
