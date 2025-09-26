"""
Web Security Scanner Module
Analyzes HTTP security headers and common web vulnerabilities
"""

import asyncio
import aiohttp
import ssl
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Any, Optional
from datetime import datetime
import re

class WebSecurityScanner:
    """Comprehensive web security scanner"""

    SECURITY_HEADERS = {
        'Content-Security-Policy': {
            'importance': 'Critical',
            'description': 'Prevents XSS and data injection attacks',
            'recommendation': 'Implement a strict CSP policy'
        },
        'Strict-Transport-Security': {
            'importance': 'High',
            'description': 'Enforces HTTPS connections',
            'recommendation': 'Set HSTS with max-age of at least 31536000 seconds'
        },
        'X-Frame-Options': {
            'importance': 'High',
            'description': 'Prevents clickjacking attacks',
            'recommendation': 'Set to DENY or SAMEORIGIN'
        },
        'X-Content-Type-Options': {
            'importance': 'Medium',
            'description': 'Prevents MIME type sniffing',
            'recommendation': 'Set to nosniff'
        },
        'Referrer-Policy': {
            'importance': 'Medium',
            'description': 'Controls referrer information sent',
            'recommendation': 'Set to strict-origin-when-cross-origin'
        },
        'Permissions-Policy': {
            'importance': 'Medium',
            'description': 'Controls browser features',
            'recommendation': 'Define appropriate feature policies'
        },
        'X-XSS-Protection': {
            'importance': 'Low',
            'description': 'Legacy XSS protection (deprecated but still useful)',
            'recommendation': 'Set to 1; mode=block'
        }
    }

    def __init__(self, config):
        self.config = config
        self.session = None

    async def __aenter__(self):
        """Async context manager entry"""
        connector = aiohttp.TCPConnector(ssl=ssl.create_default_context())
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Perform comprehensive web security scan

        Args:
            target: URL or domain to scan

        Returns:
            Dictionary containing scan results
        """
        if not target.startswith(('http://', 'https://')):
            target = f'https://{target}'

        async with self:
            results = {
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'security_headers': {},
                'ssl_info': {},
                'server_info': {},
                'security_score': 0,
                'missing_headers': [],
                'vulnerabilities': [],
                'recommendations': []
            }

            try:
                # Analyze HTTP headers
                headers_result = await self._analyze_headers(target)
                results.update(headers_result)

                # Check SSL/TLS configuration
                ssl_result = await self._analyze_ssl(target)
                results['ssl_info'] = ssl_result

                # Basic vulnerability checks
                vuln_result = await self._check_basic_vulnerabilities(target)
                results['vulnerabilities'].extend(vuln_result)

                # Calculate security score
                results['security_score'] = self._calculate_security_score(results)

            except Exception as e:
                results['error'] = str(e)

            return results

    async def _analyze_headers(self, target: str) -> Dict[str, Any]:
        """Analyze HTTP security headers"""
        try:
            async with self.session.get(target, allow_redirects=True) as response:
                headers = dict(response.headers)

                security_headers = {}
                missing_headers = []

                for header_name, header_info in self.SECURITY_HEADERS.items():
                    header_key = header_name.lower()
                    found_header = None

                    # Check for header (case-insensitive)
                    for key, value in headers.items():
                        if key.lower() == header_key:
                            found_header = value
                            break

                    if found_header:
                        security_headers[header_name] = {
                            'value': found_header,
                            'status': 'Present',
                            'analysis': self._analyze_header_value(header_name, found_header)
                        }
                    else:
                        missing_headers.append(header_name)
                        security_headers[header_name] = {
                            'value': None,
                            'status': 'Missing',
                            'importance': header_info['importance'],
                            'recommendation': header_info['recommendation']
                        }

                return {
                    'security_headers': security_headers,
                    'missing_headers': missing_headers,
                    'server_info': {
                        'server': headers.get('server', 'Unknown'),
                        'powered_by': headers.get('x-powered-by', 'Unknown'),
                        'status_code': response.status
                    }
                }

        except Exception as e:
            return {'error': f'Header analysis failed: {str(e)}'}

    def _analyze_header_value(self, header_name: str, value: str) -> Dict[str, Any]:
        """Analyze specific security header values"""
        analysis = {'score': 0, 'issues': [], 'recommendations': []}

        if header_name == 'Content-Security-Policy':
            # Basic CSP analysis
            if 'unsafe-inline' in value:
                analysis['issues'].append("Contains 'unsafe-inline' directive")
                analysis['score'] -= 20
            if 'unsafe-eval' in value:
                analysis['issues'].append("Contains 'unsafe-eval' directive")  
                analysis['score'] -= 20
            if '*' in value and 'script-src' in value:
                analysis['issues'].append("Wildcard (*) in script-src is dangerous")
                analysis['score'] -= 30
            analysis['score'] = max(0, 100 + analysis['score'])

        elif header_name == 'Strict-Transport-Security':
            # HSTS analysis
            max_age_match = re.search(r'max-age=(\d+)', value)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 31536000:  # 1 year
                    analysis['issues'].append(f"max-age ({max_age}) is less than 1 year")
                    analysis['score'] = 70
                else:
                    analysis['score'] = 100
            else:
                analysis['issues'].append("max-age directive missing")
                analysis['score'] = 50

        elif header_name == 'X-Frame-Options':
            if value.upper() in ['DENY', 'SAMEORIGIN']:
                analysis['score'] = 100
            else:
                analysis['issues'].append(f"Value '{value}' may not provide adequate protection")
                analysis['score'] = 70

        else:
            # Default scoring for other headers
            analysis['score'] = 80

        return analysis

    async def _analyze_ssl(self, target: str) -> Dict[str, Any]:
        """Analyze SSL/TLS configuration"""
        try:
            parsed_url = urlparse(target)
            if parsed_url.scheme != 'https':
                return {'error': 'Target is not HTTPS', 'score': 0}

            # Basic SSL check through connection
            async with self.session.get(target) as response:
                ssl_info = {
                    'https_enabled': True,
                    'score': 80,  # Basic score for HTTPS
                    'recommendations': []
                }

                # Check for HSTS
                hsts = response.headers.get('strict-transport-security')
                if hsts:
                    ssl_info['hsts_enabled'] = True
                    ssl_info['score'] += 20
                else:
                    ssl_info['hsts_enabled'] = False
                    ssl_info['recommendations'].append('Enable HSTS header')

                return ssl_info

        except Exception as e:
            return {'error': f'SSL analysis failed: {str(e)}', 'score': 0}

    async def _check_basic_vulnerabilities(self, target: str) -> List[Dict[str, Any]]:
        """Check for basic web vulnerabilities"""
        vulnerabilities = []

        try:
            # Check for server information disclosure
            async with self.session.get(target) as response:
                headers = dict(response.headers)

                # Server header disclosure
                server_header = headers.get('server', '')
                if server_header and any(keyword in server_header.lower() 
                                       for keyword in ['apache/', 'nginx/', 'iis/', 'version']):
                    vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'severity': 'LOW',
                        'description': f'Server header reveals software version: {server_header}',
                        'recommendation': 'Configure server to hide version information'
                    })

                # X-Powered-By header disclosure  
                powered_by = headers.get('x-powered-by', '')
                if powered_by:
                    vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'severity': 'LOW', 
                        'description': f'X-Powered-By header reveals technology: {powered_by}',
                        'recommendation': 'Remove or configure X-Powered-By header'
                    })

                # Check for directory listing
                test_paths = ['/admin/', '/backup/', '/test/', '/dev/']
                for path in test_paths:
                    test_url = urljoin(target, path)
                    try:
                        async with self.session.get(test_url) as test_response:
                            if test_response.status == 200:
                                content = await test_response.text()
                                if 'index of' in content.lower():
                                    vulnerabilities.append({
                                        'type': 'Directory Listing',
                                        'severity': 'MEDIUM',
                                        'description': f'Directory listing enabled at {path}',
                                        'recommendation': 'Disable directory listing on web server'
                                    })
                    except:
                        pass  # Ignore connection errors for test paths

        except Exception as e:
            vulnerabilities.append({
                'type': 'Scan Error',
                'severity': 'INFO',
                'description': f'Could not complete vulnerability scan: {str(e)}',
                'recommendation': 'Manual verification may be required'
            })

        return vulnerabilities

    def _calculate_security_score(self, results: Dict[str, Any]) -> int:
        """Calculate overall security score (0-100)"""
        score = 0
        max_score = 100

        # Security headers scoring (60% weight)
        headers_score = 0
        headers_count = len(self.SECURITY_HEADERS)

        for header_name, header_info in results.get('security_headers', {}).items():
            if header_info.get('status') == 'Present':
                # Get analysis score if available
                analysis = header_info.get('analysis', {})
                header_score = analysis.get('score', 80)  # Default 80 if present

                # Weight by importance
                importance = self.SECURITY_HEADERS[header_name]['importance']
                if importance == 'Critical':
                    weight = 1.5
                elif importance == 'High':
                    weight = 1.2
                elif importance == 'Medium':
                    weight = 1.0
                else:  # Low
                    weight = 0.8

                headers_score += (header_score * weight) / headers_count

        score += (headers_score * 0.6)

        # SSL/TLS scoring (25% weight)
        ssl_score = results.get('ssl_info', {}).get('score', 0)
        score += (ssl_score * 0.25)

        # Vulnerability penalty (15% weight)
        vulnerabilities = results.get('vulnerabilities', [])
        vuln_penalty = 0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            if severity == 'CRITICAL':
                vuln_penalty += 30
            elif severity == 'HIGH':
                vuln_penalty += 20
            elif severity == 'MEDIUM':
                vuln_penalty += 10
            elif severity == 'LOW':
                vuln_penalty += 5

        score -= (vuln_penalty * 0.15)

        return max(0, min(100, int(score)))
