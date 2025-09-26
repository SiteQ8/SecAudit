"""
Threat Intelligence Engine Module
Integrates with free threat intelligence feeds and APIs
"""

import asyncio
import aiohttp
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import hashlib
import re
from urllib.parse import urlparse

class ThreatIntelligenceEngine:
    """Threat Intelligence integration engine"""

    def __init__(self, config):
        self.config = config
        self.session = None
        self.cache = {}

        # Free threat intelligence sources
        self.sources = {
            'threatminer': {
                'domain_url': 'https://api.threatminer.org/v2/domain.php',
                'ip_url': 'https://api.threatminer.org/v2/host.php',
                'enabled': True,
                'rate_limit': 10  # requests per minute
            },
            'urlhaus': {
                'url': 'https://urlhaus-api.abuse.ch/v1/url/',
                'enabled': True,
                'rate_limit': 1000  # requests per day
            },
            'phishtank': {
                'url': 'http://checkurl.phishtank.com/checkurl/',
                'enabled': False,  # Requires API key
                'rate_limit': 500
            }
        }

    async def __aenter__(self):
        """Async context manager entry"""
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    async def enrich(self, target: str) -> Dict[str, Any]:
        """
        Enrich target with threat intelligence data

        Args:
            target: URL or domain to enrich

        Returns:
            Dictionary containing threat intelligence results
        """
        async with self:
            parsed_url = urlparse(target if target.startswith('http') else f'https://{target}')
            domain = parsed_url.netloc or parsed_url.path

            results = {
                'target': target,
                'domain': domain,
                'timestamp': datetime.now().isoformat(),
                'risk_score': 0.0,
                'threat_sources': {},
                'indicators': [],
                'reputation': 'UNKNOWN',
                'recommendations': []
            }

            try:
                # Query multiple threat intelligence sources
                tasks = []

                if self.sources['threatminer']['enabled']:
                    tasks.append(self._query_threatminer(domain))

                if self.sources['urlhaus']['enabled']:
                    tasks.append(self._query_urlhaus(target))

                # Execute all queries concurrently
                source_results = await asyncio.gather(*tasks, return_exceptions=True)

                # Process results from each source
                for i, result in enumerate(source_results):
                    if isinstance(result, Exception):
                        continue

                    source_name = list(self.sources.keys())[i]
                    if result:
                        results['threat_sources'][source_name] = result

                # Calculate overall risk score
                results['risk_score'] = self._calculate_risk_score(results)
                results['reputation'] = self._determine_reputation(results['risk_score'])
                results['recommendations'] = self._generate_recommendations(results)

            except Exception as e:
                results['error'] = str(e)

            return results

    async def _query_threatminer(self, domain: str) -> Optional[Dict[str, Any]]:
        """Query ThreatMiner API for domain intelligence"""
        try:
            # Domain information
            params = {
                'q': domain,
                'rt': '1'  # WHOIS data
            }

            async with self.session.get(
                self.sources['threatminer']['domain_url'],
                params=params
            ) as response:
                if response.status == 200:
                    data = await response.json()

                    if data.get('status_code') == '200' and data.get('results'):
                        return {
                            'source': 'ThreatMiner',
                            'status': 'found',
                            'data': data['results'],
                            'risk_indicators': self._parse_threatminer_data(data['results'])
                        }

            return {'source': 'ThreatMiner', 'status': 'not_found', 'data': None}

        except Exception as e:
            return {'source': 'ThreatMiner', 'status': 'error', 'error': str(e)}

    async def _query_urlhaus(self, url: str) -> Optional[Dict[str, Any]]:
        """Query URLhaus API for URL reputation"""
        try:
            data = {'url': url}

            async with self.session.post(
                self.sources['urlhaus']['url'],
                data=data
            ) as response:
                if response.status == 200:
                    result = await response.json()

                    if result.get('query_status') == 'ok':
                        return {
                            'source': 'URLhaus',
                            'status': 'found',
                            'data': result,
                            'risk_indicators': self._parse_urlhaus_data(result)
                        }
                    elif result.get('query_status') == 'no_results':
                        return {'source': 'URLhaus', 'status': 'clean', 'data': result}

            return {'source': 'URLhaus', 'status': 'not_found', 'data': None}

        except Exception as e:
            return {'source': 'URLhaus', 'status': 'error', 'error': str(e)}

    def _parse_threatminer_data(self, data: List[Dict]) -> List[Dict[str, Any]]:
        """Parse ThreatMiner results for risk indicators"""
        indicators = []

        for item in data:
            if isinstance(item, dict):
                # Check for suspicious patterns in WHOIS data
                whois_data = str(item).lower()

                suspicious_patterns = [
                    r'privacy.*protect',
                    r'domain.*proxy',
                    r'whois.*guard',
                    r'perfect.*privacy'
                ]

                for pattern in suspicious_patterns:
                    if re.search(pattern, whois_data):
                        indicators.append({
                            'type': 'Privacy Protection',
                            'severity': 'LOW',
                            'description': f'Domain uses privacy protection service',
                            'pattern_matched': pattern
                        })

                # Check registration date (newly registered domains can be suspicious)
                creation_date = item.get('creation_date', '')
                if creation_date:
                    try:
                        # Simple check for recently created domains
                        if '202' in creation_date:  # Rough check for recent years
                            indicators.append({
                                'type': 'Recent Registration',
                                'severity': 'MEDIUM',
                                'description': f'Domain recently registered: {creation_date}'
                            })
                    except:
                        pass

        return indicators

    def _parse_urlhaus_data(self, data: Dict) -> List[Dict[str, Any]]:
        """Parse URLhaus results for risk indicators"""
        indicators = []

        if data.get('query_status') == 'ok':
            indicators.append({
                'type': 'Malicious URL',
                'severity': 'CRITICAL',
                'description': 'URL found in URLhaus malware database',
                'threat_type': data.get('threat', 'Unknown'),
                'date_added': data.get('date_added', 'Unknown'),
                'tags': data.get('tags', [])
            })

        return indicators

    def _calculate_risk_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall risk score (0-10)"""
        score = 0.0

        # Process indicators from all sources
        for source_name, source_data in results.get('threat_sources', {}).items():
            if source_data.get('status') == 'found' and source_data.get('risk_indicators'):
                for indicator in source_data['risk_indicators']:
                    severity = indicator.get('severity', 'LOW')

                    if severity == 'CRITICAL':
                        score += 3.0
                    elif severity == 'HIGH':
                        score += 2.0
                    elif severity == 'MEDIUM':
                        score += 1.0
                    elif severity == 'LOW':
                        score += 0.5

        return min(10.0, score)

    def _determine_reputation(self, risk_score: float) -> str:
        """Determine reputation based on risk score"""
        if risk_score >= 7.0:
            return 'MALICIOUS'
        elif risk_score >= 5.0:
            return 'SUSPICIOUS'
        elif risk_score >= 2.0:
            return 'QUESTIONABLE'
        elif risk_score > 0.0:
            return 'LOW_RISK'
        else:
            return 'CLEAN'

    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on threat intelligence findings"""
        recommendations = []
        risk_score = results.get('risk_score', 0)
        reputation = results.get('reputation', 'UNKNOWN')

        if reputation in ['MALICIOUS', 'SUSPICIOUS']:
            recommendations.extend([
                'Block access to this domain/URL immediately',
                'Add to threat intelligence feeds and blocklists',
                'Monitor network traffic for communications with this indicator',
                'Investigate any recent connections to this resource'
            ])

        elif reputation == 'QUESTIONABLE':
            recommendations.extend([
                'Exercise caution when accessing this resource',
                'Implement additional monitoring for this domain',
                'Consider using web filtering or proxy solutions'
            ])

        elif reputation == 'LOW_RISK':
            recommendations.extend([
                'Continue standard monitoring procedures',
                'Periodic re-evaluation recommended'
            ])

        # Add specific recommendations based on indicators
        for source_data in results.get('threat_sources', {}).values():
            if source_data.get('risk_indicators'):
                for indicator in source_data['risk_indicators']:
                    if indicator.get('type') == 'Recent Registration':
                        recommendations.append('Verify legitimacy of recently registered domain')
                    elif indicator.get('type') == 'Privacy Protection':
                        recommendations.append('Additional verification recommended for privacy-protected domains')

        return list(set(recommendations))  # Remove duplicates
