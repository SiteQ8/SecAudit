"""
CVSS Calculator Module
Calculates CVSS scores for vulnerability risk assessment
"""

from typing import Dict, Any, Optional
from datetime import datetime
import json

class CVSSCalculator:
    """CVSS v3.1 calculator for vulnerability scoring"""

    def __init__(self):
        # CVSS v3.1 scoring tables
        self.base_scores = {
            'attack_vector': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
            'attack_complexity': {'L': 0.77, 'H': 0.44},
            'privileges_required': {
                'N': {'unchanged': 0.85, 'changed': 0.85},
                'L': {'unchanged': 0.62, 'changed': 0.68},
                'H': {'unchanged': 0.27, 'changed': 0.50}
            },
            'user_interaction': {'N': 0.85, 'R': 0.62},
            'scope': {'U': 'unchanged', 'C': 'changed'},
            'confidentiality': {'N': 0.0, 'L': 0.22, 'H': 0.56},
            'integrity': {'N': 0.0, 'L': 0.22, 'H': 0.56},
            'availability': {'N': 0.0, 'L': 0.22, 'H': 0.56}
        }

        # Severity ratings
        self.severity_ratings = {
            (0.0, 0.0): 'None',
            (0.1, 3.9): 'Low',
            (4.0, 6.9): 'Medium',
            (7.0, 8.9): 'High',
            (9.0, 10.0): 'Critical'
        }

    def calculate_base_score(self, 
                           attack_vector: str,
                           attack_complexity: str,
                           privileges_required: str,
                           user_interaction: str,
                           scope: str,
                           confidentiality: str,
                           integrity: str,
                           availability: str) -> Dict[str, Any]:
        """
        Calculate CVSS v3.1 base score

        Args:
            attack_vector: N(etwork)/A(djacent)/L(ocal)/P(hysical)
            attack_complexity: L(ow)/H(igh)
            privileges_required: N(one)/L(ow)/H(igh)
            user_interaction: N(one)/R(equired)
            scope: U(nchanged)/C(hanged)
            confidentiality: N(one)/L(ow)/H(igh)
            integrity: N(one)/L(ow)/H(igh)
            availability: N(one)/L(ow)/H(igh)

        Returns:
            Dictionary with score and details
        """
        try:
            # Get metric values
            av = self.base_scores['attack_vector'][attack_vector.upper()]
            ac = self.base_scores['attack_complexity'][attack_complexity.upper()]

            scope_val = self.base_scores['scope'][scope.upper()]
            pr = self.base_scores['privileges_required'][privileges_required.upper()][scope_val]

            ui = self.base_scores['user_interaction'][user_interaction.upper()]
            c = self.base_scores['confidentiality'][confidentiality.upper()]
            i = self.base_scores['integrity'][integrity.upper()]
            a = self.base_scores['availability'][availability.upper()]

            # Calculate exploitability
            exploitability = 8.22 * av * ac * pr * ui

            # Calculate impact
            iss_base = 1 - (1 - c) * (1 - i) * (1 - a)

            if scope.upper() == 'U':
                impact = 6.42 * iss_base
            else:  # Changed scope
                impact = 7.52 * (iss_base - 0.029) - 3.25 * pow(iss_base - 0.02, 15)

            # Calculate base score
            if impact <= 0:
                base_score = 0.0
            elif scope.upper() == 'U':
                base_score = min(10.0, exploitability + impact)
            else:
                base_score = min(10.0, 1.08 * (exploitability + impact))

            # Round up to nearest 0.1
            base_score = self._round_up(base_score)

            # Determine severity
            severity = self._get_severity(base_score)

            return {
                'base_score': base_score,
                'severity': severity,
                'exploitability': round(exploitability, 1),
                'impact': round(impact, 1),
                'vector_string': f'CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/PR:{privileges_required}/UI:{user_interaction}/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}',
                'calculated_at': datetime.now().isoformat()
            }

        except KeyError as e:
            return {'error': f'Invalid CVSS metric value: {e}'}
        except Exception as e:
            return {'error': f'CVSS calculation error: {e}'}

    def calculate_from_vulnerability(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate CVSS score from vulnerability data

        Args:
            vulnerability: Vulnerability dictionary with details

        Returns:
            CVSS calculation result
        """
        # Map vulnerability types to CVSS metrics
        vuln_type = vulnerability.get('type', '').lower()
        severity = vulnerability.get('severity', 'MEDIUM').upper()

        # Default values based on vulnerability type and severity
        if 'sql injection' in vuln_type or 'injection' in vuln_type:
            metrics = {
                'attack_vector': 'N',  # Network
                'attack_complexity': 'L',  # Low
                'privileges_required': 'N',  # None
                'user_interaction': 'N',  # None
                'scope': 'C',  # Changed (can access other systems)
                'confidentiality': 'H',  # High
                'integrity': 'H',  # High  
                'availability': 'H'  # High
            }
        elif 'xss' in vuln_type or 'cross-site' in vuln_type:
            metrics = {
                'attack_vector': 'N',
                'attack_complexity': 'L',
                'privileges_required': 'N',
                'user_interaction': 'R',  # Required
                'scope': 'C',
                'confidentiality': 'L',
                'integrity': 'L',
                'availability': 'N'
            }
        elif 'information disclosure' in vuln_type:
            metrics = {
                'attack_vector': 'N',
                'attack_complexity': 'L',
                'privileges_required': 'N',
                'user_interaction': 'N',
                'scope': 'U',  # Unchanged
                'confidentiality': 'L' if severity in ['LOW', 'MEDIUM'] else 'H',
                'integrity': 'N',
                'availability': 'N'
            }
        elif 'path' in vuln_type or 'directory' in vuln_type:
            metrics = {
                'attack_vector': 'N',
                'attack_complexity': 'L',
                'privileges_required': 'N',
                'user_interaction': 'N',
                'scope': 'U',
                'confidentiality': 'L',
                'integrity': 'N',
                'availability': 'N'
            }
        elif 'configuration' in vuln_type or 'header' in vuln_type:
            metrics = {
                'attack_vector': 'N',
                'attack_complexity': 'L',
                'privileges_required': 'N',
                'user_interaction': 'N',
                'scope': 'U',
                'confidentiality': 'L',
                'integrity': 'L',
                'availability': 'N'
            }
        else:
            # Default for unknown vulnerability types
            metrics = {
                'attack_vector': 'N',
                'attack_complexity': 'L',
                'privileges_required': 'L',
                'user_interaction': 'N',
                'scope': 'U',
                'confidentiality': 'L',
                'integrity': 'L',
                'availability': 'L'
            }

        # Adjust based on severity
        if severity == 'CRITICAL':
            metrics['confidentiality'] = 'H'
            metrics['integrity'] = 'H'
            metrics['availability'] = 'H'
            metrics['scope'] = 'C'
        elif severity == 'HIGH':
            metrics['confidentiality'] = 'H'
            metrics['integrity'] = 'H'
        elif severity == 'LOW':
            metrics['confidentiality'] = 'L'
            metrics['integrity'] = 'L'
            metrics['availability'] = 'L'

        return self.calculate_base_score(**metrics)

    def _round_up(self, score: float) -> float:
        """Round score up to nearest 0.1"""
        import math
        return math.ceil(score * 10) / 10

    def _get_severity(self, score: float) -> str:
        """Get severity rating for score"""
        for (min_score, max_score), severity in self.severity_ratings.items():
            if min_score <= score <= max_score:
                return severity
        return 'Unknown'

    def generate_cvss_report(self, vulnerabilities: list) -> Dict[str, Any]:
        """
        Generate CVSS report for multiple vulnerabilities

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            CVSS analysis report
        """
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_vulnerabilities': len(vulnerabilities),
            'cvss_scores': [],
            'severity_distribution': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'None': 0},
            'average_score': 0.0,
            'highest_score': 0.0,
            'risk_summary': ''
        }

        total_score = 0.0

        for vuln in vulnerabilities:
            cvss_result = self.calculate_from_vulnerability(vuln)

            if 'error' not in cvss_result:
                score = cvss_result['base_score']
                severity = cvss_result['severity']

                # Add to report
                report['cvss_scores'].append({
                    'vulnerability': vuln.get('type', 'Unknown'),
                    'cvss_score': score,
                    'severity': severity,
                    'vector': cvss_result['vector_string'],
                    'target': vuln.get('target', 'Unknown')
                })

                # Update statistics
                report['severity_distribution'][severity] += 1
                total_score += score
                report['highest_score'] = max(report['highest_score'], score)

        # Calculate averages and summary
        if len(vulnerabilities) > 0:
            report['average_score'] = round(total_score / len(vulnerabilities), 1)

        # Generate risk summary
        critical_count = report['severity_distribution']['Critical']
        high_count = report['severity_distribution']['High']

        if critical_count > 0:
            report['risk_summary'] = f'CRITICAL: {critical_count} critical vulnerabilities requiring immediate attention'
        elif high_count > 0:
            report['risk_summary'] = f'HIGH: {high_count} high-severity vulnerabilities need prompt remediation'
        elif report['average_score'] > 4.0:
            report['risk_summary'] = 'MEDIUM: Multiple medium-severity issues identified'
        else:
            report['risk_summary'] = 'LOW: Low-impact vulnerabilities identified'

        return report
