"""
Security Reporter Module
Generates comprehensive security assessment reports in multiple formats
"""

import json
import csv
from datetime import datetime
from typing import Dict, List, Any, Optional
import os
from pathlib import Path

class SecurityReporter:
    """Comprehensive security report generator"""

    def __init__(self, config):
        self.config = config
        self.report_templates = {
            'executive': self._generate_executive_summary,
            'technical': self._generate_technical_report,
            'json': self._generate_json_report,
            'csv': self._generate_csv_report
        }

    async def generate_report(self, results: Dict[str, Any], 
                            format_type: str = 'all',
                            output_dir: str = 'reports') -> str:
        """
        Generate comprehensive security assessment report

        Args:
            results: Security assessment results
            format_type: Type of report ('executive', 'technical', 'json', 'csv', 'all')
            output_dir: Output directory for reports

        Returns:
            Path to generated report(s)
        """
        # Create output directory
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        target_name = self._sanitize_filename(results['scan_info']['target'])
        base_filename = f'secaudit_{target_name}_{timestamp}'

        generated_files = []

        if format_type == 'all':
            formats = ['executive', 'technical', 'json', 'csv']
        else:
            formats = [format_type]

        for fmt in formats:
            if fmt in self.report_templates:
                filename = f'{base_filename}_{fmt}'
                filepath = self._generate_report_format(results, fmt, output_dir, filename)
                if filepath:
                    generated_files.append(filepath)

        return generated_files[0] if generated_files else None

    def _generate_report_format(self, results: Dict[str, Any], 
                               fmt: str, output_dir: str, filename: str) -> Optional[str]:
        """Generate report in specific format"""
        try:
            if fmt == 'json':
                filepath = os.path.join(output_dir, f'{filename}.json')
                with open(filepath, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
                return filepath

            elif fmt == 'csv':
                filepath = os.path.join(output_dir, f'{filename}.csv')
                self._generate_csv_report(results, filepath)
                return filepath

            else:
                # HTML reports for executive and technical
                filepath = os.path.join(output_dir, f'{filename}.html')
                html_content = self.report_templates[fmt](results)

                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                return filepath

        except Exception as e:
            print(f'Error generating {fmt} report: {e}')
            return None

    def _generate_executive_summary(self, results: Dict[str, Any]) -> str:
        """Generate executive summary report"""
        scan_info = results.get('scan_info', {})
        risk_assessment = results.get('risk_assessment', {})
        vulnerabilities = results.get('vulnerabilities', [])
        recommendations = results.get('recommendations', [])

        # Count vulnerabilities by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            if severity in severity_counts:
                severity_counts[severity] += 1

        risk_level = risk_assessment.get('risk_level', 'UNKNOWN')
        overall_score = risk_assessment.get('overall_score', 0)
        target_name = scan_info.get('target', 'Unknown Target')
        timestamp = scan_info.get('timestamp', datetime.now().isoformat())
        formatted_date = datetime.fromisoformat(timestamp).strftime('%B %d, %Y at %H:%M')

        # Create CSS styles
        css_styles = """
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }
        .header h1 { margin: 0; font-size: 2.5em; font-weight: 300; }
        .header .subtitle { margin-top: 10px; opacity: 0.9; font-size: 1.1em; }
        .content { padding: 30px; }
        .risk-overview { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .risk-card { padding: 20px; border-radius: 8px; text-align: center; }
        .risk-critical { background: #fee; border-left: 4px solid #dc3545; }
        .risk-high { background: #fff3cd; border-left: 4px solid #fd7e14; }
        .risk-medium { background: #d4edda; border-left: 4px solid #28a745; }
        .risk-low { background: #d1ecf1; border-left: 4px solid #17a2b8; }
        .risk-number { font-size: 2.5em; font-weight: bold; margin-bottom: 10px; }
        .risk-label { color: #666; text-transform: uppercase; font-size: 0.9em; letter-spacing: 1px; }
        .section { margin-bottom: 30px; }
        .section h2 { color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
        .vuln-summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .vuln-count { background: #f8f9fa; padding: 15px; border-radius: 6px; text-align: center; border-left: 4px solid #6c757d; }
        .critical { border-left-color: #dc3545 !important; }
        .high { border-left-color: #fd7e14 !important; }
        .medium { border-left-color: #ffc107 !important; }
        .low { border-left-color: #28a745 !important; }
        .recommendations { background: #f8f9fa; padding: 20px; border-radius: 6px; }
        .recommendations ul { margin: 0; padding-left: 20px; }
        .recommendations li { margin-bottom: 10px; line-height: 1.6; }
        .footer { background: #f8f9fa; padding: 20px; text-align: center; color: #666; border-radius: 0 0 8px 8px; }
        .status-badge { display: inline-block; padding: 4px 12px; border-radius: 20px; color: white; font-weight: bold; font-size: 0.85em; }
        .status-critical { background: #dc3545; }
        .status-high { background: #fd7e14; }
        .status-medium { background: #ffc107; color: #333; }
        .status-low { background: #28a745; }
        """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecAudit Executive Summary - {target_name}</title>
    <style>{css_styles}</style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SecAudit Security Assessment</h1>
            <div class="subtitle">Executive Summary Report</div>
            <div style="margin-top: 20px;">
                <strong>Target:</strong> {target_name}<br>
                <strong>Assessment Date:</strong> {formatted_date}
            </div>
        </div>

        <div class="content">
            <div class="section">
                <h2>Risk Assessment Overview</h2>
                <div class="risk-overview">
                    <div class="risk-card risk-{risk_level.lower()}">
                        <div class="risk-number">{overall_score:.1f}</div>
                        <div class="risk-label">Overall Risk Score</div>
                        <div class="status-badge status-{risk_level.lower()}">{risk_level}</div>
                    </div>
                    <div class="risk-card">
                        <div class="risk-number">{len(vulnerabilities)}</div>
                        <div class="risk-label">Total Issues Found</div>
                    </div>
                    <div class="risk-card">
                        <div class="risk-number">{severity_counts['CRITICAL'] + severity_counts['HIGH']}</div>
                        <div class="risk-label">High Priority Issues</div>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2>Vulnerability Summary</h2>
                <div class="vuln-summary">
                    <div class="vuln-count critical">
                        <div style="font-size: 1.8em; font-weight: bold; color: #dc3545;">{severity_counts['CRITICAL']}</div>
                        <div>Critical</div>
                    </div>
                    <div class="vuln-count high">
                        <div style="font-size: 1.8em; font-weight: bold; color: #fd7e14;">{severity_counts['HIGH']}</div>
                        <div>High</div>
                    </div>
                    <div class="vuln-count medium">
                        <div style="font-size: 1.8em; font-weight: bold; color: #ffc107;">{severity_counts['MEDIUM']}</div>
                        <div>Medium</div>
                    </div>
                    <div class="vuln-count low">
                        <div style="font-size: 1.8em; font-weight: bold; color: #28a745;">{severity_counts['LOW']}</div>
                        <div>Low</div>
                    </div>
                </div>
            </div>

            <div class="section">
                <h2>Key Findings</h2>
                <div class="recommendations">
                    <h3>Critical Actions Required:</h3>
                    <ul>"""

        # Add top recommendations
        priority_recommendations = [rec for rec in recommendations if rec.get('priority') in ['Critical', 'High']][:5]
        for rec in priority_recommendations:
            title = rec.get('title', 'Unknown')
            description = rec.get('description', '')
            html_content += f'<li><strong>{title}:</strong> {description}</li>\n'

        if not priority_recommendations:
            html_content += '<li>No critical actions required at this time.</li>\n'

        html_content += """</ul>
                </div>
            </div>

            <div class="section">
                <h2>Risk Factors</h2>
                <ul>"""

        # Add risk factors
        risk_factors = risk_assessment.get('risk_factors', [])
        for factor in risk_factors[:5]:  # Top 5 risk factors
            category = factor.get('category', 'Unknown')
            description = factor.get('description', '')
            html_content += f'<li><strong>{category}:</strong> {description}</li>\n'

        if not risk_factors:
            html_content += '<li>No significant risk factors identified.</li>\n'

        html_content += """</ul>
            </div>
        </div>

        <div class="footer">
            <p>Generated by SecAudit v1.0 - Comprehensive Security Assessment Platform</p>
            <p>For technical details and remediation guidance, refer to the detailed technical report.</p>
        </div>
    </div>
</body>
</html>"""

        return html_content

    def _generate_technical_report(self, results: Dict[str, Any]) -> str:
        """Generate detailed technical report"""
        return "<html><body><h1>Technical Report</h1><p>Detailed technical analysis would be here...</p></body></html>"

    def _generate_csv_report(self, results: Dict[str, Any], filepath: str):
        """Generate CSV report of vulnerabilities"""
        vulnerabilities = results.get('vulnerabilities', [])

        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Type', 'Severity', 'Target', 'Description', 'Recommendation', 'CWE', 'Timestamp']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for vuln in vulnerabilities:
                writer.writerow({
                    'Type': vuln.get('type', ''),
                    'Severity': vuln.get('severity', ''),
                    'Target': vuln.get('target', ''),
                    'Description': vuln.get('description', ''),
                    'Recommendation': vuln.get('recommendation', ''),
                    'CWE': vuln.get('cwe', ''),
                    'Timestamp': vuln.get('timestamp', '')
                })

    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for safe file system usage"""
        import re
        # Remove or replace problematic characters
        filename = re.sub(r'[<>:"/\|?*]', '_', filename)
        filename = re.sub(r'^https?://', '', filename)
        filename = re.sub(r'[./]+', '_', filename)
        return filename[:50]  # Limit length
