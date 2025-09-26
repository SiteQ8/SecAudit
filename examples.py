#!/usr/bin/env python3
"""
SecAudit Usage Examples
Comprehensive examples of how to use SecAudit for various security assessments
"""

import os

def print_header(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def print_example(title, description, command, notes=None):
    print(f"\n{title}")
    print("-" * len(title))
    print(f"Description: {description}")
    print(f"Command: {command}")
    if notes:
        print(f"Notes: {notes}")

def main():
    print("SecAudit - Usage Examples & Best Practices")

    print_header("Basic Usage Examples")

    print_example(
        "Simple Security Assessment",
        "Basic security scan of a website",
        "python3 secaudit.py example.com",
        "Performs all scan types: web, vuln, threat, risk"
    )

    print_example(
        "Web Security Headers Only",
        "Focus on HTTP security headers analysis",
        "python3 secaudit.py example.com --scans web",
        "Fastest scan option, good for quick header checks"
    )

    print_example(
        "Vulnerability Assessment",
        "Focus on vulnerability detection",
        "python3 secaudit.py example.com --scans vuln",
        "May take longer depending on target complexity"
    )

    print_example(
        "Threat Intelligence Enrichment",
        "Check domain/IP reputation",
        "python3 secaudit.py example.com --scans threat",
        "Queries multiple threat intelligence sources"
    )

    print_header("Advanced Usage Examples")

    print_example(
        "Custom Output Directory",
        "Save reports to specific location",
        "python3 secaudit.py example.com --output /path/to/reports",
        "Creates directory structure if it doesn't exist"
    )

    print_example(
        "Multiple Scan Types",
        "Run specific combination of scans",
        "python3 secaudit.py example.com --scans web vuln",
        "Space-separated list of scan types"
    )

    print_example(
        "Custom Configuration",
        "Use custom settings file",
        "python3 secaudit.py example.com --config my_config.json",
        "Override default settings for timeouts, sources, etc."
    )

    print_header("Batch Processing Examples")

    print("Multiple Targets from File:")
    print("-" * 30)
    print("# Create targets.txt with one domain per line")
    print("echo 'example.com' > targets.txt")
    print("echo 'google.com' >> targets.txt")
    print("")
    print("# Process all targets")
    print("for target in $(cat targets.txt); do")
    print("    python3 secaudit.py $target --output reports/$target/")
    print("done")

    print("\nSubdomain Scanning:")
    print("-" * 20)
    print("# Scan multiple subdomains")
    print("subdomains=('www' 'api' 'admin' 'dev')")
    print("for sub in \"${subdomains[@]}\"; do")
    print("    python3 secaudit.py \"$sub.example.com\" --output \"reports/$sub/\"")
    print("done")

    print_header("Report Generation Examples")

    print("\nGenerated Reports:")
    print("-" * 18)
    print("• Executive Summary (HTML) - Business-focused overview")
    print("• Technical Report (HTML) - Detailed technical findings") 
    print("• JSON Export - Machine-readable data")
    print("• CSV Export - Spreadsheet-compatible vulnerability list")

    print("\nReport Locations:")
    print("-" * 17)
    print("reports/")
    print("├── secaudit_example_com_20241226_143022_executive.html")
    print("├── secaudit_example_com_20241226_143022_technical.html")
    print("├── secaudit_example_com_20241226_143022_json.json")
    print("└── secaudit_example_com_20241226_143022_csv.csv")

    print_header("Integration Examples")

    print("\nCI/CD Pipeline Integration:")
    print("-" * 28)
    print("# Add to .github/workflows/security.yml")
    print("- name: Run Security Assessment")
    print("  run: |")
    print("    python3 secaudit.py ${{ secrets.TARGET_DOMAIN }}")
    print("    # Parse results and fail build if critical issues found")

    print("\nCron Job for Regular Scanning:")
    print("-" * 31)
    print("# Add to crontab for daily scanning")
    print("0 2 * * * cd /path/to/secaudit && python3 secaudit.py production.example.com")

    print_header("Configuration Examples")

    print("\nCustom Configuration (secaudit.json):")
    print("-" * 37)
    print('{')
    print('  "general": {')
    print('    "timeout": 60,')
    print('    "user_agent": "MyOrg Security Scanner"')
    print('  },')
    print('  "scanning": {')
    print('    "max_concurrent_requests": 5,')
    print('    "delay_between_requests": 0.5')
    print('  },')
    print('  "threat_intelligence": {')
    print('    "enabled_sources": ["threatminer"],')
    print('    "cache_ttl": 7200')
    print('  }')
    print('}')

    print_header("Best Practices")

    practices = [
        "Always ensure you have permission to scan target systems",
        "Use virtual environments to avoid dependency conflicts",
        "Review generated reports in both executive and technical formats",
        "Save configuration files for consistent scanning across teams",
        "Monitor logs/ directory for detailed scan information",
        "Use custom output directories for organized report management",
        "Consider rate limiting for large-scale assessments",
        "Regularly update SecAudit for latest security checks"
    ]

    for i, practice in enumerate(practices, 1):
        print(f"{i}. {practice}")

    print_header("Troubleshooting")

    issues = [
        ("Connection timeouts", "Increase timeout in configuration or check network connectivity"),
        ("Permission denied errors", "Ensure you have permission to scan the target"),
        ("Missing dependencies", "Run 'pip install -r requirements.txt' to install all dependencies"),
        ("Reports not generating", "Check write permissions in output directory"),
        ("Threat intel not working", "Verify internet connection and API availability")
    ]

    for issue, solution in issues:
        print(f"\nIssue: {issue}")
        print(f"Solution: {solution}")

    print(f"\n{'='*60}")
    print("For more help:")
    print("• Run: python3 secaudit.py --help")
    print("• Check: README.md")
    print("• Demo: python3 demo.py")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
