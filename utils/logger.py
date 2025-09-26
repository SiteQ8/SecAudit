"""
Security Logger Module
Provides comprehensive logging for security assessment activities
"""

import logging
import sys
from datetime import datetime
from typing import Optional
import os
from pathlib import Path

class SecurityLogger:
    """Advanced logging for security assessments"""

    def __init__(self, log_level: str = 'INFO', log_dir: str = 'logs'):
        self.log_level = getattr(logging, log_level.upper())
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Create formatters
        self.detailed_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        self.simple_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )

        # Setup loggers
        self.main_logger = self._setup_logger('secaudit', 'secaudit.log')
        self.scan_logger = self._setup_logger('secaudit.scanner', 'scanner.log')
        self.threat_logger = self._setup_logger('secaudit.threat', 'threat_intel.log')

    def _setup_logger(self, name: str, filename: str) -> logging.Logger:
        """Setup a logger with file and console handlers"""
        logger = logging.getLogger(name)
        logger.setLevel(self.log_level)

        # Clear existing handlers
        logger.handlers.clear()

        # File handler
        file_handler = logging.FileHandler(
            self.log_dir / filename,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(self.detailed_formatter)
        logger.addHandler(file_handler)

        # Console handler (only for main logger)
        if name == 'secaudit':
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(self.log_level)
            console_handler.setFormatter(self.simple_formatter)
            logger.addHandler(console_handler)

        return logger

    def info(self, message: str, category: str = 'main'):
        """Log info message"""
        logger = self._get_logger(category)
        logger.info(message)

    def warning(self, message: str, category: str = 'main'):
        """Log warning message"""
        logger = self._get_logger(category)
        logger.warning(message)

    def error(self, message: str, category: str = 'main'):
        """Log error message"""
        logger = self._get_logger(category)
        logger.error(message)

    def debug(self, message: str, category: str = 'main'):
        """Log debug message"""
        logger = self._get_logger(category)
        logger.debug(message)

    def critical(self, message: str, category: str = 'main'):
        """Log critical message"""
        logger = self._get_logger(category)
        logger.critical(message)

    def _get_logger(self, category: str) -> logging.Logger:
        """Get appropriate logger for category"""
        if category == 'scanner':
            return self.scan_logger
        elif category == 'threat':
            return self.threat_logger
        else:
            return self.main_logger

    def log_vulnerability_found(self, vulnerability: dict):
        """Log discovered vulnerability"""
        vuln_type = vulnerability.get('type', 'Unknown')
        severity = vulnerability.get('severity', 'Unknown')
        target = vulnerability.get('target', 'Unknown')

        self.scan_logger.warning(
            f"Vulnerability found: {vuln_type} ({severity}) on {target}"
        )

    def log_threat_intelligence(self, target: str, reputation: str, risk_score: float):
        """Log threat intelligence findings"""
        self.threat_logger.info(
            f"Threat intel for {target}: Reputation={reputation}, Risk={risk_score:.1f}"
        )

    def log_scan_start(self, target: str, scan_types: list):
        """Log scan start"""
        self.main_logger.info(
            f"Starting security assessment of {target} with scans: {', '.join(scan_types)}"
        )

    def log_scan_complete(self, target: str, duration: float, vulnerabilities_found: int):
        """Log scan completion"""
        self.main_logger.info(
            f"Assessment of {target} completed in {duration:.1f}s. Found {vulnerabilities_found} issues."
        )
