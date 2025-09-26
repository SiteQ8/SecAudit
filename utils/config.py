"""
Configuration Management Module
Handles configuration settings for SecAudit
"""

import json
import os
from typing import Dict, Any, Optional
from pathlib import Path

class Config:
    """Configuration manager for SecAudit"""

    DEFAULT_CONFIG = {
        'general': {
            'user_agent': 'SecAudit/1.0 (Security Assessment Tool)',
            'timeout': 30,
            'max_redirects': 5,
            'verify_ssl': True
        },
        'scanning': {
            'max_concurrent_requests': 10,
            'delay_between_requests': 0.1,
            'enable_web_scan': True,
            'enable_vuln_scan': True,
            'enable_threat_intel': True,
            'max_scan_depth': 3
        },
        'threat_intelligence': {
            'enabled_sources': ['threatminer', 'urlhaus'],
            'cache_ttl': 3600,  # 1 hour
            'max_queries_per_minute': 10
        },
        'reporting': {
            'output_formats': ['html', 'json', 'csv'],
            'output_directory': 'reports',
            'include_executive_summary': True,
            'include_technical_details': True
        },
        'logging': {
            'level': 'INFO',
            'directory': 'logs',
            'max_file_size': 10485760,  # 10MB
            'backup_count': 5
        }
    }

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or 'secaudit.json'
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default"""
        config_file = Path(self.config_path)

        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)

                # Merge with defaults
                config = self.DEFAULT_CONFIG.copy()
                self._deep_update(config, user_config)
                return config

            except (json.JSONDecodeError, IOError) as e:
                print(f"Error loading config file: {e}")
                print("Using default configuration")

        return self.DEFAULT_CONFIG.copy()

    def _deep_update(self, base_dict: Dict, update_dict: Dict):
        """Recursively update nested dictionary"""
        for key, value in update_dict.items():
            if isinstance(value, dict) and key in base_dict and isinstance(base_dict[key], dict):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def set(self, key: str, value: Any):
        """Set configuration value using dot notation"""
        keys = key.split('.')
        config = self.config

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value

    def save(self) -> bool:
        """Save current configuration to file"""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except IOError as e:
            print(f"Error saving config: {e}")
            return False

    def create_default_config(self, force: bool = False):
        """Create default configuration file"""
        config_file = Path(self.config_path)

        if not config_file.exists() or force:
            try:
                with open(config_file, 'w') as f:
                    json.dump(self.DEFAULT_CONFIG, f, indent=2)
                print(f"Created default configuration: {self.config_path}")
                return True
            except IOError as e:
                print(f"Error creating config file: {e}")
                return False
        else:
            print(f"Configuration file already exists: {self.config_path}")
            return False
