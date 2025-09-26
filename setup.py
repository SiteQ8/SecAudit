#!/usr/bin/env python3
"""
Setup script for SecAudit - Comprehensive Security Assessment Platform
"""

from setuptools import setup, find_packages
import os

# Read README for long description
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="secaudit",
    version="1.0.0",
    author="Cybersecurity Community",
    author_email="security@example.com",
    description="Comprehensive Security Assessment Platform",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/secaudit",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "secaudit=secaudit.secaudit:main",
        ],
    },
    keywords="security, vulnerability, assessment, penetration-testing, cybersecurity",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/secaudit/issues",
        "Source": "https://github.com/yourusername/secaudit",
        "Documentation": "https://github.com/yourusername/secaudit/wiki",
    },
)
