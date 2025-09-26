#!/bin/bash
# SecAudit Installation Script
# Automated installation for SecAudit Security Assessment Platform

set -e  # Exit on any error

echo "=================================================="
echo "SecAudit - Security Assessment Platform Installer"
echo "=================================================="
echo ""

# Check Python version
echo "Checking Python version..."
python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
required_version="3.8"

if [[ $(echo "$python_version >= $required_version" | bc -l) -eq 1 ]]; then
    echo "✓ Python $python_version detected (>= 3.8 required)"
else
    echo "✗ Python $python_version is too old. Python 3.8+ required."
    echo "Please upgrade Python and try again."
    exit 1
fi

# Check if pip is available
echo "Checking pip availability..."
if command -v pip3 &> /dev/null; then
    echo "✓ pip3 found"
    PIP_CMD="pip3"
elif command -v pip &> /dev/null; then
    echo "✓ pip found"
    PIP_CMD="pip"
else
    echo "✗ pip not found. Please install pip and try again."
    exit 1
fi

# Create virtual environment (recommended)
echo ""
read -p "Create virtual environment? [Y/n]: " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
    echo "Creating virtual environment..."
    python3 -m venv secaudit_env
    echo "✓ Virtual environment created: secaudit_env"

    echo "Activating virtual environment..."
    source secaudit_env/bin/activate
    echo "✓ Virtual environment activated"

    PIP_CMD="pip"  # Use pip in virtual environment
fi

# Install dependencies
echo ""
echo "Installing SecAudit dependencies..."
$PIP_CMD install -r requirements.txt

if [ $? -eq 0 ]; then
    echo "✓ Dependencies installed successfully"
else
    echo "✗ Failed to install dependencies"
    exit 1
fi

# Make scripts executable
echo ""
echo "Setting up executable permissions..."
chmod +x secaudit.py
chmod +x demo.py
echo "✓ Scripts are now executable"

# Create directories
echo ""
echo "Creating necessary directories..."
mkdir -p reports logs
echo "✓ Directories created: reports/, logs/"

# Test installation
echo ""
echo "Testing SecAudit installation..."
if python3 secaudit.py --help > /dev/null 2>&1; then
    echo "✓ SecAudit installed successfully!"
else
    echo "✗ Installation test failed"
    exit 1
fi

echo ""
echo "=================================================="
echo "           Installation Complete!"
echo "=================================================="
echo ""
echo "To get started:"
echo ""
if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
    echo "1. Activate virtual environment:"
    echo "   source secaudit_env/bin/activate"
    echo ""
fi
echo "2. Run demo:"
echo "   python3 demo.py"
echo ""
echo "3. Scan a target:"
echo "   python3 secaudit.py example.com"
echo ""
echo "4. View help:"
echo "   python3 secaudit.py --help"
echo ""
echo "Documentation: README.md"
echo "Reports will be saved to: reports/"
echo ""
echo "Happy hacking! 🔒"
