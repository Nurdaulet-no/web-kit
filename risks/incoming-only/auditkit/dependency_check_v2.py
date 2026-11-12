#!/usr/bin/env python3
"""Enhanced dependency vulnerability checking with pip-audit and npm audit."""

import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Any

from .reports import empty_report


def check_dependencies(scope, on_event=None):
    """Check for vulnerable dependencies in project packages."""
    data = empty_report()
    data.update(mode="dependencies", findings=[], errors=[], requests=0)
    
    # Try to check for pip-audit
    try:
        result = subprocess.run(["pip-audit", "--version"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            # Run pip-audit if available
            result = subprocess.run(["pip-audit", "--format", "json"], capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                audit_data = json.loads(result.stdout)
                for item in audit_data:
                    data["findings"].append({
                        "rule": "dependency.vulnerability",
                        "title": f"Vulnerable dependency: {item.get('package', 'unknown')}",
                        "url": "file://pip-audit-report.json",
                        "severity": "high",
                        "confidence": "observed",
                        "evidence": f"Vulnerability found: {item.get('vulnerability', 'unknown')}",
                        "recommendation": "Update dependency to fix vulnerability"
                    })
                    data["requests"] += 1
            else:
                data["errors"].append({
                    "type": "PipAuditError",
                    "message": f"pip-audit failed: {result.stderr}"
                })
    except (subprocess.SubprocessError, FileNotFoundError):
        # pip-audit not available, continue with basic checks
        pass
    
    # Try to check for npm audit
    try:
        result = subprocess.run(["npm", "audit", "--version"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            # Run npm audit if package.json exists
            package_json = Path(".") / "package.json"
            if package_json.exists():
                result = subprocess.run(["npm", "audit", "--json"], capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    audit_data = json.loads(result.stdout)
                    if "vulnerabilities" in audit_data:
                        for key, value in audit_data["vulnerabilities"].items():
                            data["findings"].append({
                                "rule": "dependency.vulnerability",
                                "title": f"Vulnerable npm dependency: {key}",
                                "url": "file://package.json",
                                "severity": "high",
                                "confidence": "observed",
                                "evidence": f"Vulnerability found: {value.get('name', 'unknown')}",
                                "recommendation": "Update npm dependency to fix vulnerability"
                            })
                            data["requests"] += 1
                else:
                    data["errors"].append({
                        "type": "NpmAuditError",
                        "message": f"npm audit failed: {result.stderr}"
                    })
    except (subprocess.SubprocessError, FileNotFoundError):
        # npm audit not available, continue with basic checks
        pass
    
    # Check for requirements.txt
    requirements_file = Path(".") / "requirements.txt"
    if requirements_file.exists():
        try:
            content = requirements_file.read_text(encoding="utf-8")
            # Simple check for common vulnerable packages
            vulnerable_packages = [
                "django<3.2.0",
                "flask<1.0.0",
                "express<4.0.0",
                "jquery<3.0.0",
                "bootstrap<4.0.0",
            ]
            
            for package in vulnerable_packages:
                if package in content:
                    data["findings"].append({
                        "rule": "dependency.outdated",
                        "title": f"Outdated package found: {package}",
                        "url": "file://requirements.txt",
                        "severity": "medium",
                        "confidence": "observed",
                        "evidence": f"Package {package} found in requirements.txt",
                        "recommendation": "Update package to latest version"
                    })
                    data["requests"] += 1
        except Exception as e:
            data["errors"].append({
                "type": "RequirementsReadError",
                "message": f"Error reading requirements.txt: {str(e)}"
            })
    
    return data
