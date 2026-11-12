"""Enhanced dependency vulnerability checking with pip-audit and npm audit."""

import subprocess
import json
import re
from pathlib import Path
from .reports import empty_report


def check_dependencies_enhanced(scope, code_path=None, on_event=None):
    """Check for vulnerable dependencies using pip-audit and npm audit."""
    data = empty_report()
    data.update(mode="deps-check", findings=[], errors=[], requests=0)
    
    if not code_path:
        data["errors"].append({"type": "NoCodePath", "message": "No code path specified for dependency check"})
        return data
    
    # Check if path exists
    path = Path(code_path)
    if not path.exists():
        data["errors"].append({"type": "PathNotFound", "message": f"Code path {code_path} not found"})
        return data
    
    # Find all requirements files and package.json
    found_files = []
    for root, dirs, files in path.walk():
        for file in files:
            if file in ("requirements.txt", "setup.py", "pyproject.toml", "Pipfile", "poetry.lock", "package.json"):
                found_files.append(root / file)
    
    # Try to check for pip-audit
    try:
        result = subprocess.run(["pip-audit", "--version"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            # Run pip-audit on all found files
            for file_path in found_files:
                if file_path.name in ("requirements.txt", "setup.py", "pyproject.toml", "Pipfile", "poetry.lock"):
                    # Create a temporary requirements file if needed
                    cmd = ["pip-audit", "--format", "json", str(file_path)]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        try:
                            audit_data = json.loads(result.stdout)
                            if "vulnerabilities" in audit_data and audit_data["vulnerabilities"]:
                                for vuln in audit_data["vulnerabilities"]:
                                    # Extract vulnerability details
                                    vuln_id = vuln.get("id", "unknown")
                                    package_name = vuln.get("package", {}).get("name", "unknown")
                                    version = vuln.get("package", {}).get("version", "unknown")
                                    severity = vuln.get("severity", "unknown")
                                    description = vuln.get("description", "No description")
                                    
                                    # Extract vulnerability sources
                                    sources = ""
                                    if "source" in vuln:
                                        sources = f"Source: {vuln['source']}"
                                    
                                    data["findings"].append({
                                        "rule": f"deps.pip.vulnerability.{vuln_id.lower()}",
                                        "title": f"Pip vulnerability: {package_name} v{version}",
                                        "url": str(file_path),
                                        "severity": severity.lower(),
                                        "confidence": "observed",
                                        "evidence": f"Package: {package_name} v{version} - {description}",
                                        "recommendation": f"Update {package_name} to fix vulnerability {vuln_id}"
                                    })
                        except json.JSONDecodeError:
                            data["errors"].append({
                                "type": "AuditParseError",
                                "message": f"Failed to parse pip-audit output for {file_path}"
                            })
                    else:
                        data["errors"].append({
                            "type": "AuditError",
                            "message": f"pip-audit failed on {file_path}: {result.stderr}"
                        })
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
        # pip-audit not available, continue with basic checks
        pass
    
    # Try to check for npm audit
    try:
        result = subprocess.run(["npm", "audit", "--version"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            # Run npm audit if package.json exists
            for file_path in found_files:
                if file_path.name == "package.json":
                    result = subprocess.run(["npm", "audit", "--json"], capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        try:
                            audit_data = json.loads(result.stdout)
                            if "vulnerabilities" in audit_data and audit_data["vulnerabilities"]:
                                for vuln in audit_data["vulnerabilities"]:
                                    # Extract vulnerability details
                                    name = vuln.get("name", "unknown")
                                    severity = vuln.get("severity", "unknown")
                                    
                                    data["findings"].append({
                                        "rule": f"deps.npm.vulnerability.{name.lower()}",
                                        "title": f"NPM vulnerability: {name}",
                                        "url": str(file_path),
                                        "severity": severity.lower(),
                                        "confidence": "observed",
                                        "evidence": f"Vulnerability: {name} - {vuln.get('severity', 'unknown')}",
                                        "recommendation": f"Update {name} to fix vulnerability"
                                    })
                        except json.JSONDecodeError:
                            data["errors"].append({
                                "type": "AuditParseError",
                                "message": f"Failed to parse npm audit output for {file_path}"
                            })
                    else:
                        data["errors"].append({
                            "type": "AuditError",
                            "message": f"npm audit failed on {file_path}: {result.stderr}"
                        })
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
        # npm audit not available, continue with basic checks
        pass
    
    # Fallback: basic dependency checks
    if not data["findings"]:
        # Look for common vulnerable patterns in requirements files
        vulnerable_patterns = [
            (r"(\w+)\s*==\s*([\d\.]+)\s*#\s*(.*?)(?:\s+|\Z)", "Exact version dependency"),
            (r"(\w+)\s*>=\s*([\d\.]+)\s*#\s*(.*?)(?:\s+|\Z)", "Minimum version dependency"),
            (r"(\w+)\s*~\s*([\d\.]+)\s*#\s*(.*?)(?:\s+|\Z)", "Compatible version dependency"),
        ]
        
        for file_path in found_files:
            if file_path.name in ("requirements.txt", "setup.py", "pyproject.toml", "Pipfile"):
                try:
                    content = file_path.read_text(encoding="utf-8")
                    for pattern, title in vulnerable_patterns:
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            data["findings"].append({
                                "rule": f"deps.pattern.{title.lower().replace(' ', '_')}",
                                "title": f"Dependency pattern: {title}",
                                "url": str(file_path),
                                "severity": "medium",
                                "confidence": "observed",
                                "evidence": f"Pattern '{pattern}' found in {file_path}",
                                "recommendation": "Review dependency versions for potential vulnerabilities"
                            })
                except Exception as e:
                    data["errors"].append({
                        "type": "FileReadError",
                        "message": f"Error reading {file_path}: {str(e)}"
                    })
    
    return data


def check_dependencies_simple(scope, code_path=None, on_event=None):
    """Simple dependency check for when advanced tools are not available."""
    data = empty_report()
    data.update(mode="deps-check", findings=[], errors=[], requests=0)
    
    if not code_path:
        data["errors"].append({"type": "NoCodePath", "message": "No code path specified for dependency check"})
        return data
    
    # Check if path exists
    path = Path(code_path)
    if not path.exists():
        data["errors"].append({"type": "PathNotFound", "message": f"Code path {code_path} not found"})
        return data
    
    # Simple check for vulnerable packages
    vulnerable_packages = {
        "django": ["1.11", "2.0", "2.1", "2.2", "3.0"],
        "flask": ["0.12", "1.0"],
        "requests": ["2.18", "2.19", "2.20"],
        "pyyaml": ["3.12"],
        "jinja2": ["2.10", "2.11"],
        "werkzeug": ["0.14", "0.15"],
        "sqlalchemy": ["1.2", "1.3"],
        "pillow": ["6.0"],
    }
    
    # Look for requirements files
    requirements_files = []
    for root, dirs, files in path.walk():
        for file in files:
            if file in ("requirements.txt", "setup.py", "pyproject.toml", "Pipfile"):
                requirements_files.append(root / file)
    
    for file_path in requirements_files:
        try:
            content = file_path.read_text(encoding="utf-8")
            for package, versions in vulnerable_packages.items():
                # Look for package patterns
                pattern = r"(\w+)\s*(?:==|>=|<=|~=|>|<)\s*(\d+(?:\.\d+)*(?:\.\d+)?)"
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    matched_package = match.group(1)
                    matched_version = match.group(2)
                    if matched_package.lower() == package.lower():
                        data["findings"].append({
                            "rule": f"deps.vulnerable.{package.lower()}",
                            "title": f"Vulnerable package: {package}",
                            "url": str(file_path),
                            "severity": "high",
                            "confidence": "observed",
                            "evidence": f"Found vulnerable version {matched_version} of {package}",
                            "recommendation": f"Update {package} to a more secure version"
                        })
        except Exception as e:
            data["errors"].append({
                "type": "FileReadError",
                "message": f"Error reading {file_path}: {str(e)}"
            })
    
    return data
