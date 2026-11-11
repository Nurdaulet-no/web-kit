"""Security checks including dependency vulnerabilities and RCE detection."""
import json
import subprocess
import sys
from pathlib import Path
from .reports import empty_report
from .scope import canonical_url, origin, public_url

def check_dependencies(scope, on_event=None):
    """Check for known vulnerabilities in dependencies."""
    data = empty_report()
    data.update(mode="dependency-check", findings=[], errors=[], requests=0)
    
    # Look for common dependency files
    dependency_files = ["requirements.txt", "package.json", "Gemfile", "go.mod", "pom.xml"]
    found_files = []
    
    # Check current directory and subdirectories for dependency files
    for root, dirs, files in Path(".").walk():
        for file in files:
            if file in dependency_files:
                found_files.append(root / file)
    
    if not found_files:
        data["errors"].append({"type": "NoDependencies", "message": "No dependency files found"})
        return data
    
    # For now, just log that we found dependency files
    data["findings"].append({
        "rule": "deps.found",
        "title": "Dependency files found",
        "url": "file://.",
        "severity": "info",
        "confidence": "observed",
        "evidence": f"Found {len(found_files)} dependency files",
        "recommendation": "Run a full dependency vulnerability scan with tools like npm audit, pip-audit, or bundler-audit"
    })
    
    # Try to run vulnerability scans if tools are available
    try:
        # Check for pip-audit
        result = subprocess.run(["pip-audit", "--version"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            # Run pip-audit on requirements.txt if it exists
            for file_path in found_files:
                if file_path.name == "requirements.txt":
                    result = subprocess.run(["pip-audit", "-r", str(file_path)], capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        # Parse results
                        lines = result.stdout.strip().split('\n')
                        for line in lines:
                            if line.startswith("  - "):
                                data["findings"].append({
                                    "rule": "deps.vulnerability",
                                    "title": "Dependency vulnerability found",
                                    "url": str(file_path),
                                    "severity": "high",
                                    "confidence": "observed",
                                    "evidence": line.strip(),
                                    "recommendation": "Update the vulnerable dependency"
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
                                    data["findings"].append({
                                        "rule": "deps.npm.vulnerability",
                                        "title": f"npm vulnerability: {vuln.get('name', 'unknown')}",
                                        "url": str(file_path),
                                        "severity": "high",
                                        "confidence": "observed",
                                        "evidence": f"Vulnerability: {vuln.get('name', 'unknown')} - {vuln.get('severity', 'unknown')}",
                                        "recommendation": f"Update {vuln.get('name', 'unknown')} to fix vulnerability"
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
    
    return data

def check_rce_potential(scope, code_path=None, on_event=None):
    """Search for RCE potential in source code."""
    data = empty_report()
    data.update(mode="rce-check", findings=[], errors=[], requests=0)
    
    if not code_path:
        data["errors"].append({"type": "NoCodePath", "message": "No code path specified for RCE check"})
        return data
    
    # Check if path exists
    path = Path(code_path)
    if not path.exists():
        data["errors"].append({"type": "PathNotFound", "message": f"Code path {code_path} not found"})
        return data
    
    # Look for dangerous patterns in code files
    dangerous_patterns = [
        r"eval\(",
        r"exec\(",
        r"execfile\(",
        r"compile\(",
        r"subprocess\.",
        r"os\.",
        r"sys\.",
        r"pickle\.",
        r"marshal\.",
        r"importlib\.",
        r"__import__\(",
        r"globals\(\)",
        r"locals\(\)",
        r"exec\(",
        r"execfile\(",
        r"eval\(",
        r"open\(",
        r"input\(",
        r"raw_input\(",
        r"__reduce__",
        r"__new__",
        r"__getattr__",
        r"__getattribute__"
    ]
    
    findings = []
    for root, dirs, files in path.walk():
        for file in files:
            if file.endswith(('.py', '.js', '.php', '.pl', '.rb', '.sh')):
                file_path = root / file
                try:
                    content = file_path.read_text(encoding="utf-8")
                    for pattern in dangerous_patterns:
                        if pattern in content:
                            findings.append({
                                "rule": f"rce.pattern.{pattern.replace('(', '').replace(')', '')}",
                                "title": f"Potential RCE pattern found: {pattern}",
                                "url": str(file_path),
                                "severity": "high",
                                "confidence": "observed",
                                "evidence": f"Pattern '{pattern}' found in {file_path}",
                                "recommendation": "Review this code for potential RCE vulnerabilities"
                            })
                except Exception as e:
                    data["errors"].append({
                        "type": "FileReadError",
                        "message": f"Error reading {file_path}: {str(e)}"
                    })
    
    data["findings"].extend(findings)
    return data

def check_configuration(scope, code_path=None, on_event=None):
    """Check for dangerous configuration patterns."""
    data = empty_report()
    data.update(mode="config-check", findings=[], errors=[], requests=0)
    
    if not code_path:
        data["errors"].append({"type": "NoCodePath", "message": "No code path specified for configuration check"})
        return data
    
    # Check for dangerous configuration patterns
    config_patterns = [
        (r"(?i)debug\s*=\s*(?:true|1)", "Debug mode enabled", "medium"),
        (r"(?i)verify\s*=\s*false", "TLS verification disabled", "medium"),
        (r'(?:secret|password|api_key|access_token|session_token)\s*[:=]\s*["\'][^"\n]{8,}["\']', "Possible secret in code", "medium"),
        (r"(?i)allow_all_origins", "CORS allow all origins", "high"),
        (r"(?i)enable_cors", "CORS enabled", "medium"),
        (r"(?i)shell_exec", "Shell execution function found", "high"),
        (r"(?i)system\(", "System command execution", "high"),
        (r"(?i)passthru\(", "Pass through function", "high"),
        (r"(?i)shell_exec\(", "Shell execution function", "high"),
        (r"(?i)pcntl_exec\(", "PCNTL execution", "high"),
        (r"(?i)proc_open\(", "Process open function", "high"),
    ]
    
    findings = []
    for root, dirs, files in Path(code_path).walk():
        for file in files:
            if file.endswith(('.py', '.js', '.php', '.pl', '.rb', '.sh', '.yml', '.yaml', '.json', '.conf', '.ini')):
                file_path = root / file
                try:
                    content = file_path.read_text(encoding="utf-8")
                    for pattern, title, severity in config_patterns:
                        if pattern in content:
                            findings.append({
                                "rule": f"config.pattern.{title.lower().replace(' ', '_')}",
                                "title": title,
                                "url": str(file_path),
                                "severity": severity,
                                "confidence": "observed",
                                "evidence": f"Pattern '{pattern}' found in {file_path}",
                                "recommendation": "Review this configuration for potential security issues"
                            })
                except Exception as e:
                    data["errors"].append({
                        "type": "FileReadError",
                        "message": f"Error reading {file_path}: {str(e)}"
                    })
    
    data["findings"].extend(findings)
    return data