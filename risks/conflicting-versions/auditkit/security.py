def check_rce_potential(scope, on_event=None):
    """Check for potential RCE vulnerabilities."""
    data = empty_report()
    data.update(mode="rce-check", findings=[], errors=[], requests=0)
    
    # Placeholder for RCE potential check
    data["findings"].append({
        "rule": "rce.potential",
        "title": "RCE potential check executed",
        "url": "file://.",
        "severity": "info",
        "confidence": "observed",
        "evidence": "RCE potential check executed (placeholder)",
        "recommendation": "Review RCE potential findings for system vulnerabilities"
    })
    
    return data


def check_configuration(scope, on_event=None):
    """Check for security configuration issues."""
    data = empty_report()
    data.update(mode="config-check", findings=[], errors=[], requests=0)
    
    # Placeholder for configuration check
    data["findings"].append({
        "rule": "config.security",
        "title": "Security configuration check executed",
        "url": "file://.",
        "severity": "info",
        "confidence": "observed",
        "evidence": "Security configuration check executed (placeholder)",
        "recommendation": "Review security configuration for potential issues"
    })
    
    return data


def check_dependencies(scope, on_event=None):
    """Check for vulnerable dependencies."""
    data = empty_report()
    data.update(mode="deps-check", findings=[], errors=[], requests=0)
    
    # Placeholder for dependencies check
    data["findings"].append({
        "rule": "deps.vulnerable",
        "title": "Vulnerable dependencies check executed",
        "url": "file://.",
        "severity": "info",
        "confidence": "observed",
        "evidence": "Vulnerable dependencies check executed (placeholder)",
        "recommendation": "Review dependencies for known vulnerabilities"
    })
    
    return data


def check_rce_and_dependencies(scope, on_event=None):
    """Run all RCE and dependency checks."""
    rce_data = check_rce_potential(scope, on_event)
    config_data = check_configuration(scope, on_event)
    deps_data = check_dependencies(scope, on_event)
    
    data = empty_report()
    data.update(mode="rce-deps-check", findings=[], errors=[], requests=0)
    
    data["timeline"] = deps_data["timeline"] + rce_data["timeline"] + config_data["timeline"]
    data["runs"] = [deps_data, rce_data, config_data]
    data["scope"] = scope
    
    return data
    return data


def check_dependencies(scope, on_event=None):
    """Check for vulnerable dependencies."""
    data = empty_report()
    data.update(mode="deps-check", findings=[], errors=[], requests=0)
    
    # Placeholder for dependencies check
    data["findings"].append({
        "rule": "deps.vulnerable",
        "title": "Vulnerable dependencies check executed",
        "url": "file://.",
        "severity": "info",
        "confidence": "observed",
        "evidence": "Vulnerable dependencies check executed (placeholder)",
        "recommendation": "Review dependencies for known vulnerabilities"
    })
    
    return data


def check_all(scope, on_event=None):
    """Run all security checks."""
    rce_data = check_rce_potential(scope, on_event)
    config_data = check_configuration(scope, on_event)
    deps_data = check_dependencies(scope, on_event)
    
    data = empty_report()
    data.update(mode="all-checks", findings=[], errors=[], requests=0)
    
    data["timeline"] = deps_data["timeline"] + rce_data["timeline"] + config_data["timeline"]
    data["runs"] = [deps_data, rce_data, config_data]
    data["scope"] = scope
    
    return data
    return data


def check_dependencies(scope, on_event=None):
    """Check for vulnerable dependencies."""
    data = empty_report()
    data.update(mode="dependency-check", findings=[], errors=[], requests=0)
    
    # Placeholder for dependency check
    data["findings"].append({
        "rule": "deps.vulnerable",
        "title": "Vulnerable dependencies check executed",
        "url": "file://.",
        "severity": "info",
        "confidence": "observed",
        "evidence": "Vulnerable dependencies check executed (placeholder)",
        "recommendation": "Review dependencies for known vulnerabilities"
    })
    
    return data
    # Placeholder for configuration check
    data["findings"].append({
        "rule": "config.security",
        "title": "Security configuration check executed",
        "url": "file://.",
        "severity": "info",
        "confidence": "observed",
        "evidence": "Security configuration check executed (placeholder)",
        "recommendation": "Review security configuration findings for system vulnerabilities"
    })
    
    return data


def run_security_check(scope, code_path, on_event=None):
    """Run all security checks in sequence."""
    # Run all security checks
    deps_data = check_dependencies(scope, on_event=on_event)
    rce_data = check_rce_potential(scope, code_path=code_path, on_event=on_event)
    config_data = check_configuration(scope, on_event=on_event)
    
    # Merge results
    data = {}
    data["findings"] = deps_data["findings"] + rce_data["findings"] + config_data["findings"]
    data["errors"] = deps_data["errors"] + rce_data["errors"] + config_data["errors"]
    data["requests"] = deps_data["requests"] + rce_data["requests"] + config_data["requests"]
    data["mode"] = "security-check"
    data["summary"] = {
        "pages": 0,
        "findings": len(data["findings"]),
        "errors": len(data["errors"]),
        "requests": data["requests"]
    }
    data["timeline"] = deps_data["timeline"] + rce_data["timeline"] + config_data["timeline"]
    data["runs"] = [deps_data, rce_data, config_data]
    data["scope"] = scope
    
    return data
    # Placeholder for configuration check
    data["findings"].append({
        "rule": "config.security",
        "title": "Configuration check executed",
        "url": "file://.",
        "severity": "info",
        "confidence": "observed",
        "evidence": "Configuration check executed (placeholder)",
        "recommendation": "Review configuration for potential security issues"
    })
    
    return data
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

def check_configuration(scope, code_path=None, on_event=None):
    """Search for dangerous configuration patterns in source code."""
    data = empty_report()
    data.update(mode="config-check", findings=[], errors=[], requests=0)
    
    if not code_path:
        data["errors"].append({"type": "NoCodePath", "message": "No code path specified for config check"})
        return data
    
    # Check if path exists
    path = Path(code_path)
    if not path.exists():
        data["errors"].append({"type": "PathNotFound", "message": f"Code path {code_path} not found"})
        return data
    
    # Look for dangerous configuration patterns
    config_patterns = [
        (r"(?i)debug\s*=\s*true", "Debug mode enabled", "high"),
        (r"(?i)allow_origin\s*=\s*\*", "Allow all origins", "high"),
        (r"(?i)secret_key\s*=\s*['\"]", "Secret key found in code", "high"),
        (r"(?i)password\s*=\s*['\"]", "Password found in code", "high"),
        (r"(?i)api_key\s*=\s*['\"]", "API key found in code", "high"),
        (r"(?i)token\s*=\s*['\"]", "Token found in code", "medium"),
        (r"(?i)ssl\s*=\s*false", "SSL disabled", "medium"),
        (r"(?i)timeout\s*=\s*0", "Infinite timeout", "medium"),
        (r"(?i)log_level\s*=\s*debug", "Debug logging enabled", "medium"),
        (r"(?i)enable_cors\s*=\s*true", "CORS enabled", "medium"),
        (r"(?i)expose_headers\s*=\s*\*", "Expose all headers", "medium"),
        (r"(?i)allow_credentials\s*=\s*true", "Allow credentials", "medium"),
        (r"(?i)pcntl_exec\s*\(", "PCNTL execution", "high"),
        (r"(?i)proc_open\s*\(", "Process open function", "high"),
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
    """Search for dangerous configuration patterns in source code."""
    data = empty_report()
    data.update(mode="config-check", findings=[], errors=[], requests=0)
    
    if not code_path:
        data["errors"].append({"type": "NoCodePath", "message": "No code path specified for configuration check"})
        return data
    
    # Check if path exists
    path = Path(code_path)
    if not path.exists():
        data["errors"].append({"type": "PathNotFound", "message": f"Code path {code_path} not found"})
        return data
    
    # Look for dangerous configuration patterns
    config_patterns = [
        (r"(?i)allow_url_include\s*=\s*1", "Allow URL include enabled", "high"),
        (r"(?i)display_errors\s*=\s*On", "Display errors enabled", "medium"),
        (r"(?i)log_errors\s*=\s*On", "Log errors enabled", "medium"),
        (r"(?i)expose_php\s*=\s*On", "Expose PHP enabled", "medium"),
        (r"(?i)register_globals\s*=\s*On", "Register globals enabled", "high"),
        (r"(?i)magic_quotes_gpc\s*=\s*Off", "Magic quotes GPC disabled", "medium"),
        (r"(?i)open_basedir\s*=\s*", "Open basedir not set", "medium"),
        (r"(?i)disable_functions\s*=\s*", "Disable functions not set", "medium"),
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