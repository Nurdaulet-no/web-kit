"""Project-specific pip-audit and npm audit adapters; never install or fix packages."""
import json
import os
from pathlib import Path
import shutil
import tempfile

from .engines import bounded_json, execute
from .reports import empty_report


def _finding(path, package, identifier, severity, evidence):
    return {"rule": "dependency." + identifier, "title": "Dependency advisory: " + package,
            "url": str(path), "severity": severity, "confidence": "unverified-tool-alert",
            "evidence": evidence, "recommendation": "Review the advisory and upgrade to a compatible fixed version."}


def parse_pip(payload, path):
    if not isinstance(payload, dict) or not isinstance(payload.get("dependencies"), list):
        raise ValueError("Unsupported pip-audit JSON schema")
    findings = []
    for package in payload["dependencies"]:
        if not isinstance(package, dict) or not isinstance(package.get("name"), str):
            raise ValueError("Invalid pip-audit dependency")
        if package.get("skip_reason"):
            raise ValueError("pip-audit skipped a dependency: " + package["name"])
        vulns = package.get("vulns")
        if not isinstance(vulns, list):
            raise ValueError("Missing pip-audit vulns")
        for vuln in vulns:
            if not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str):
                raise ValueError("Invalid pip-audit advisory")
            findings.append(_finding(path, package["name"], vuln["id"], "info",
                {"id": vuln["id"], "version": package.get("version"),
                 "fix_versions": vuln.get("fix_versions", []), "severity": "not supplied by pip-audit"}))
    return findings


def parse_npm(payload, path):
    if not isinstance(payload, dict) or payload.get("error") or not isinstance(payload.get("vulnerabilities"), dict):
        raise ValueError("Unsupported npm audit JSON schema or registry error")
    findings = []
    for name, advisory in payload["vulnerabilities"].items():
        if not isinstance(advisory, dict):
            raise ValueError("Invalid npm audit advisory")
        severity = advisory.get("severity", "info")
        severity = "medium" if severity == "moderate" else severity
        if severity not in ("info", "low", "medium", "high", "critical"):
            severity = "info"
        findings.append(_finding(path, name, "npm." + name, severity,
            {"range": advisory.get("range"), "via": advisory.get("via", []),
             "fix_available": advisory.get("fixAvailable", False)}))
    return findings


def check_dependencies(scope=None, code_path=None, on_event=None):
    data = empty_report()
    data.update(mode="dependency-check", dependency_checks=[], requests=0,
                limitations=["Only requirements.txt and npm package-lock.json/npm-shrinkwrap.json are audited.",
                             "External tools contact their advisory services; their HTTP requests are not counted.",
                             "pip-audit does not supply severity; these advisories are marked info, not guessed."])
    if not code_path:
        raise ValueError("Dependency audit requires code_path")
    root = Path(code_path)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Dependency audit requires a local directory, not a symlink")
    root = root.resolve()
    ignored = {".git", ".venv", "venv", "env", "node_modules", "__pycache__", "archive", "reports", "risks"}
    manifests = []
    def traversal_error(exc):
        data["errors"].append({"type": "TraversalError", "message": str(exc)})
    for directory, folders, names in os.walk(root, followlinks=False, onerror=traversal_error):
        folders[:] = sorted(name for name in folders if name not in ignored and not (Path(directory) / name).is_symlink())
        for name in sorted(set(names) & {"requirements.txt", "package.json", "pyproject.toml", "Pipfile", "Gemfile", "go.mod", "pom.xml"}):
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                continue
            manifests.append(path)
        if len(manifests) > 100:
            data["errors"].append({"type": "FileLimit", "message": "Only the first 100 manifests are audited."})
            manifests = manifests[:100]
            break
    for index, path in enumerate(manifests):
        record = {"file": path.relative_to(root).as_posix(), "status": "error"}
        data["dependency_checks"].append(record)
        if on_event:
            on_event({"message": "Dependencies: " + record["file"], "completed": index, "total": len(manifests), "finished": False})
        if path.name not in ("requirements.txt", "package.json"):
            record["status"] = "unsupported"
            data["errors"].append({"type": "UnsupportedManifest", "file": record["file"]})
            continue
        tool = "pip-audit" if path.name == "requirements.txt" else "npm"
        binary = shutil.which(tool)
        if not binary:
            record["status"] = "unavailable"
            data["errors"].append({"type": "ToolUnavailable", "tool": tool, "file": record["file"]})
            continue
        try:
            with tempfile.TemporaryDirectory(prefix="audit-dependencies-") as temporary:
                if tool == "pip-audit":
                    output = Path(temporary) / "audit.json"
                    command = [binary, "-r", str(path), "--format", "json", "--output", str(output), "--progress-spinner", "off"]
                else:
                    locks = [path.parent / name for name in ("package-lock.json", "npm-shrinkwrap.json")]
                    if any(lock.is_symlink() for lock in locks):
                        raise ValueError("Symlink package locks are not supported")
                    if not any(lock.is_file() and not lock.is_symlink() for lock in locks):
                        raise ValueError("npm audit requires an existing package lock")
                    command = [binary, "audit", "--json", "--ignore-scripts", "--audit-level=low"]
                execution = execute(command, 60, cwd=path.parent)
                record.update(exit_code=execution["exit_code"], status=execution["status"])
                if execution["status"] != "completed" or execution["exit_code"] not in (0, 1):
                    raise ValueError(f"{tool}: {execution['status']}, exit={execution['exit_code']}")
                payload = bounded_json(output) if tool == "pip-audit" else json.loads(execution["log"])
                findings = (parse_pip if tool == "pip-audit" else parse_npm)(payload, record["file"])
                if execution["exit_code"] == 1 and not findings:
                    raise ValueError(f"{tool}: nonzero exit without advisory results")
                data["findings"].extend(findings)
                record["findings"] = len(findings)
                if payload.get("fixes"):
                    raise ValueError("Unexpected remediation output from read-only audit")
        except (OSError, ValueError, TypeError, KeyError) as exc:
            record["status"] = "error"
            data["errors"].append({"type": "DependencyAuditError", "file": record["file"], "message": str(exc)})
    if not manifests:
        data["limitations"].append("No supported dependency manifests found; dependency vulnerabilities were not assessed.")
    return data
