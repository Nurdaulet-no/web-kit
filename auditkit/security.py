"""Defensive local checks with one report schema and no simulated findings."""
from dataclasses import asdict

from .dependency_check import check_dependencies
from .reports import empty_report
from .safe import review_code


def check_rce_potential(scope=None, code_path=None, on_event=None):
    data = review_code(code_path, on_event=on_event)
    data["mode"] = "rce-code-review"
    data["requests"] = 0
    data["findings"] = [item for item in data["findings"] if item["rule"] == "code.dynamic_execution"]
    data["limitations"].append("Static Python heuristics only; no exploit execution or confirmation of RCE.")
    return data


def check_configuration(scope=None, code_path=None, on_event=None):
    data = review_code(code_path, on_event=on_event)
    data["mode"] = "configuration-review"
    data["requests"] = 0
    data["findings"] = [item for item in data["findings"] if item["rule"] != "code.dynamic_execution"]
    return data


def run_security_check(scope, code_path, on_event=None):
    local = review_code(code_path, on_event=on_event)
    dependencies = check_dependencies(scope, code_path=code_path, on_event=on_event)
    data = empty_report()
    data.update(mode="security-check", requests=0, runs=[local, dependencies],
                findings=local["findings"] + dependencies["findings"],
                errors=local["errors"] + dependencies["errors"],
                timeline=local.get("timeline", []) + dependencies.get("timeline", []),
                limitations=local.get("limitations", []) + dependencies.get("limitations", []),
                dependency_checks=dependencies["dependency_checks"])
    if scope is not None:
        data["scope"] = asdict(scope)
        data["scope"]["allowed_origins"] = sorted(scope.allowed_origins)
    return data
