"""Compatibility entry point for local, unconfirmed Python execution-risk review."""
from .security import check_rce_potential


def check_rce_potential_enhanced(scope=None, code_path=None, on_event=None):
    return check_rce_potential(scope, code_path=code_path, on_event=on_event)
