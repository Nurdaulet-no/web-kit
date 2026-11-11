"""Redacted event stream shared by reports and terminal renderers."""
from datetime import datetime, timezone
from .reports import sanitize


class Events:
    def __init__(self, callback=None):
        self.callback = callback
        self.items = []

    def emit(self, message, completed=0, total=1, **fields):
        event = sanitize({"timestamp": datetime.now(timezone.utc).isoformat(),
                          "message": message, "completed": completed, "total": total, **fields})
        self.items.append(event)
        if self.callback:
            self.callback(event)
