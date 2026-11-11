"""Dependency-free terminal dashboard with a plain-text pipe/CI fallback."""
from collections import deque
import os
import re
import shutil
import sys


class TerminalUI:
    def __init__(self, mode="auto", stream=None):
        self.stream = stream or sys.stderr
        self.enabled = mode != "off"
        self.terminal = self.enabled and self.stream.isatty() and os.environ.get("TERM") != "dumb"
        self.logs = deque(maxlen=200)
        self.percent = 0

    def __enter__(self):
        if self.terminal:
            self.stream.write("\033[?1049h\033[?25l")
            self.render()
        return self

    def __exit__(self, *exc):
        if self.terminal:
            self.stream.write("\033[?25h\033[?1049l")
            self.stream.flush()

    def __call__(self, event):
        if not self.enabled:
            return
        self.percent = max(self.percent, min(99, int(100 * event["completed"] / max(1, event["total"]))))
        if event.get("finished"):
            self.percent = 100
        # Strip all control sequences from remote paths/messages before terminal output.
        line = f"{event['timestamp'][11:19]} {event['message']} {event.get('url', '')}"
        line = re.sub(r"[\x00-\x1f\x7f-\x9f]", "?", line)
        self.logs.append(line)
        if self.terminal:
            self.render()
        else:
            self.stream.write(f"[{self.percent:3d}%] {line}\n")
            self.stream.flush()

    def render(self):
        width, height = shutil.get_terminal_size((80, 24))
        width = max(1, width - 1)
        bar_width = max(1, min(40, width - 18))
        filled = bar_width * self.percent // 100
        title = f"Web Audit Kit · UTC  {self.percent:3d}%"
        bar = "[" + "#" * filled + "-" * (bar_width - filled) + "]"
        rows = [title, bar, "События:"] + list(self.logs)[-max(1, height - 5):]
        self.stream.write("\033[H\033[2J" + "\n".join(row[:width] for row in rows))
        self.stream.flush()
