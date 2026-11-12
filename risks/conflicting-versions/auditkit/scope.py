"""Validate explicit origins, limits and paths before any network access."""
from dataclasses import dataclass
import math
from urllib.parse import urlsplit, urlunsplit, unquote


def canonical_url(value):
    if not isinstance(value, str) or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ValueError("URL должен быть строкой без пробелов и управляющих символов")
    p = urlsplit(value)
    if p.scheme not in ("http", "https") or not p.hostname or p.username is not None or p.password is not None:
        raise ValueError("Нужен HTTP(S) URL без учётных данных")
    host = p.hostname.encode("idna").decode("ascii").lower()
    if "\\" in host or "%" in host:
        raise ValueError("Некорректный hostname")
    port = p.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Некорректный порт")
    host = f"[{host}]" if ":" in host else host
    if port is not None and port != (443 if p.scheme == "https" else 80):
        host += f":{port}"
    return urlunsplit((p.scheme, host, p.path or "/", p.query, ""))


def origin(url):
    p = urlsplit(canonical_url(url))
    return f"{p.scheme}://{p.netloc}"


def public_url(url):
    """Do not retain query values or fragments in reports."""
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, "REDACTED" if p.query else "", ""))


@dataclass
class Scope:
    targets: list
    allowed_origins: set
    allowed_ports: list  # New field for allowed ports
    exclude_paths: list
    max_pages: int = 10
    delay: float = 1
    timeout: float = 10
    max_bytes: int = 262144

    @classmethod
    def from_dict(cls, data):
        if not isinstance(data, dict):
            raise ValueError("Scope должен быть JSON-объектом")
        unknown = set(data) - {"targets", "allowed_origins", "allowed_ports", "exclude_paths", "max_pages", "delay", "timeout", "max_bytes"}
        if unknown:
            raise ValueError("Неизвестные поля scope: " + ", ".join(sorted(unknown)))
        targets, origins = data.get("targets"), data.get("allowed_origins")
        if not isinstance(targets, list) or not targets or not isinstance(origins, list) or not origins:
            raise ValueError("Нужны непустые списки targets и allowed_origins")
        allowed = set()
        for value in origins:
            normalized = canonical_url(value)
            p = urlsplit(normalized)
            if p.path != "/" or p.query:
                raise ValueError("allowed_origins содержит только схему, хост и порт")
            allowed.add(origin(normalized))
        exclude = data.get("exclude_paths", ["/logout", "/signout", "/delete", "/remove"])
        if not isinstance(exclude, list) or any(not isinstance(x, str) or not x.startswith("/") for x in exclude):
            raise ValueError("exclude_paths должен содержать абсолютные пути")
        
        # Handle allowed_ports
        allowed_ports = data.get("allowed_ports", [])
        if not isinstance(allowed_ports, list) or not all(isinstance(port, int) and 1 <= port <= 65535 for port in allowed_ports):
            raise ValueError("allowed_ports должен быть списком целых чисел от 1 до 65535")
        
        values = {}
        for name, default, lo, hi in [("max_pages", 10, 1, 1000), ("delay", 1, 0.1, 60), ("timeout", 10, 1, 60), ("max_bytes", 262144, 1024, 2097152)]:
            value = data.get(name, default)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not lo <= value <= hi:
                raise ValueError(f"{name}: допустимо {lo}–{hi}")
            if name in ("max_pages", "max_bytes") and not isinstance(value, int):
                raise ValueError(f"{name} должен быть целым")
            values[name] = value
        
        result = cls([canonical_url(x) for x in targets], allowed, allowed_ports, exclude, **values)
        if len(set(result.targets)) > result.max_pages:
            raise ValueError("max_pages меньше количества targets")
        for target in result.targets:
            if not result.permits(target):
                raise ValueError("Цель вне области проверки: " + public_url(target))
        return result

    def permits(self, url):
        url = canonical_url(url)
        path = unquote(urlsplit(url).path).lower()
        
        # Check if the origin is allowed
        origin_allowed = origin(url) in self.allowed_origins
        
        # Check if the port is allowed (if specified)
        url_port = urlsplit(url).port
        port_allowed = True  # Default to allowed if no ports specified
        if self.allowed_ports:
            port_allowed = url_port in self.allowed_ports
        
        # Check if path is excluded
        path_excluded = any(x.lower() in path for x in self.exclude_paths)
        
        return origin_allowed and port_allowed and not path_excluded
    
    def is_target(self, url):
        """Check if URL is a target URL."""
        return url in self.targets
    
    def is_external(self, url):
        """Check if URL is external to targets."""
        return origin(url) not in self.allowed_origins
    
    def get_allowed_hosts(self):
        """Get list of allowed hosts."""
        return self.allowed_origins
    
    def get_allowed_ports(self):
        """Get list of allowed ports."""
        return self.allowed_ports
