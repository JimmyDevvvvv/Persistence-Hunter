#!/usr/bin/env python3
"""
RegHunt API Test Suite
Run with: python test_api.py [--verbose] [--base-url http://localhost:8000] [--full]
"""

import argparse
import sys
import time
from typing import Optional, Dict, Any
import requests

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()


class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


class ApiTester:
    def __init__(self, base_url: str, verbose: bool = False):
        self.base_url = base_url.rstrip("/")
        self.verbose = verbose
        self.passed = 0
        self.failed = 0
        self.session = requests.Session()
        
    def log(self, msg: str, color: str = ""):
        print(f"{color}{msg}{Colors.RESET}")
        
    def header(self, text: str):
        print(f"\n{Colors.CYAN}{'='*50}{Colors.RESET}")
        print(f"{Colors.CYAN}  {text}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*50}{Colors.RESET}")
        
    def test(self, name: str, method: str, endpoint: str, 
             body: Optional[Dict] = None, expected_status: int = 200) -> Optional[Dict]:
        url = f"{self.base_url}{endpoint}"
        
        if self.verbose:
            self.log(f"\n[TEST] {name}", Colors.YELLOW)
            self.log(f"  {method} {url}", Colors.GRAY)
            if body:
                self.log(f"  Body: {body}", Colors.GRAY)
        
        try:
            if method == "GET":
                resp = self.session.get(url, timeout=30)
            elif method == "POST":
                resp = self.session.post(url, json=body, timeout=30)
            elif method == "DELETE":
                resp = self.session.delete(url, timeout=30)
            else:
                raise ValueError(f"Unknown method: {method}")
                
            status = resp.status_code
            
        except requests.exceptions.ConnectionError as e:
            self.log(f"✗ FAIL: {name} - Connection refused", Colors.RED)
            self.log(f"  Is the API server running?", Colors.GRAY)
            self.failed += 1
            return None
        except Exception as e:
            self.log(f"✗ FAIL: {name} - {str(e)}", Colors.RED)
            self.failed += 1
            return None
            
        # Check result
        if status == expected_status:
            self.log(f"✓ PASS: {name}" + (f" (expected {expected_status})" if expected_status != 200 else ""), Colors.GREEN)
            self.passed += 1
            
            if self.verbose and resp.text:
                try:
                    data = resp.json()
                    import json
                    self.log(f"  Response: {json.dumps(data, indent=2, default=str)[:500]}", Colors.GRAY)
                except:
                    self.log(f"  Response: {resp.text[:200]}", Colors.GRAY)
                    
            try:
                return resp.json()
            except:
                return {"status_code": status}
        else:
            self.log(f"✗ FAIL: {name} (HTTP {status}, expected {expected_status})", Colors.RED)
            if resp.text:
                self.log(f"  {resp.text[:200]}", Colors.GRAY)
            self.failed += 1
            return None
            
    def run_all_tests(self, full: bool = False):
        """Run complete test suite"""
        
        # 1. HEALTH & INFO
        self.header("1. HEALTH & INFO")
        self.test("Root endpoint", "GET", "/")
        stats = self.test("Stats endpoint", "GET", "/api/stats")
        self.test("Dashboard endpoint", "GET", "/api/dashboard")
        
        # 2. REGISTRY ENTRIES
        self.header("2. REGISTRY ENTRIES")
        entries = self.test("List all entries", "GET", "/api/entries?limit=5")
        self.test("Filter by severity=critical", "GET", "/api/entries?severity=critical&limit=5")
        self.test("Filter by hive=HKCU", "GET", "/api/entries?hive=HKCU&limit=5")
        self.test("Filter has_chain=true", "GET", "/api/entries?has_chain=true&limit=5")
        
        # Get first entry for detailed tests
        first_id = 1
        if entries and entries.get("entries"):
            first_id = entries["entries"][0].get("id", 1)
            
        self.test(f"Get specific entry (ID {first_id})", "GET", f"/api/entries/{first_id}")
        self.test("Get entry with chain", "GET", f"/api/entries/{first_id}?include_chain=true")
        self.test("Get attack chain", "GET", f"/api/entries/{first_id}/chain")
        
        # 3. SCANNING OPERATIONS
        self.header("3. SCANNING OPERATIONS (Background Tasks)")
        self.test("Scan registry", "POST", "/api/scan", {"extended": False})
        time.sleep(1)
        
        self.test("Scan scheduled tasks", "POST", "/api/scan-tasks")
        time.sleep(1)
        
        self.test("Scan services", "POST", "/api/scan-services")
        time.sleep(1)
        
        self.test("Collect Sysmon (24h)", "POST", "/api/collect-sysmon", {"hours_back": 24})
        time.sleep(1)
        
        self.test("Collect 4688 events (24h)", "POST", "/api/collect-events", {"hours_back": 24})
        time.sleep(1)
        
        if full:
            self.test("Full collection (all)", "POST", "/api/collect-all", {"hours_back": 24})
            time.sleep(2)
            
        # 4. CHAIN OPERATIONS
        self.header("4. CHAIN OPERATIONS")
        self.test("Rebuild chain for entry", "POST", f"/api/rebuild-chain/{first_id}")
        
        if full:
            self.test("Rebuild all chains", "POST", "/api/rebuild-all-chains?severity=high,critical")
            
        # 5. PROCESS EVENTS (4688)
        self.header("5. PROCESS EVENTS (4688)")
        self.test("List 4688 processes", "GET", "/api/processes?limit=5")
        self.test("Search processes by name", "GET", "/api/processes?name=reg&limit=5")
        self.test("Filter by hours_back", "GET", "/api/processes?hours_back=24&limit=5")
        
        # 6. SYSMON PROCESS EVENTS
        self.header("6. SYSMON PROCESS EVENTS")
        self.test("List Sysmon processes", "GET", "/api/sysmon-processes?limit=5")
        self.test("Filter by PID", "GET", "/api/sysmon-processes?pid=1&limit=5")
        self.test("Filter by parent PID", "GET", "/api/sysmon-processes?parent_pid=0&limit=5")
        
        # 7. SYSMON REGISTRY EVENTS
        self.header("7. SYSMON REGISTRY EVENTS")
        self.test("List registry events", "GET", "/api/registry-events?limit=5")
        self.test("Search by key path", "GET", "/api/registry-events?key_path=Run&limit=5")
        self.test("Search by value name", "GET", "/api/registry-events?value_name=Spotify&limit=5")
        
        # 8. SCHEDULED TASKS
        self.header("8. SCHEDULED TASKS")
        tasks = self.test("List all tasks", "GET", "/api/tasks?limit=5")
        self.test("Filter tasks by severity", "GET", "/api/tasks?severity=high&limit=5")
        self.test("Filter by enabled", "GET", "/api/tasks?enabled=true&limit=5")
        
        # 9. SERVICES
        self.header("9. SERVICES")
        services = self.test("List all services", "GET", "/api/services?limit=5")
        self.test("Filter services by severity", "GET", "/api/services?severity=critical&limit=5")
        
        # 10. WRITER LOOKUP
        self.header("10. WRITER LOOKUP")
        self.test("Lookup writer by entry_id", "GET", f"/api/writer-lookup?entry_id={first_id}")
        self.test("Lookup writer by path", "GET", "/api/writer-lookup?reg_path=HKCU%5CSoftware%5CMicrosoft%5CWindows%5CCurrentVersion%5CRun&value_name=Test")
        
        # 11. FRONTEND / UI
        self.header("11. FRONTEND / UI")
        self.test("UI endpoint", "GET", "/ui")
        self.test("Static assets (may 404)", "GET", "/app/", expected_status=404)
        
        # 12. ERROR HANDLING
        self.header("12. ERROR HANDLING")
        self.test("Non-existent entry (expect 404)", "GET", "/api/entries/999999", expected_status=404)
        self.test("Invalid severity (returns empty)", "GET", "/api/entries?severity=invalid&limit=5")
        self.test("Missing writer params (expect 400)", "GET", "/api/writer-lookup", expected_status=400)
        
        # 13. DESTRUCTIVE (only if full mode)
        if full:
            self.header("13. DESTRUCTIVE OPERATIONS")
            self.test("Delete non-existent entry (expect 404)", "DELETE", "/api/entries/999999", expected_status=404)
        
        # SUMMARY
        self.header("TEST SUMMARY")
        total = self.passed + self.failed
        self.log(f"Total Tests: {total}", Colors.BOLD)
        self.log(f"Passed:      {self.passed}", Colors.GREEN if self.failed == 0 else Colors.GREEN)
        self.log(f"Failed:      {self.failed}", Colors.RED if self.failed > 0 else Colors.GREEN)
        
        if stats:
            self.log(f"\nCurrent DB Stats:", Colors.CYAN)
            s = stats.get("stats", stats)  # Handle nested or flat structure
            self.log(f"  Registry Entries: {s.get('total', 'N/A')}", Colors.GRAY)
            self.log(f"  Critical: {s.get('critical', 0)}, High: {s.get('high', 0)}, Medium: {s.get('medium', 0)}, Low: {s.get('low', 0)}", Colors.GRAY)
            self.log(f"  4688 Events: {s.get('process_events', 0)}", Colors.GRAY)
            self.log(f"  Sysmon Events: {s.get('sysmon_events', 0)}", Colors.GRAY)
            if "tasks" in s:
                t = s["tasks"]
                self.log(f"  Tasks: {t.get('total', 0)} total", Colors.GRAY)
            if "services" in s:
                sv = s["services"]
                self.log(f"  Services: {sv.get('total', 0)} total", Colors.GRAY)
        
        return self.failed


def main():
    parser = argparse.ArgumentParser(description="Test RegHunt API")
    parser.add_argument("--base-url", default="http://localhost:8000", help="API base URL")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--full", action="store_true", help="Include full scans and destructive tests")
    
    args = parser.parse_args()
    
    tester = ApiTester(args.base_url, args.verbose)
    
    try:
        failed = tester.run_all_tests(full=args.full)
        sys.exit(failed)
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(1)


if __name__ == "__main__":
    main()