"""
Erebus Modules Test Runner
===========================
Runs all test suites for plugins and archived modules.
"""

import sys
import pathlib
import subprocess
import time
from datetime import datetime


class TestRunner:
    """Orchestrates execution of all test suites"""
    
    def __init__(self):
        self.tests_dir = pathlib.Path(__file__).parent
        self.test_files = [
            ("MSI Container", "test_container_msi.py"),
            ("Code Signer", "test_codesigner.py"),
            ("ISO Container", "test_container_iso.py"),
            ("LNK Trigger", "test_trigger_lnk.py"),
        ]
        self.results = []
        
    def run_test(self, name, filename):
        """Run a single test file and capture results"""
        test_path = self.tests_dir / filename
        
        if not test_path.exists():
            return {
                "name": name,
                "file": filename,
                "status": "SKIP",
                "exit_code": -1,
                "duration": 0,
                "error": "Test file not found"
            }
        
        print(f"\n{'=' * 80}")
        print(f"Running: {name} ({filename})")
        print(f"{'=' * 80}")
        
        start_time = time.time()
        
        try:
            # Run test with Python from virtual environment
            python_exe = sys.executable
            
            result = subprocess.run(
                [python_exe, str(test_path)],
                capture_output=False,  # Let output stream to console
                cwd=str(self.tests_dir),
                timeout=300  # 5 minute timeout per test
            )
            
            duration = time.time() - start_time
            
            return {
                "name": name,
                "file": filename,
                "status": "PASS" if result.returncode == 0 else "FAIL",
                "exit_code": result.returncode,
                "duration": duration,
                "error": None
            }
            
        except subprocess.TimeoutExpired:
            duration = time.time() - start_time
            return {
                "name": name,
                "file": filename,
                "status": "TIMEOUT",
                "exit_code": -1,
                "duration": duration,
                "error": "Test exceeded 5 minute timeout"
            }
            
        except Exception as e:
            duration = time.time() - start_time
            return {
                "name": name,
                "file": filename,
                "status": "ERROR",
                "exit_code": -1,
                "duration": duration,
                "error": str(e)
            }
    
    def print_summary(self):
        """Print summary of all test results"""
        print("\n\n")
        print("=" * 80)
        print("TEST SUMMARY")
        print("=" * 80)
        
        total_duration = sum(r["duration"] for r in self.results)
        passed = sum(1 for r in self.results if r["status"] == "PASS")
        failed = sum(1 for r in self.results if r["status"] == "FAIL")
        errors = sum(1 for r in self.results if r["status"] == "ERROR")
        timeouts = sum(1 for r in self.results if r["status"] == "TIMEOUT")
        skipped = sum(1 for r in self.results if r["status"] == "SKIP")
        
        for result in self.results:
            status_symbol = {
                "PASS": "✓",
                "FAIL": "✗",
                "ERROR": "⚠",
                "TIMEOUT": "⏱",
                "SKIP": "⊘"
            }.get(result["status"], "?")
            
            duration_str = f"{result['duration']:.2f}s"
            print(f"\n  {status_symbol} {result['name']:20} {result['status']:8} [{duration_str:>8}]")
            
            if result["error"]:
                print(f"    Error: {result['error']}")
            
            if result["status"] == "FAIL":
                print(f"    Exit code: {result['exit_code']}")
        
        print("\n" + "-" * 80)
        print(f"Total Tests:  {len(self.results)}")
        print(f"Passed:       {passed}")
        print(f"Failed:       {failed}")
        if errors > 0:
            print(f"Errors:       {errors}")
        if timeouts > 0:
            print(f"Timeouts:     {timeouts}")
        if skipped > 0:
            print(f"Skipped:      {skipped}")
        print(f"Duration:     {total_duration:.2f}s")
        print("=" * 80)
        
        return failed + errors + timeouts
    
    def run_all(self):
        """Run all tests and return exit code"""
        print("\n" + "=" * 80)
        print("EREBUS MODULES TEST SUITE")
        print("=" * 80)
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Python: {sys.version.split()[0]}")
        print(f"Tests Directory: {self.tests_dir}")
        print("=" * 80)
        
        for name, filename in self.test_files:
            result = self.run_test(name, filename)
            self.results.append(result)
        
        failures = self.print_summary()
        
        return 0 if failures == 0 else 1


def main():
    """Main entry point"""
    runner = TestRunner()
    
    try:
        exit_code = runner.run_all()
        sys.exit(exit_code)
        
    except KeyboardInterrupt:
        print("\n\n" + "=" * 80)
        print("Tests interrupted by user")
        print("=" * 80 + "\n")
        sys.exit(1)
        
    except Exception as e:
        print(f"\n\nFATAL ERROR in test runner: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
