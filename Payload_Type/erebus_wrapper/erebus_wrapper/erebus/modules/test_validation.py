#!/usr/bin/env python3
"""Quick test of the plugin validation system"""

import sys
import os
from pathlib import Path

# Change to modules directory
os.chdir(Path(__file__).parent)
sys.path.insert(0, str(Path(__file__).parent))

# Import as if we're in the modules directory
import __init__ as modules

if __name__ == "__main__":
    print("[+] Plugin Validation Test")
    print("=" * 60)
    
    results = modules.get_initialization_results()
    passed = modules.get_validated_plugins()
    failed = modules.get_failed_plugins()
    
    print(f"\nValidation Results:")
    print(f"  Total Plugins: {results['total']}")
    print(f"  Passed: {results['passed_count']}")
    print(f"  Failed: {results['failed_count']}")
    
    if passed:
        print(f"\n✓ Passed ({len(passed)}):")
        for name in sorted(passed.keys()):
            print(f"    - {name}")
    
    if failed:
        print(f"\n✗ Failed ({len(failed)}):")
        for name, error in sorted(failed.items()):
            print(f"    - {name}: {error}")
    
    print("\n" + "=" * 60)
    print("[+] Test complete")
