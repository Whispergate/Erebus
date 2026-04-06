# Erebus Modules Test Suite

This directory contains comprehensive tests for all Erebus plugins and archived modules.

## Test Coverage

### Archive Modules
- `test_container_msi.py` - MSI container creation and hijacking
- `test_codesigner.py` - Code signing functionality
- `test_container_iso.py` - ISO container generation
- `test_trigger_lnk.py` - LNK file trigger creation

### Plugin Modules
Tests for plugin wrappers are included in the respective archive module tests since plugins delegate to archive implementations.

## Running Tests

### Run All Tests
```powershell
python test_runner.py
```

### Run Individual Test
```powershell
python test_container_msi.py
python test_codesigner.py
python test_container_iso.py
python test_trigger_lnk.py
```

### Requirements
- Python 3.11+
- Windows environment (required for msilib, code signing, LNK creation)
- Test MSI file at: `D:\CyberSecurity\SharedDisk\temp\go1.26.0.windows-amd64.msi`

#### Core Dependencies (from requirements.txt)
```bash
pip install olefile pylnk3
```

#### Optional Dependencies (for specific tests)
```bash
# For codesigner tests
pip install cryptography

# For ISO container tests
pip install pycdlib
```

Tests will gracefully skip if optional dependencies are missing.

## Test Output
- Results printed to console
- Temp files created in system temp directory
- Failed tests exit with code 1
- Tests with missing dependencies return code 0 (skip)
