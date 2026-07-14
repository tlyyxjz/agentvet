"""Pytest configuration — ensures the project root is on sys.path so that
`from scanner.engine import ScanEngine` works when running tests without
installing the package."""
import sys
from pathlib import Path

# The project root is the parent of the tests/ directory.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))
