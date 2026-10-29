"""
conftest.py - Pytest Configuration and Test Environment Setup
Ensures existing test files retain access to in-process adapters
via MAC_UNSAFE_INPROCESS_FOR_TESTS=1 without editing legacy test assertions.
"""

import os

# Default to in-process mode for tests to preserve all legacy test assertions untouched
os.environ.setdefault("MAC_UNSAFE_INPROCESS_FOR_TESTS", "1")
