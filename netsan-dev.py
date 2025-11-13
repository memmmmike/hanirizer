#!/usr/bin/env python3
"""
Development wrapper for netsan - runs directly from source
Use this instead of 'netsan' to test changes without reinstalling
"""

import sys
from pathlib import Path

# Add project root to path (not src)
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import and run CLI
from src.cli import main

if __name__ == "__main__":
    main()
