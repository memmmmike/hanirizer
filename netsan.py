#!/usr/bin/env python3
"""
Hanirizer CLI Entry Point
Run this script to use hanirizer from source without installation
"""
import sys
from pathlib import Path

# Add parent directory to Python path so we can import 'src' as a package
parent_dir = Path(__file__).parent
sys.path.insert(0, str(parent_dir))

# Now import from src package
from src.cli import main

if __name__ == "__main__":
    sys.exit(main())
