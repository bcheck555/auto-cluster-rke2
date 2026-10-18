#!/usr/bin/env python3
"""Destroy the local RKE2 lab, including partial deployments and disk files."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lab.libvirt.lifecycle import main

if __name__ == '__main__':
    sys.exit(main('destroy'))
