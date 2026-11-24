#!/usr/bin/env python3
"""Verify the standalone against the published SHA-256 manifest."""
import hashlib, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
expected, name = (ROOT / 'SHA256SUMS').read_text(encoding='utf-8').strip().split(maxsplit=1)
if len(sys.argv) > 2:
    raise SystemExit('Usage: python scripts/verify_release.py [html-file]')
path = Path(sys.argv[1]) if len(sys.argv) == 2 else ROOT / 'dist' / name
try:
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
except OSError as exc:
    raise SystemExit(str(exc))
print(f'Expected: {expected}\nActual:   {actual}')
if actual != expected:
    raise SystemExit('FAIL: SHA-256 mismatch')
print('OK: SHA-256 matches')
