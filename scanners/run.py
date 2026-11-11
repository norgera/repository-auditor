"""Start one scanner: python -m scanners.run s1"""
import os
import sys

from scanner_kit import serve
from scanners import ADAPTERS, PORTS


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ADAPTERS:
        sys.exit(f"usage: python -m scanners.run {{{','.join(ADAPTERS)}}}")
    sid = sys.argv[1]
    os.environ.setdefault("PORT", str(PORTS[sid]))
    serve(ADAPTERS[sid]())


if __name__ == "__main__":
    main()
