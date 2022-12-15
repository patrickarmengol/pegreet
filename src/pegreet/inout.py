import sys
from pathlib import Path

import pefile


def load(filepath: Path) -> pefile.PE:
    try:
        pe = pefile.PE(filepath)
    except pefile.PEFormatError:
        print('file not in valid PE format')
        sys.exit()
    return pe
