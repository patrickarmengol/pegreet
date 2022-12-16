import sys
from pathlib import Path
from typing import Any

import pefile


def load(filepath: Path) -> pefile.PE:
    try:
        pe = pefile.PE(filepath)
    except pefile.PEFormatError:
        print('file not in valid PE format')
        sys.exit()
    return pe


def pretty_info(info_dict: dict[str, Any]) -> str:
    # TODO: color coding per value type

    file_keys = ['size', 'md5', 'sha1', 'sha256', 'imphash', 'ssdeep', 'entropy', 'parsing_warnings']
    file_info = '\n'.join([f'{k:20}{info_dict[k]}' for k in file_keys])
    file_wall = f"""
--- general info ---
{file_info}
"""

    headers_keys = ['timestamp', 'pe_type', 'machine', 'pe_magic',
                    'subsystem', 'image_size', 'image_base', 'entry_point']
    headers_info = '\n'.join([f'{k:20}{info_dict[k]}' for k in headers_keys])
    headers_wall = f"""
--- pe info ---
{headers_info}
"""

    sections_keys = ['name', 'vaddr', 'vsize', 'rsize', 'entropy', 'flags']
    column_paddings = [10, 12, 12, 12, 24, 10]
    sections_columns = ''.join(f'{k:{p}}' for k, p in zip(sections_keys, column_paddings))
    sections_info = '\n'.join(
        ''.join(f'{str(section_dict[k]):{p}}' for k, p in zip(sections_keys, column_paddings))
        for section_dict in info_dict['sections']
    )
    sections_wall = f"""
--- sections ---
{sections_columns}
{sections_info}
"""

    # TODO: color code
    imports_info = '\n\n'.join(
        f'{entry["dll"]}' + '\n'
        + '\n'.join(f'{"":4}{imp["address"]:12}{imp["name"]}{" " + ("-" * (40 - len(imp["name"]))) + " " + imp["annotation"]["description"] if imp["annotation"] else ""}'
                    for imp in entry['imported_functions'])
        for entry in info_dict['imports']
    )
    imports_wall = f"""
--- imports ---
{imports_info}
"""

    exports_info = '\n'.join(
        f'{export["address"]:12}{export["name"]:40}{"ord[" + export["ordinal"] + "]" if export["ordinal"] else ""}' for export in info_dict['exports'])
    exports_wall = f"""
--- exports ---
{exports_info}
"""

    wall = file_wall + headers_wall + sections_wall + imports_wall + exports_wall
    return wall


def pretty_strings(string_dict: dict[str, list[str]], show_uncategorized: bool = False) -> str:
    return '\n\n'.join(f'--- {cn} ---' + '\n' + '\n'.join(cl) for cn, cl in string_dict.items() if cn != 'uncategorized' or (cn == 'uncategorized' and show_uncategorized))
