import datetime
import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

import capstone
import pefile
import peutils
import ppdeep

import pegreet.inout


def info(pe: pefile.PE) -> dict[str, Any]:
    if not isinstance(pe, pefile.PE):
        raise Exception('invalid argument pe_file; must be pefile.PE')

    # init return dict
    d: dict[str, Any] = dict()  # TODO: initialize dict here to populate defaults
    raw = bytes(pe.__data__)

    # load helper data here

    # sus_dict
    try:
        with open(Path('data/annotation_dictionary.json')) as f:
            sus_dict = json.load(f)
    except Exception as e:
        print('problem loading annotation dictionary')
        raise e

    # peid db
    try:
        peid_db = peutils.SignatureDatabase(Path('data/userdb.txt'))
    except Exception as e:
        print('problem loading peid database')
        raise e

    # --- file ---

    # d['filename']  # TODO: would need to pass this as an argument

    d['size'] = len(raw)

    d['md5'] = hashlib.md5(raw).hexdigest()
    d['sha1'] = hashlib.sha1(raw).hexdigest()
    d['sha256'] = hashlib.sha256(raw).hexdigest()
    d['imphash'] = pe.get_imphash()

    d['ssdeep'] = ppdeep.hash(raw)

    def entropy(data: bytes) -> float:
        p, lns = Counter(data), float(len(data))
        return -sum(count/lns * math.log(count/lns, 2) for count in p.values())
    d['entropy'] = entropy(raw)

    # --- warnings ---

    d['parsing_warnings'] = pe.get_warnings()

    # --- headers ---

    d['timestamp'] = datetime.datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat()

    if pe.is_driver():
        d['pe_type'] = 'driver'
    elif pe.is_dll():
        d['pe_type'] = 'dll'
    elif pe.is_exe():
        d['pe_type'] = 'exe'
    else:
        d['pe_type'] = 'unknown'

    d['machine'] = pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine][19:]

    match pe.OPTIONAL_HEADER.Magic:
        case pefile.OPTIONAL_HEADER_MAGIC_PE:
            d['pe_magic'] = '32 bit'
        case pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
            d['pe_magic'] = '62 bit'
        case _:
            d['pe_magic'] = 'unknown'

    d['subsystem'] = pefile.SUBSYSTEM_TYPE[pe.OPTIONAL_HEADER.Subsystem][16:]

    d['image_size'] = hex(pe.OPTIONAL_HEADER.SizeOfImage)
    d['image_base'] = hex(pe.OPTIONAL_HEADER.ImageBase)
    d['entry_point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    # TODO: test no match
    # TODO: try match_all()

    d['peid'] = peid_db.match(pe) if peid_db else None

    # TODO: dll characteristics

    # --- sections ---

    d['sections'] = []  # TODO: rethink the structure of this
    for section in pe.sections:
        pot_flags = sorted(pefile.retrieve_flags(pefile.SECTION_CHARACTERISTICS, 'IMAGE_SCN_'))
        section_flags = []
        for flag in sorted(pot_flags):
            if getattr(section, flag[0]):
                section_flags.append(flag[0][10:])
        d['sections'].append({
            'name': section.Name.rstrip(b'\x00').decode(),
            'vaddr': hex(section.VirtualAddress),
            'vsize': hex(section.Misc_VirtualSize),
            'rsize': hex(section.SizeOfRawData),
            'entropy': section.get_entropy(),
            'flags': section_flags,
        })
    # TODO: section hashes

    # --- imports ---

    def sus_check(imp_name: str) -> dict[str, str] | None:
        return sus_dict.get(imp_name)

    d['imports'] = []  # TODO: rethink the structure of this
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            d['imports'].append({
                'dll': entry.dll.decode(),
                'imported_functions': [{
                    'name': imp.name.decode(),
                    'address': hex(imp.address),
                    'ordinal': imp.ordinal,
                    'annotation': sus_check(imp.name.decode()),
                } for imp in entry.imports]
            })

    # --- exports ---

    d['exports'] = []  # TODO: rethink the structure of this
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            # TODO: add suscheck to exports
            d['exports'].append({
                'name': exp.name.decode(),
                'address': hex(pe.OPTIONAL_HEADER.ImageBase + exp.address),
                'ordinal': exp.ordinal,
            })

    return d


def find_strings(pe: pefile.PE) -> dict[str, list[str]]:
    raw = bytes(pe.__data__)

    # many ways to get strings from raw
    # i will try regex for both collection and categorization

    string_pattern = re.compile(rb'[\x20-\x7f]{5,}')

    cat_patterns = {
        'url': re.compile(b'(https?|smb|s?ftp|file|mailto|irc|data)://', re.IGNORECASE),
        'ip': re.compile(
            b'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'),
        'registry': re.compile(b'HKEY_'),
        'path': re.compile(b'[a-z]:\\\\', re.IGNORECASE),
        'file': re.compile(b'.txt', re.IGNORECASE),
    }

    cat_strings: dict[str, list[str]] = {
        'url': [],
        'ip': [],
        'registry': [],
        'path': [],
        'file': [],
        'uncategorized': [],
    }

    strings_list = string_pattern.findall(raw)
    for string_item in strings_list:
        categorized = False
        for cn, cp in cat_patterns.items():
            if cp.match(string_item):
                cat_strings[cn].append(string_item.decode())
                categorized = True
        if not categorized:  # can't for-else since all patterns should be tested for each str
            cat_strings['uncategorized'].append(string_item.decode())

    return cat_strings


def disasm(pe: pefile.PE, num_lines: int) -> str:
    # TODO: support custom addr

    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    epa = ep + pe.OPTIONAL_HEADER.ImageBase
    data = pe.get_memory_mapped_image()[ep:]
    # TODO: make this dynamic based on machine type and optional magic value
    disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

    dlines = ''
    for index, instruction in enumerate(disassembler.disasm(data, epa)):
        if index < num_lines:
            dlines += f'0x{instruction.address:<12x}{instruction.mnemonic:<10}{instruction.op_str:<20}\n'
        else:
            break
    return dlines
