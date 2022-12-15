import datetime
import hashlib
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any

import pefile
import peutils
import ppdeep

import pegreet.inout


def info(pe_file: pefile.PE | Path) -> dict[str, Any]:
    if isinstance(pe_file, Path):
        pe = pegreet.inout.load(pe_file)
    elif isinstance(pe_file, pefile.PE):
        pe = pe_file
    else:
        raise Exception('invalid argument pe_file; must be pefile.PE or pathlib.Path')

    # init return dict
    d: dict[str, Any] = dict()  # TODO: initialize dict here to pop defaults
    raw = bytes(pe.__data__)  # TODO: how do i avoid an error here

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

    # d['filename']

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


def find_strings() -> list[str]:
    pass
