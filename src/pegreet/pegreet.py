import argparse
import os
import sys
import json
import datetime
import hashlib
import math
import re
from collections import Counter
try:
    import pefile # ext | req
    import peutils # ext | req
except ImportException:
    print('required library pefile not installed, see https://github.com/erocarrera/pefile')
    sys.exit()
try:
    import ssdeep # ext | opt
    ssdeep_imported = True
except ImportException:
    #print('optional library \'ssdeep\' not installed, see https://github.com/DinoTools/python-ssdeep')
    ssdeep_imported = False
try:
    import capstone # ext | opt
    capstone_imported = True
except ImportException:
    #print('optional library \'capstone\' not installed, see http://www.capstone-engine.org/documentation.html')
    capstone_imported = False

# colors
DEFAULT = '\033[39m'
CYAN = '\033[36m'
GREEN = '\033[32m'
RED = '\033[31m'
ORANGE = '\033[33m'
YELLOW = '\033[93m'
WHITE = '\033[97m'
GREY = '\033[90m'


def dump_warnings():
    warnings = pe.get_warnings()
    if warnings:
        print('\n---------- parsing warnings ----------')
        for warning in warnings:
            print('>',warning)

def dump_file_info():
    print('\n---------- general info ----------')

    raw = bytes(pe.__data__)

    print('{:<20}{:<}'.format('filename:', args.file))

    #size
    print('{:<20}{:<} {}'.format('size', len(raw), 'bytes'))

    # hash
    print('{:<20}{:<}'.format('md5:', hashlib.md5(raw).hexdigest()))
    print('{:<20}{:<}'.format('sha1:', hashlib.sha1(raw).hexdigest()))
    print('{:<20}{:<}'.format('sha256:', hashlib.sha256(raw).hexdigest()))

    # imphash
    print('{:<20}{:<}'.format('imphash:', pe.get_imphash()))

    # ssdeep
    if ssdeep_imported:
        print('{:<20}{:<}'.format('ssdeep:', ssdeep.hash(raw)))

    # entropy
    print('{:<20}{:<f}'.format('entropy:', entropy_calc(raw)))

    # todo: vt detection count + keyword; see https://www.academia.edu/39543734/Selecting_Prominent_API_Calls_and_Labeling_Malicious_Samples_for_Effective_Malware_Family_Classification
    # vt link

    # nsrl

    # pub sandbox lookup?

def dump_header_info():
    print('\n---------- pe info ----------')

    # timestamp
    print('{:<20}{:<}'.format('timestamp:', datetime.datetime.utcfromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat()))

    # exe/dll/driver
    if pe.is_driver():
        pe_type = 'driver'
    elif pe.is_dll():
        pe_type = 'dll'
    elif pe.is_exe():
        pe_type = 'exe'
    print('{:<20}{:<}'.format('type:', pe_type))

    # machine
    print('{:<20}{:<}'.format('machine:', pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine][19:]))

    # characteristics - currently replaced by the exe/dll/driver check above
    # image_flags = pefile.retrieve_flags(pefile.IMAGE_CHARACTERISTICS, 'IMAGE_FILE_')
    # flags = []
    # for flag in sorted(image_flags):
    #     if getattr(pe.FILE_HEADER, flag[0]):
    #         flags.append(flag[0][11:])
    # if flags:
    #     print('{:<20}{:<}'.format('characteristics:', ', '.join(flags)))

    # magic
    if pe.OPTIONAL_HEADER.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE:
        pe_magic = '32 bit'
    elif pe.OPTIONAL_HEADER.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
        pe_magic = '64 bit'
    print('{:<20}{:<}'.format('magic:', pe_magic))

    # subsystem
    print('{:<20}{:<}'.format('subsystem:', pefile.SUBSYSTEM_TYPE[pe.OPTIONAL_HEADER.Subsystem][16:]))

    # todo: add comparison to size on disk
    # image size
    print('{:<20}{:<}'.format('image size:', hex(pe.OPTIONAL_HEADER.SizeOfImage)))

    # image base
    print('{:<20}{:<}'.format('image base:', hex(pe.OPTIONAL_HEADER.ImageBase)))

    # entry point
    print('{:<20}{:<}'.format('entry point:', hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)))

    # peid check
    if peid_db:
        peid_result = peid_check()
        print('{:<20}{:<}'.format('peid:', str(peid_result).strip('[\']') if peid_result else 'None'))

    # todo: dll characteristics


def dump_sections():
    print('\n---------- sections ----------')
    if pe.sections:
        print('{:<10}{:<16}{:<16}{:<16}{:<16}{:<16}'.format('name','virtual addr','virtual size','raw size','entropy','flags'))
        section_flags = pefile.retrieve_flags(pefile.SECTION_CHARACTERISTICS, 'IMAGE_SCN_')
        for section in pe.sections:
            s_name = section.Name.rstrip(b'\x00').decode()
            s_vaddr = hex(section.VirtualAddress)
            s_vsize = hex(section.Misc_VirtualSize)
            s_rsize = hex(section.SizeOfRawData)
            s_entropy = section.get_entropy()
            flags = []
            for flag in sorted(section_flags):
                if getattr(section, flag[0]):
                    flags.append(flag[0][10:])
            s_flags = ', '.join(flags)
            print('{:<10}{:<16}{:<16}{:<16}{:<16f}{:<}'.format(s_name,s_vaddr,s_vsize,s_rsize,s_entropy,s_flags))
            # todo: figure out how to fit hashes in here
            # want to keep horizontal consiseness
            # maybe below the table?

def dump_imports():
    print('\n---------- imports ----------')
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(entry.dll.decode())
            # todo: clean this up; messy af
            for imp in entry.imports:
                imp_address = hex(imp.address)
                imp_name = imp.name.decode() if imp.name else ''
                # stripping suffixes here simplifies writing the annotation dictionary
                stripped_imp_name = imp_name
                for suffix in ['ExA','ExW','A','W','Ex']:
                    if imp_name.endswith(suffix):
                        stripped_imp_name = imp_name[:-(len(suffix))]
                        # print('converted {} to {}'.format(imp_name,stripped_imp_name))
                        break
                imp_annot = ''
                if sus_dict and imp_name:
                    imp_annot = sus_check(stripped_imp_name)
                elif imp.import_by_ordinal and not imp_name:
                    imp_ordinal = 'Ordinal [{}]'.format(imp.ordinal)
                # todo: add colors to func based on category
                # todo: should addr<->func spacing be static?
                # todo: remove addr?
                # todo: not addr, just offset?
                if imp_annot:
                    print('{:<8}{:<12}{:<}{:<}'.format('', imp_address, CYAN+imp_name+DEFAULT, GREY+' - '+imp_annot['description']+DEFAULT))
                else:
                    print('{:<8}{:<12}{:<}'.format('', imp_address, imp_name if imp_name else imp_ordinal))
    else:
        print('no imports')

def dump_exports():
    print('\n---------- exports ----------')
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exp_name = exp.name.decode()
            # todo: add suscheck
            print(hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp_name, exp.ordinal)
    else:
        print('no exports')

def dump_disassembly(lines):
    print('\n---------- code ----------')
    if not capstone_imported:
        print('this option requires capstone')
        return
    # todo: support custom addr
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    epa = ep + pe.OPTIONAL_HEADER.ImageBase
    data = pe.get_memory_mapped_image()[ep:]
    # todo: make this dynamic based on machine type and optional magic value
    disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    for index,instruction in enumerate(disassembler.disasm(data, epa)):
        if index < lines:
            print('0x{:<12x}{:<10}{:<20}'.format(instruction.address, instruction.mnemonic, instruction.op_str))
        else:
            break

def dump_strings(option):

    raw = bytes(pe.__data__)

    # many ways to get strings from raw
    # i will try regex for both collection and categorization

    # define all strings
    strings_match = re.compile(b'[\x20-\x7f]{5,}')

    categories = {
        'url': {
            'match': re.compile(b'(https?|smb|s?ftp|file|mailto|irc|data)://', re.IGNORECASE),
            'list': []
        },
        'ip': {
            'match': re.compile(b'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'),
            'list': []
        },
        'registry': {
            'match': re.compile(b'HKEY_'),
            'list': []
        },
        'path': {
            'match': re.compile(b'[a-z]:\\\\', re.IGNORECASE),
            'list': []
        },
        'file': {
            # not too sure how to match files without catching a bunch of garbage
            'match': re.compile(b'.txt', re.IGNORECASE),
            'list': []
        }
    }
    uncategorized_list = []

    strings_list = strings_match.findall(raw)
    if strings_list:
        for string_item in strings_list:
            categorized = False
            for catdata in categories.values():
                if catdata['match'].match(string_item):
                    catdata['list'].append(string_item.decode())
                    categorized = True
            if not categorized:
                uncategorized_list.append(string_item.decode())
    for catname, catdata in categories.items():
        if catdata['list']:
            print('\n-- ' + catname + ' --')
            for string_item in catdata['list']:
                print(string_item)
    if option == 'a':
        print('\n-- uncategorized --')
        for string_item in uncategorized_list:
            print(string_item)



def sus_load():
    try:
        with open('annotation_dictionary.json') as fp:
            return json.load(fp)
    except:
        print('problem loading \'annotation_dictionary.json\'')
        return

def sus_check(string_to_check):
    # todo: explore a wildcard/regex approach
    # https://www.sciencedirect.com/science/article/pii/S016740481831246X
    # dict = [('a.*', 'asdf'),('b.*', 'qwer')]
    # def lookup(s, dict):
    # for pattern, value in dict:
    #     if re.search(pattern, s):
    #         return value
    # return None
    try:
        return sus_dict[string_to_check]
    except:
        return

def peid_load():
    try:
        # todo: allow user's peid db
        # db_file = args.db instead of ''
        # or maybe do this in main and pass as arg
        db_file = ''
        if db_file == '':
            db_file = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'userdb.txt')
        if os.path.exists(db_file):
            return peutils.SignatureDatabase(db_file)
        else:
            print('problem loading peid database file')
            return
    except:
        print('problem loading peid database file')
        return

def peid_check():
    # todo: try match_all()
    # todo: test no match
    return peid_db.match(pe)

def entropy_calc(data):
    # i stole this from rosetta code
    # test if equivalent to pefile section get_entropy()
    p, lns = Counter(data), float(len(data))
    return -sum( count/lns * math.log(count/lns, 2) for count in p.values())

#---------------------------------------------


if __name__=='__main__':

    parser = argparse.ArgumentParser(description='a tool to perform static analysis and feature extraction on Portable Executable files')

    parser.add_argument('file', help='the file\'s path')
    parser.add_argument('-i', help='print useful info', action='store_true')
    parser.add_argument('-s', help='print strings - [c]ategorized (default) or [a]ll', choices=['c','a'], default='c', const='c', nargs='?')
    parser.add_argument('-d', help='disassemble a specified number instructions from entry point', metavar='N', type=int)
    #parser.add_argument('-d', help='print dump info via pefile', action='store_true')

    args = parser.parse_args()

    # todo: add support for directory walk
    # requires rewrite of other code
    try:
        pe = pefile.PE(args.file)
    except pefile.PEFormatError:
        print('file not in valid PE format')
        sys.exit()

    if args.i:
        sus_dict = sus_load()
        peid_db = peid_load()
        dump_file_info()
        dump_warnings() # where should this go?
        dump_header_info()
        dump_sections()
        dump_imports()
        dump_exports()

    # todo: add support for fireeye's floss and stringsifter
    if args.s:
        dump_strings(args.s)

    if args.d:
        dump_disassembly(args.d)

    if args.d:
        pe.print_info()

    # todo: yara
    # todo: resource extraction

    print() # trailing space
