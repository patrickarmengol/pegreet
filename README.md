# pegreet

[![PyPI - Version](https://img.shields.io/pypi/v/pegreet.svg)](https://pypi.org/project/pegreet)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/pegreet.svg)](https://pypi.org/project/pegreet)


Greet your malware samples before you tear them apart.

`pegreet` is a tool that performs static analysis and feature extraction on Portable Executable files. As a cli app, it should help with first steps in malware analysis / reverse engineering. As a library, it can be used to extract useful information from samples in bulk for use in exploratory data analysis or building malware classification models. 

---

**Table of Contents**

- [Features](#features)
- [Screenshots](#screenshots)
- [Installation](#installation)
- [Resources](#resources)
- [Notes](#notes)
- [License](#license)

## Features

#### Implemented

- dump __general file information__
- compute __hashes__ (MD5, SHA1, SHA256, Imphash, SSDEEP)
- calculate __entropy__
- detect __packers__ via PEiD signatures
- dump info from __headers__
- dump info from __sections__
- dump __imports and exports__
- annotate __suspicious Windows API functions__
- display file parsing __warnings__
- __disassemble code__ from entry point
- find __strings__
- categorize __strings__

#### To Do

- recognize __known malicious section names__
- annotate __suspicious entropy__ and __size mismatches__
- extract __resources__
- lookup on __VirusTotal__
- lookup for __public sandbox reports__
- check file against __YARA__ rules
- check __digital signature__
- sort __strings__ with [StringSifter](https://github.com/fireeye/stringsifter)
- extract __obfuscated strings__ with [FLOSS](https://github.com/fireeye/flare-floss)
- __custom output__ (csv, json, markdown)


## Screenshots

![i](/media/i.png?raw=true)


## Installation

### as a module

```console
<virtual environment shenanigans>
pip install pegreet
```

### as a cli app

```console
pipx install pegreet
```

---

## Usage

### as a module
```
from pathlib import Path
import pegreet

pe = pegreet.load(Path('data/samples/petya.exe'))

info_data = pegreet.info(pe)
print(info_data)
print(pegreet.pretty_info(info_data))

strings_data = pegreet.find_strings(pe)
print(strings_data)
print(pegreet.pretty_strings(strings_data))

print(pegreet.disasm(pe, num_lines=40))
```


### as a cli app
```
$ pegreet --help

 Usage: pegreet [OPTIONS] COMMAND [ARGS]...

╭─ Options ───────────────────────────────────────────╮
│ --help                        Show this message and │
│                               exit.                 │
╰─────────────────────────────────────────────────────╯
╭─ Commands ──────────────────────────────────────────╮
│ disassemble  disassemble a specified number         │
│              instructions from entry point          │
│ info         print useful info                      │
│ strings      print strings                          │
╰─────────────────────────────────────────────────────╯


$ pegreet info data/samples/petya.exe
...


$ pegreet strings --show-uncategorized data/samples/petya.exe
...


$ pegreet disassemble data/samples/petya.exe 40
...
```

## Notes

I started this project in 2020 in an attempt to learn about PE files and feature extraction for use in malware data science.

There are many other (better) tools available that implement similar functionality (see below). What I tried to do with `pegreet` is to focus on only the features that are useful to malware analysis to make it easier to digest the information. `pegreet` also provides annotations for suspicious indicators that can be used as jumping points for an investigation.

The [pefile](https://github.com/erocarrera/pefile) library was used extensively to implement the parsing of PE files. I would like to explore using the [LIEF](https://github.com/lief-project/LIEF) project instead as it supports multiple executable formats and it was used in the [EMBER](https://github.com/endgameinc/ember) dataset. Maybe I'll follow this project up with an 'ELFgreet'.

## Resources

#### Similar Tools

- [pefile](https://github.com/erocarrera/pefile) - python library for reading PE info
- [peframe](https://github.com/guelfoweb/peframe) - PE analysis tool
- [PEpper](https://github.com/Th3Hurrican3/PEpper) - PE analysis tool
- [PEcli](https://github.com/Te-k/pecli) - PE analysis tool
- [PPEE](https://www.mzrst.com/) - PE analysis tool
- [PE Studio](https://winitor.com/index.html) - PE analysis tool
- [pev](http://pev.sourceforge.net/) - PE analysis tool
- [pecheck](https://blog.didierstevens.com/2019/10/27/update-pecheck-py-version-0-7-8/) - PE analysis tool
- [PE-bear](https://hshrzd.wordpress.com/pe-bear/) - PE analysis tool
- [PE-sieve](https://hshrzd.wordpress.com/pe-sieve/) - scans live PEs for suspicious indicators and dumps
- [PE_unmapper](https://hshrzd.wordpress.com/pe_unmapper/) - convert dump to raw
- [IAT Patcher](https://hshrzd.wordpress.com/iat-patcher/) - IAT editor

#### PE file info

- [corkami PE101](https://github.com/corkami/pics/tree/master/binary/pe101) and [PE102](https://github.com/corkami/pics/tree/master/binary/pe102) - fantastic visualizations
- [corkami PE wiki](https://code.google.com/archive/p/corkami/wikis/PE.wiki) - lots of info
- [corkami PE POCs](https://github.com/corkami/pocs/tree/master/PE) - cool/weird stuff
- [PE format layout graph](https://drive.google.com/file/d/0B3_wGJkuWLytbnIxY1J5WUs4MEk/view) - nice visualization
- [PE format walkthrough](https://drive.google.com/file/d/0B3_wGJkuWLytQmc2di0wajB1Xzg/view) - overlay of PE format on raw hex
- [PE Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format) - PE documentation by MS
- [An In-Depth Look into the Win32 Portable Executable File Format Part 1](https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/february/inside-windows-win32-portable-executable-file-format-in-detail) and [Part 2](https://docs.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2) - writeups by MS


## License

`pegreet` is distributed under the terms of any of the following licenses:

- [Apache-2.0](https://spdx.org/licenses/Apache-2.0.html)
- [MIT](https://spdx.org/licenses/MIT.html)
