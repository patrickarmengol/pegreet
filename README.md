# PEgreet

Greet your samples before you tear them apart.

PEgreet is a tool that performs static analysis and feature extraction on Portable Executable files. It should help with your first steps in analyzing a malware sample.

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

#### In Progress

- recognize __known malicious section names__

#### To Do

- annotate __suspicious entropy__ and __size mismatches__
- extract __resources__
- lookup on __VirusTotal__
- lookup for __public sandbox reports__
- check file against __YARA__ rules
- check __digital signature__
- sort __strings__ with [StringSifter](https://github.com/fireeye/stringsifter)
- extract __obfuscated strings__ with [FLOSS](https://github.com/fireeye/flare-floss)
- __custom output__ (csv, json, markdown)
- __modular design__

## Screenshots

![i](/media/i.png?raw=true)

## Installation

PEgreet uses Python 3

#### Get PEgreet
```
git clone https://github.com/patrickarmengol/PEgreet.git
cd PEgreet
```

#### Install Required Dependencies

- [pefile](https://github.com/erocarrera/pefile)

```
pip install -r requirements.txt
```

#### Install Optional Dependencies

- [ssdeep](https://ssdeep-project.github.io/ssdeep/index.html) + [python-ssdeep](https://github.com/DinoTools/python-ssdeep) for generating ssdeep hashes
- [capstone](http://www.capstone-engine.org/) for code disassembly

```
(install ssdeep using package manager)
pip install -r optional-requirements.txt
```

## Usage

```
usage: pegreet.py [-h] [-i] [-s [{c,a}]] [-d N] file

a tool to perform static analysis and feature extraction on Portable Executable files

positional arguments:
  file        the file's path

optional arguments:
  -h, --help  show this help message and exit
  -i          print useful info
  -s [{c,a}]  print strings - [c]ategorized (default) or [a]ll
  -d N        disassemble a specified number instructions from entry point
```

## Notes

I started this project in an attempt to learn about PE files and feature extraction for use in malware data science.

There are many other (better) tools available that implement similar functionality (see below). What I tried to do with PEgreet is to focus on only the features that are useful to malware analysis to make it easier to digest the information. PEgreet also provides annotations for suspicious indicators that can be used as jumping points for an investigation.

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
