<p align="center">
  <img width=256 height=256 src="https://github.com/Dax89/REDasm/blob/master/artwork/logo.png?raw=true"/>
</p>

#
<p align="center">
  A crossplatform, multiarchitecture disassembler.
  <img height="450" src="https://github.com/Dax89/REDasm/blob/master/artwork/Screenshot.png?raw=true">
</p>

## Project Status

### Supported Formats
| Format | Supported | Info |
|--------|-----------|------|
| PE | Yes | VB6 can be decompiled, Delphi support is WIP |
| ELF | Yes ||
| PSX | Yes | PsyQ 4.7 signatures available |

### Supported Architectures
| Format | Capstone | Info |
|--------|-----------|------|
| x86 | Yes | |
| MIPS | Yes ||
| ARM | Yes |32 bit only|

## How to compile
I don't provide prebuilt binaries yet, these are the steps required to compile REDasm:
```
git clone --recursive https://github.com/Dax89/REDasm.git
cd REDasm
qmake && make
```
**NOTE**: I have compiled and tested it only with GCC compiler on Linux

## Dependencies
- C++11 compiler
- Qt >= 5.6
- [Capstone](https://github.com/aquynh/capstone) 
- [JSON](https://github.com/nlohmann/json)
