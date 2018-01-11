<p align="center">
  <img width=256 height=256 src="https://github.com/Dax89/REDasm/blob/master/artwork/logo.png?raw=true"/><br>
  <a href="https://travis-ci.org/REDasmOrg/REDasm">
    <img src="https://travis-ci.org/REDasmOrg/REDasm.svg?branch=master">
  </a>
  <a href="https://ci.appveyor.com/project/Dax89/redasm">
    <img src="https://ci.appveyor.com/api/projects/status/github/redasmorg/redasm?svg=true">
  </a>
  <a href="https://t.me/REDasm_Disassembler">
    <img src="https://github.com/Patrolavia/telegram-badge/blob/master/chat.svg">
  </a>
</p>

***

<p align="center">
  <i>A crossplatform, multiarchitecture disassembler.</i>
  <img height="450" src="https://github.com/Dax89/REDasm/blob/master/artwork/Screenshot.png?raw=true">
</p>

## Project Status

### Supported Formats
| Format | Notes                                        |
|--------|----------------------------------------------|
| PE     | VB6 can be decompiled, Delphi support is WIP |
| ELF    |                                              |
| PSX    | PsyQ 4.7 signatures available                |
| Dex    |                                              |

### Supported Architectures
| Format | Backend   | Notes          |
|--------|-----------|----------------|
| x86    | Capstone  |                |
| MIPS   | Capstone  |                |
| ARM    | Capstone  |32 bit only     |
| Dalvik | REDasm    |                |
| CHIP-8 | REDasm    | Just for fun :)|

## How to compile
I don't provide prebuilt binaries yet, these are the steps required to compile REDasm:
```
git clone --recursive https://github.com/Dax89/REDasm.git
cd REDasm
qmake && make
```
**NOTE**: I have compiled and tested it only with GCC compiler on Linux

## Dependencies & Requirements
- C++11 compiler (tested on GCC 6.x)
- Qt >= 5.6
- [Capstone](https://github.com/aquynh/capstone) 
- [JSON](https://github.com/nlohmann/json)
