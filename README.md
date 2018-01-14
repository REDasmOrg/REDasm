<p align="center">
  <img width=256 height=256 src="https://github.com/Dax89/REDasm/blob/master/artwork/logo.png?raw=true"/><br>
  <a href="https://travis-ci.org/REDasmOrg/REDasm">
    <img src="https://img.shields.io/travis/REDasmOrg/REDasm.svg?style=flat-square&logo=travis">
  </a>
  <a href="https://ci.appveyor.com/project/Dax89/redasm">
    <img src="https://img.shields.io/appveyor/ci/Dax89/redasm.svg?style=flat-square&logo=appveyor">
  </a>
  <a href="https://t.me/REDasm_Disassembler">
    <img src="https://img.shields.io/badge/chat-on%20Telegram-2fade6.svg?style=flat-square">
  </a>
  <img src="https://img.shields.io/badge/license-GPL2-8e725e.svg?style=flat-square">
</p>

***

<p align="center">
  <i>A crossplatform, multiarchitecture disassembler.</i>
  <img height="450" src="https://github.com/REDasmOrg/REDasm/blob/master/artwork/Preview.gif">
</p>

***

REDasm is an interactive, multiarchitecture disassembler written in C++ using Qt5 as UI Framework, its core is light and it can be extended in order to support new instructions and file formats.<br>
In the future, Python scripting will be supported.

## Why another disassembler?
I have created REDasm because I always wanted an human friendly disassembler, like IDA, but free and open source so everyone can use, extend and hack it without any issues/limitations.

## Nightly Builds
Nightly builds are produced by AppVeyor (Windows) and TravisCI (Linux) and they can be downloaded from [here](https://github.com/REDasmOrg/REDasm-Builds).

## Project Status
Currently, these are the supported Formats/Assemblers, I will plan to add it more.

### Supported Formats
| Format | Notes                                        |
|-------:|:---------------------------------------------|
| PE     | VB6 can be decompiled, Delphi support is WIP |
| ELF    |                                              |
| PSX    | PsyQ 4.7 signatures available                |
| Dex    |                                              |

### Supported Assemblers
| Assembler | Backend   | Notes           |
|----------:|:---------:|:----------------|
|  x86      | Capstone  |                 |
|  MIPS     | Capstone  |                 |
|  ARM      | Capstone  |32 bit only      |
|  Dalvik   | REDasm    |                 |
|  CHIP-8   | REDasm    | Just for fun :) |

#### Your Format/Assembler is not available?
Read the [Wiki](https://github.com/REDasmOrg/REDasm/wiki) and send a Pull Request!

## Compilation
These are the steps required to compile REDasm:
```
git clone --recursive https://github.com/REDasmOrg/REDasm.git
cd REDasm
qmake && make
```

## Dependencies & Requirements
- C++11 compiler (tested on GCC 6.x)
- Qt >= 5.6
- [Capstone](https://github.com/aquynh/capstone) 
- [JSON](https://github.com/nlohmann/json)
