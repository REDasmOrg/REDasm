<div align="center">
  <img src="https://raw.githubusercontent.com/REDasmOrg/REDasm/master/artwork/logo_readme_20200905.png"/>
</div>
<br>
<div align="center">
  <a href="https://github.com/REDasmOrg/REDasm/actions?query=workflow%3AREDasm-Builds">
    <img src="https://github.com/REDasmOrg/REDasm/workflows/REDasm-Builds/badge.svg">
  </a>
  <a href="https://lgtm.com/projects/g/REDasmOrg/REDasm/context:cpp">
    <img alt="Language grade: C/C++" src="https://img.shields.io/lgtm/grade/cpp/g/REDasmOrg/REDasm.svg?logo=lgtm&logoWidth=18">
  </a>
  <img src="https://img.shields.io/badge/license-GPL3-8e725e.svg?style=flat-square">
  <a href="https://github.com/ellerbrock/open-source-badges/">
    <img src="https://badges.frapsoft.com/os/v1/open-source.png?v=103">
  </a>
</div>
<h5 align="center">
  <a href="#features">Features</a>
  <span> | </span>
  <a href="https://github.com/REDasmOrg/REDasm/blob/master/COMPILE.md">Compile</a>
  <span> | </span>
  <a href="https://www.reddit.com/r/REDasm">Reddit</a>
  <span> | </span>
  <a href="https://twitter.com/re_dasm">Twitter</a>
  <span> | </span>
  <a href="https://t.me/REDasmDisassembler">Telegram</a>
</h5>
<hr>
REDasm is a cross platform disassembler with a modern codebase useful 
from the hobbyist to the professional reverse engineer.<br>
All features are provided by <a href="https://github.com/REDasmOrg/REDasm-Library/tree/master">LibREDasm</a> which loads
plugins developed in C, C++ and Python3 (you can also support new languages if you want!) and an user friendly Qt frontend.<br>
LibREDasm also provides a plain C API for maximum ABI compatibility along with a C++17 core.<br>
<br>
<p align="right"><i>Tested on Windows and Linux.</i></p>
<p align="center">
  <img src="https://raw.githubusercontent.com/REDasmOrg/REDasm/master/artwork/Preview_20201204.png">
</p>

### Features
REDasm is still under heavy development, currently it supports:
- C++ and Python 3 Plugins
- Multithreaded analysis
- Binary lifting and intermediate language analysis (RDIL)
- *Loaders*
  - Portable Executable (with VB decompilation)
  - ELF
  - XBox 1
  - PS1
- *Assemblers*
  - x86 and x86\_64
  - MIPS
  - ARM64
  - ARM (WIP)
- *More features are under development!*

### Requirements
- CMake 3.12
- C++17 compiler (tested on GCC 10.x and MSVC2019)
- Qt 5.12

### Building from source
Read [here](COMPILE.md)

### Thanks to
- [MiniZ](https://github.com/richgel999/miniz) : ZLib's drop in replacement
- [TaoJSON](https://github.com/taocpp/json): C++ header-only JSON library 
- [UndName](https://github.com/wine-mirror/wine/blob/master/dlls/msvcrt/undname.c): MSVC Demangler
- [Libiberty](https://github.com/bminor/binutils-gdb/tree/master/libiberty): Binutils Demangler
- [Zydis](https://github.com/zyantific/zydis): Fast and lightweight x86/x86-64 disassembler library 
- [Capstone](https://github.com/aquynh/capstone): Disassembler Framework

### License
- *LibREDasm* is released under GNU LGPL3 License
- *REDasm* is released under GNU GPL3 License
