<p align="center">
  <img src="https://raw.githubusercontent.com/REDasmOrg/REDasm/master/artworklogo_readme_20190203.png/"/>
  <p align="center">
    <a href="https://travis-ci.org/REDasmOrg/REDasm">
      <img src="https://img.shields.io/travis/REDasmOrg/REDasm.svg?style=flat-square&logo=travis">
    </a>
    <a href="https://ci.appveyor.com/project/Dax89/redasm">
      <img src="https://img.shields.io/appveyor/ci/Dax89/redasm.svg?style=flat-square&logo=appveyor">
    </a>
    <a href="https://lgtm.com/projects/g/REDasmOrg/REDasm/context:cpp">
      <img alt="Language grade: C/C++" src="https://img.shields.io/lgtm/grade/cpp/g/REDasmOrg/REDasm.svg?logo=lgtm&logoWidth=18">
    </a>
    <img src="https://img.shields.io/badge/license-GPL3-8e725e.svg?style=flat-square">
    <a href="https://github.com/ellerbrock/open-source-badges/">
      <img src="https://badges.frapsoft.com/os/v1/open-source.png?v=103">
    </a>
  </p>
</p>

## Introduction
REDasm is an interactive, multiarchitecture disassembler written in C++ using Qt5 as UI Framework.<br>
Its core is light and simple, it can be extended in order to support new instruction sets and file formats.<br>
In the future, Python scripting will be supported.<br><br>
*Runs on Windows and Linux.*<br>

<p align="center">
  <img height="450" src="https://raw.githubusercontent.com/REDasmOrg/REDasm/master/artwork/Slideshow.gif">
</p>

## Why another Disassembler?
I have designed and programmed REDasm because I always wanted an *easy-to-use* Free and Open Source disassembler that can be compared to IDA.<br>
You can hack, extend and improve REDasm without any issues and limitations.<br>

## Compiling from Source
See [COMPILE.md](COMPILE.md) (for Windows and Linux).

## Compiling from Source with docker
```
cd docker
# create a docker image
./build.sh image
# build REDasm
./build.sh nightly
# remove docker image
./build rm
```
after compiling the binary is in the folder release

## Nightly Builds
Nightly builds are produced by AppVeyor (Windows) and TravisCI (Linux) and they can be downloaded from [here](https://github.com/REDasmOrg/REDasm-Builds).

## Support
* Loaders
  * PE: *VB6 can be decompiled, Delphi support is WIP*
  * ELF
  * PS1 Executables: *PsyQ 4.7 signatures available*
  * Android Dalvik Executables (DEX)
  * XBox1 Executables (XBE)
* Assemblers
  *  x86: *With Capstone backend*
  *  MIPS: *With Capstone backend*
  *  ARM: *32-bit only*
  * Dalvik
  * CHIP-8: *Just for fun :)*

## Contributing
Read the [Wiki](https://github.com/REDasmOrg/REDasm/wiki) and send a Pull Request!

## Requirements
- CMake >= 3.10
- C++11 compiler (tested on GCC 6.x and MSVC2017)
- Qt >= 5.9 LTS

## Dependencies
- [Capstone](https://github.com/aquynh/capstone) : Capstone provides the most common architectures
- [JSON](https://github.com/nlohmann/json): A single header library for JSON
- [D3](https://github.com/d3/d3): Used by QtWebEngine for Graph Rendering
- [Dagre](https://github.com/dagrejs/dagre): Used for Graph Layout
- [Dagre-D3](https://github.com/dagrejs/dagre-d3): Graph Layout Rendering with D3

## License
REDasm is released under GNU GPL3 License.
